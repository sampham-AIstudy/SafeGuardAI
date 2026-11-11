"""Bounded local ingress; serialized consumers per scoped conversation."""

import asyncio
from collections import Counter, deque
from dataclasses import dataclass, fields
import inspect
import logging
import math
from uuid import uuid4

from safeguard.adapters import Adapter, AdapterError
from safeguard.original_assets import AssetError, AssetKey, LocalAssetStore
from safeguard.conversation_memory import HistoryError
from safeguard.scam_detection.intake import DetectionIntake
from .limits import InputLimits, InputViolation


LOG = logging.getLogger("safeguard.ingress")


class IngressError(ValueError):
    """Public fixed reasons; never include message/exception text."""

    def __init__(self, stage, code):
        self.stage, self.code = stage, code
        super().__init__(stage+": "+code)


@dataclass(frozen=True, slots=True)
class AccessContext:
    """Trusted-host permission snapshot; this is not authentication proof."""
    account_id: str
    conversations: frozenset[str]

    def __post_init__(self):
        if type(self.account_id) is not str or not self.account_id.strip():
            raise IngressError("authorization", "invalid_context")
        if type(self.conversations) is not frozenset or any(type(v) is not str or not v.strip() for v in self.conversations):
            raise IngressError("authorization", "invalid_context")


@dataclass(frozen=True, slots=True)
class ProcessingLimits:
    workers: int
    max_pending: int
    max_pending_bytes: int
    per_account: int
    per_conversation: int
    consumer_timeout: float

    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)
            if field.name == "consumer_timeout":
                if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                    raise ValueError("Consumer timeout must be positive and finite")
            elif type(value) is not int or value <= 0:
                raise ValueError("Processing limits must be positive integers")


@dataclass(frozen=True, slots=True)
class Outcome:
    trace_id: str
    status: str
    stage: str
    code: str
    queue_seconds: float
    processing_seconds: float
    total_seconds: float


@dataclass(frozen=True, slots=True)
class Ticket:
    _future: asyncio.Future

    async def wait(self) -> Outcome:
        # Cancelling a waiter does not silently cancel an admitted message.
        return await asyncio.shield(self._future)


@dataclass(slots=True)
class _Job:
    message: object
    size: int
    trace: str
    received: float
    enqueued: float
    future: asyncio.Future


class ConversationIngress:
    """One event-loop-owned pipeline, with no deployment limit defaults.

    Consumer must be cooperative async, return None, and honor cancellation.
    Its effects may be uncertain after a failure/timeout; no automatic replay.
    Capacity includes running work. Native-byte budget is not a hard RSS cap.
    """

    def __init__(self, consumer, *, input_limits: InputLimits, processing_limits: ProcessingLimits, adapter: Adapter, intake=None):
        if type(input_limits) is not InputLimits or type(processing_limits) is not ProcessingLimits:
            raise IngressError("configuration", "invalid_limits")
        if type(adapter) is not Adapter:
            raise IngressError("configuration", "invalid_adapter")
        if intake is not None and type(intake) is not DetectionIntake:
            raise IngressError("configuration", "invalid_intake")
        if not (inspect.iscoroutinefunction(consumer) or inspect.iscoroutinefunction(getattr(consumer, "__call__", None))):
            raise IngressError("configuration", "expected_async_consumer")
        self.consumer, self.input_limits, self.limits, self.adapter = consumer, input_limits, processing_limits, adapter
        self.intake = intake
        self._state = "new"
        self._queues = {}
        self._active = set()
        self._blocked = set()
        self._accounts = Counter()
        self._key_counts = Counter()
        self._stats = dict(admitted=0, completed=0, failed=0, blocked=0, cancelled=0, rejected=0,
                           pending=0, pending_bytes=0, active=0, peak_pending=0, peak_pending_bytes=0, peak_active=0)
        self._had_failure = False

    async def __aenter__(self):
        if self._state != "new":
            raise IngressError("lifecycle", "already_started")
        self._loop = asyncio.get_running_loop()
        self._ready = asyncio.Queue(maxsize=self.limits.max_pending)
        self._drained = asyncio.Event()
        self._drained.set()
        self._state = "open"
        self._workers = [asyncio.create_task(self._worker()) for _ in range(self.limits.workers)]
        return self

    def _owned(self):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            raise IngressError("lifecycle", "wrong_event_loop") from None
        if self._state != "open" or loop is not self._loop:
            raise IngressError("lifecycle", "not_open")

    @property
    def stats(self):
        return dict(self._stats, tracked_conversations=len(self._queues)+len(self._blocked))

    @staticmethod
    def _audit(trace, status, stage, code, *, size=None, elapsed=None):
        LOG.info("ingress_event trace=%s status=%s stage=%s code=%s bytes=%s elapsed_seconds=%s",
                 trace, status, stage, code, size, elapsed)

    def _reject(self, trace, stage, code):
        self._stats["rejected"] += 1
        self._audit(trace, "rejected", stage, code)
        raise IngressError(stage, code) from None

    def _capacity(self, trace):
        if self._stats["pending"] >= self.limits.max_pending:
            self._reject(trace, "admission", "busy")

    def submit(self, native, context: AccessContext) -> Ticket:
        return self._submit(native, context, raw=False)

    def submit_json(self, raw: bytes, context: AccessContext) -> Ticket:
        return self._submit(raw, context, raw=True)

    def submit_files(self, native, uploads: dict, context: AccessContext, *, store: LocalAssetStore) -> Ticket:
        """Admit metadata plus cooperative binary streams; disk IO is synchronous.

        New originals remain until explicit host deletion/store close, including
        after consumer failure. Caller owns streams. No content reader is run.
        """
        return self._submit(native, context, raw=False, uploads=uploads, store=store, files=True)

    def _submit(self, value, context, *, raw, uploads=None, store=None, files=False):
        self._owned()
        trace, received = uuid4().hex, self._loop.time()
        if type(context) is not AccessContext:
            self._reject(trace, "authorization", "trusted_context_required")
        self._capacity(trace)
        try:
            native = self.input_limits.decode(value) if raw else value
            size = self.input_limits.inspect(native)
        except InputViolation as error:
            self._reject(trace, "input", error.code)
        if raw:
            size = max(size, len(value))
        try:
            key = self.adapter.conversation_key(native, context.account_id)
        except AdapterError as error:
            self._reject(trace, error.stage, error.code)
        if key[2] not in context.conversations:
            self._reject(trace, "authorization", "conversation_not_allowed")
        if key in self._blocked:
            self._reject(trace, "admission", "conversation_failed")
        if key not in self._queues and len(self._queues)+len(self._blocked) >= self.limits.max_pending:
            self._reject(trace, "admission", "conversation_capacity")
        if self._accounts[context.account_id] >= self.limits.per_account or self._key_counts[key] >= self.limits.per_conversation:
            self._reject(trace, "admission", "scope_busy")
        if self._stats["pending_bytes"]+size > self.limits.max_pending_bytes:
            self._reject(trace, "admission", "byte_capacity")
        try:
            message = self.adapter.receive(native, account_id=context.account_id, conversation_id=key[2])
        except AdapterError as error:
            self._reject(trace, error.stage, error.code)
        try:
            self.input_limits.inspect_content(message)
        except InputViolation as error:
            self._reject(trace, "normalizer", error.code)
        if files and self.intake is not None:
            try:
                self.intake.check(message, context)
            except HistoryError as error:
                self._reject(trace, "engine_intake", error.code)
        stored = ()
        if files:
            if type(store) is not LocalAssetStore or type(uploads) is not dict:
                self._reject(trace, "assets", "invalid_uploads")
            ids = [a["asset_id"] for a in message["assets"]]
            if set(uploads) != set(ids) or not ids:
                self._reject(trace, "assets", "upload_reference_mismatch")
            try:
                stored = store.put_batch(context, {AssetKey.from_message(message, asset_id): uploads[asset_id] for asset_id in ids})
            except AssetError as error:
                self._reject(trace, "assets", error.code)
        if self.intake is not None:
            try:
                message = self.intake.record(message, context)
            except HistoryError as error:
                try:
                    for receipt in stored:
                        store.delete(context, receipt.key)
                except AssetError:
                    self._reject(trace, "assets", "cleanup_failed")
                self._reject(trace, "engine_intake", error.code)
        job = _Job(message, size, trace, received, self._loop.time(), self._loop.create_future())
        if key not in self._queues:
            self._queues[key] = deque()
            self._ready.put_nowait(key)
        self._queues[key].append(job)
        self._accounts[context.account_id] += 1
        self._key_counts[key] += 1
        self._stats["pending"] += 1
        self._stats["pending_bytes"] += size
        self._stats["admitted"] += 1
        for name in ("pending", "pending_bytes"):
            self._stats["peak_"+name] = max(self._stats["peak_"+name], self._stats[name])
        self._drained.clear()
        self._audit(trace, "admitted", "admission", "ok", size=size, elapsed=self._loop.time()-received)
        return Ticket(job.future)

    def acknowledge_failure(self, context: AccessContext, conversation_id: str):
        """Host explicitly resolves uncertain prior effects; does not replay work."""
        self._owned()
        if type(context) is not AccessContext or type(conversation_id) is not str or conversation_id not in context.conversations:
            raise IngressError("authorization", "conversation_not_allowed")
        self._blocked.discard((self.adapter.source, context.account_id, conversation_id))

    def _finish(self, key, job, status, stage, code, started=None):
        now = self._loop.time()
        start = started if started is not None else now
        outcome = Outcome(job.trace, status, stage, code, start-job.enqueued,
                          now-start, now-job.received)
        job.future.set_result(outcome)
        self._stats[status] += 1
        self._stats["pending"] -= 1
        self._stats["pending_bytes"] -= job.size
        for counter, scope in ((self._accounts, key[1]), (self._key_counts, key)):
            counter[scope] -= 1
            if counter[scope] == 0:
                del counter[scope]
        self._audit(job.trace, status, stage, code, size=job.size, elapsed=outcome.total_seconds)
        if self._stats["pending"] == 0:
            self._drained.set()

    async def _worker(self):
        while self._state in ("open", "closing"):
            key = await self._ready.get()
            try:
                await self._process(key)
            finally:
                self._ready.task_done()

    async def _process(self, key):
        job = self._queues[key].popleft()
        started = self._loop.time()
        self._active.add(key)
        self._stats["active"] += 1
        self._stats["peak_active"] = max(self._stats["peak_active"], self._stats["active"])
        status, stage, code = "completed", "consumer", "ok"
        try:
            try:
                payload = self.intake.snapshot(job.message) if self.intake is not None else job.message
            except HistoryError:
                status, stage, code = "failed", "engine_intake", "snapshot_failed"
            if status == "completed":
                returned = await asyncio.wait_for(self.consumer(payload), self.limits.consumer_timeout)
                if returned is not None:
                    status, code = "failed", "invalid_consumer_return"
        except asyncio.CancelledError:
            status, code = ("cancelled", "shutdown") if self._state == "aborting" else ("failed", "consumer_cancelled")
        except TimeoutError:
            status, code = "failed", "consumer_timeout"
        except Exception:
            status, code = "failed", "consumer_failed"
        self._active.remove(key)
        self._stats["active"] -= 1
        self._finish(key, job, status, stage, code, started)
        if status != "completed":
            self._had_failure = True
            self._blocked.add(key)
            while self._queues[key]:
                self._finish(key, self._queues[key].popleft(), "blocked", "consumer", "prior_failure")
        if self._queues[key]:
            self._ready.put_nowait(key)
        else:
            del self._queues[key]

    async def drain(self):
        self._owned()
        await self._drained.wait()
        if self._had_failure:
            raise IngressError("processing", "run_failed")

    async def _abort(self):
        self._state = "aborting"
        for task in self._workers:
            task.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        for key, jobs in list(self._queues.items()):
            while jobs:
                self._finish(key, jobs.popleft(), "cancelled", "lifecycle", "shutdown")
        self._queues.clear()

    async def __aexit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self._state = "closing"
                try:
                    await self._drained.wait()
                    if self._had_failure:
                        raise IngressError("processing", "run_failed")
                finally:
                    await self._abort()
            else:
                await self._abort()
        finally:
            self._state = "closed"
