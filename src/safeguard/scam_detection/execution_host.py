"""Common scoped execution envelope; no workflow, agent or model implementation."""

import asyncio
from dataclasses import asdict, dataclass, field, fields
import hashlib
import inspect
import json
import math
import re
import time
from uuid import uuid4

from safeguard.memory.conversation_status import HistoryError
from safeguard.scam_detection.context import ContextError, ContextPreparer, PreparedContext
from safeguard.scam_detection.tools.evidence import PartReference
from safeguard.scam_detection.intake import DetectionIntake, DetectionRequest


_NAME = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


class ExecutionError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _async_callable(value):
    return callable(value) and (inspect.iscoroutinefunction(value) or inspect.iscoroutinefunction(getattr(value, "__call__", None)))


def _identity(name, version):
    if type(name) is not str or not _NAME.fullmatch(name) or type(version) is not str or not _VERSION.fullmatch(version):
        raise ExecutionError("invalid_identity")


def _same_json(left, right):
    """JSON types matter: Python equates booleans, integers and some floats."""
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return all(type(key) is str for key in left) and left.keys() == right.keys() and all(_same_json(left[key], right[key]) for key in left)
    if type(left) is list:
        return len(left) == len(right) and all(_same_json(a, b) for a, b in zip(left, right))
    return left == right


@dataclass(frozen=True, slots=True)
class ExecutionLimits:
    max_context_bytes: int
    max_state_bytes: int
    max_argument_bytes: int
    max_capability_result_bytes: int
    max_assessment_bytes: int
    max_result_bytes: int
    max_calls: int
    max_model_calls: int
    max_inflight_calls: int
    max_references: int
    max_json_depth: int
    max_json_nodes: int
    timeout_seconds: float

    def __post_init__(self):
        for item in fields(self):
            value = getattr(self, item.name)
            if item.name == "timeout_seconds":
                if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                    raise ValueError("Execution timeout must be positive and finite")
            elif type(value) is not int or value < (0 if item.name in ("max_calls", "max_model_calls", "max_references") else 1):
                raise ValueError("Invalid execution limit")


@dataclass(frozen=True, slots=True)
class TokenUsage:
    input_tokens: int | None
    output_tokens: int | None

    def __post_init__(self):
        if any(value is not None and (type(value) is not int or value < 0) for value in (self.input_tokens, self.output_tokens)):
            raise ExecutionError("invalid_token_usage")


@dataclass(frozen=True, slots=True)
class CapabilityReply:
    json_bytes: bytes = field(repr=False)
    tokens: TokenUsage | None = None


@dataclass(frozen=True, slots=True)
class CapabilitySpec:
    name: str
    version: str
    kind: str
    execute: object = field(repr=False, compare=False)

    def __post_init__(self):
        _identity(self.name, self.version)
        if self.kind not in ("tool", "model") or not _async_callable(self.execute):
            raise ExecutionError("invalid_capability")


@dataclass(frozen=True, slots=True)
class CapabilityIdentity:
    name: str
    version: str
    kind: str


@dataclass(frozen=True, slots=True)
class ControllerSpec:
    name: str
    version: str
    execute: object = field(repr=False, compare=False)

    def __post_init__(self):
        _identity(self.name, self.version)
        if not _async_callable(self.execute):
            raise ExecutionError("invalid_strategy")


@dataclass(frozen=True, slots=True)
class AssessmentProfile:
    name: str
    version: str
    validate: object = field(repr=False, compare=False)

    def __post_init__(self):
        _identity(self.name, self.version)
        if not callable(self.validate) or _async_callable(self.validate):
            raise ExecutionError("invalid_profile")


@dataclass(frozen=True, slots=True)
class ControllerReply:
    assessment_json: bytes | None = field(repr=False)
    supporting: tuple[PartReference, ...] = ()
    counter: tuple[PartReference, ...] = ()
    unresolved: tuple[PartReference, ...] = ()
    unavailable_code: str | None = None


@dataclass(frozen=True, slots=True)
class DetectionInvocation:
    run_id: str
    prepared: PreparedContext
    initial_state_json: bytes = field(repr=False)
    capabilities: tuple[CapabilityIdentity, ...]
    limits: ExecutionLimits


@dataclass(frozen=True, slots=True)
class CapabilityScope:
    prepared: PreparedContext
    access: object = field(repr=False)
    initial_state_json: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class DetectionOutcome:
    status: str
    code: str
    json_bytes: bytes = field(repr=False)

    def to_dict(self):
        return json.loads(self.json_bytes)


class DetectionCancelled(asyncio.CancelledError):
    """Cancellation remains cancellation; a host can inspect its terminal outcome."""

    def __init__(self, outcome, result_error=None):
        self.outcome = outcome
        self.result_error = result_error
        super().__init__("engine_cancelled")


class CapabilitySession:
    """One loop-owned invocation; provider tasks are tracked and cooperatively closed."""

    def __init__(self, scope, capabilities, limits, decode):
        self._scope, self._capabilities, self._limits, self._decode = scope, capabilities, limits, decode
        self._open = True
        self._slots = asyncio.Semaphore(limits.max_inflight_calls)
        self._tasks, self._callers, self._events = set(), set(), []
        self._attempts = self._calls = self._model_calls = 0
        self._limit_code = None

    async def call(self, name: str, arguments_json: bytes) -> bytes:
        if not self._open:
            raise ExecutionError("session_closed")
        self._attempts += 1
        if self._attempts > self._limits.max_calls:
            self._limit_code = "call_limit"
        if self._limit_code:
            raise ExecutionError(self._limit_code)
        spec = self._capabilities.get(name) if type(name) is str else None
        event = dict(capability=None if spec is None else spec.name, kind=None if spec is None else spec.kind,
                     status="rejected", code="capability_not_allowed", invoked=False, elapsed_ns=0,
                     input_tokens=None, output_tokens=None, result_sha256=None)
        self._events.append(event)
        if spec is None:
            raise ExecutionError("capability_not_allowed")
        if type(arguments_json) is bytes and len(arguments_json) > self._limits.max_argument_bytes:
            self._limit_code = event["code"] = "argument_limit"
            raise ExecutionError("argument_limit")
        try:
            arguments = self._decode(arguments_json, self._limits.max_argument_bytes, "invalid_arguments")
        except ExecutionError:
            event["code"] = "invalid_arguments"
            raise
        caller = asyncio.current_task()
        self._callers.add(caller)
        task = asyncio.create_task(self._invoke(spec, arguments, event))
        self._tasks.add(task)
        try:
            return await task
        finally:
            self._tasks.discard(task)
            self._callers.discard(caller)

    async def _invoke(self, spec, arguments, event):
        started = time.perf_counter_ns()
        try:
            async with self._slots:
                if not self._open:
                    raise ExecutionError("session_closed")
                if self._limit_code:
                    raise ExecutionError(self._limit_code)
                if spec.kind == "model" and self._model_calls >= self._limits.max_model_calls:
                    self._limit_code = "model_call_limit"
                    raise ExecutionError("model_call_limit")
                self._calls += 1
                self._model_calls += spec.kind == "model"
                event["invoked"] = True
                try:
                    reply = await spec.execute(self._scope, arguments)
                except Exception:
                    raise ExecutionError("capability_failed") from None
                if inspect.iscoroutine(reply):
                    reply.close()
                if type(reply) is not CapabilityReply or type(reply.json_bytes) is not bytes:
                    raise ExecutionError("invalid_capability_result")
                if spec.kind == "model" and type(reply.tokens) is TokenUsage:
                    event.update(input_tokens=reply.tokens.input_tokens, output_tokens=reply.tokens.output_tokens)
                elif reply.tokens is not None:
                    raise ExecutionError("invalid_capability_result")
                if len(reply.json_bytes) > self._limits.max_capability_result_bytes:
                    self._limit_code = "capability_result_limit"
                    raise ExecutionError("capability_result_limit")
                self._decode(reply.json_bytes, self._limits.max_capability_result_bytes, "invalid_capability_result")
                event.update(status="completed", code="ok", result_sha256=hashlib.sha256(reply.json_bytes).hexdigest())
                return reply.json_bytes
        except asyncio.CancelledError:
            event.update(status="cancelled", code="cancelled")
            raise
        except ExecutionError as error:
            event.update(status="failed", code=error.code)
            raise
        finally:
            event["elapsed_ns"] = time.perf_counter_ns() - started

    def pending(self):
        return bool(self._tasks or self._callers)

    async def close(self):
        self._open = False
        current = asyncio.current_task()
        tasks = (self._tasks | self._callers) - {current}
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def usage(self, elapsed_ns):
        models = [e for e in self._events if e["invoked"] and e["kind"] == "model"]
        totals = {name: None if any(e[name] is None for e in models) else sum(e[name] for e in models)
                  for name in ("input_tokens", "output_tokens")}
        return dict(attempted_calls=self._attempts, capability_calls=self._calls, model_calls=self._model_calls,
                    **totals, token_usage_complete=all(v is not None for v in totals.values()),
                    measurement_scope="registered_capabilities_only", elapsed_ns=elapsed_ns,
                    calls=[dict(e) for e in self._events])


class ExecutionHost:
    def __init__(self, *, intake: DetectionIntake, preparer: ContextPreparer, limits: ExecutionLimits,
                 capabilities: tuple[CapabilitySpec, ...], profile: AssessmentProfile):
        if type(intake) is not DetectionIntake or type(preparer) is not ContextPreparer or type(limits) is not ExecutionLimits or type(profile) is not AssessmentProfile:
            raise ExecutionError("invalid_configuration")
        if type(capabilities) is not tuple or any(type(c) is not CapabilitySpec for c in capabilities) or len({c.name for c in capabilities}) != len(capabilities):
            raise ExecutionError("invalid_configuration")
        self.intake, self.preparer, self.limits, self.profile = intake, preparer, limits, profile
        self._capabilities = {c.name: c for c in capabilities}

    def _decode(self, raw, limit, code):
        from safeguard.ingress.limits import InputLimits, InputViolation

        if type(raw) is not bytes or len(raw) > limit:
            raise ExecutionError(code)
        limits = InputLimits(limit, limit, self.limits.max_json_depth, self.limits.max_json_nodes, limit, limit)
        try:
            document = limits.decode(raw)
            limits.inspect(document)
        except InputViolation:
            raise ExecutionError(code) from None
        if type(document) is not dict:
            raise ExecutionError(code)
        return document

    async def run(self, request: DetectionRequest, *, strategy: ControllerSpec, allowed_capabilities: frozenset[str],
                  initial_state_json: bytes) -> DetectionOutcome:
        if type(request) is not DetectionRequest or type(strategy) is not ControllerSpec:
            raise ExecutionError("invalid_request")
        if type(allowed_capabilities) is not frozenset or not allowed_capabilities <= self._capabilities.keys():
            raise ExecutionError("invalid_capability_grants")
        self._decode(initial_state_json, self.limits.max_state_bytes, "invalid_initial_state")
        try:
            prepared = self.preparer.prepare(self.intake.snapshot(request), request.context)
        except (HistoryError, ContextError):
            raise ExecutionError("request_rejected") from None
        if len(prepared.json_bytes) > self.limits.max_context_bytes:
            raise ExecutionError("context_limit")
        identities = tuple(CapabilityIdentity(c.name, c.version, c.kind) for c in
                           (self._capabilities[name] for name in sorted(allowed_capabilities)))
        invocation = DetectionInvocation(uuid4().hex, prepared, initial_state_json, identities, self.limits)
        session = CapabilitySession(CapabilityScope(prepared, request.context, initial_state_json),
                                    {name: self._capabilities[name] for name in allowed_capabilities}, self.limits, self._decode)
        status, code, validated = "failed", "strategy_failed", None
        started = time.perf_counter_ns()
        timer = asyncio.timeout(self.limits.timeout_seconds)
        try:
            async with timer:
                reply = await strategy.execute(invocation, session)
                if session.pending():
                    code = "unfinished_capabilities"
                else:
                    try:
                        validated = self._validate_reply(reply, prepared)
                        status, code = ("completed", "ok") if reply.assessment_json is not None else ("unavailable", reply.unavailable_code)
                    except ExecutionError as error:
                        status = "limited" if error.code in ("assessment_limit", "reference_limit") else "failed"
                        code = error.code
        except asyncio.CancelledError:
            status, code = "cancelled", "cancelled"
        except TimeoutError:
            status, code = ("timeout", "deadline_exceeded") if timer.expired() else ("failed", "strategy_failed")
        except Exception:
            status, code = "failed", "strategy_failed"
        finally:
            await session.close()
        if timer.expired() and status != "cancelled":
            status, code = "timeout", "deadline_exceeded"
        elif session._limit_code and status != "cancelled":
            status, code = "limited", session._limit_code
        usage = session.usage(time.perf_counter_ns() - started)
        try:
            outcome = self._outcome(invocation, strategy, status, code, validated, usage)
        except ExecutionError as error:
            if status == "cancelled":
                raise DetectionCancelled(None, error.code) from None
            if error.code != "result_byte_limit" or status != "completed":
                raise
            outcome = self._outcome(invocation, strategy, "limited", "result_byte_limit", None, usage)
        if status == "cancelled":
            raise DetectionCancelled(outcome) from None
        return outcome

    def _validate_reply(self, reply, prepared):
        if inspect.iscoroutine(reply):
            reply.close()
        if type(reply) is not ControllerReply:
            raise ExecutionError("invalid_strategy_reply")
        groups = (reply.supporting, reply.counter, reply.unresolved)
        if any(type(group) is not tuple for group in groups):
            raise ExecutionError("invalid_reference")
        if sum(map(len, groups)) > self.limits.max_references:
            raise ExecutionError("reference_limit")
        document = prepared.to_dict()
        for group in groups:
            for ref in group:
                if type(ref) is not PartReference or ref.observation_number > prepared.observed_count:
                    raise ExecutionError("invalid_reference")
                parts = document["messages"][ref.observation_number - 1]["content_parts"]
                if ref.part_index >= len(parts):
                    raise ExecutionError("invalid_reference")
        if reply.assessment_json is None:
            if reply.unavailable_code not in ("no_usable_input", "unsupported_input", "incomplete") or reply.supporting or reply.counter:
                raise ExecutionError("invalid_strategy_reply")
            assessment = None
        else:
            if reply.unavailable_code is not None:
                raise ExecutionError("invalid_strategy_reply")
            if type(reply.assessment_json) is bytes and len(reply.assessment_json) > self.limits.max_assessment_bytes:
                raise ExecutionError("assessment_limit")
            assessment = self._decode(reply.assessment_json, self.limits.max_assessment_bytes, "invalid_assessment")
            view = json.loads(reply.assessment_json)
            try:
                returned = self.profile.validate(view)
                if inspect.iscoroutine(returned):
                    returned.close()
                if returned is not None or not _same_json(view, assessment):
                    raise ValueError()
            except Exception:
                raise ExecutionError("invalid_assessment") from None
        return dict(assessment=assessment, supporting=[asdict(r) for r in reply.supporting],
                    counter=[asdict(r) for r in reply.counter], unresolved=[asdict(r) for r in reply.unresolved])

    def _outcome(self, invocation, strategy, status, code, validated, usage):
        prepared = invocation.prepared
        usable = validated if status in ("completed", "unavailable") else None
        payload = dict(engine_result_schema_version="1.0", run_id=invocation.run_id,
                       source=prepared.key.source, account_id=prepared.key.account_id,
                       conversation_id=prepared.key.conversation_id, observed_count=prepared.observed_count,
                       context_sha256=hashlib.sha256(prepared.json_bytes).hexdigest(),
                       initial_state_sha256=hashlib.sha256(invocation.initial_state_json).hexdigest(),
                       strategy=dict(name=strategy.name, version=strategy.version),
                       assessment_profile=dict(name=self.profile.name, version=self.profile.version),
                       status=status, code=code, assessment=None if usable is None else usable["assessment"],
                       supporting=[] if usable is None else usable["supporting"], counter=[] if usable is None else usable["counter"],
                       unresolved=[] if usable is None else usable["unresolved"],
                       input_coverage=prepared.to_dict()["coverage"], usage=usage)
        encoded = bytearray()
        for chunk in json.JSONEncoder(ensure_ascii=False, allow_nan=False, separators=(",", ":")).iterencode(payload):
            data = chunk.encode("utf-8")
            if len(data) > self.limits.max_result_bytes - len(encoded):
                raise ExecutionError("result_byte_limit")
            encoded.extend(data)
        return DetectionOutcome(status, code, bytes(encoded))
