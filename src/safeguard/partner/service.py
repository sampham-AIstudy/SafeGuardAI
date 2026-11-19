"""A bounded partner handoff for the local messaging integration."""

import asyncio
from base64 import b64decode
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
from io import BytesIO
from pathlib import Path

from safeguard.adapters.core import Adapter
from safeguard.detection.execution_host import DetectionOutcome
from safeguard.detection.intake import DetectionRequest
from safeguard.detection.media import IMAGE_SUFFIXES, MediaError, recognize_media
from safeguard.ingress import AccessContext, ConversationIngress, IngressError, InputViolation
from safeguard.memory.conversation_status import ConversationKey, HistoryError
from safeguard.memory.original_assets import AssetError, AssetKey
from safeguard.warning import WarningDecision, WarningPolicy


class PartnerError(ValueError):
    """Public reasons are fixed codes without account or message data."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class PartnerReceipt:
    observed_count: int
    duplicate: bool
    warning: WarningDecision

    def to_dict(self):
        return asdict(self)


def upload_wire_bytes(limits):
    return limits.input.max_bytes + 4 * ((limits.assets.max_file_bytes + 2) // 3)


class PartnerService:
    """Accept one permitted event at a time in arrival order on the owner loop.

    The transport supplies a trusted AccessContext. Initial history uses the
    same event handoff and must finish before sending later events. An event
    ID identifies immutable content within one source/account/conversation.
    """

    def __init__(self, runtime, *, adapter: Adapter, limits, processing_limits, policy: WarningPolicy,
                 outgoing_label: str | None = None):
        self._runtime = runtime
        self._adapter = adapter
        self._limits = limits
        self._wire_limits = replace(limits.input, max_bytes=upload_wire_bytes(limits))
        self._processing = processing_limits
        self._policy = policy
        self._outgoing_label = outgoing_label
        self._admission = asyncio.Lock()

    def _key(self, context, conversation):
        if type(context) is not AccessContext or type(conversation) is not str or conversation not in context.conversations:
            raise PartnerError("conversation_not_allowed")
        return ConversationKey(self._adapter.source, context.account_id, conversation)

    def _snapshot(self, context, key):
        history = self._runtime.memory.observations
        try:
            head = history.head(context, key)
        except HistoryError as error:
            if error.code == "conversation_not_found":
                return None, ()
            raise
        return head, history.snapshot(context, head).messages

    def conversation(self, context, conversation):
        key = self._key(context, conversation)
        head, history = self._snapshot(context, key)
        active = self._active_warning(context, key, history) if head is not None else None
        messages = []
        for number, message in enumerate(history, 1):
            attachments = []
            for index, asset in enumerate(message["assets"], 1):
                filename = asset["filename"]
                attachment = {"id": asset["asset_id"], "filename": filename}
                if Path(filename or "").suffix.lower() in IMAGE_SUFFIXES:
                    attachment["preview_url"] = f"/api/conversations/{conversation}/images/{head.store_id}/{number}/{index}"
                attachments.append(attachment)
            messages.append({"id": message["message_id"],
                             "author": self._outgoing_label if self._outgoing(message) else message["sender_id"],
                             "parts": message["content_parts"], "attachments": attachments})
        return {"messages": messages, "active_warning": None if active is None else asdict(active)}

    def image_preview(self, context, conversation, store_id, number, index):
        head, history = self._snapshot(context, self._key(context, conversation))
        if head is None or head.store_id != store_id or not 1 <= number <= len(history):
            raise PartnerError("image_not_found")
        message = history[number - 1]
        if not 1 <= index <= len(message["assets"]):
            raise PartnerError("image_not_found")
        asset = message["assets"][index - 1]
        if Path(asset["filename"] or "").suffix.lower() not in IMAGE_SUFFIXES:
            raise PartnerError("image_not_found")
        try:
            data = self._runtime.originals.read(context, AssetKey.from_message(message, asset["asset_id"]))
            media_type = recognize_media(data)
        except (AssetError, MediaError) as error:
            raise PartnerError("image_not_found") from error
        if media_type not in {"image/png", "image/jpeg"}:
            raise PartnerError("image_not_found")
        return media_type, data

    def _outgoing(self, message):
        return self._outgoing_label is not None and (message["is_from_observed_account"]
                                                    or message["sender_id"] == self._outgoing_label)

    def _active_warning(self, context, key, history):
        active = self._policy.current(context, key)
        if active and any(self._outgoing(history[ref.observation_number - 1]) for ref in active.supporting):
            return None
        return active

    def _event(self, raw, key):
        try:
            event = self._wire_limits.decode(raw)
        except InputViolation as error:
            raise PartnerError("invalid_event") from error
        if (type(event) is not dict or set(event) - {"id", "author", "body", "attachment"}
                or any(type(event.get(field)) is not str or not event[field].strip() for field in ("id", "author"))
                or type(event.get("body")) is not str):
            raise PartnerError("invalid_event")
        author = key.account_id if event["author"] == self._outgoing_label else event["author"]
        native = {"thread": key.conversation_id, "id": event["id"], "author": author}
        if "attachment" not in event:
            if not event["body"].strip():
                raise PartnerError("invalid_event")
            return dict(native, body=event["body"]), None
        attachment = event["attachment"]
        if (type(attachment) is not dict or set(attachment) != {"id", "filename", "base64"}
                or any(type(attachment[field]) is not str for field in attachment)
                or not attachment["id"].strip() or not attachment["filename"].strip()):
            raise PartnerError("invalid_attachment")
        maximum = self._limits.assets.max_file_bytes
        if len(attachment["base64"]) > 4 * ((maximum + 2) // 3):
            raise PartnerError("attachment_too_large")
        try:
            data = b64decode(attachment["base64"], validate=True)
        except ValueError as error:
            raise PartnerError("invalid_attachment") from error
        if len(data) > maximum:
            raise PartnerError("attachment_too_large")
        ident = attachment["id"]
        parts = [{"kind": "text", "text": event["body"]}] if event["body"].strip() else []
        parts.append({"kind": "file", "asset_id": ident})
        native.update(content_parts=parts,
                      assets=[{"asset_id": ident, "filename": attachment["filename"], "declared_size_bytes": len(data)}])
        return native, data

    def _duplicate(self, context, head, history, native, data):
        for number, observed in enumerate(history, 1):
            if observed["message_id"] != native["id"]:
                continue
            original = observed["raw_payload"]
            if self._outgoing(observed) and native["author"] == context.account_id:
                original = dict(original, author=context.account_id)
            if original != native:
                raise PartnerError("event_conflict")
            if data is not None:
                try:
                    receipt = self._runtime.originals.describe(context, AssetKey.from_message(observed, native["assets"][0]["asset_id"]))
                except AssetError as error:
                    raise PartnerError("original_unavailable") from error
                if receipt.sha256 != sha256(data).hexdigest():
                    raise PartnerError("event_conflict")
            active = self._active_warning(context, head.key, history)
            if self._outgoing(observed):
                warning = WarningDecision("no_action", "outgoing_message", active)
            elif number == head.observed_count:
                snapshot = self._runtime.memory.detector.snapshot(context, head)
                result = next((record for record in snapshot.records if record.record_id == "latest" and record.boundary == head), None)
                if result is None:
                    warning = WarningDecision("unavailable", "assessment_not_committed", active)
                else:
                    view = result.payload()
                    warning = self._policy.apply(DetectionRequest(head, context), DetectionOutcome(view["status"], view["code"], result.payload_json))
            else:
                warning = WarningDecision("no_action", "duplicate_event", active)
            return PartnerReceipt(head.observed_count, True, warning)
        return None

    async def submit(self, context, conversation, raw):
        key = self._key(context, conversation)
        native, data = self._event(raw, key)
        async with self._admission:
            head, history = self._snapshot(context, key)
            duplicate = self._duplicate(context, head, history, native, data)
            if duplicate is not None:
                return duplicate
            return await self._accept(context, native, data, key)

    async def _accept(self, context, native, data, key):
        runtime = self._runtime
        decisions = []

        async def consume(snapshot):
            head = runtime.memory.observations.head(context, key)
            if head.observed_count != snapshot.observed_count:
                raise PartnerError("observation_boundary_changed")
            if self._outgoing(snapshot.messages[-1]):
                active = self._active_warning(context, key, snapshot.messages)
                decisions.append(WarningDecision("no_action", "outgoing_message", active))
                return
            request = DetectionRequest(head, context)
            result = await runtime.detection.run(request)
            decisions.append(self._policy.apply(request, result))

        outcome = None
        try:
            async with ConversationIngress(consume, input_limits=self._limits.input,
                    processing_limits=self._processing, adapter=self._adapter, intake=runtime.detection.host.intake) as ingress:
                try:
                    if data is None:
                        ticket = ingress.submit(native, context)
                    else:
                        ident = native["assets"][0]["asset_id"]
                        with BytesIO(data) as stream:
                            ticket = ingress.submit_files(native, {ident: stream}, context, store=runtime.originals)
                except IngressError as error:
                    raise PartnerError("event_rejected") from error
                outcome = await ticket.wait()
        except IngressError as error:
            if outcome is None or outcome.status == "completed" or error.code != "run_failed":
                raise PartnerError("processing_unavailable") from error
        head = runtime.memory.observations.head(context, key)
        if outcome.status != "completed":
            active = self._policy.current(context, key)
            return PartnerReceipt(head.observed_count, False, WarningDecision("unavailable", "processing_failed", active))
        return PartnerReceipt(head.observed_count, False, decisions[0])
