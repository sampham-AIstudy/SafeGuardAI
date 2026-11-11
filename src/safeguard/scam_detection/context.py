"""Prepare bounded, source-anchored context without readers, models or IO."""

from dataclasses import dataclass, field, fields
import json

from safeguard.conversation_memory import ConversationKey, HistorySnapshot
from safeguard.adapters.norm import NormalizationError, normalize


_JSON = dict(ensure_ascii=False, allow_nan=False, separators=(",", ":"))


class ContextError(ValueError):
    """Fixed reasons without message text, native keys or scoped identifiers."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ContextLimits:
    max_messages: int
    max_input_bytes: int
    max_output_bytes: int
    max_text_chars: int
    max_content_parts: int
    max_assets: int

    def __post_init__(self):
        if any(type(getattr(self, f.name)) is not int or getattr(self, f.name) <= 0 for f in fields(self)):
            raise ValueError("Context limits must be positive integers")


@dataclass(frozen=True, slots=True)
class ContextStats:
    input_json_bytes: int
    output_json_bytes: int
    text_chars: int
    content_parts: int
    assets: int


@dataclass(frozen=True, slots=True)
class PreparedContext:
    """Immutable generated document; decoded views belong to the receiver.

    References are positions within this document, not globally unique evidence
    identities or access capabilities. Construct through ContextPreparer.
    """

    key: ConversationKey
    observed_count: int
    json_bytes: bytes = field(repr=False)
    stats: ContextStats

    def to_dict(self) -> dict:
        return json.loads(self.json_bytes)

    def resolve_part(self, source_ref: dict) -> dict:
        """Resolve a local reference, returning a fresh detached part."""
        if type(source_ref) is not dict or set(source_ref) != {"observation_number", "part_index"}:
            raise ContextError("invalid_source_ref")
        number, index = source_ref["observation_number"], source_ref["part_index"]
        if type(number) is not int or type(index) is not int or not 1 <= number <= self.observed_count or index < 0:
            raise ContextError("invalid_source_ref")
        parts = self.to_dict()["messages"][number - 1]["content_parts"]
        if index >= len(parts):
            raise ContextError("invalid_source_ref")
        return parts[index]


class ContextPreparer:
    """Consume host-supplied history and permissions, with no state commits.

    Structure validation cannot authenticate a caller-created history. The host
    must obtain snapshots from DetectionIntake using its trusted access context.
    Permission snapshots do not implement login, revocation or tenant isolation.
    """

    def __init__(self, *, message_limits, limits: ContextLimits):
        # Avoid the ingress -> Engine intake -> state import cycle.
        from safeguard.ingress.limits import InputLimits

        if type(message_limits) is not InputLimits or type(limits) is not ContextLimits:
            raise ContextError("invalid_configuration")
        self.message_limits, self.limits = message_limits, limits

    def prepare(self, snapshot: HistorySnapshot, context) -> PreparedContext:
        from safeguard.ingress import AccessContext
        from safeguard.ingress.limits import InputViolation

        if type(context) is not AccessContext:
            raise ContextError("trusted_context_required")
        if type(snapshot) is not HistorySnapshot or type(snapshot.key) is not ConversationKey:
            raise ContextError("invalid_snapshot")
        key, count = snapshot.key, snapshot.observed_count
        if context.account_id != key.account_id or key.conversation_id not in context.conversations:
            raise ContextError("conversation_not_allowed")
        if type(count) is not int or count < 0 or type(snapshot.messages) is not tuple or count != len(snapshot.messages):
            raise ContextError("invalid_boundary")
        if count > self.limits.max_messages:
            raise ContextError("message_limit")

        # Preflight all input before normalization copies or output assembly.
        input_bytes = text_chars = part_count = asset_count = 0
        for message in snapshot.messages:
            if type(message) is not dict:
                raise ContextError("invalid_normalized_message")
            if any(message.get(name) != getattr(key, name) for name in ("source", "account_id", "conversation_id")):
                raise ContextError("scope_mismatch")
            try:
                input_bytes += self.message_limits.inspect(message)
            except InputViolation as error:
                raise ContextError("message_" + error.code) from None
            if input_bytes > self.limits.max_input_bytes:
                raise ContextError("input_byte_limit")
            parts, assets = message.get("content_parts"), message.get("assets")
            if type(parts) is not list or type(assets) is not list:
                raise ContextError("invalid_normalized_message")
            part_count += len(parts)
            asset_count += len(assets)
            text_chars += sum(len(p["text"]) for p in parts
                              if type(p) is dict and p.get("kind") == "text" and type(p.get("text")) is str)
            for measured, limit, code in (
                (part_count, self.limits.max_content_parts, "part_limit"),
                (asset_count, self.limits.max_assets, "asset_limit"),
                (text_chars, self.limits.max_text_chars, "text_limit"),
            ):
                if measured > limit:
                    raise ContextError(code)

        messages, attachments = [], []
        for number, message in enumerate(snapshot.messages, 1):
            canonical = self._canonical(message)
            parts = []
            catalogue = {asset["asset_id"]: asset for asset in canonical["assets"]}
            for index, part in enumerate(canonical["content_parts"]):
                ref = dict(observation_number=number, part_index=index)
                parts.append(dict(part, source_ref=ref))
                if part["kind"] != "text":
                    asset = catalogue[part["asset_id"]]
                    status = asset["source_status"]
                    gap = "source_reported_" + status if status in ("pending", "unavailable", "failed") else "reader_not_run"
                    attachments.append(dict(source_ref=ref, kind=part["kind"], asset_id=part["asset_id"],
                                            source_status=status, processing_status="not_requested", gap_reason=gap))
            messages.append(dict(
                observation_number=number, message_id=canonical["message_id"], sender_id=canonical["sender_id"],
                is_from_observed_account=canonical["is_from_observed_account"], observed_at=canonical["observed_at"],
                sent_at=canonical["sent_at"], content_parts=parts, assets=canonical["assets"],
            ))
        document = dict(context_schema_version="1.0", source=key.source, account_id=key.account_id,
                        conversation_id=key.conversation_id, observed_count=count, messages=messages,
                        coverage=dict(attachment_parts=len(attachments), unprocessed_attachment_parts=len(attachments),
                                      attachments=attachments))
        encoded = bytearray()
        for chunk in json.JSONEncoder(**_JSON).iterencode(document):
            chunk_bytes = chunk.encode("utf-8")
            if len(chunk_bytes) > self.limits.max_output_bytes - len(encoded):
                raise ContextError("output_byte_limit")
            encoded.extend(chunk_bytes)
        return PreparedContext(key, count, bytes(encoded), ContextStats(input_bytes, len(encoded), text_chars, part_count, asset_count))

    @staticmethod
    def _canonical(message):
        try:
            canonical = normalize(dict(
                schema_version="1.0", source=message.get("source"), account_id=message.get("account_id"),
                conversation_id=message.get("conversation_id"), message_id=message.get("message_id"),
                sender_id=message.get("sender_id"), event_type="message.created",
                observed_at=message.get("observed_at"), payload=message.get("raw_payload"),
            ))
            if json.dumps(canonical, sort_keys=True, **_JSON) != json.dumps(message, sort_keys=True, **_JSON):
                raise ContextError("invalid_normalized_message")
        except (NormalizationError, ValueError, RecursionError):
            raise ContextError("invalid_normalized_message") from None
        return canonical
