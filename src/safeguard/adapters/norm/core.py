"""Convert one v1.0 demo envelope without IO, clocks, history or inference."""

from datetime import datetime, timezone
import json
import math
import re
from typing import Any, Literal, TypedDict

from safeguard.adapters.content import demo_content
from safeguard.messages import AssetDescriptor, ContentPart


class NormalizedMessage(TypedDict):
    """Provisional multipart record, separate from the adapter envelope."""

    message_schema_version: Literal["2.0"]
    source: str
    account_id: str
    conversation_id: str
    message_id: str
    sender_id: str
    content_parts: list[ContentPart]
    assets: list[AssetDescriptor]
    is_from_observed_account: bool
    observed_at: str
    sent_at: str | None
    raw_payload: dict[str, Any]


class NormalizationError(ValueError):
    """A fixed field/code reason that does not echo source values or keys."""

    def __init__(self, field: str, code: str):
        self.field = field
        self.code = code
        super().__init__(f"{field}: {code}")

    def as_dict(self) -> dict[str, str]:
        return {"field": self.field, "code": self.code}


_FIELDS = ("schema_version", "source", "account_id", "conversation_id", "message_id",
           "sender_id", "event_type", "observed_at", "payload")
_IDS = ("account_id", "conversation_id", "message_id", "sender_id")
_NATIVE_IDS = (("thread", "conversation_id"), ("id", "message_id"), ("author", "sender_id"))
_SOURCE = re.compile(r"[a-z][a-z0-9_.-]*")
_TIMESTAMP = re.compile(
    r"(?P<calendar>[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt](?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9])"
    r"(?P<fraction>\.[0-9]+)?(?P<offset>[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)


def _identifier(value: object, field: str) -> None:
    if type(value) is not str or not value.strip():
        raise NormalizationError(field, "expected_nonblank_string")


def _timestamp(value: object, field: str, *, observation: bool = False) -> str:
    if type(value) is not str:
        raise NormalizationError(field, "expected_datetime_string")
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        raise NormalizationError(field, "invalid_datetime")
    calendar, fraction, offset = match.group("calendar", "fraction", "offset")
    if observation and ("T" not in calendar or offset != "Z"):
        raise NormalizationError(field, "expected_utc_datetime")
    try:
        # Convert whole seconds only. Reattach the untouched fractional digits
        # so datetime cannot silently truncate nanosecond or finer precision.
        parsed = datetime.fromisoformat(calendar.replace("t", "T") + offset.upper())
        utc = parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise NormalizationError(field, "invalid_datetime") from None
    if observation:
        return value
    return utc.replace(tzinfo=None).isoformat(timespec="seconds") + (fraction or "") + "Z"


def _copy_payload(value: object, ancestors: set[int]) -> Any:
    """Validate/copy the receiving boundary independently of adapter internals."""
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise NormalizationError("payload", "expected_finite_number")
        return value
    if type(value) not in (dict, list):
        raise NormalizationError("payload", "expected_json_value")
    identity = id(value)
    if identity in ancestors:
        raise NormalizationError("payload", "cyclic_payload")
    ancestors.add(identity)
    try:
        if type(value) is list:
            return [_copy_payload(item, ancestors) for item in value]
        if any(type(key) is not str for key in value):
            raise NormalizationError("payload", "expected_string_keys")
        return {key: _copy_payload(item, ancestors) for key, item in value.items()}
    finally:
        ancestors.remove(identity)


def validate_envelope(adapter_event: object) -> None:
    """Validate the common v1 envelope without selecting a source mapping."""
    if type(adapter_event) is not dict:
        raise NormalizationError("event", "expected_object")
    for field in _FIELDS:
        if field not in adapter_event:
            raise NormalizationError(field, "required")
    if any(field not in _FIELDS for field in adapter_event):
        raise NormalizationError("event", "unexpected_fields")
    if adapter_event["schema_version"] != "1.0":
        raise NormalizationError("schema_version", "unsupported_version")
    source = adapter_event["source"]
    if type(source) is not str or not _SOURCE.fullmatch(source):
        raise NormalizationError("source", "invalid_source_identifier")
    if adapter_event["event_type"] != "message.created":
        raise NormalizationError("event_type", "unsupported_event_type")
    for field in _IDS:
        _identifier(adapter_event[field], field)
    _timestamp(adapter_event["observed_at"], "observed_at", observation=True)
    payload = adapter_event["payload"]
    if type(payload) is not dict or not payload:
        raise NormalizationError("payload", "expected_nonempty_object")


def normalize(adapter_event: object) -> NormalizedMessage:
    """Map one demo envelope to v2; preserve content and native provenance."""
    validate_envelope(adapter_event)
    source = adapter_event["source"]
    if source != "demo":
        raise NormalizationError("source", "unsupported_source")
    observed = adapter_event["observed_at"]
    payload = adapter_event["payload"]
    for native, common in _NATIVE_IDS:
        field = "payload." + native
        if native not in payload:
            raise NormalizationError(field, "required")
        _identifier(payload[native], field)
        if payload[native] != adapter_event[common]:
            raise NormalizationError(field, "identity_mismatch")
    parts, assets = demo_content(payload, NormalizationError)
    sent = payload.get("sent_at")
    sent_at = None if sent is None else _timestamp(sent, "payload.sent_at")
    try:
        raw = _copy_payload(payload, set())
    except RecursionError:
        raise NormalizationError("payload", "nesting_too_deep") from None
    return {
        "message_schema_version": "2.0", "source": source,
        "account_id": adapter_event["account_id"], "conversation_id": adapter_event["conversation_id"],
        "message_id": adapter_event["message_id"], "sender_id": adapter_event["sender_id"],
        "content_parts": parts, "assets": assets,
        "is_from_observed_account": adapter_event["sender_id"] == adapter_event["account_id"],
        "observed_at": observed, "sent_at": sent_at, "raw_payload": raw,
    }


def validate_message(message: object, envelope: dict) -> NormalizedMessage:
    """Check the common output/provenance contract, without source inference.

    A source Norm still owns semantic mapping. History/context independently
    revalidate their supported demo mapping; this check adds no source profile.
    """
    if type(message) is not dict or set(message) != set(NormalizedMessage.__required_keys__):
        raise NormalizationError("message", "invalid_fields")
    if message["message_schema_version"] != "2.0":
        raise NormalizationError("message_schema_version", "unsupported_version")
    for key in ("source", *_IDS, "observed_at"):
        if type(message[key]) is not str or message[key] != envelope.get(key):
            raise NormalizationError("message", "provenance_mismatch")
    for key in _IDS:
        _identifier(message[key], key)
    _timestamp(message["observed_at"], "observed_at", observation=True)
    if message["sent_at"] is not None:
        _timestamp(message["sent_at"], "sent_at", observation=True)
    own = message["is_from_observed_account"]
    if type(own) is not bool or own != (message["sender_id"] == message["account_id"]):
        raise NormalizationError("is_from_observed_account", "invalid_sender_flag")
    detached = _copy_payload(message, set())
    if type(detached["raw_payload"]) is not dict or not detached["raw_payload"]:
        raise NormalizationError("raw_payload", "invalid_payload")
    options = dict(ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":"))
    if json.dumps(detached["raw_payload"], **options) != json.dumps(envelope.get("payload"), **options):
        raise NormalizationError("raw_payload", "provenance_mismatch")
    assets = detached["assets"]
    asset_fields = {"asset_id", "filename", "declared_media_type", "declared_size_bytes", "source_status", "processing_status"}
    if type(assets) is not list or any(type(a) is not dict or set(a) != asset_fields or
                                      a["processing_status"] != "not_requested" for a in assets):
        raise NormalizationError("assets", "invalid_asset_fields")
    parts, canonical_assets = demo_content({"content_parts": detached["content_parts"],
        "assets": [{k: v for k, v in a.items() if k != "processing_status"} for a in assets]}, NormalizationError)
    if parts != detached["content_parts"] or canonical_assets != assets:
        raise NormalizationError("message", "invalid_content")
    try:
        json.dumps(detached, **options).encode("utf-8")
    except (UnicodeEncodeError, ValueError, RecursionError):
        raise NormalizationError("message", "invalid_json") from None
    return detached
