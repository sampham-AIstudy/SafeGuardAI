"""Build a source handoff for one decoded demo message.

No network, normalization, message storage or delivery is performed here.
"""

from collections.abc import Callable
from datetime import datetime, timezone
import math
from typing import Any


class AdapterInputError(ValueError):
    """A field-level rejection without echoing message content or account data."""

    def __init__(self, field: str, code: str):
        self.field = field
        self.code = code
        super().__init__(f"{field}: {code}")

    def as_dict(self) -> dict[str, str]:
        return {"field": self.field, "code": self.code}


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdapterInputError(field, "expected_nonblank_string")
    return value


def _copy_json(value: object, field: str, ancestors: set[int]) -> Any:
    """Copy JSON values exactly, rejecting unsupported types and cyclic inputs."""
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise AdapterInputError(field, "expected_finite_number")
        return value
    if type(value) not in (dict, list):
        raise AdapterInputError(field, "expected_json_value")
    identity = id(value)
    if identity in ancestors:
        raise AdapterInputError(field, "cyclic_payload")
    ancestors.add(identity)
    try:
        if type(value) is list:
            return [_copy_json(item, field, ancestors) for item in value]
        # Do not echo native keys in errors: unknown keys can contain private data.
        if any(type(key) is not str for key in value):
            raise AdapterInputError(field, "expected_string_keys")
        return {key: _copy_json(item, field, ancestors) for key, item in value.items()}
    finally:
        ancestors.remove(identity)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DemoAdapter:
    """Receive a single demo-native event and return a detached handoff envelope.

    Native required fields: thread, id, author (nonblank strings), body (nonempty
    string). Extra JSON fields stay opaque. account_id comes from explicit source
    context. An injected clock must return a timezone-aware datetime; its instant
    is represented in UTC. Validation errors produce no partial envelope.
    """

    def __init__(self, account_id: str, *, clock: Callable[[], datetime] = _utc_now):
        self._account_id = _identifier(account_id, "account_id")
        if not callable(clock):
            raise AdapterInputError("observed_at", "clock_not_callable")
        self._clock = clock

    def receive(self, event: object) -> dict[str, Any]:
        if type(event) is not dict:
            raise AdapterInputError("payload", "expected_object")
        for field in ("thread", "id", "author", "body"):
            if field not in event:
                raise AdapterInputError(f"payload.{field}", "required")
        for field in ("thread", "id", "author"):
            _identifier(event[field], f"payload.{field}")
        if not isinstance(event["body"], str) or not event["body"]:
            raise AdapterInputError("payload.body", "expected_nonempty_string")
        try:
            payload = _copy_json(event, "payload", set())
        except RecursionError:
            raise AdapterInputError("payload", "nesting_too_deep") from None
        try:
            observed = self._clock()
        except Exception:
            raise AdapterInputError("observed_at", "clock_failed") from None
        if not isinstance(observed, datetime) or observed.tzinfo is None:
            raise AdapterInputError("observed_at", "expected_aware_datetime")
        try:
            if observed.utcoffset() is None:
                raise ValueError("Missing UTC offset")
            observed_at = observed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except (ValueError, OverflowError, TypeError):
            raise AdapterInputError("observed_at", "invalid_datetime") from None
        return {
            "schema_version": "1.0",
            "source": "demo",
            "account_id": self._account_id,
            "conversation_id": payload["thread"],
            "message_id": payload["id"],
            "sender_id": payload["author"],
            "event_type": "message.created",
            "observed_at": observed_at,
            "payload": payload,
        }
