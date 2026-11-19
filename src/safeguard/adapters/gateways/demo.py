"""Build source handoffs for decoded demo messages in supplied arrival order.

Handoff calls a supplied synchronous receiver. This Gateway is one component inside Adapter; normalization is composed separately.
No network or message storage is performed here.
"""

from collections.abc import Callable, Iterable, Iterator, Mapping
from datetime import datetime, timezone
import math
from typing import Any

from ..content import demo_content


class GatewayInputError(ValueError):
    """A field-level rejection without echoing message content or account data."""

    def __init__(self, field: str, code: str):
        self.field = field
        self.code = code
        super().__init__(f"{field}: {code}")

    def as_dict(self) -> dict[str, str]:
        return {"field": self.field, "code": self.code}


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GatewayInputError(field, "expected_nonblank_string")
    return value


def _copy_json(value: object, field: str, ancestors: set[int]) -> Any:
    """Copy JSON values exactly, rejecting unsupported types and cyclic inputs."""
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise GatewayInputError(field, "expected_finite_number")
        return value
    if type(value) not in (dict, list):
        raise GatewayInputError(field, "expected_json_value")
    identity = id(value)
    if identity in ancestors:
        raise GatewayInputError(field, "cyclic_payload")
    ancestors.add(identity)
    try:
        if type(value) is list:
            return [_copy_json(item, field, ancestors) for item in value]
        # Do not echo native keys in errors: unknown keys can contain private data.
        if any(type(key) is not str for key in value):
            raise GatewayInputError(field, "expected_string_keys")
        return {key: _copy_json(item, field, ancestors) for key, item in value.items()}
    finally:
        ancestors.remove(identity)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DemoGateway:
    source = "demo"

    @staticmethod
    def conversation_id(event: object) -> str:
        """Inspect routing identity without copies, clock reads or IO."""
        if type(event) is not dict or "thread" not in event:
            raise GatewayInputError("payload.thread", "required")
        return _identifier(event["thread"], "payload.thread")

    """Receive demo-native events and return detached handoff envelopes.

    Native IDs: thread, id, author (nonblank strings). Content is either legacy
    body or ordered typed content_parts with asset descriptors. Extra JSON fields
    stay opaque. account_id comes from explicit source
    context. An injected clock must return a timezone-aware datetime; its instant
    is represented in UTC. Validation errors produce no partial envelope.
    """

    def __init__(self, account_id: str, *, clock: Callable[[], datetime] = _utc_now):
        self._account_id = _identifier(account_id, "account_id")
        if not callable(clock):
            raise GatewayInputError("observed_at", "clock_not_callable")
        self._clock = clock

    def deliver_stream(self, events: Iterable[object],
                       receiver: Callable[[dict[str, Any]], None]) -> int:
        """Hand each envelope to a receiver before reading another native event.

        The receiver returns None after acceptance or raises to reject/fail.
        Return the completed-call count on full success. Any error terminates
        delivery without retry or rollback; acceptance of a failing call is
        unknown because it may already have performed an effect. This is local
        callback handoff, not durable delivery. The caller owns source cleanup.
        """
        if not callable(receiver):
            raise GatewayInputError("receiver", "expected_callable")
        completed = 0
        for envelope in self.receive_stream(events):
            if receiver(envelope) is not None:
                raise GatewayInputError("receiver", "expected_none_return")
            completed += 1
        return completed

    def receive_stream(self, events: Iterable[object]) -> Iterator[dict[str, Any]]:
        """Yield one envelope per requested event, without prefetch or sorting.

        Validation happens when the iterator advances. Invalid events or clock
        failures terminate it using the existing receive() errors. Previously
        yielded envelopes remain available; later inputs stay unread. Errors
        advancing the source propagate without retry. This adapter neither owns
        nor closes the supplied source; its caller manages source resources.
        """
        if isinstance(events, (str, bytes, bytearray, Mapping)):
            raise GatewayInputError("events", "expected_event_iterable")
        try:
            iterator = iter(events)
        except TypeError:
            raise GatewayInputError("events", "expected_event_iterable") from None
        while True:
            try:
                event = next(iterator)
            except StopIteration:
                return
            yield self.receive(event)

    def receive(self, event: object) -> dict[str, Any]:
        if type(event) is not dict:
            raise GatewayInputError("payload", "expected_object")
        for field in ("thread", "id", "author"):
            if field not in event:
                raise GatewayInputError(f"payload.{field}", "required")
        for field in ("thread", "id", "author"):
            _identifier(event[field], f"payload.{field}")
        demo_content(event, GatewayInputError)
        try:
            payload = _copy_json(event, "payload", set())
        except RecursionError:
            raise GatewayInputError("payload", "nesting_too_deep") from None
        try:
            observed = self._clock()
        except Exception:
            raise GatewayInputError("observed_at", "clock_failed") from None
        if not isinstance(observed, datetime) or observed.tzinfo is None:
            raise GatewayInputError("observed_at", "expected_aware_datetime")
        try:
            if observed.utcoffset() is None:
                raise ValueError("Missing UTC offset")
            observed_at = observed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except (ValueError, OverflowError, TypeError):
            raise GatewayInputError("observed_at", "invalid_datetime") from None
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
