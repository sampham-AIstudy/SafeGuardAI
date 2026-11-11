"""Compose a configured Gateway and Norm into the common message boundary."""

from collections.abc import Mapping
from dataclasses import dataclass, field
import inspect
import re

from .norm import validate_message
from .norm.core import _copy_payload, validate_envelope


class AdapterError(ValueError):
    """Fixed stage/code diagnostics; never expose callback exceptions or input."""

    def __init__(self, stage: str, code: str):
        self.stage, self.code = stage, code
        super().__init__(stage + ": " + code)


def _sync_callable(value):
    return callable(value) and not (inspect.iscoroutinefunction(value) or
                                   inspect.iscoroutinefunction(getattr(value, "__call__", None)))


def _no_awaitable(value):
    if inspect.isawaitable(value):
        if inspect.iscoroutine(value):
            value.close()
        raise ValueError("Synchronous component returned an awaitable")
    return value


@dataclass(frozen=True, slots=True, init=False)
class Adapter:
    """Trusted source components; no partner registry or automatic detection.

    gateway_factory exposes source, conversation_id(native), and constructs an
    account-bound receiver. Norm accepts its v1 envelope and returns a v2 message.
    The coordinator authorizes/checks capacity between scope inspection and receipt.
    """

    source: str
    _factory: object = field(repr=False)
    _identify: object = field(repr=False)
    _norm: object = field(repr=False)
    _clock: object = field(repr=False)

    def __init__(self, *, gateway_factory, norm, clock=None):
        source = getattr(gateway_factory, "source", None)
        identify = getattr(gateway_factory, "conversation_id", None)
        if (type(source) is not str or not re.fullmatch(r"[a-z][a-z0-9_.-]*", source) or
                not _sync_callable(gateway_factory) or not _sync_callable(identify) or
                not _sync_callable(norm) or (clock is not None and not _sync_callable(clock))):
            raise AdapterError("configuration", "invalid_components")
        for name, value in (("source", source), ("_factory", gateway_factory), ("_identify", identify),
                            ("_norm", norm), ("_clock", clock)):
            object.__setattr__(self, name, value)

    def conversation_key(self, native, account_id: str) -> tuple[str, str, str]:
        if type(account_id) is not str or not account_id.strip():
            raise AdapterError("authorization", "invalid_account")
        try:
            conversation = _no_awaitable(self._identify(native))
            if type(conversation) is not str or not conversation.strip():
                raise ValueError("Invalid conversation")
        except Exception:
            raise AdapterError("gateway", "invalid_message") from None
        return self.source, account_id, conversation

    def receive(self, native, *, account_id: str, conversation_id: str):
        expected = self.conversation_key(native, account_id)
        if type(conversation_id) is not str or conversation_id != expected[2]:
            raise AdapterError("gateway", "scope_mismatch")
        try:
            receiver = _no_awaitable(self._factory(account_id, **({"clock": self._clock} if self._clock is not None else {})))
            envelope = _copy_payload(_no_awaitable(receiver.receive(native)), set())
            validate_envelope(envelope)
            if (type(envelope) is not dict or
                    tuple(envelope.get(k) for k in ("source", "account_id", "conversation_id")) != expected):
                raise ValueError("Gateway changed scope")
        except Exception:
            raise AdapterError("gateway", "invalid_message") from None
        try:
            # Keep an independent witness: Norm cannot rewrite its input to make
            # a changed identity or raw payload appear to match the source.
            witness = _copy_payload(envelope, set())
            result = _no_awaitable(self._norm(envelope))
            return validate_message(result, witness)
        except Exception:
            raise AdapterError("normalizer", "invalid_message") from None

    def receive_stream(self, events, *, account_id: str):
        """Lazy ordered conversion; caller owns the source and resource limits."""
        if isinstance(events, (str, bytes, bytearray, Mapping)):
            raise AdapterError("gateway", "invalid_stream")
        try:
            iterator = iter(events)
        except TypeError:
            raise AdapterError("gateway", "invalid_stream") from None
        for native in iterator:
            key = self.conversation_key(native, account_id)
            yield self.receive(native, account_id=account_id, conversation_id=key[2])

    def deliver_stream(self, events, receiver, *, account_id: str) -> int:
        """Fail-stop synchronous delivery of normalized messages, without retry."""
        if not _sync_callable(receiver):
            raise AdapterError("receiver", "expected_sync_receiver")
        completed = 0
        for message in self.receive_stream(events, account_id=account_id):
            returned = receiver(message)
            try:
                _no_awaitable(returned)
            except ValueError:
                raise AdapterError("receiver", "expected_none_return") from None
            if returned is not None:
                raise AdapterError("receiver", "expected_none_return")
            completed += 1
        return completed
