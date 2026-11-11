"""Bounded append-only observations with detached prefix snapshots."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, fields
import json
import threading
from typing import TYPE_CHECKING
from uuid import uuid4

from safeguard.conversation_memory.history import build_observed_history
from safeguard.adapters.norm import NormalizationError, normalize

if TYPE_CHECKING:
    from safeguard.ingress.limits import InputLimits


class HistoryError(ValueError):
    """Fixed reasons, without private values, identifiers or native keys."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ConversationKey:
    source: str
    account_id: str
    conversation_id: str

    def __post_init__(self):
        if any(type(getattr(self, f.name)) is not str or not getattr(self, f.name).strip() for f in fields(self)):
            raise HistoryError("invalid_conversation_key")
        if self.source != "demo":
            raise HistoryError("unsupported_source")


@dataclass(frozen=True, slots=True)
class HistoryLimits:
    max_conversations: int
    max_messages: int
    max_bytes: int
    max_conversation_messages: int
    max_conversation_bytes: int
    max_account_messages: int
    max_account_bytes: int

    def __post_init__(self):
        if any(type(getattr(self, f.name)) is not int or getattr(self, f.name) <= 0 for f in fields(self)):
            raise ValueError("History limits must be positive integers")


@dataclass(frozen=True, slots=True)
class HistoryBoundary:
    key: ConversationKey
    observed_count: int
    store_id: str


@dataclass(frozen=True, slots=True)
class HistorySnapshot:
    """Detached membership/content; nested dicts remain mutable for the receiver."""
    key: ConversationKey
    observed_count: int
    messages: tuple


class InMemoryConversationMemory:
    """One-thread-owned demo lifetime; JSON accounting is not a hard RSS bound.

    No deduplication, edits, sorting, eviction, replay, derived analysis or IO.
    The host supplies trusted permission snapshots; no session provider is selected.
    """
    def __init__(self, *, message_limits: InputLimits, limits: HistoryLimits):
        from safeguard.ingress.limits import InputLimits
        if type(message_limits) is not InputLimits or type(limits) is not HistoryLimits:
            raise HistoryError("invalid_limits")
        self.message_limits, self.limits = message_limits, limits
        self._state, self._owner, self._id = "new", threading.get_ident(), uuid4().hex
        self._messages, self._key_bytes = {}, Counter()
        self._account_messages, self._account_bytes = Counter(), Counter()
        self._count, self._bytes = 0, 0

    def __enter__(self):
        if self._state != "new":
            raise HistoryError("already_started")
        self._state = "open"
        return self

    def _check(self):
        if self._state != "open":
            raise HistoryError("history_not_open")
        if threading.get_ident() != self._owner:
            raise HistoryError("wrong_thread")

    def _authorize(self, context, key):
        self._check()
        # Reuse the existing host permission contract after module initialization.
        from safeguard.ingress.pipeline import AccessContext
        if type(context) is not AccessContext:
            raise HistoryError("trusted_context_required")
        if type(key) is not ConversationKey:
            raise HistoryError("invalid_conversation_key")
        if context.account_id != key.account_id or key.conversation_id not in context.conversations:
            raise HistoryError("conversation_not_allowed")

    @property
    def stats(self):
        return dict(state=self._state, conversations=len(self._messages), messages=self._count, bytes=self._bytes)

    def _prepare(self, context, message):
        from safeguard.ingress.limits import InputViolation
        self._check()
        if type(message) is not dict:
            raise HistoryError("invalid_normalized_message")
        # Resource checks precede copies, including raw_payload and extensions.
        try:
            size = self.message_limits.inspect(message)
        except InputViolation as error:
            raise HistoryError(error.code) from None
        key = ConversationKey(message.get("source"), message.get("account_id"), message.get("conversation_id"))
        self._authorize(context, key)
        try:
            canonical = normalize(dict(schema_version="1.0", source=message.get("source"),
                account_id=message.get("account_id"), conversation_id=message.get("conversation_id"),
                message_id=message.get("message_id"), sender_id=message.get("sender_id"),
                event_type="message.created", observed_at=message.get("observed_at"), payload=message.get("raw_payload")))
            # JSON comparison distinguishes bool/int without depending on key order.
            options = dict(ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":"))
            if json.dumps(message, **options) != json.dumps(canonical, **options):
                raise HistoryError("invalid_normalized_message")
        except (NormalizationError, ValueError, RecursionError):
            raise HistoryError("invalid_normalized_message") from None
        self._capacity(key, size)
        return key, canonical, size

    def _capacity(self, key, size):
        limits = self.limits
        checks = (
            (key not in self._messages and len(self._messages) >= limits.max_conversations, "conversation_limit"),
            (self._count >= limits.max_messages, "message_limit"),
            (self._bytes+size > limits.max_bytes, "byte_limit"),
            (len(self._messages.get(key, ())) >= limits.max_conversation_messages, "conversation_message_limit"),
            (self._key_bytes[key]+size > limits.max_conversation_bytes, "conversation_byte_limit"),
            (self._account_messages[key.account_id] >= limits.max_account_messages, "account_message_limit"),
            (self._account_bytes[key.account_id]+size > limits.max_account_bytes, "account_byte_limit"),
        )
        for failed, code in checks:
            if failed:
                raise HistoryError(code)

    def check(self, context, message):
        """Preflight without retaining history; append rechecks before committing."""
        self._prepare(context, message)

    def append(self, context, message) -> HistoryBoundary:
        key, canonical, size = self._prepare(context, message)
        if key not in self._messages:
            self._messages[key] = []
        self._messages[key].append(canonical)
        self._count += 1
        self._bytes += size
        self._key_bytes[key] += size
        self._account_messages[key.account_id] += 1
        self._account_bytes[key.account_id] += size
        return HistoryBoundary(key, len(self._messages[key]), self._id)

    def head(self, context, key) -> HistoryBoundary:
        self._authorize(context, key)
        if key not in self._messages:
            raise HistoryError("conversation_not_found")
        return HistoryBoundary(key, len(self._messages[key]), self._id)

    def snapshot(self, context, boundary) -> HistorySnapshot:
        self._check()
        if type(boundary) is not HistoryBoundary:
            raise HistoryError("invalid_boundary")
        self._authorize(context, boundary.key)
        if boundary.store_id != self._id or type(boundary.observed_count) is not int:
            raise HistoryError("invalid_boundary")
        records = self._messages.get(boundary.key)
        if records is None or not 1 <= boundary.observed_count <= len(records):
            raise HistoryError("invalid_boundary")
        return HistorySnapshot(boundary.key, boundary.observed_count,
                               build_observed_history(records, boundary.observed_count))

    def close(self):
        if threading.get_ident() != self._owner:
            raise HistoryError("wrong_thread")
        self._messages.clear(); self._key_bytes.clear()
        self._account_messages.clear(); self._account_bytes.clear()
        self._count, self._bytes, self._state = 0, 0, "closed"

    def __exit__(self, exc_type, exc, tb):
        self.close()
