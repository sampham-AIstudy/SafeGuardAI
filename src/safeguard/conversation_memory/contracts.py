"""Scoped observed-history identities, boundaries and quotas."""

from dataclasses import dataclass, fields

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
