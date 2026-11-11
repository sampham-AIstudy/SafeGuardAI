"""Observed-history port shared by admission and detection intake."""

from abc import ABC, abstractmethod

from .contracts import ConversationKey, HistoryBoundary, HistoryLimits, HistorySnapshot


class ObservedHistory(ABC):
    """Host-owned observations, exact detached prefixes and explicit quotas.

    Implementations recheck current access and limits on append. Check is a
    preflight, not a reservation. Boundaries carry store identity and prefix count.
    No controller/model write permission follows from receiving a snapshot.
    """

    limits: HistoryLimits

    @abstractmethod
    def check(self, context, message): ...

    @abstractmethod
    def append(self, context, message) -> HistoryBoundary: ...

    @abstractmethod
    def head(self, context, key: ConversationKey) -> HistoryBoundary: ...

    @abstractmethod
    def snapshot(self, context, boundary: HistoryBoundary) -> HistorySnapshot: ...

    @abstractmethod
    def close(self): ...


class DerivedState(ABC):
    """Atomic channel-scoped revisions with immutable records and retry identity."""

    history: ObservedHistory

    @abstractmethod
    def snapshot(self, context, boundary, *, channel): ...

    @abstractmethod
    def commit(self, context, boundary, *, channel, expected_version, operation_id, writes): ...

    @abstractmethod
    def close(self): ...
