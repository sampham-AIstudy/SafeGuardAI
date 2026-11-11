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
