"""Deterministic Engine entry; no model, fraud assessment or risk output."""

from dataclasses import dataclass

from safeguard.conversation_memory import HistoryBoundary, HistoryError, ObservedHistory


@dataclass(frozen=True, slots=True)
class DetectionRequest:
    boundary: HistoryBoundary
    context: object


class DetectionIntake:
    def __init__(self, history: ObservedHistory):
        if not isinstance(history, ObservedHistory):
            raise HistoryError("invalid_history")
        self.history = history

    def check(self, message, context):
        self.history.check(context, message)

    def record(self, message, context) -> DetectionRequest:
        return DetectionRequest(self.history.append(context, message), context)

    def snapshot(self, request: DetectionRequest):
        if type(request) is not DetectionRequest:
            raise HistoryError("invalid_request")
        return self.history.snapshot(request.context, request.boundary)
