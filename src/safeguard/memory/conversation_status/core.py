"""Conversation Status composition and trusted channel-specific views."""

from .ports import DerivedState, ObservedHistory
from .derived import StateError


class ConversationStatusReader:
    """Read-only interface handed to readers/tools; no commit method."""
    def __init__(self, state, channel):
        self._state, self._channel = state, channel

    def snapshot(self, context, boundary):
        return self._state.snapshot(context, boundary, channel=self._channel)


class ConversationStatusWriter(ConversationStatusReader):
    """Trusted host view; channel is selected by composition, never a model argument."""
    def commit(self, context, boundary, *, expected_version, operation_id, writes):
        return self._state.commit(context, boundary, channel=self._channel,
            expected_version=expected_version,operation_id=operation_id,writes=writes)

    def reader(self):
        return ConversationStatusReader(self._state,self._channel)


class ConversationStatus:
    """Compose opened observations with derived state for the same history instance.

    Trusted assembly gives detector/warning views to their owners and only reader
    views to tools. Python object encapsulation is not an authentication sandbox.
    The caller opens the selected history backend; close releases both backends.
    """
    def __init__(self, *, observations, derived):
        if not isinstance(observations,ObservedHistory) or not isinstance(derived,DerivedState) or getattr(derived,'history',None) is not observations:
            raise StateError('invalid_memory_configuration')
        self.observations, self._derived = observations, derived
        self.detector = ConversationStatusWriter(derived,'detector')
        self.warning_history = ConversationStatusWriter(derived,'warning_history')

    def close(self):
        self._derived.close()
        self.observations.close()

    def __enter__(self): return self

    def __exit__(self, exc_type, exc, tb): self.close()
