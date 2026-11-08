"""Construct observed history without selecting an engine message schema."""

from collections.abc import Sequence
from copy import deepcopy
from typing import TypeVar


Message = TypeVar("Message")


def build_observed_history(
    messages: Sequence[Message], observed_count: int
) -> tuple[Message, ...]:
    """Return a detached copy of the first ``observed_count`` entries.

    The caller supplies an ordered history. The count is a number of observed
    entries, not an inclusive message index; zero produces an empty prefix.
    Preserve the selected payloads and their order without sorting or inference.

    The tuple fixes the returned sequence's membership. Nested payloads can still
    be mutable, but do not share mutable objects with the source history. This
    function does not validate payload meaning or restrict other future callers'
    access to messages. It performs no file, network or model operations.
    """
    if type(observed_count) is not int:
        raise TypeError("observed_count must be an integer, not a boolean")
    if not 0 <= observed_count <= len(messages):
        raise ValueError("observed_count must be between zero and history length")
    return tuple(deepcopy(messages[:observed_count]))
