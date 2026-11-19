"""Bounded application glue around Adapter/Norm; not a new pipeline block."""

from .limits import InputLimits, InputViolation
from .pipeline import AccessContext, ConversationIngress, IngressError, Outcome, ProcessingLimits, Ticket

__all__ = ["AccessContext", "ConversationIngress", "IngressError", "InputLimits", "InputViolation",
           "Outcome", "ProcessingLimits", "Ticket"]
