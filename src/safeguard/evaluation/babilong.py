"""Bounded native QA conversion with separate input, reference, and finite answers.

This module performs no corpus IO, Engine submission, run selection, or aggregate scoring.
Native comparison is restricted to canonical QA1/QA2/QA3 answers, not arbitrary model text.
"""

from dataclasses import dataclass, field, fields
import hashlib
import json
import re

from safeguard.detection.execution_host import AssessmentProfile
from safeguard.detection.model_contract import OutputProfile, encoded, schema_document, validate_schema


BABILONG_ANSWERS = ("bathroom", "bedroom", "garden", "hallway", "kitchen", "office")
_TASKS = frozenset(("qa1", "qa2", "qa3"))
_ERRORS = frozenset(("invalid_limits", "invalid_row", "invalid_text", "invalid_identity", "invalid_task",
    "invalid_provenance", "invalid_target", "invalid_case", "invalid_answer", "context_limit",
    "question_limit", "input_byte_limit", "identifier_limit"))


class BabilongAdapterError(ValueError):
    """Fixed public codes without source values or partial conversion results."""

    def __init__(self, code):
        if type(code) is not str or code not in _ERRORS:
            raise ValueError("invalid_babilong_adapter_error")
        self.code = code
        super().__init__(code)


def _text(value, code):
    if type(value) is not str:
        raise BabilongAdapterError(code)
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise BabilongAdapterError(code) from None


def _identifier(value, limit=None):
    if type(value) is not str:
        raise BabilongAdapterError("invalid_identity")
    if limit is not None and len(value) > limit:
        raise BabilongAdapterError("identifier_limit")
    _text(value, "invalid_identity")
    if not value.strip():
        raise BabilongAdapterError("invalid_identity")


def _sha256(value):
    if type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None:
        raise BabilongAdapterError("invalid_provenance")


def _task(value):
    if type(value) is not str or value not in _TASKS:
        raise BabilongAdapterError("invalid_task")


def _answer(value, code):
    if type(value) is not str or value not in BABILONG_ANSWERS:
        raise BabilongAdapterError(code)


@dataclass(frozen=True, slots=True)
class BabilongLimits:
    max_context_chars: int
    max_question_chars: int
    max_input_bytes: int
    max_identifier_chars: int

    def __post_init__(self):
        if any(type(getattr(self, item.name)) is not int or getattr(self, item.name) < 1 for item in fields(self)):
            raise BabilongAdapterError("invalid_limits")


@dataclass(frozen=True, slots=True)
class BabilongProvenance:
    """Caller-asserted release/shard/row identity, without file attestation or pairing."""

    release_sha256: str = field(repr=False)
    shard_sha256: str = field(repr=False)
    row_index: int = field(repr=False)

    def __post_init__(self):
        _sha256(self.release_sha256)
        _sha256(self.shard_sha256)
        if type(self.row_index) is not int or self.row_index < 0:
            raise BabilongAdapterError("invalid_provenance")


def _encode_model(context_text, question, byte_limit=None):
    result = bytearray()
    encoder = json.JSONEncoder(ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
    for piece in encoder.iterencode(dict(input=context_text, question=question)):
        raw = piece.encode("utf-8")
        if byte_limit is not None and len(raw) > byte_limit - len(result):
            raise BabilongAdapterError("input_byte_limit")
        result.extend(raw)
    return bytes(result)


@dataclass(frozen=True, slots=True)
class BabilongInput:
    """Observed strings only; model_json excludes operational identity and evaluator metadata."""

    case_id: str
    context_text: str = field(repr=False)
    question: str = field(repr=False)

    def __post_init__(self):
        _identifier(self.case_id)
        _text(self.context_text, "invalid_text")
        _text(self.question, "invalid_text")

    def model_json(self) -> bytes:
        return _encode_model(self.context_text, self.question)


@dataclass(frozen=True, slots=True)
class BabilongReference:
    case_id: str
    task: str
    length_label: str = field(repr=False)
    target: str = field(repr=False)
    input_sha256: str
    provenance: BabilongProvenance = field(repr=False)

    def __post_init__(self):
        _identifier(self.case_id)
        _task(self.task)
        _identifier(self.length_label)
        _answer(self.target, "invalid_target")
        _sha256(self.input_sha256)
        if type(self.provenance) is not BabilongProvenance:
            raise BabilongAdapterError("invalid_provenance")


@dataclass(frozen=True, slots=True)
class BabilongCase:
    input: BabilongInput
    reference: BabilongReference = field(repr=False)

    def __post_init__(self):
        if (type(self.input) is not BabilongInput or type(self.reference) is not BabilongReference
                or self.input.case_id != self.reference.case_id
                or hashlib.sha256(self.input.model_json()).hexdigest() != self.reference.input_sha256):
            raise BabilongAdapterError("invalid_case")


def adapt_babilong(row, *, case_id, task, length_label, provenance, limits) -> BabilongCase:
    if (type(row) is not dict or any(type(key) is not str for key in row)
            or set(row) != {"input", "question", "target"}):
        raise BabilongAdapterError("invalid_row")
    if type(limits) is not BabilongLimits:
        raise BabilongAdapterError("invalid_limits")
    if type(provenance) is not BabilongProvenance:
        raise BabilongAdapterError("invalid_provenance")
    _identifier(case_id, limits.max_identifier_chars)
    _identifier(length_label, limits.max_identifier_chars)
    _task(task)
    _answer(row["target"], "invalid_target")
    context_text, question = row["input"], row["question"]
    if type(context_text) is not str or type(question) is not str:
        raise BabilongAdapterError("invalid_text")
    if len(context_text) > limits.max_context_chars:
        raise BabilongAdapterError("context_limit")
    if len(question) > limits.max_question_chars:
        raise BabilongAdapterError("question_limit")
    observed = BabilongInput(case_id, context_text, question)
    model_bytes = _encode_model(context_text, question, limits.max_input_bytes)
    reference = BabilongReference(case_id, task, length_label, row["target"],
        hashlib.sha256(model_bytes).hexdigest(), provenance)
    return BabilongCase(observed, reference)


def native_answer_matches(case: BabilongCase, answer: str) -> bool:
    """Match the pinned native rule only for exact canonical QA1/QA2/QA3 answers."""
    if type(case) is not BabilongCase:
        raise BabilongAdapterError("invalid_case")
    _answer(answer, "invalid_answer")
    return case.reference.target == answer and answer not in case.input.question.lower()


_SCHEMA_JSON = encoded(dict(type="object", additionalProperties=False,
    properties=dict(answer=dict(type="string", enum=list(BABILONG_ANSWERS))), required=["answer"]))


def _validate_answer(value):
    validate_schema(value, schema_document(_SCHEMA_JSON))


BABILONG_QA_PROFILE = OutputProfile(AssessmentProfile("babilong-qa", "1.0", _validate_answer), _SCHEMA_JSON)
