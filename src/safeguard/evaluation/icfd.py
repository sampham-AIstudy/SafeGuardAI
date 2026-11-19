"""Pure native ICFD projection; references/provenance never enter model_json().

Callers supply rows and asserted file identities. This module performs no corpus IO,
Engine submission, label inference, or selection/failure-scoring policy.
"""

from dataclasses import dataclass, field, fields
import hashlib
import json
import math
import re


_TASKS = frozenset(("icfd-static", "icfd-streaming"))
_ERRORS = frozenset(("invalid_limits", "invalid_identity", "invalid_provenance", "invalid_row",
    "invalid_reference", "invalid_transcript", "invalid_timestamp", "unordered_turn", "future_turn",
    "invalid_prefix_json", "turn_limit", "text_limit", "input_byte_limit", "prefix_byte_limit",
    "identifier_limit", "split_mismatch", "invalid_case"))


class IcfdAdapterError(ValueError):
    """Fixed public reasons without row values, parser messages, or partial results."""

    def __init__(self, code):
        if type(code) is not str or code not in _ERRORS:
            raise ValueError("invalid_icfd_adapter_error")
        self.code = code
        super().__init__(code)


def _text(value, code):
    if type(value) is not str:
        raise IcfdAdapterError(code)
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise IcfdAdapterError(code) from None


def _identifier(value, *, limit=None):
    if type(value) is not str:
        raise IcfdAdapterError("invalid_identity")
    if limit is not None and len(value) > limit:
        raise IcfdAdapterError("identifier_limit")
    _text(value, "invalid_identity")
    if not value.strip():
        raise IcfdAdapterError("invalid_identity")


def _sha256(value):
    if type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None:
        raise IcfdAdapterError("invalid_provenance")


def _timestamp(value):
    if type(value) not in (int, float):
        raise IcfdAdapterError("invalid_timestamp")
    try:
        valid = value >= 0 and math.isfinite(value)
    except OverflowError:
        valid = False
    if not valid:
        raise IcfdAdapterError("invalid_timestamp")


@dataclass(frozen=True, slots=True)
class IcfdLimits:
    max_turns: int
    max_text_chars: int
    max_input_bytes: int
    max_prefix_json_bytes: int
    max_identifier_chars: int

    def __post_init__(self):
        if any(type(getattr(self, item.name)) is not int or getattr(self, item.name) < 1 for item in fields(self)):
            raise IcfdAdapterError("invalid_limits")


@dataclass(frozen=True, slots=True)
class IcfdTurn:
    speaker: str = field(repr=False)
    text: str = field(repr=False)
    timestamp_end: int | float = field(repr=False)

    def __post_init__(self):
        _text(self.speaker, "invalid_transcript")
        _text(self.text, "invalid_transcript")
        _timestamp(self.timestamp_end)


@dataclass(frozen=True, slots=True)
class IcfdProvenance:
    """Caller-asserted release/shard/row identity, not file or content attestation."""

    release_sha256: str = field(repr=False)
    shard_sha256: str = field(repr=False)
    row_index: int = field(repr=False)
    expected_split: str = field(repr=False)

    def __post_init__(self):
        _sha256(self.release_sha256)
        _sha256(self.shard_sha256)
        if type(self.row_index) is not int or self.row_index < 0:
            raise IcfdAdapterError("invalid_provenance")
        _identifier(self.expected_split)


def _encode_model(turns, byte_limit=None):
    document = dict(messages=[dict(speaker=turn.speaker, text=turn.text,
        timestamp_end=turn.timestamp_end) for turn in turns])
    result = bytearray()
    encoder = json.JSONEncoder(ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
    for piece in encoder.iterencode(document):
        raw = piece.encode("utf-8")
        if byte_limit is not None and len(raw) > byte_limit - len(result):
            raise IcfdAdapterError("input_byte_limit")
        result.extend(raw)
    return bytes(result)


@dataclass(frozen=True, slots=True)
class IcfdInput:
    """Immutable observed turns; model_json excludes operational case/task metadata."""

    case_id: str
    task: str
    turns: tuple[IcfdTurn, ...] = field(repr=False)
    observation_time: int | float | None = field(repr=False)

    def __post_init__(self):
        _identifier(self.case_id)
        if type(self.task) is not str or self.task not in _TASKS:
            raise IcfdAdapterError("invalid_case")
        if type(self.turns) is not tuple or any(type(turn) is not IcfdTurn for turn in self.turns):
            raise IcfdAdapterError("invalid_transcript")
        if self.task == "icfd-static":
            if self.observation_time is not None:
                raise IcfdAdapterError("invalid_timestamp")
        else:
            _timestamp(self.observation_time)
        previous = None
        for turn in self.turns:
            if previous is not None and turn.timestamp_end < previous:
                raise IcfdAdapterError("unordered_turn")
            if self.observation_time is not None and turn.timestamp_end > self.observation_time:
                raise IcfdAdapterError("future_turn")
            previous = turn.timestamp_end

    def model_json(self) -> bytes:
        return _encode_model(self.turns)


@dataclass(frozen=True, slots=True)
class IcfdReference:
    case_id: str
    task: str
    source_uid: str = field(repr=False)
    split: str = field(repr=False)
    label: int = field(repr=False)
    input_sha256: str
    provenance: IcfdProvenance = field(repr=False)

    def __post_init__(self):
        _identifier(self.case_id)
        _identifier(self.source_uid)
        _identifier(self.split)
        if type(self.task) is not str or self.task not in _TASKS or type(self.label) is not int or self.label not in (0, 1):
            raise IcfdAdapterError("invalid_reference")
        _sha256(self.input_sha256)
        if type(self.provenance) is not IcfdProvenance:
            raise IcfdAdapterError("invalid_provenance")
        if self.split != self.provenance.expected_split:
            raise IcfdAdapterError("split_mismatch")


@dataclass(frozen=True, slots=True)
class IcfdCase:
    input: IcfdInput
    reference: IcfdReference = field(repr=False)

    def __post_init__(self):
        if (type(self.input) is not IcfdInput or type(self.reference) is not IcfdReference
                or self.input.case_id != self.reference.case_id or self.input.task != self.reference.task
                or hashlib.sha256(self.input.model_json()).hexdigest() != self.reference.input_sha256):
            raise IcfdAdapterError("invalid_case")


def _configuration(row, case_id, provenance, limits):
    if type(row) is not dict:
        raise IcfdAdapterError("invalid_row")
    if type(limits) is not IcfdLimits:
        raise IcfdAdapterError("invalid_limits")
    if type(provenance) is not IcfdProvenance:
        raise IcfdAdapterError("invalid_provenance")
    _identifier(case_id, limit=limits.max_identifier_chars)
    _identifier(provenance.expected_split, limit=limits.max_identifier_chars)


def _reference_fields(row, metadata, limits):
    if type(metadata) is not dict:
        raise IcfdAdapterError("invalid_reference")
    uid, split, verdict = metadata.get("conversation_uid"), metadata.get("split"), row.get("final_verdict")
    _identifier(uid, limit=limits.max_identifier_chars)
    _identifier(split, limit=limits.max_identifier_chars)
    if type(verdict) is not str or verdict not in ("YES", "NO"):
        raise IcfdAdapterError("invalid_reference")
    return uid, split, int(verdict == "YES")


def _turns(raw, limits):
    if type(raw) is not list:
        raise IcfdAdapterError("invalid_transcript")
    if len(raw) > limits.max_turns:
        raise IcfdAdapterError("turn_limit")
    selected, characters = [], 0
    for item in raw:
        if type(item) is not dict or any(name not in item for name in ("speaker", "text", "timestamp_end")):
            raise IcfdAdapterError("invalid_transcript")
        speaker, text, end = item["speaker"], item["text"], item["timestamp_end"]
        if type(speaker) is not str or type(text) is not str:
            raise IcfdAdapterError("invalid_transcript")
        characters += len(speaker) + len(text)
        if characters > limits.max_text_chars:
            raise IcfdAdapterError("text_limit")
        selected.append((speaker, text, end))
    return tuple(IcfdTurn(*item) for item in selected)


def _case(row, metadata, raw_turns, *, task, observation_time, case_id, provenance, limits):
    uid, split, label = _reference_fields(row, metadata, limits)
    if split != provenance.expected_split:
        raise IcfdAdapterError("split_mismatch")
    observed = IcfdInput(case_id, task, _turns(raw_turns, limits), observation_time)
    model_json = _encode_model(observed.turns, limits.max_input_bytes)
    reference = IcfdReference(case_id, task, uid, split, label, hashlib.sha256(model_json).hexdigest(), provenance)
    return IcfdCase(observed, reference)


def adapt_static(row, *, case_id, provenance, limits) -> IcfdCase:
    _configuration(row, case_id, provenance, limits)
    return _case(row, row.get("release_metadata"), row.get("transcript"), task="icfd-static",
        observation_time=None, case_id=case_id, provenance=provenance, limits=limits)


def _prefix_json(raw, byte_limit):
    if type(raw) is not str:
        raise IcfdAdapterError("invalid_prefix_json")
    if len(raw) > byte_limit:
        raise IcfdAdapterError("prefix_byte_limit")
    try:
        encoded = raw.encode("utf-8")
    except UnicodeError:
        raise IcfdAdapterError("invalid_prefix_json") from None
    if len(encoded) > byte_limit:
        raise IcfdAdapterError("prefix_byte_limit")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_key")
            result[key] = value
        return result

    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("nonfinite_number")
        return number

    def constant(value):
        raise ValueError("nonfinite_number")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_float=finite_float, parse_constant=constant)
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise IcfdAdapterError("invalid_prefix_json") from None


def adapt_streaming(row, *, case_id, provenance, limits) -> IcfdCase:
    _configuration(row, case_id, provenance, limits)
    observation_time = row.get("chunk_timestamp")
    _timestamp(observation_time)
    raw_turns = _prefix_json(row.get("cumulative_transcript_json"), limits.max_prefix_json_bytes)
    return _case(row, row, raw_turns, task="icfd-streaming", observation_time=observation_time,
        case_id=case_id, provenance=provenance, limits=limits)
