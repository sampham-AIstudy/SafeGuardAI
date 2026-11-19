"""Pure released-row conversion and fixed native-strict PhishRewrite cohorts.

Only PhishInput projects model text. Cohorts use declared flags and source joins before
predictions, without corpus IO, URL validation, Engine submission, or aggregate scoring.
Canonical CSV parsing, duplicate rejection, and nonempty eligibility are explicit boundaries.
"""

from dataclasses import dataclass, field, fields
import hashlib
import json
import re


PHISHREWRITE_LEVELS = ("0.25", "0.5", "0.75", "1.0")
_EMAIL_COLUMNS = frozenset(("id", "label", "source", "split", "original_id", "had_html", "subject", "body", "text"))
_REWRITE_COLUMNS = frozenset(("original_id", "source", "severity", "provider", "model", "temperature",
    "refused", "n_orig_urls", "retained_urls_strict", "retained_urls_primary", "n_primary_urls",
    "rewrite_subject", "rewrite_body", "rewrite_text"))
_REASONS = ("missing_level", "retention_unknown", "retention_false", "refused", "empty_text")
_ERRORS = frozenset(("invalid_limits", "invalid_row", "invalid_text", "invalid_identity", "invalid_provenance",
    "invalid_label", "invalid_split", "invalid_severity", "invalid_flag", "invalid_parent", "invalid_case",
    "invalid_cohort", "text_limit", "input_byte_limit", "identifier_limit", "original_count_limit",
    "rewrite_count_limit", "duplicate_case_id", "duplicate_email_id", "duplicate_original_id",
    "duplicate_provenance", "duplicate_rewrite", "missing_parent", "parent_mismatch", "release_mismatch"))


class PhishRewriteError(ValueError):
    """Fixed public reasons without source values or partial accepted results."""

    def __init__(self, code):
        if type(code) is not str or code not in _ERRORS:
            raise ValueError("invalid_phishrewrite_error")
        self.code = code
        super().__init__(code)


def _text(value, code="invalid_text"):
    if type(value) is not str:
        raise PhishRewriteError(code)
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise PhishRewriteError(code) from None


def _identifier(value, limit=None):
    if type(value) is not str:
        raise PhishRewriteError("invalid_identity")
    if limit is not None and len(value) > limit:
        raise PhishRewriteError("identifier_limit")
    _text(value, "invalid_identity")
    if not value.strip():
        raise PhishRewriteError("invalid_identity")


def _sha256(value):
    if type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None:
        raise PhishRewriteError("invalid_provenance")


def _severity(value):
    if type(value) is not str or value not in PHISHREWRITE_LEVELS:
        raise PhishRewriteError("invalid_severity")


def _flag(value, *, nullable=False):
    if type(value) is not str:
        raise PhishRewriteError("invalid_flag")
    if nullable and value == "":
        return None
    if len(value) not in (4, 5) or value.lower() not in ("true", "false"):
        raise PhishRewriteError("invalid_flag")
    return value.lower() == "true"


@dataclass(frozen=True, slots=True)
class PhishLimits:
    max_text_chars: int
    max_input_bytes: int
    max_identifier_chars: int

    def __post_init__(self):
        if any(type(getattr(self, item.name)) is not int or getattr(self, item.name) < 1 for item in fields(self)):
            raise PhishRewriteError("invalid_limits")


@dataclass(frozen=True, slots=True)
class PhishCohortLimits:
    max_originals: int
    max_rewrites: int
    case_limits: PhishLimits

    def __post_init__(self):
        if (type(self.max_originals) is not int or self.max_originals < 1
                or type(self.max_rewrites) is not int or self.max_rewrites < 1
                or type(self.case_limits) is not PhishLimits):
            raise PhishRewriteError("invalid_limits")


@dataclass(frozen=True, slots=True)
class PhishProvenance:
    """Caller-asserted release/shard/row identity, not file attestation."""

    release_sha256: str = field(repr=False)
    shard_sha256: str = field(repr=False)
    row_index: int = field(repr=False)

    def __post_init__(self):
        _sha256(self.release_sha256)
        _sha256(self.shard_sha256)
        if type(self.row_index) is not int or self.row_index < 0:
            raise PhishRewriteError("invalid_provenance")


def _encode_model(text, byte_limit=None):
    result = bytearray()
    encoder = json.JSONEncoder(ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
    for piece in encoder.iterencode(dict(text=text)):
        raw = piece.encode("utf-8")
        if byte_limit is not None and len(raw) > byte_limit - len(result):
            raise PhishRewriteError("input_byte_limit")
        result.extend(raw)
    return bytes(result)


@dataclass(frozen=True, slots=True)
class PhishInput:
    """One unchanged source string; model_json excludes operational and reference metadata."""

    case_id: str
    text: str = field(repr=False)

    def __post_init__(self):
        _identifier(self.case_id)
        _text(self.text)

    def model_json(self) -> bytes:
        return _encode_model(self.text)


@dataclass(frozen=True, slots=True)
class PhishOriginalReference:
    case_id: str
    email_id: str = field(repr=False)
    original_id: str = field(repr=False)
    label: int = field(repr=False)
    split: str = field(repr=False)
    input_sha256: str
    provenance: PhishProvenance = field(repr=False)

    def __post_init__(self):
        for value in (self.case_id, self.email_id, self.original_id):
            _identifier(value)
        if type(self.label) is not int or self.label not in (0, 1):
            raise PhishRewriteError("invalid_label")
        if type(self.split) is not str or self.split != "test":
            raise PhishRewriteError("invalid_split")
        _sha256(self.input_sha256)
        if type(self.provenance) is not PhishProvenance:
            raise PhishRewriteError("invalid_provenance")


@dataclass(frozen=True, slots=True)
class PhishRewriteReference:
    case_id: str
    parent: PhishOriginalReference = field(repr=False)
    provider: str = field(repr=False)
    model: str = field(repr=False)
    severity: str = field(repr=False)
    refused: bool = field(repr=False)
    retained_urls_strict: bool | None = field(repr=False)
    input_sha256: str
    provenance: PhishProvenance = field(repr=False)

    def __post_init__(self):
        for value in (self.case_id, self.provider, self.model):
            _identifier(value)
        if type(self.parent) is not PhishOriginalReference or self.parent.label != 1:
            raise PhishRewriteError("invalid_parent")
        _severity(self.severity)
        if type(self.refused) is not bool or (self.retained_urls_strict is not None
                and type(self.retained_urls_strict) is not bool):
            raise PhishRewriteError("invalid_flag")
        _sha256(self.input_sha256)
        if type(self.provenance) is not PhishProvenance:
            raise PhishRewriteError("invalid_provenance")
        if self.provenance.release_sha256 != self.parent.provenance.release_sha256:
            raise PhishRewriteError("release_mismatch")


@dataclass(frozen=True, slots=True)
class PhishCase:
    input: PhishInput
    reference: PhishOriginalReference | PhishRewriteReference = field(repr=False)

    def __post_init__(self):
        if (type(self.input) is not PhishInput
                or type(self.reference) not in (PhishOriginalReference, PhishRewriteReference)
                or self.input.case_id != self.reference.case_id
                or hashlib.sha256(self.input.model_json()).hexdigest() != self.reference.input_sha256):
            raise PhishRewriteError("invalid_case")


def _original_case(value, label):
    return (type(value) is PhishCase and type(value.reference) is PhishOriginalReference
        and value.reference.label == label)


def _level_reasons(case):
    reference = case.reference
    reasons = []
    if reference.retained_urls_strict is None:
        reasons.append("retention_unknown")
    elif reference.retained_urls_strict is False:
        reasons.append("retention_false")
    if reference.refused:
        reasons.append("refused")
    if not case.input.text.strip():
        reasons.append("empty_text")
    return reasons


@dataclass(frozen=True, slots=True)
class PhishParentGroup:
    """One eligible original and four ordered rewrites; level views share this membership."""

    original: PhishCase = field(repr=False)
    rewrites: tuple[PhishCase, ...] = field(repr=False)

    def __post_init__(self):
        if (not _original_case(self.original, 1) or type(self.rewrites) is not tuple
                or len(self.rewrites) != len(PHISHREWRITE_LEVELS)):
            raise PhishRewriteError("invalid_cohort")
        provider = None
        for level, case in zip(PHISHREWRITE_LEVELS, self.rewrites):
            if (type(case) is not PhishCase or type(case.reference) is not PhishRewriteReference
                    or case.reference.parent != self.original.reference or case.reference.severity != level
                    or _level_reasons(case)):
                raise PhishRewriteError("invalid_cohort")
            if provider is not None and case.reference.provider != provider:
                raise PhishRewriteError("invalid_cohort")
            provider = case.reference.provider


@dataclass(frozen=True, slots=True)
class PhishParentExclusion:
    parent: PhishOriginalReference = field(repr=False)
    level_reasons: tuple[tuple[str, str], ...]

    def __post_init__(self):
        if (type(self.parent) is not PhishOriginalReference or self.parent.label != 1
                or type(self.level_reasons) is not tuple or not 1 <= len(self.level_reasons) <= 12):
            raise PhishRewriteError("invalid_cohort")
        ranks, per_level = [], {}
        for item in self.level_reasons:
            if (type(item) is not tuple or len(item) != 2 or type(item[0]) is not str
                    or item[0] not in PHISHREWRITE_LEVELS or type(item[1]) is not str or item[1] not in _REASONS):
                raise PhishRewriteError("invalid_cohort")
            level, reason = item
            ranks.append((PHISHREWRITE_LEVELS.index(level), _REASONS.index(reason)))
            per_level.setdefault(level, set()).add(reason)
        if ranks != sorted(set(ranks)):
            raise PhishRewriteError("invalid_cohort")
        if any(("missing_level" in reasons and len(reasons) != 1)
                or {"retention_unknown", "retention_false"} <= reasons for reasons in per_level.values()):
            raise PhishRewriteError("invalid_cohort")


def _unique_references(references):
    case_ids, email_ids, original_ids, rows, variants, releases = set(), set(), set(), set(), set(), set()
    for reference in references:
        if reference.case_id in case_ids:
            raise PhishRewriteError("duplicate_case_id")
        case_ids.add(reference.case_id)
        if type(reference) is PhishOriginalReference:
            if reference.email_id in email_ids:
                raise PhishRewriteError("duplicate_email_id")
            if reference.original_id in original_ids:
                raise PhishRewriteError("duplicate_original_id")
            email_ids.add(reference.email_id)
            original_ids.add(reference.original_id)
        else:
            variant = (reference.provider, reference.parent.original_id, reference.severity)
            if variant in variants:
                raise PhishRewriteError("duplicate_rewrite")
            variants.add(variant)
        provenance = reference.provenance
        row = (provenance.release_sha256, provenance.shard_sha256, provenance.row_index)
        if row in rows:
            raise PhishRewriteError("duplicate_provenance")
        rows.add(row)
        releases.add(provenance.release_sha256)
        if len(releases) > 1:
            raise PhishRewriteError("release_mismatch")


@dataclass(frozen=True, slots=True)
class PhishCohort:
    """Evaluator-side groups and diagnostics; empty populations do not imply a usable run."""

    provider: str = field(repr=False)
    parents: tuple[PhishParentGroup, ...] = field(repr=False)
    ham: tuple[PhishCase, ...] = field(repr=False)
    exclusions: tuple[PhishParentExclusion, ...] = field(repr=False)
    unrewritten: tuple[PhishOriginalReference, ...] = field(repr=False)

    def __post_init__(self):
        _identifier(self.provider)
        if (any(type(items) is not tuple for items in (self.parents, self.ham, self.exclusions, self.unrewritten))
                or any(type(group) is not PhishParentGroup for group in self.parents)
                or any(not _original_case(case, 0) for case in self.ham)
                or any(type(item) is not PhishParentExclusion for item in self.exclusions)
                or any(type(ref) is not PhishOriginalReference or ref.label != 1 for ref in self.unrewritten)):
            raise PhishRewriteError("invalid_cohort")
        populations = (tuple(group.original.reference for group in self.parents),
            tuple(case.reference for case in self.ham), tuple(item.parent for item in self.exclusions), self.unrewritten)
        all_originals = tuple(ref for population in populations for ref in population)
        if any(tuple(ref.original_id for ref in population) != tuple(sorted(ref.original_id for ref in population))
                for population in populations):
            raise PhishRewriteError("invalid_cohort")
        if len({ref.original_id for ref in all_originals}) != len(all_originals):
            raise PhishRewriteError("invalid_cohort")
        if any(case.reference.provider != self.provider for group in self.parents for case in group.rewrites):
            raise PhishRewriteError("invalid_cohort")
        _unique_references(all_originals + tuple(case.reference for group in self.parents for case in group.rewrites))

    def baseline_cases(self) -> tuple[PhishCase, ...]:
        return tuple(group.original for group in self.parents) + self.ham

    def rewrite_cases(self, severity: str) -> tuple[PhishCase, ...]:
        _severity(severity)
        index = PHISHREWRITE_LEVELS.index(severity)
        return tuple(group.rewrites[index] for group in self.parents) + self.ham


def _row_configuration(row, columns, case_id, provenance, limits):
    if (type(row) is not dict or len(row) != len(columns) or any(type(key) is not str for key in row)
            or set(row) != columns):
        raise PhishRewriteError("invalid_row")
    if type(limits) is not PhishLimits:
        raise PhishRewriteError("invalid_limits")
    if type(provenance) is not PhishProvenance:
        raise PhishRewriteError("invalid_provenance")
    _identifier(case_id, limits.max_identifier_chars)


def _bounded_input(case_id, text, limits):
    if type(text) is not str:
        raise PhishRewriteError("invalid_text")
    if len(text) > limits.max_text_chars:
        raise PhishRewriteError("text_limit")
    observed = PhishInput(case_id, text)
    model_bytes = _encode_model(text, limits.max_input_bytes)
    return observed, hashlib.sha256(model_bytes).hexdigest()


def adapt_original(row, *, case_id, provenance, limits) -> PhishCase:
    _row_configuration(row, _EMAIL_COLUMNS, case_id, provenance, limits)
    email_id, original_id, label, split = row["id"], row["original_id"], row["label"], row["split"]
    for value in (email_id, original_id):
        _identifier(value, limits.max_identifier_chars)
    if type(label) is not str or label not in ("0", "1"):
        raise PhishRewriteError("invalid_label")
    if type(split) is not str or split != "test":
        raise PhishRewriteError("invalid_split")
    observed, input_hash = _bounded_input(case_id, row["text"], limits)
    return PhishCase(observed, PhishOriginalReference(case_id, email_id, original_id, int(label), split,
        input_hash, provenance))


def adapt_rewrite(row, *, case_id, parent, provenance, limits) -> PhishCase:
    _row_configuration(row, _REWRITE_COLUMNS, case_id, provenance, limits)
    if type(parent) is not PhishOriginalReference or parent.label != 1:
        raise PhishRewriteError("invalid_parent")
    for value in (parent.case_id, parent.email_id, parent.original_id, row["original_id"], row["provider"], row["model"]):
        _identifier(value, limits.max_identifier_chars)
    if row["original_id"] != parent.original_id:
        raise PhishRewriteError("parent_mismatch")
    _severity(row["severity"])
    refused = _flag(row["refused"])
    retained = _flag(row["retained_urls_strict"], nullable=True)
    observed, input_hash = _bounded_input(case_id, row["rewrite_text"], limits)
    return PhishCase(observed, PhishRewriteReference(case_id, parent, row["provider"], row["model"],
        row["severity"], refused, retained, input_hash, provenance))


def _admit_case(case, reference_type, limits):
    if type(case) is not PhishCase or type(case.reference) is not reference_type:
        raise PhishRewriteError("invalid_cohort")
    reference = case.reference
    identifiers = [case.input.case_id, reference.case_id]
    if reference_type is PhishOriginalReference:
        identifiers.extend((reference.email_id, reference.original_id))
    else:
        identifiers.extend((reference.provider, reference.model, reference.parent.case_id,
            reference.parent.email_id, reference.parent.original_id))
    for value in identifiers:
        _identifier(value, limits.max_identifier_chars)
    if len(case.input.text) > limits.max_text_chars:
        raise PhishRewriteError("text_limit")
    _encode_model(case.input.text, limits.max_input_bytes)


def build_fixed_cohort(originals, rewrites, *, provider, limits) -> PhishCohort:
    if type(limits) is not PhishCohortLimits:
        raise PhishRewriteError("invalid_limits")
    if type(originals) is not tuple or type(rewrites) is not tuple:
        raise PhishRewriteError("invalid_cohort")
    if len(originals) > limits.max_originals:
        raise PhishRewriteError("original_count_limit")
    if len(rewrites) > limits.max_rewrites:
        raise PhishRewriteError("rewrite_count_limit")
    _identifier(provider, limits.case_limits.max_identifier_chars)
    for case in originals:
        _admit_case(case, PhishOriginalReference, limits.case_limits)
    for case in rewrites:
        _admit_case(case, PhishRewriteReference, limits.case_limits)
    _unique_references(tuple(case.reference for case in originals + rewrites))
    by_original = {case.reference.original_id: case for case in originals}
    selected = {}
    for case in rewrites:
        reference = case.reference
        parent = by_original.get(reference.parent.original_id)
        if parent is None:
            raise PhishRewriteError("missing_parent")
        if parent.reference != reference.parent:
            raise PhishRewriteError("parent_mismatch")
        if reference.provider == provider:
            selected.setdefault(reference.parent.original_id, {})[reference.severity] = case
    parents, exclusions = [], []
    for original_id in sorted(selected):
        per_level = selected[original_id]
        issues = []
        for level in PHISHREWRITE_LEVELS:
            if level not in per_level:
                issues.append((level, "missing_level"))
            else:
                issues.extend((level, reason) for reason in _level_reasons(per_level[level]))
        original = by_original[original_id]
        if issues:
            exclusions.append(PhishParentExclusion(original.reference, tuple(issues)))
        else:
            parents.append(PhishParentGroup(original, tuple(per_level[level] for level in PHISHREWRITE_LEVELS)))
    ordered = sorted(originals, key=lambda case: case.reference.original_id)
    ham = tuple(case for case in ordered if case.reference.label == 0)
    unrewritten = tuple(case.reference for case in ordered if case.reference.label == 1
        and case.reference.original_id not in selected)
    return PhishCohort(provider, tuple(parents), ham, tuple(exclusions), unrewritten)
