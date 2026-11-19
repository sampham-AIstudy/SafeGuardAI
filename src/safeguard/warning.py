"""Decide and persist local warning actions from scoped Detection results."""

from dataclasses import asdict, dataclass

from safeguard.detection.execution_host import DetectionOutcome
from safeguard.detection.intake import DetectionRequest
from safeguard.detection.model_contract import encoded
from safeguard.memory.conversation_status import SourceReference, StateError, StateProfile, StateWrite


@dataclass(frozen=True, slots=True)
class WarningNotice:
    rationale: str
    observed_count: int
    supporting: tuple[SourceReference, ...]


@dataclass(frozen=True, slots=True)
class WarningDecision:
    action: str
    reason: str
    active: WarningNotice | None


def _notice(value):
    if value is None:
        return None
    if (type(value) is not dict or set(value) != {"rationale", "observed_count", "supporting"}
            or type(value["rationale"]) is not str or not value["rationale"].strip()
            or type(value["observed_count"]) is not int or value["observed_count"] < 1
            or type(value["supporting"]) is not list or not value["supporting"]):
        raise ValueError("invalid_warning_notice")
    refs = tuple(SourceReference(**ref) for ref in value["supporting"])
    if len(set(refs)) != len(refs) or any(ref.observation_number > value["observed_count"] for ref in refs):
        raise ValueError("invalid_warning_notice")
    return WarningNotice(value["rationale"], value["observed_count"], refs)


_STORED_REASONS = {
    "warn": {"scam"},
    "update": {"new_evidence"},
    "no_action": {"no_scam_evidence", "insufficient_evidence", "same_evidence", "warnings_disabled"},
}


def _validate_warning(value):
    if (set(value) != {"assessment_run_id", "action", "reason", "active"}
            or type(value["assessment_run_id"]) is not str or not value["assessment_run_id"]
            or value["reason"] not in _STORED_REASONS.get(value["action"], ())):
        raise ValueError("invalid_warning_decision")
    active = _notice(value["active"])
    if active is None and value["action"] in {"warn", "update"}:
        raise ValueError("invalid_warning_decision")


WARNING_PROFILE = StateProfile("warning-decision", "1.0", _validate_warning)


def _decision(result, active, warn_on_scam):
    assessment = result["assessment"]
    if assessment["verdict"] != "scam":
        return WarningDecision("no_action", assessment["verdict"], active)
    if not warn_on_scam:
        return WarningDecision("no_action", "warnings_disabled", active)
    refs = tuple(SourceReference(**ref) for ref in result["supporting"])
    if active is not None and set(refs) == set(active.supporting):
        return WarningDecision("no_action", "same_evidence", active)
    notice = WarningNotice(assessment["rationale"], result["observed_count"], refs)
    return WarningDecision("warn", "scam", notice) if active is None else WarningDecision("update", "new_evidence", notice)


class WarningPolicy:
    """Apply a scoped result only while its committed analysis and prefix are current."""

    def __init__(self, memory, *, warn_on_scam: bool):
        if type(warn_on_scam) is not bool:
            raise ValueError("invalid_warning_settings")
        self._memory = memory
        self._warn_on_scam = warn_on_scam

    def current(self, context, key):
        head = self._memory.observations.head(context, key)
        snapshot = self._memory.warning_history.snapshot(context, head)
        record = next((record for record in snapshot.records if record.record_id == "latest"), None)
        return None if record is None else _notice(record.payload()["active"])

    def apply(self, request: DetectionRequest, outcome: DetectionOutcome) -> WarningDecision:
        if type(request) is not DetectionRequest or type(outcome) is not DetectionOutcome:
            raise ValueError("invalid_warning_input")
        boundary, context = request.boundary, request.context
        head = self._memory.observations.head(context, boundary.key)
        snapshot = self._memory.warning_history.snapshot(context, head)
        latest = next((record.payload() for record in snapshot.records if record.record_id == "latest"), None)
        active = None if latest is None else _notice(latest["active"])
        if head != boundary:
            return WarningDecision("no_action", "stale_boundary", active)
        if outcome.status != "completed":
            return WarningDecision("unavailable", "detection_failed", active)
        result = outcome.to_dict()
        analysis = self._memory.detector.snapshot(context, boundary)
        saved = next((record for record in analysis.records if record.record_id == "latest"), None)
        if saved is None or saved.boundary != boundary or saved.payload_json != encoded(result):
            return WarningDecision("no_action", "uncommitted_assessment", active)
        if latest is not None and latest["assessment_run_id"] == result["run_id"]:
            return WarningDecision("no_action", "duplicate_assessment", active)
        decision = _decision(result, active, self._warn_on_scam)
        payload = dict(asdict(decision), assessment_run_id=result["run_id"])
        references = () if decision.active is None else decision.active.supporting
        try:
            self._memory.warning_history.commit(context, boundary, expected_version=snapshot.version,
                operation_id=result["run_id"], writes=(StateWrite("warnings", "latest", encoded(payload), references),))
        except StateError:
            return WarningDecision("unavailable", "warning_storage_failed", active)
        return decision
