"""Compose the agent with durable Memory and an injected model client."""

from collections.abc import Callable
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path

from safeguard.detection.agent_controller import AgentController
from safeguard.detection.assessment import SCAM_INSTRUCTIONS, SCAM_PROFILE
from safeguard.detection.context import ContextLimits, ContextPreparer, PreparedContext
from safeguard.detection.execution_host import ExecutionHost, ExecutionLimits
from safeguard.detection.intake import DetectionIntake
from safeguard.detection.media import MediaLimits, MediaPreparer, MediaSelection
from safeguard.detection.model_access import ModelAccess
from safeguard.detection.service import DetectionService
from safeguard.detection.tools.catalog import evidence_tool, observed_part_tool
from safeguard.detection.tools.evidence import EvidenceLimits, EvidencePreparer
from safeguard.detection.tools.readers import Utf8TextReader
from safeguard.ingress import InputLimits
from safeguard.memory.conversation_status import (
    ConversationStatus, HistoryLimits, SqliteConversationStatus, SqliteDerivedState,
    StateLimits, StateProfile,
)
from safeguard.memory.original_assets import AssetLimits, PersistentAssetStore
from safeguard.storage.local import StorageLimits
from safeguard.warning import WARNING_PROFILE


@dataclass(frozen=True, slots=True)
class AgentLimits:
    """Explicit application limits. No production resource defaults are selected."""

    input: InputLimits
    history: HistoryLimits
    state: StateLimits
    assets: AssetLimits
    storage: StorageLimits
    context: ContextLimits
    execution: ExecutionLimits
    evidence: EvidenceLimits


@dataclass(frozen=True, slots=True)
class NativeMediaOptions:
    """Bound the original files an application may send to its model client."""

    limits: MediaLimits
    select_media: Callable[[PreparedContext], tuple[MediaSelection, ...]]


@dataclass(frozen=True, slots=True)
class AgentRuntime:
    memory: ConversationStatus
    originals: PersistentAssetStore
    detection: DetectionService


def _analysis_profile(document):
    if (document.get("engine_result_schema_version") != "1.0"
            or document.get("status") != "completed" or document.get("code") != "ok"
            or document.get("assessment_profile") != SCAM_PROFILE.identity()):
        raise ValueError("invalid_agent_analysis")
    SCAM_PROFILE.validate(document["assessment"])
    SCAM_PROFILE.assessment.validate_result(document)


@contextmanager
def open_agent_runtime(*, root, limits: AgentLimits, client, settings, input_fit,
                       reader: Utf8TextReader, native_media: NativeMediaOptions | None = None,
                       private_outgoing_sender: str | None = None):
    """Open stores below an existing parent and close them on every exit path.

    The caller owns permissions, ingress, admission scheduling, and any live-job
    authorization. Native media is opt-in and selection is scoped to the observed prefix.
    Model clients are injected; this function does not discover credentials.
    """
    root = Path(root)
    with ExitStack() as stack:
        history = stack.enter_context(SqliteConversationStatus(root=root / "memory",
            message_limits=limits.input, limits=limits.history, storage_limits=limits.storage))
        originals = stack.enter_context(PersistentAssetStore(root=root / "originals",
            limits=limits.assets, storage_limits=limits.storage))
        derived = SqliteDerivedState(history=history, limits=limits.state,
            profiles={"analysis": StateProfile("agent-scam-analysis", "1.0", _analysis_profile),
                      "warnings": WARNING_PROFILE})
        stack.callback(derived.close)
        memory = ConversationStatus(observations=history, derived=derived)
        tools = (observed_part_tool(), evidence_tool(
            preparer=EvidencePreparer(store=originals, limits=limits.evidence),
            spec=reader.spec, reader=reader))
        media_preparer = None
        if native_media is not None:
            if type(native_media) is not NativeMediaOptions:
                raise ValueError("invalid_native_media_options")
            media_preparer = MediaPreparer(store=originals, limits=native_media.limits,
                                           select_media=native_media.select_media)
        instructions = SCAM_INSTRUCTIONS
        if private_outgoing_sender is not None:
            instructions += ("\nAssess incoming messages. Empty outgoing entries preserve their positions only. "
                             "Their contents and attachments are withheld. Do not infer or cite those contents.\n")
        model = ModelAccess(name="agent-model", version="1.0", client=client,
            instructions=instructions, profile=SCAM_PROFILE, tools=tools,
            settings=settings, input_fit=input_fit, select_visible_state=lambda initial: b"{}",
            media_preparer=media_preparer)
        host = ExecutionHost(intake=DetectionIntake(history),
            preparer=ContextPreparer(message_limits=limits.input, limits=limits.context,
                                     private_outgoing_sender=private_outgoing_sender),
            limits=limits.execution,
            capabilities=(model.capability(),) + tuple(tool.capability() for tool in tools),
            profile=SCAM_PROFILE.assessment)
        detection = DetectionService(host=host, memory=memory,
            controller=AgentController(model=model).spec,
            allowed_capabilities=frozenset((model.name, *(tool.name for tool in tools))))
        yield AgentRuntime(memory, originals, detection)
