"""Shared Detection assembly; selecting a controller does not change other blocks."""

import inspect

from safeguard.memory.conversation_status import (
    ConversationStatus, SourceReference, StateWrite,
)
from safeguard.detection.execution_host import ControllerSpec, ExecutionError, ExecutionHost, _async_callable
from safeguard.detection.intake import DetectionRequest
from safeguard.detection.model_contract import encoded


class DetectionService:
    """Bind exact observed/derived boundaries and commit only validated assessments.

    A failed/uncertain commit returns no assessment. Its run_id is the Memory
    operation identity for diagnosis; automatic retries or stale-result overwrite
    are deliberately absent. The same service accepts any ControllerSpec.
    """

    def __init__(self, *, host: ExecutionHost, memory: ConversationStatus,
                 controller: ControllerSpec, allowed_capabilities: frozenset[str], select_initial_state=None):
        if type(host) is not ExecutionHost or type(memory) is not ConversationStatus or type(controller) is not ControllerSpec:
            raise ExecutionError("invalid_detection_configuration")
        if host.intake.history is not memory.observations:
            raise ExecutionError("invalid_detection_memory")
        if type(allowed_capabilities) is not frozenset:
            raise ExecutionError("invalid_capability_grants")
        if select_initial_state is not None and (not callable(select_initial_state) or _async_callable(select_initial_state)):
            raise ExecutionError("invalid_state_selector")
        self.host, self.memory, self.controller = host, memory, controller
        self.allowed_capabilities = allowed_capabilities
        self.select_initial_state = select_initial_state

    async def run(self, request):
        if type(request) is not DetectionRequest:
            raise ExecutionError("invalid_request")
        snapshot = self.memory.detector.snapshot(request.context, request.boundary)
        # Explicitly expose only Memory revision metadata to the controller. A model's
        # visible-state selector still needs to opt in to any of these fields.
        initial = encoded(dict(memory_version=snapshot.version)) if self.select_initial_state is None else self.select_initial_state(snapshot)
        if inspect.iscoroutine(initial):
            initial.close()
            raise ExecutionError("invalid_initial_state")

        async def finalize(invocation, outcome):
            document = outcome.to_dict()
            references = tuple(SourceReference(*key) for key in sorted({
                (ref["observation_number"], ref["part_index"])
                for group in ("supporting", "counter", "unresolved") for ref in document[group]}))
            self.memory.detector.commit(request.context, request.boundary,
                expected_version=snapshot.version, operation_id=invocation.run_id,
                writes=(StateWrite("analysis", "latest", outcome.json_bytes, references),))

        return await self.host.run(request, strategy=self.controller,
            allowed_capabilities=self.allowed_capabilities, initial_state_json=initial, finalizer=finalize)
