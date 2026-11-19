"""Scoped, read-only capabilities; model arguments contain local source refs only."""

from safeguard.detection.model_contract import ToolDefinition, encoded
from safeguard.detection.execution_host import CapabilityReply
from safeguard.detection.tools.evidence import EvidencePreparer, PartReference, ReaderSpec


REFERENCE_SCHEMA = encoded(dict(type="object", additionalProperties=False,
    properties=dict(observation_number=dict(type="integer", minimum=1),
                    part_index=dict(type="integer", minimum=0)),
    required=["observation_number", "part_index"]))


def _check_reference(prepared, arguments):
    prepared.resolve_part(arguments)


def observed_part_tool():
    """Return a detached part from the Host-bound prefix, never a later observation."""
    async def execute(scope, arguments):
        return CapabilityReply(encoded(dict(source_ref=arguments,
            part=scope.prepared.resolve_part(arguments))))
    return ToolDefinition("observed-part", "1.0", "Read one source part in the bound observed prefix.",
        REFERENCE_SCHEMA, _check_reference, execute)


def evidence_tool(*, preparer: EvidencePreparer, spec: ReaderSpec, reader):
    """Bind one trusted reader; no model-selected reader, path, URL or storage scope."""
    if type(preparer) is not EvidencePreparer or type(spec) is not ReaderSpec or not callable(reader):
        raise ValueError("invalid_evidence_tool")

    def validate(prepared, arguments):
        part = prepared.resolve_part(arguments)
        if part["kind"] == "text":
            raise ValueError("attachment_required")

    async def execute(scope, arguments):
        result = preparer.process(scope.prepared, scope.access, PartReference(**arguments), spec=spec, reader=reader)
        return CapabilityReply(result.json_bytes)

    return ToolDefinition("read-evidence", "1.0", "Read a bound attachment using the configured content reader.",
        REFERENCE_SCHEMA, validate, execute)
