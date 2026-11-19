"""Provider-independent model access and run-local, source-separated interactions.

Clients are injected trusted async adapters. This module does not select a model,
make network requests, retry a provider or transmit original attachment bytes.
"""

import asyncio
from dataclasses import dataclass, field, replace
import hashlib
import inspect
import json
import re
from typing import Protocol

from safeguard.detection.execution_host import (
    CapabilityReply, CapabilitySpec, DetectionInvocation, ExecutionError, TokenUsage,
    _async_callable, _identity, _same_json,
)
from safeguard.detection.model_contract import (
    OutputProfile, ToolDefinition, closed, decode, encoded, text,
)
from safeguard.detection.media import MediaError, MediaPreparer, NativeMedia, media_ledger


FAILURES = frozenset(("invalid_request", "unsupported_request", "context_limit", "provider_error",
    "provider_timeout", "malformed_response", "invalid_action", "invalid_assessment", "output_limit", "unknown_completion"))
NO_RESULT = frozenset(("no_usable_input", "unsupported_input", "incomplete"))


class ModelContractError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ModelSettings:
    provider: str
    model: str
    configuration_sha256: str
    max_output_tokens: int
    max_presentation_bytes: int
    max_trace_bytes: int

    def __post_init__(self):
        text(self.provider)
        text(self.model)
        if type(self.configuration_sha256) is not str or re.fullmatch("[0-9a-f]{64}", self.configuration_sha256) is None:
            raise ValueError("invalid_model_settings")
        if any(type(v) is not int or v < 1 for v in
               (self.max_output_tokens, self.max_presentation_bytes, self.max_trace_bytes)):
            raise ValueError("invalid_model_settings")


@dataclass(frozen=True, slots=True)
class ModelCallBinding:
    run_id: str
    call_id: str
    prepared: object = field(repr=False)
    access: object = field(repr=False)
    settings: ModelSettings
    deadline: float
    presentation_json: bytes = field(repr=False)
    trace_json: bytes = field(repr=False)
    media: tuple[NativeMedia, ...] = field(default=(), repr=False)


class ModelClient(Protocol):
    """Trusted backend adapter; normalized finish/attempt metadata and actual usage.

    A concrete adapter must enforce its selected provider limits, avoid hidden
    retries and propagate cancellation. A scripted client verifies none of that IO.
    """

    async def __call__(self, binding: ModelCallBinding, request: dict) -> CapabilityReply: ...


def _failure(call_id, code, attempted=False, finish=None):
    return dict(model_contract_version="1.0", call_id=call_id, provider_attempted=attempted,
                finish_reason=finish or ("complete" if attempted else "not_started"),
                output=dict(kind="failure", code=code))


def _references(values, prepared, limit):
    if type(values) is not list or len(values) > limit:
        raise ValueError("invalid_references")
    seen = set()
    for value in values:
        prepared.resolve_part(value)
        key = (value["observation_number"], value["part_index"])
        if key in seen:
            raise ValueError("duplicate_reference")
        seen.add(key)


class ModelAccess:
    """Trusted assembly configuration; interaction state is local to each run."""

    def __init__(self, *, name, version, client: ModelClient, instructions, profile: OutputProfile,
                 tools: tuple[ToolDefinition, ...], settings: ModelSettings, input_fit, select_visible_state,
                 media_preparer: MediaPreparer | None = None):
        _identity(name, version)
        text(instructions)
        if not _async_callable(client) or type(profile) is not OutputProfile or type(settings) is not ModelSettings:
            raise ValueError("invalid_model_configuration")
        if type(tools) is not tuple or any(type(t) is not ToolDefinition for t in tools) or len({t.name for t in tools}) != len(tools) or name in {t.name for t in tools}:
            raise ValueError("invalid_tool_catalog")
        if any(not callable(f) or _async_callable(f) for f in (input_fit, select_visible_state)):
            raise ValueError("invalid_model_configuration")
        if media_preparer is not None and type(media_preparer) is not MediaPreparer:
            raise ValueError("invalid_model_configuration")
        self.name, self.version = name, version
        self.client, self.instructions, self.profile = client, instructions, profile
        self.tools, self.settings = tools, settings
        self.input_fit, self.select_visible_state = input_fit, select_visible_state
        self.media_preparer = media_preparer

    def capability(self):
        return CapabilitySpec(self.name, self.version, "model", self.execute)

    def conversation(self, invocation):
        return ModelConversation(self, invocation)

    def _binding(self, scope, request, conversation):
        if type(conversation) is not ModelConversation or conversation._model is not self or conversation._closed:
            raise ValueError("invalid_binding")
        invocation = conversation._invocation
        if scope.invocation is not invocation or scope.prepared is not invocation.prepared or scope.deadline is None:
            raise ValueError("invalid_binding")
        if invocation.profile is not self.profile.assessment or not _same_json(request, conversation._request):
            raise ValueError("invalid_binding")
        if conversation._pending_tools or conversation._issued:
            raise ValueError("unsettled_interaction")
        grants = {(c.name, c.version, c.kind) for c in invocation.capabilities}
        if (self.name, self.version, "model") not in grants or any((t.name, t.version, "tool") not in grants for t in self.tools):
            raise ValueError("invalid_tool_grants")
        closed(request, ("model_contract_version", "call_id", "context_sha256", "transcript_sha256",
                         "output_profile", "tool_names", "requested_outputs", "generation"))
        text(request["call_id"])
        closed(request["generation"], ("max_output_tokens",))
        tokens = request["generation"]["max_output_tokens"]
        if type(tokens) is not int or not 1 <= tokens <= self.settings.max_output_tokens:
            raise ValueError("invalid_request")
        if request["model_contract_version"] != "1.0" or request["output_profile"] != self.profile.identity():
            raise ValueError("invalid_request")
        if request["context_sha256"] != hashlib.sha256(scope.prepared.json_bytes).hexdigest() or request["transcript_sha256"] != hashlib.sha256(conversation.trace_json).hexdigest():
            raise ValueError("invalid_request")
        # The run-local builder fixes these to the complete granted catalog and supported variants.
        expected_outputs = ["structured_result", "no_result"] + (["tool_requests"] if self.tools else [])
        if request["tool_names"] != [t.name for t in self.tools] or request["requested_outputs"] != expected_outputs:
            raise ValueError("invalid_request")
        state = self.select_visible_state(scope.initial_state_json)
        if inspect.iscoroutine(state):
            state.close()
            raise ValueError("invalid_visible_state")
        state = decode(state, invocation.limits, invocation.limits.max_state_bytes)
        presentation = dict(instructions=self.instructions, observed_context=scope.prepared.to_dict(),
            visible_state=state,
            tools=[dict(name=t.name, version=t.version, description=t.description,
                        arguments_schema=json.loads(t.arguments_schema_json)) for t in self.tools],
            output_profile=dict(**self.profile.identity(), schema=json.loads(self.profile.schema_json)),
            interaction_trace=json.loads(conversation.trace_json),
            media=[dict(source_ref=p["source_ref"], mode="reference_only", processing_status="not_presented")
                   for m in scope.prepared.to_dict()["messages"] for p in m["content_parts"] if p["kind"] != "text"])
        return ModelCallBinding(invocation.run_id, request["call_id"], scope.prepared, scope.access,
            self.settings, scope.deadline, encoded(presentation), conversation.trace_json)

    def _tool_batch(self, calls, conversation):
        if type(calls) is not list or not calls:
            raise ValueError("invalid_calls")
        catalog = {t.name: t for t in self.tools}
        ids = set(conversation._tool_ids)
        for call in calls:
            closed(call, ("tool_call_id", "name", "arguments"))
            text(call["tool_call_id"])
            if call["tool_call_id"] in ids or type(call["name"]) is not str or call["name"] not in catalog:
                raise ValueError("invalid_action")
            ids.add(call["tool_call_id"])
            arguments = decode(encoded(call["arguments"]), conversation._invocation.limits,
                               conversation._invocation.limits.max_argument_bytes)
            catalog[call["name"]].check(conversation._invocation.prepared, arguments)

    def _validate_reply(self, reply, request, conversation):
        try:
            closed(reply, ("model_contract_version", "call_id", "provider_attempted", "finish_reason", "output"))
            if reply["model_contract_version"] != "1.0" or reply["call_id"] != request["call_id"] or type(reply["provider_attempted"]) is not bool:
                raise ValueError()
            attempted, finish, output = reply["provider_attempted"], reply["finish_reason"], reply["output"]
            if attempted and finish in ("output_limit", "unknown"):
                code = "output_limit" if finish == "output_limit" else "unknown_completion"
                return _failure(request["call_id"], code, True, finish)
            if type(output) is not dict or type(output.get("kind")) is not str:
                raise ValueError()
            kind = output["kind"]
            if kind == "failure":
                closed(output, ("kind", "code"))
                if output["code"] not in FAILURES:
                    raise ValueError()
                if finish != ("complete" if attempted else "not_started"):
                    raise ValueError()
                if output["code"] in ("invalid_request", "unsupported_request") and attempted:
                    raise ValueError()
                if output["code"] in ("output_limit", "unknown_completion"):
                    raise ValueError()
                return reply
            if not attempted or finish != "complete" or (kind not in request["requested_outputs"] and kind != "refusal"):
                raise ValueError()
            if kind == "tool_requests":
                closed(output, ("kind", "calls", "public_text"))
                if output["public_text"] is not None and type(output["public_text"]) is not str:
                    raise ValueError()
                try:
                    self._tool_batch(output["calls"], conversation)
                except Exception:
                    raise ModelContractError("invalid_action") from None
            elif kind in ("structured_result", "no_result"):
                try:
                    if kind == "structured_result":
                        closed(output, ("kind", "profile", "payload", "supporting", "counter", "unresolved"))
                        if output["profile"] != self.profile.identity():
                            raise ValueError()
                        payload = decode(encoded(output["payload"]), conversation._invocation.limits,
                                         conversation._invocation.limits.max_assessment_bytes)
                        self.profile.validate(payload)
                        groups = (output["supporting"], output["counter"], output["unresolved"])
                    else:
                        closed(output, ("kind", "reason", "unresolved"))
                        if output["reason"] not in NO_RESULT:
                            raise ValueError()
                        groups = (output["unresolved"],)
                    limit = conversation._invocation.limits.max_references
                    if any(type(g) is not list for g in groups) or sum(map(len, groups)) > limit:
                        raise ValueError()
                    for group in groups:
                        _references(group, conversation._invocation.prepared, limit)
                except Exception:
                    raise ModelContractError("invalid_assessment") from None
            elif kind == "refusal":
                closed(output, ("kind", "reason"))
                if output["reason"] != "model_refusal":
                    raise ValueError()
            else:
                raise ValueError()
            return reply
        except ModelContractError:
            raise
        except Exception:
            raise ModelContractError("malformed_response") from None

    async def execute(self, scope, request):
        conversation = scope.model_binding
        try:
            binding = self._binding(scope, request, conversation)
        except Exception:
            return CapabilityReply(encoded(_failure(request.get("call_id", "invalid-call"), "invalid_request")), TokenUsage(0, 0))
        conversation._issued = True
        call_id = request["call_id"]
        tokens = TokenUsage(0, 0)
        try:
            if len(binding.presentation_json) > self.settings.max_presentation_bytes:
                reply = _failure(call_id, "context_limit")
            elif asyncio.get_running_loop().time() >= binding.deadline:
                reply = _failure(call_id, "provider_timeout")
            else:
                if conversation._media is None:
                    conversation._media = (() if self.media_preparer is None else
                        self.media_preparer.prepare(binding.prepared, binding.access))
                presentation = json.loads(binding.presentation_json)
                presentation["media"] = media_ledger(binding.prepared, binding.access, conversation._media,
                    max_context_bytes=self.settings.max_presentation_bytes)
                binding = replace(binding, presentation_json=encoded(presentation), media=conversation._media)
                if len(binding.presentation_json) > self.settings.max_presentation_bytes:
                    raise MediaError("context_limit")
                if asyncio.get_running_loop().time() >= binding.deadline:
                    raise TimeoutError
                fit = self.input_fit(binding, json.loads(encoded(request)))
                if inspect.iscoroutine(fit):
                    fit.close()
                if type(fit) is not bool:
                    reply = _failure(call_id, "unsupported_request")
                elif not fit:
                    reply = _failure(call_id, "context_limit")
                elif asyncio.get_running_loop().time() >= binding.deadline:
                    reply = _failure(call_id, "provider_timeout")
                else:
                    tokens = None
                    try:
                        raw = await self.client(binding, json.loads(encoded(request)))
                        if type(raw) is not CapabilityReply or (raw.tokens is not None and type(raw.tokens) is not TokenUsage):
                            raise ModelContractError("malformed_response")
                        tokens = raw.tokens
                        try:
                            value = decode(raw.json_bytes, conversation._invocation.limits,
                                           conversation._invocation.limits.max_capability_result_bytes)
                        except ValueError:
                            raise ModelContractError("malformed_response") from None
                        reply = self._validate_reply(value, request, conversation)
                    except ModelContractError as error:
                        reply = _failure(call_id, error.code, True)
                    except TimeoutError:
                        reply = _failure(call_id, "provider_timeout", True)
                    except Exception:
                        reply = _failure(call_id, "provider_error", True)
        except MediaError as error:
            reply = _failure(call_id, error.code)
        except TimeoutError:
            reply = _failure(call_id, "provider_timeout")
        except Exception:
            reply = _failure(call_id, "unsupported_request")
        conversation._accept(request, reply)
        return CapabilityReply(encoded(reply), tokens)


class ModelConversation:
    """Run-local journal; only actual broker observations enter the next presentation."""

    def __init__(self, model, invocation):
        if type(model) is not ModelAccess or type(invocation) is not DetectionInvocation or invocation._model_journal.claimed:
            raise ExecutionError("invalid_interaction_state")
        invocation._model_journal.claimed = True
        self._model, self._invocation = model, invocation
        self._trace = []
        self._tool_ids, self._pending_tools = set(), []
        self._request, self._issued, self._closed = None, False, False
        self._call_number = 0
        self._media = None

    @property
    def trace_json(self):
        return encoded(self._trace)

    def _append(self, entry):
        if len(encoded(self._trace + [entry])) > self._model.settings.max_trace_bytes:
            raise ExecutionError("interaction_trace_limit")
        self._trace.append(json.loads(encoded(entry)))

    async def next(self, broker):
        if self._closed or self._pending_tools or self._request is not None:
            raise ExecutionError("invalid_interaction_state")
        model = self._model
        self._call_number += 1
        request = dict(model_contract_version="1.0", call_id=f"{self._invocation.run_id}:{self._call_number}",
            context_sha256=hashlib.sha256(self._invocation.prepared.json_bytes).hexdigest(),
            transcript_sha256=hashlib.sha256(self.trace_json).hexdigest(),
            output_profile=model.profile.identity(), tool_names=[t.name for t in model.tools],
            requested_outputs=["structured_result", "no_result"] + (["tool_requests"] if model.tools else []),
            generation=dict(max_output_tokens=model.settings.max_output_tokens))
        self._request = json.loads(encoded(request))
        reply = await broker.call(model.name, encoded(request), model_binding=self)
        return decode(reply, self._invocation.limits, self._invocation.limits.max_capability_result_bytes)

    def _accept(self, request, reply):
        self._append(dict(kind="model_exchange", request=request, reply=reply))
        if reply["output"]["kind"] == "tool_requests":
            self._pending_tools = json.loads(encoded(reply["output"]["calls"]))
            self._tool_ids.update(c["tool_call_id"] for c in self._pending_tools)
        self._request, self._issued = None, False

    async def run_tools(self, broker):
        if self._closed or not self._pending_tools:
            raise ExecutionError("invalid_interaction_state")
        broker.validate_tool_batch(self._pending_tools, self._model.tools)
        while self._pending_tools:
            call = self._pending_tools[0]
            try:
                raw = await broker.call(call["name"], encoded(call["arguments"]))
                outcome = dict(status="completed", payload=decode(raw, self._invocation.limits,
                    self._invocation.limits.max_capability_result_bytes))
            except ExecutionError as error:
                # Broker errors are fixed public codes; callback exception strings never escape.
                outcome = dict(status="failed", code=error.code)
            self._append(dict(kind="tool_observation", tool_call_id=call["tool_call_id"],
                              name=call["name"], outcome=outcome))
            self._pending_tools.pop(0)

    def close(self):
        self._closed = True
        self._pending_tools.clear()
        self._trace.clear()
        self._request = None
        self._media = None
