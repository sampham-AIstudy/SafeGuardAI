"""Shared Engine contract, independent neutral fixtures and two test controllers."""

import asyncio
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timezone
import gc
import hashlib
import json
import unittest

from safeguard.adapters.demo import create_demo_adapter
import warnings

from safeguard.adapters.gateways.demo import DemoGateway
from safeguard.conversation_memory import HistoryBoundary, HistoryLimits, InMemoryConversationMemory
from safeguard.scam_detection.context import ContextLimits, ContextPreparer
from safeguard.scam_detection.tools.evidence import PartReference
from safeguard.scam_detection.execution_host import (AssessmentProfile, CapabilityReply, CapabilitySpec, DetectionCancelled,
    ExecutionHost, ExecutionError, ExecutionLimits, ControllerReply, ControllerSpec, TokenUsage)
from safeguard.scam_detection.intake import DetectionIntake, DetectionRequest
from safeguard.ingress import AccessContext, ConversationIngress, InputLimits, ProcessingLimits
from safeguard.adapters.norm import normalize


INPUT = InputLimits(65536, 4096, 20, 8192, 32, 16)
CONTEXT = ContextLimits(64, 1048576, 1048576, 65536, 256, 128)
HISTORY = HistoryLimits(16, 128, 2097152, 64, 1048576, 128, 2097152)
LIMITS = ExecutionLimits(1048576, 4096, 4096, 8192, 8192, 131072, 8, 2, 2, 16, 20, 8192, 1.)
ACCESS = AccessContext("host-account", frozenset(("host-room", "host-garden")))
NOW = datetime(2026, 1, 6, tzinfo=timezone.utc)


def native(index=0, room="host-room"):
    return dict(thread=room, id=str(index), author="host-reader", body="Independently authored neutral shelf note.")


def encoded(document):
    return json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def validate_toy(document):
    if set(document) != {"summary"} or type(document["summary"]) is not str:
        raise ValueError("PRIVATE_PROFILE_DETAIL")


PROFILE = AssessmentProfile("neutral-test-profile", "1.0", validate_toy)


async def direct_controller(invocation, capabilities):
    return ControllerReply(encoded(dict(summary="A neutral test finding.")), supporting=(PartReference(1, 0),))


async def tool_controller(invocation, capabilities):
    response = await capabilities.call("echo", encoded(dict(summary="A neutral test finding.")))
    return ControllerReply(response, supporting=(PartReference(1, 0),))


async def echo(scope, arguments):
    return CapabilityReply(encoded(arguments))


class ExecutionHostTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.history = InMemoryConversationMemory(message_limits=INPUT, limits=HISTORY)
        self.history.__enter__()
        self.addCleanup(self.history.close)
        self.intake = DetectionIntake(self.history)
        self.preparer = ContextPreparer(message_limits=INPUT, limits=CONTEXT)
        self.request = self.intake.record(normalize(DemoGateway(account_id=ACCESS.account_id, clock=lambda: NOW).receive(native())), ACCESS)

    def host(self, *, limits=LIMITS, capabilities=None, profile=PROFILE):
        if capabilities is None:
            capabilities = (CapabilitySpec("echo", "1.0", "tool", echo),)
        return ExecutionHost(intake=self.intake, preparer=self.preparer, limits=limits, capabilities=capabilities, profile=profile)

    async def run_controller(self, controller=direct_controller, *, host=None, request=None,
                             grants=frozenset(("echo",)), state=b'{"counter":0}', name="test-controller"):
        return await (host or self.host()).run(request or self.request, strategy=ControllerSpec(name, "1.0", controller),
                                             allowed_capabilities=grants, initial_state_json=state)

    async def rejected(self, coroutine, code):
        with self.assertRaises(ExecutionError) as caught:
            await coroutine
        self.assertEqual((caught.exception.code, str(caught.exception)), (code, code))

    async def test_two_controllers_use_same_caller_input_profile_and_envelope(self):
        host = self.host()
        results = [await self.run_controller(controller, host=host, name=name) for controller, name in
                   ((direct_controller, "test-direct"), (tool_controller, "test-tool-user"))]
        views = [r.to_dict() for r in results]
        for result in results:
            self.assertEqual((result.status, result.code), ("completed", "ok"))
        for name in ("source", "account_id", "conversation_id", "observed_count", "context_sha256",
                     "initial_state_sha256", "assessment_profile", "assessment", "supporting", "input_coverage"):
            self.assertEqual(views[0][name], views[1][name], name)
        self.assertNotEqual(views[0]["run_id"], views[1]["run_id"])
        self.assertEqual([v["usage"]["capability_calls"] for v in views], [0, 1])
        self.assertEqual([v["usage"]["model_calls"] for v in views], [0, 0])
        self.assertEqual(self.history.stats["messages"], 1)

    async def test_input_prefix_scope_and_isolated_initial_state_are_exact(self):
        later = self.intake.record(normalize(DemoGateway(account_id=ACCESS.account_id, clock=lambda: NOW).receive(native(1))), ACCESS)
        observed = []

        async def controller(invocation, capabilities):
            state = json.loads(invocation.initial_state_json)
            state["counter"] += 1
            document = invocation.prepared.to_dict()
            observed.append((document["observed_count"], state["counter"]))
            self.assertEqual(len(document["messages"]), 1)
            document["messages"][0]["content_parts"][0]["text"] = "Receiver edit"
            with self.assertRaises(FrozenInstanceError):
                invocation.initial_state_json = b"{}"
            return await direct_controller(invocation, capabilities)

        for _ in range(2):
            result = await self.run_controller(controller)
            self.assertEqual(result.status, "completed")
        self.assertEqual(observed, [(1, 1), (1, 1)])
        self.assertEqual(self.intake.snapshot(later).messages[0]["content_parts"][0]["text"], native()["body"])

    async def test_capability_scope_and_argument_mutation_do_not_change_input(self):
        async def provider(scope, arguments):
            self.assertEqual(scope.access, ACCESS)
            self.assertEqual(scope.prepared.observed_count, 1)
            state = json.loads(scope.initial_state_json)
            self.assertEqual(state, dict(counter=0))
            arguments["summary"] = "Provider-owned argument copy."
            return CapabilityReply(encoded(arguments))

        original = encoded(dict(summary="Controller-owned bytes."))
        async def controller(invocation, capabilities):
            result = await capabilities.call("echo", original)
            self.assertEqual(original, encoded(dict(summary="Controller-owned bytes.")))
            return ControllerReply(result)

        result = await self.run_controller(controller, host=self.host(capabilities=(CapabilitySpec("echo", "1.0", "tool", provider),)))
        self.assertEqual(result.to_dict()["assessment"], dict(summary="Provider-owned argument copy."))

    async def test_permission_and_invalid_initial_state_reject_before_controller(self):
        async def forbidden(invocation, capabilities):
            self.fail("Rejected input reached controller")
        bad = replace(self.request, context=AccessContext("other-account", ACCESS.conversations))
        await self.rejected(self.run_controller(forbidden, request=bad), "request_rejected")
        for state in (b"[]", b'{"x":1,"x":2}', b'{"x":NaN}', b"[", b'\xff', b'{"x":"' + b"a" * 4096 + b'"}'):
            with self.subTest(state_size=len(state)):
                await self.rejected(self.run_controller(forbidden, state=state), "invalid_initial_state")
        await self.rejected(self.run_controller(forbidden, grants=frozenset(("unknown",))), "invalid_capability_grants")

    async def test_missing_unsupported_and_incomplete_are_explicit_unavailable_outcomes(self):
        for code in ("no_usable_input", "unsupported_input", "incomplete"):
            with self.subTest(code=code):
                async def controller(invocation, capabilities):
                    return ControllerReply(None, unresolved=(PartReference(1, 0),), unavailable_code=code)
                result = await self.run_controller(controller)
                self.assertEqual((result.status, result.code), ("unavailable", code))
                self.assertIsNone(result.to_dict()["assessment"])

    async def test_invalid_profile_payload_and_references_never_become_assessments(self):
        replies = [None, {}, ControllerReply(b'{"wrong":1}'), ControllerReply(b'{"summary":NaN}'),
                   ControllerReply(encoded(dict(summary="Neutral")), supporting=(PartReference(2, 0),)),
                   ControllerReply(encoded(dict(summary="Neutral")), supporting=(PartReference(1, 9),)),
                   ControllerReply(encoded(dict(summary="Neutral")), supporting=[PartReference(1, 0)]),
                   ControllerReply(None, unavailable_code="PRIVATE_ERROR"),
                   ControllerReply(None, supporting=(PartReference(1, 0),), unavailable_code="incomplete")]
        for reply in replies:
            with self.subTest(reply_type=type(reply)):
                async def controller(invocation, capabilities):
                    return reply
                result = await self.run_controller(controller)
                self.assertEqual(result.status, "failed")
                self.assertIsNone(result.to_dict()["assessment"])
                self.assertNotIn(b"PRIVATE", result.json_bytes)

    async def test_profile_must_not_mutate_numeric_types(self):
        async def controller(invocation, capabilities):
            return ControllerReply(b'{"count":1}')
        for replacement in (True, 1.0):
            with self.subTest(replacement_type=type(replacement)):
                def mutate(view):
                    view["count"] = replacement
                result = await self.run_controller(controller, host=self.host(profile=AssessmentProfile("mutation-test", "1.0", mutate)))
                self.assertEqual((result.status, result.code), ("failed", "invalid_assessment"))

    async def test_token_usage_is_adapter_reported_unknown_aware_and_counts_failures(self):
        for tokens, expected in ((TokenUsage(3, 5), (3, 5, True)), (None, (None, None, False)),
                                 (TokenUsage(None, 5), (None, 5, False))):
            with self.subTest(tokens=tokens):
                async def provider(scope, arguments):
                    return CapabilityReply(encoded(arguments), tokens)
                result = await self.run_controller(tool_controller, host=self.host(capabilities=(CapabilitySpec("echo", "1.0", "model", provider),)))
                usage = result.to_dict()["usage"]
                self.assertEqual((usage["model_calls"], usage["capability_calls"]), (1, 1))
                self.assertEqual((usage["input_tokens"], usage["output_tokens"], usage["token_usage_complete"]), expected)
        async def failed(scope, arguments):
            raise RuntimeError("PRIVATE_PROVIDER /private/file")
        result = await self.run_controller(tool_controller, host=self.host(capabilities=(CapabilitySpec("echo", "1.0", "model", failed),)))
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.to_dict()["usage"]["model_calls"], 1)
        self.assertIsNone(result.to_dict()["usage"]["input_tokens"])
        self.assertNotIn(b"PRIVATE_PROVIDER", result.json_bytes)

    async def test_call_and_model_ceilings_cannot_be_hidden_by_controller_recovery(self):
        called = []
        async def provider(scope, arguments):
            called.append(True)
            return CapabilityReply(encoded(arguments), TokenUsage(1, 1))
        async def recovering(invocation, capabilities):
            try:
                await capabilities.call("echo", b"{}")
            except ExecutionError:
                pass
            return await direct_controller(invocation, capabilities)
        for limits, kind, code in ((replace(LIMITS, max_calls=0), "model", "call_limit"),
                                   (replace(LIMITS, max_model_calls=0), "model", "model_call_limit")):
            with self.subTest(code=code):
                result = await self.run_controller(recovering, host=self.host(limits=limits, capabilities=(CapabilitySpec("echo", "1.0", kind, provider),)))
                self.assertEqual((result.status, result.code), ("limited", code))
                self.assertIsNone(result.to_dict()["assessment"])
        self.assertEqual(called, [])

    async def test_argument_capability_assessment_and_reference_limits(self):
        async def large_args(invocation, capabilities):
            await capabilities.call("echo", b'{"x":"too large"}')
        result = await self.run_controller(large_args, host=self.host(limits=replace(LIMITS, max_argument_bytes=2)))
        self.assertEqual((result.status, result.code), ("limited", "argument_limit"))
        async def provider(scope, arguments):
            return CapabilityReply(b'{"summary":"too large"}')
        result = await self.run_controller(tool_controller, host=self.host(limits=replace(LIMITS, max_capability_result_bytes=2), capabilities=(CapabilitySpec("echo", "1.0", "tool", provider),)))
        self.assertEqual((result.status, result.code), ("limited", "capability_result_limit"))
        for limits, code in ((replace(LIMITS, max_assessment_bytes=2), "assessment_limit"), (replace(LIMITS, max_references=0), "reference_limit")):
            with self.subTest(code=code):
                result = await self.run_controller(host=self.host(limits=limits))
                self.assertEqual((result.status, result.code), ("limited", code))

    async def test_denied_and_malformed_capability_calls_have_explicit_attempt_accounting(self):
        for name, args in (("PRIVATE_UNKNOWN_TOOL", b"{}"), ("echo", b"[]"), ("echo", b'{"x":1,"x":2}')):
            with self.subTest(name=name, args=args):
                async def controller(invocation, capabilities):
                    await capabilities.call(name, args)
                result = await self.run_controller(controller)
                usage = result.to_dict()["usage"]
                self.assertEqual((result.status, usage["attempted_calls"], usage["capability_calls"]), ("failed", 1, 0))
                self.assertNotIn(b"PRIVATE_UNKNOWN_TOOL", result.json_bytes)

    async def test_timeout_cancels_provider_and_reports_unknown_model_usage(self):
        released = asyncio.Event()
        async def provider(scope, arguments):
            try:
                await asyncio.Event().wait()
            finally:
                released.set()
        host = self.host(limits=replace(LIMITS, timeout_seconds=.005), capabilities=(CapabilitySpec("echo", "1.0", "model", provider),))
        result = await self.run_controller(tool_controller, host=host)
        self.assertEqual((result.status, result.code), ("timeout", "deadline_exceeded"))
        self.assertTrue(released.is_set())
        self.assertEqual(result.to_dict()["usage"]["calls"][0]["status"], "cancelled")
        self.assertIsNone(result.to_dict()["usage"]["input_tokens"])

    async def test_external_cancellation_preserves_control_semantics_and_terminal_result(self):
        entered, released = asyncio.Event(), asyncio.Event()
        async def provider(scope, arguments):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                released.set()
        host = self.host(capabilities=(CapabilitySpec("echo", "1.0", "tool", provider),))
        task = asyncio.create_task(self.run_controller(tool_controller, host=host))
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        with self.assertRaises(DetectionCancelled) as caught:
            await task
        self.assertEqual(caught.exception.outcome.status, "cancelled")
        self.assertIsNone(caught.exception.outcome.to_dict()["assessment"])
        self.assertTrue(task.cancelled() and released.is_set())
        self.assertEqual(self.history.stats["messages"], 1)

    async def test_cancellation_remains_cancellation_when_terminal_envelope_cannot_fit(self):
        entered, released = asyncio.Event(), asyncio.Event()
        async def provider(scope, arguments):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                released.set()
        host = self.host(limits=replace(LIMITS, max_result_bytes=1), capabilities=(CapabilitySpec("echo", "1.0", "tool", provider),))
        task = asyncio.create_task(self.run_controller(tool_controller, host=host))
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError) as caught:
            await task
        self.assertIsNone(caught.exception.outcome)
        self.assertEqual(caught.exception.result_error, "result_byte_limit")
        self.assertTrue(task.cancelled() and released.is_set())

    async def test_external_cancellation_during_deadline_cleanup_keeps_priority(self):
        cleanup_entered = asyncio.Event()
        async def provider(scope, arguments):
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cleanup_entered.set()
                await asyncio.Event().wait()
                raise
        host = self.host(limits=replace(LIMITS, timeout_seconds=.005), capabilities=(CapabilitySpec("echo", "1.0", "tool", provider),))
        task = asyncio.create_task(self.run_controller(tool_controller, host=host))
        await asyncio.wait_for(cleanup_entered.wait(), 1)
        task.cancel()
        with self.assertRaises(DetectionCancelled) as caught:
            await task
        self.assertEqual(caught.exception.outcome.status, "cancelled")
        self.assertTrue(task.cancelled())

    async def test_invalid_coroutine_returns_are_closed_without_runtime_warnings(self):
        async def unused():
            return None
        async def bad_strategy(invocation, capabilities):
            return unused()
        async def bad_provider(scope, arguments):
            return unused()
        cases = [(direct_controller, self.host(profile=AssessmentProfile("bad-wrapper-profile", "1.0", lambda view: unused()))),
                 (bad_strategy, self.host()),
                 (tool_controller, self.host(capabilities=(CapabilitySpec("echo", "1.0", "tool", bad_provider),)))]
        for controller, host in cases:
            with self.subTest(controller=controller.__name__), warnings.catch_warnings(record=True) as captured:
                warnings.simplefilter("always", RuntimeWarning)
                result = await self.run_controller(controller, host=host)
                self.assertEqual(result.status, "failed")
                gc.collect()
                self.assertEqual([str(w.message) for w in captured if issubclass(w.category, RuntimeWarning)], [])

    async def test_unfinished_operations_are_cancelled_before_final_outcome(self):
        entered, released = asyncio.Event(), asyncio.Event()
        children = []
        async def provider(scope, arguments):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                released.set()
        async def detached(invocation, capabilities):
            children.append(asyncio.create_task(capabilities.call("echo", b"{}")))
            await entered.wait()
            return await direct_controller(invocation, capabilities)
        result = await self.run_controller(detached, host=self.host(capabilities=(CapabilitySpec("echo", "1.0", "tool", provider),)))
        self.assertEqual((result.status, result.code), ("failed", "unfinished_capabilities"))
        self.assertTrue(released.is_set() and all(child.done() for child in children))

    async def test_closed_broker_cannot_start_later_operations(self):
        saved = []
        async def controller(invocation, capabilities):
            saved.append(capabilities)
            return await direct_controller(invocation, capabilities)
        result = await self.run_controller(controller)
        self.assertEqual(result.status, "completed")
        await self.rejected(saved[0].call("echo", b"{}"), "session_closed")

    async def test_concurrency_ceiling_is_shared_and_actual_usage_is_recorded(self):
        for concurrency in (1, 2):
            active = peak = 0
            async def provider(scope, arguments):
                nonlocal active, peak
                active += 1
                peak = max(peak, active)
                await asyncio.sleep(0)
                active -= 1
                return CapabilityReply(encoded(arguments))
            async def controller(invocation, capabilities):
                replies = await asyncio.gather(*(capabilities.call("echo", encoded(dict(summary="Neutral."))) for _ in range(2)))
                return ControllerReply(replies[0])
            with self.subTest(concurrency=concurrency):
                result = await self.run_controller(controller, host=self.host(limits=replace(LIMITS, max_inflight_calls=concurrency), capabilities=(CapabilitySpec("echo", "1.0", "tool", provider),)))
                self.assertEqual((result.status, peak, active), ("completed", concurrency, 0))
                self.assertEqual(result.to_dict()["usage"]["capability_calls"], 2)

    async def test_result_budget_falls_back_without_assessment_and_tiny_envelope_rejects(self):
        async def large(invocation, capabilities):
            return ControllerReply(encoded(dict(summary="A" * 4096)))
        result = await self.run_controller(large, host=self.host(limits=replace(LIMITS, max_result_bytes=2048)))
        self.assertEqual((result.status, result.code), ("limited", "result_byte_limit"))
        self.assertIsNone(result.to_dict()["assessment"])
        await self.rejected(self.run_controller(host=self.host(limits=replace(LIMITS, max_result_bytes=1))), "result_byte_limit")

    async def test_controller_exception_and_invalid_provider_result_do_not_leak_details(self):
        async def failed(invocation, capabilities):
            raise RuntimeError("PRIVATE_CONTROLLER_ERROR")
        result = await self.run_controller(failed)
        self.assertEqual((result.status, result.code), ("failed", "strategy_failed"))
        self.assertNotIn(b"PRIVATE_CONTROLLER_ERROR", result.json_bytes)
        for reply in (None, CapabilityReply(b"[]"), CapabilityReply(b'{"x":NaN}')):
            async def provider(scope, arguments):
                return reply
            with self.subTest(reply=type(reply)):
                result = await self.run_controller(tool_controller, host=self.host(capabilities=(CapabilitySpec("echo", "1.0", "tool", provider),)))
                self.assertEqual(result.status, "failed")
                self.assertEqual(result.to_dict()["usage"]["calls"][0]["code"], "invalid_capability_result")

    async def test_outcome_views_are_detached_and_metadata_is_immutable(self):
        result = await self.run_controller(tool_controller)
        view = result.to_dict()
        view["assessment"]["summary"] = "Receiver edit"
        view["usage"]["calls"].clear()
        self.assertEqual(result.to_dict()["assessment"]["summary"], "A neutral test finding.")
        self.assertEqual(len(result.to_dict()["usage"]["calls"]), 1)
        with self.assertRaises(FrozenInstanceError):
            result.status = "changed"

    async def test_limit_and_identity_validation(self):
        for item in fields(LIMITS):
            for value in (True, -1, None):
                with self.subTest(field=item.name, value=value), self.assertRaises(ValueError):
                    replace(LIMITS, **{item.name: value})
        for values in ((True, 0), (-1, 0), (0, 1.5)):
            with self.subTest(tokens=values), self.assertRaises(ExecutionError):
                TokenUsage(*values)
        for name in ("PRIVATE NAME", "", "a" * 65):
            with self.subTest(name=name), self.assertRaises(ExecutionError):
                ControllerSpec(name, "1.0", direct_controller)


class ExecutionHostIngressTests(unittest.IsolatedAsyncioTestCase):
    async def test_same_ingress_adapter_runs_both_controllers_without_contract_changes(self):
        all_results = []
        for controller in (direct_controller, tool_controller):
            with InMemoryConversationMemory(message_limits=INPUT, limits=HISTORY) as history:
                intake = DetectionIntake(history)
                host = ExecutionHost(intake=intake, preparer=ContextPreparer(message_limits=INPUT, limits=CONTEXT),
                                  limits=LIMITS, capabilities=(CapabilitySpec("echo", "1.0", "tool", echo),), profile=PROFILE)
                seen = []
                async def consumer(snapshot):
                    key = snapshot.key
                    # The host rechecks the exact boundary, never the later head.
                    boundary = HistoryBoundary(key, snapshot.observed_count, history.head(ACCESS, key).store_id)
                    request = DetectionRequest(boundary, ACCESS)
                    seen.append(await host.run(request, strategy=ControllerSpec("integration-controller", "1.0", controller),
                                               allowed_capabilities=frozenset(("echo",)), initial_state_json=b"{}"))
                async with ConversationIngress(consumer, adapter=create_demo_adapter(), input_limits=INPUT,
                        processing_limits=ProcessingLimits(2, 8, 1048576, 8, 8, 2.), intake=intake) as pipe:
                    tickets = [pipe.submit(native(i, room), ACCESS) for i in range(2) for room in ("host-room", "host-garden")]
                    outcomes = await asyncio.gather(*(t.wait() for t in tickets))
                self.assertTrue(all(o.status == "completed" for o in outcomes))
                self.assertTrue(all(r.status == "completed" for r in seen))
                views = [r.to_dict() for r in seen]
                for room in ("host-room", "host-garden"):
                    self.assertEqual([v["observed_count"] for v in views if v["conversation_id"] == room], [1, 2])
                all_results.append(sorted((v["conversation_id"], v["observed_count"], v["assessment"]["summary"]) for v in views))
        self.assertEqual(all_results[0], all_results[1])
