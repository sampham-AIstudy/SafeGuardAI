"""Neutral behavior regressions for reviewed Detection runtime defects."""

import asyncio
from dataclasses import replace
import time
import unittest

import test_agent_controller as agent
from safeguard.detection.execution_host import (
    AssessmentProfile, CapabilityReply, ControllerReply, ControllerSpec,
    DetectionCancelled, ExecutionError,
)
from safeguard.detection.model_access import ModelConversation
from safeguard.detection.model_contract import (
    OutputProfile, ToolDefinition, encoded, schema_document, validate_schema,
)
from safeguard.detection.tools.catalog import observed_part_tool


class RuntimeRegressionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture = agent.AgentControllerTests(
            methodName="test_immediate_result_uses_common_envelope_and_exact_binding")
        await self.fixture.asyncSetUp()
        self.addCleanup(self.fixture.doCleanups)

    async def test_blocked_model_deadline_applies_to_every_result_before_finalization(self):
        for enabled in (False, True):
            for output in (agent.result(), dict(kind="no_result", reason="incomplete", unresolved=[])):
                with self.subTest(finalizer_enabled=enabled, kind=output["kind"]):
                    saved = []

                    async def client(binding, request):
                        time.sleep(.03)
                        return CapabilityReply(encoded(agent.envelope(request, output)))

                    async def finalize(invocation, outcome):
                        saved.append(outcome)

                    outcome = await self.fixture.run_agent(self.fixture.model(client),
                        limits=replace(agent.fixtures.LIMITS, timeout_seconds=.01),
                        finalizer=finalize if enabled else None)
                    self.assertEqual((outcome.status, outcome.code), ("timeout", "deadline_exceeded"))
                    self.assertIsNone(outcome.to_dict()["assessment"])
                    self.assertEqual(saved, [])

    async def test_on_time_model_result_and_finalization_still_complete(self):
        saved = []

        async def finalize(invocation, outcome):
            saved.append(outcome)

        outcome = await self.fixture.run_agent(
            self.fixture.model(agent.ScriptedClient([agent.result()])), finalizer=finalize)
        self.assertEqual((outcome.status, outcome.code), ("completed", "ok"))
        self.assertEqual(saved, [outcome])

    async def test_cancellation_keeps_priority_after_blocked_deadline(self):
        async def client(binding, request):
            time.sleep(.03)
            raise asyncio.CancelledError()

        with self.assertRaises(DetectionCancelled) as caught:
            await self.fixture.run_agent(self.fixture.model(client),
                limits=replace(agent.fixtures.LIMITS, timeout_seconds=.01))
        self.assertEqual(caught.exception.outcome.status, "cancelled")
        self.assertIsNone(caught.exception.outcome.to_dict()["assessment"])

    async def test_late_strategy_failure_is_classified_by_the_same_deadline(self):
        async def controller(invocation, broker):
            time.sleep(.03)
            raise ValueError("Independent failing controller.")

        outcome = await self.fixture.run_agent(self.fixture.model(agent.ScriptedClient([])),
            limits=replace(agent.fixtures.LIMITS, timeout_seconds=.01),
            controller=ControllerSpec("late-strategy-failure", "1.0", controller))
        self.assertEqual((outcome.status, outcome.code), ("timeout", "deadline_exceeded"))
        self.assertIsNone(outcome.to_dict()["assessment"])

    async def test_broker_cleanup_time_counts_toward_the_deadline(self):
        entered = asyncio.Event()
        stopped = asyncio.Event()

        async def execute(scope, arguments):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                time.sleep(.03)
                stopped.set()

        tool = replace(observed_part_tool(), execute=execute)

        async def controller(invocation, broker):
            asyncio.create_task(broker.call(tool.name, encoded(agent.REF)))
            await entered.wait()
            return ControllerReply(None, unavailable_code="incomplete")

        model = self.fixture.model(agent.ScriptedClient([]), (tool,))
        outcome = await self.fixture.run_agent(model,
            limits=replace(agent.fixtures.LIMITS, timeout_seconds=.01),
            controller=ControllerSpec("late-broker-cleanup", "1.0", controller))
        self.assertTrue(stopped.is_set())
        self.assertEqual((outcome.status, outcome.code), ("timeout", "deadline_exceeded"))
        self.assertIsNone(outcome.to_dict()["assessment"])

    async def test_reopening_a_journal_cannot_repeat_model_or_tool_effects(self):
        for close_first in (False, True):
            for direct_constructor in (False, True):
                with self.subTest(close_first=close_first, direct_constructor=direct_constructor):
                    effects = []
                    rejected = []

                    async def execute(scope, arguments):
                        effects.append(arguments)
                        return CapabilityReply(b"{}")

                    tool = replace(observed_part_tool(), execute=execute)
                    client = agent.ScriptedClient([
                        agent.calls(("same-tool-id", tool.name, agent.REF)),
                        agent.calls(("same-tool-id", tool.name, agent.REF)),
                    ])
                    model = self.fixture.model(client, (tool,))

                    async def controller(invocation, broker):
                        first = model.conversation(invocation)
                        second = None
                        try:
                            await first.next(broker)
                            await first.run_tools(broker)
                            if close_first:
                                first.close()
                            try:
                                second = (ModelConversation(model, invocation) if direct_constructor
                                          else model.conversation(invocation))
                            except ExecutionError as error:
                                rejected.append(error.code)
                            else:
                                await second.next(broker)
                                await second.run_tools(broker)
                        finally:
                            first.close()
                            if second is not None:
                                second.close()
                        return ControllerReply(None, unavailable_code="incomplete")

                    outcome = await self.fixture.run_agent(model,
                        controller=ControllerSpec("journal-reopen-probe", "1.0", controller))
                    self.assertEqual(outcome.status, "unavailable")
                    self.assertEqual(rejected, ["invalid_interaction_state"])
                    self.assertEqual(len(client.requests), 1)
                    self.assertEqual(effects, [agent.REF])

    async def test_another_model_access_cannot_reset_the_same_invocation(self):
        client = agent.ScriptedClient([agent.result()])
        first_model = self.fixture.model(client)
        second_model = self.fixture.model(client)
        rejected = []

        async def controller(invocation, broker):
            first = first_model.conversation(invocation)
            try:
                await first.next(broker)
                first.close()
                try:
                    second_model.conversation(invocation)
                except ExecutionError as error:
                    rejected.append(error.code)
            finally:
                first.close()
            return ControllerReply(None, unavailable_code="incomplete")

        await self.fixture.run_agent(first_model,
            controller=ControllerSpec("another-model-access", "1.0", controller))
        self.assertEqual(rejected, ["invalid_interaction_state"])
        self.assertEqual(len(client.requests), 1)

    async def test_separate_runs_reuse_model_access_with_unique_calls_and_empty_traces(self):
        client = agent.ScriptedClient([agent.result(), agent.result()])
        model = self.fixture.model(client)
        outcomes = await asyncio.gather(self.fixture.run_agent(model), self.fixture.run_agent(model))
        self.assertTrue(all(outcome.status == "completed" for outcome in outcomes))
        self.assertEqual(len({request["call_id"] for request in client.requests}), 2)
        self.assertEqual([binding.trace_json for binding in client.bindings], [b"[]", b"[]"])


def document_schema(child):
    return schema_document(encoded(dict(type="object", properties=dict(value=child),
        required=["value"], additionalProperties=False)))


class SchemaNumericRegressionTests(unittest.TestCase):
    def test_numeric_const_enum_and_unique_items_follow_schema_value_equality(self):
        nested = dict(type="object", properties=dict(numbers=dict(type="array", items=dict(type="number"))),
                      required=["numbers"], additionalProperties=False)
        cases = [
            (dict(type="number", const=1), 1.0, True),
            (dict(type="number", enum=[1]), 1.0, True),
            (dict(type="number", const=-0.0), 0, True),
            (dict(type="number", enum=[True]), 1, False),
            (dict(type="boolean", const=1), True, False),
            (dict(type="boolean", enum=[1.0]), True, False),
            (dict(nested, const=dict(numbers=[1, 0])), dict(numbers=[1.0, -0.0]), True),
            (dict(nested, enum=[dict(numbers=[1, 0])]), dict(numbers=[1.0, -0.0]), True),
            (dict(type="array", items=dict(type="number"), uniqueItems=True), [1, 1.0], False),
            (dict(type="array", items=dict(type="number"), uniqueItems=True), [0, -0.0], False),
            (dict(type="array", items=dict(type="number"), uniqueItems=True), [1, 1.5], True),
            (dict(type="array", items=nested, uniqueItems=True),
             [dict(numbers=[1, 0]), dict(numbers=[1.0, -0.0])], False),
            (dict(type="array", items=nested, uniqueItems=True),
             [dict(numbers=[1]), dict(numbers=[2.0])], True),
        ]
        for schema, value, accepted in cases:
            with self.subTest(schema=schema, value=value, accepted=accepted):
                if accepted:
                    validate_schema(dict(value=value), document_schema(schema))
                else:
                    with self.assertRaises(ValueError):
                        validate_schema(dict(value=value), document_schema(schema))

    def test_nested_boolean_and_numeric_values_remain_distinct(self):
        schema = document_schema(dict(type="object", properties=dict(flag=dict(type="boolean")),
            required=["flag"], additionalProperties=False, enum=[dict(flag=1)]))
        with self.assertRaises(ValueError):
            validate_schema(dict(value=dict(flag=True)), schema)

    def test_numeric_profile_and_tool_use_schema_equality_but_reject_validator_mutation(self):
        profile = OutputProfile(AssessmentProfile("numeric-test-profile", "1.0", lambda value: None),
                                encoded(document_schema(dict(type="number", enum=[1]))))
        profile.validate(dict(value=1.0))

        async def execute(scope, arguments):
            return CapabilityReply(b"{}")

        tool = ToolDefinition("numeric-test-tool", "1.0", "Validate independent numeric arguments.",
            encoded(document_schema(dict(type="array", items=dict(type="number"), uniqueItems=True))),
            lambda prepared, arguments: None, execute)
        with self.assertRaises(ValueError):
            tool.check(None, dict(value=[1, 1.0]))
        tool.check(None, dict(value=[1, 1.5]))

        def mutate(value):
            value["value"] = 1.0

        mutating_profile = replace(profile,
            assessment=AssessmentProfile("mutating-numeric-profile", "1.0", mutate))
        with self.assertRaises(ValueError):
            mutating_profile.validate(dict(value=1))
