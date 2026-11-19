"""Agent assembly behavior with independent inputs and injected model replies."""

import asyncio
from dataclasses import replace
import io
import json
from pathlib import Path
import tempfile
import unittest

import test_agent_controller as agent
from safeguard.adapters.demo import create_demo_adapter
from safeguard.demo import demo_limits
from safeguard.detection.assessment import SCAM_PROFILE
from safeguard.detection.execution_host import DetectionCancelled
from safeguard.detection.tools.readers import Utf8TextReader
from safeguard.ingress import AccessContext
from safeguard.memory.conversation_status import ConversationKey, HistoryError, StateError
from safeguard.memory.original_assets import AssetKey
from safeguard.runtime import open_agent_runtime


ACCESS = AccessContext("runtime-check-account", frozenset(("independent-workshop",)))
KEY = ConversationKey("demo", ACCESS.account_id, "independent-workshop")
FILE = b"A fresh storage fixture: the workshop starts at eleven.\n"


def output(request):
    return agent.envelope(request, dict(kind="structured_result", profile=SCAM_PROFILE.identity(),
        payload=dict(verdict="insufficient_evidence", rationale="Independent protocol control; no model inference."),
        supporting=[], counter=[], unresolved=[dict(observation_number=1, part_index=0)]))


class AgentRuntimeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def runtime(self, client, **changes):
        values = dict(root=self.root, limits=demo_limits(), client=client,
            settings=agent.SETTINGS, input_fit=lambda binding, request: True,
            reader=Utf8TextReader(8192, 8192))
        values.update(changes)
        return open_agent_runtime(**values)

    def record(self, runtime, ident="workshop-first", context=ACCESS):
        common = create_demo_adapter().receive(dict(thread=KEY.conversation_id, id=ident,
            author="workshop-host", body="The independently authored workshop starts at eleven."),
            account_id=ACCESS.account_id, conversation_id=KEY.conversation_id)
        return runtime.detection.host.intake.record(common, context)

    async def test_analysis_and_exact_prefix_continue_after_reopening(self):
        client = agent.ScriptedClient([lambda binding, request: output(request)] * 2)
        with self.runtime(client) as runtime:
            first = self.record(runtime)
            result = await runtime.detection.run(first)
            self.assertEqual(result.status, "completed")
            saved = runtime.memory.detector.snapshot(ACCESS, first.boundary)
            self.assertEqual(saved.records[0].payload(), result.to_dict())
        with self.runtime(client) as runtime:
            self.assertEqual(runtime.memory.detector.snapshot(ACCESS, first.boundary), saved)
            second = self.record(runtime, "workshop-second")
            result = await runtime.detection.run(second)
            self.assertEqual(result.status, "completed")
            self.assertEqual(result.to_dict()["observed_count"], 2)
            self.assertEqual(runtime.memory.detector.snapshot(ACCESS, second.boundary).version, 2)
            self.assertEqual(runtime.memory.observations.snapshot(ACCESS, first.boundary).observed_count, 1)
        self.assertEqual([binding.prepared.observed_count for binding in client.bindings], [1, 2])

    async def test_reader_uses_persisted_original_and_returns_actual_tool_observation(self):
        common = create_demo_adapter().receive(dict(thread=KEY.conversation_id, id="with-file", author="host",
            content_parts=[dict(kind="text", text="A fresh workshop fixture is attached."),
                dict(kind="file", asset_id="workshop")],
            assets=[dict(asset_id="workshop", filename="workshop.txt")]),
            account_id=ACCESS.account_id, conversation_id=KEY.conversation_id)
        asset_key = AssetKey.from_message(common, "workshop")
        with self.runtime(agent.ScriptedClient([])) as runtime:
            with io.BytesIO(FILE) as stream:
                runtime.originals.put_batch(ACCESS, {asset_key: stream})
            request = runtime.detection.host.intake.record(common, ACCESS)

        def finish(binding, request):
            trace = json.loads(binding.trace_json)
            self.assertEqual([entry["kind"] for entry in trace], ["model_exchange", "tool_observation"])
            evidence = trace[-1]["outcome"]["payload"]
            self.assertEqual(evidence["status"], "extracted")
            self.assertEqual(evidence["segments"][0]["text"], FILE.decode())
            self.assertEqual(evidence["source_ref"], dict(observation_number=1, part_index=1))
            return output(request)

        client = agent.ScriptedClient([agent.calls(("read-original", "read-evidence",
            dict(observation_number=1, part_index=1))), finish])
        with self.runtime(client) as runtime:
            result = await runtime.detection.run(request)
            self.assertEqual(result.status, "completed")
            self.assertEqual(result.to_dict()["usage"]["model_calls"], 2)
            self.assertEqual(runtime.originals.read(ACCESS, asset_key), FILE)

    async def test_provider_failure_preserves_observed_history_without_an_analysis(self):
        with self.runtime(agent.ScriptedClient([RuntimeError("PRIVATE_PROVIDER_DETAIL")])) as runtime:
            request = self.record(runtime)
            result = await runtime.detection.run(request)
            self.assertNotEqual(result.status, "completed")
            self.assertIsNone(result.to_dict()["assessment"])
            self.assertNotIn("PRIVATE_PROVIDER_DETAIL", result.json_bytes.decode())
            self.assertEqual(runtime.memory.detector.snapshot(ACCESS, request.boundary).version, 0)
        with self.runtime(agent.ScriptedClient([])) as runtime:
            self.assertEqual(runtime.memory.observations.snapshot(ACCESS, request.boundary).observed_count, 1)
            self.assertEqual(runtime.memory.detector.snapshot(ACCESS, request.boundary).records, ())

    async def test_unauthorized_input_and_cross_account_state_access_are_rejected(self):
        client = agent.ScriptedClient([])
        with self.runtime(client) as runtime:
            with self.assertRaises(HistoryError):
                self.record(runtime, context=AccessContext("another-account", ACCESS.conversations))
            request = self.record(runtime)
            with self.assertRaises(StateError):
                runtime.memory.detector.snapshot(AccessContext("another-account", ACCESS.conversations), request.boundary)
        self.assertEqual(client.bindings, [])

    async def test_setup_error_releases_both_store_locks(self):
        with self.assertRaises(ValueError):
            with self.runtime(lambda binding, request: None):
                self.fail("Synchronous model client must fail assembly")
        with self.runtime(agent.ScriptedClient([])) as runtime:
            self.assertEqual(runtime.memory.observations.stats["messages"], 0)
            self.assertEqual(runtime.originals.stats["files"], 0)

    async def test_cancellation_closes_resources_and_keeps_observation(self):
        entered = asyncio.Event()

        async def pending(binding, request):
            entered.set()
            await asyncio.Event().wait()

        client = agent.ScriptedClient([pending])
        with self.runtime(client) as runtime:
            request = self.record(runtime)
            task = asyncio.create_task(runtime.detection.run(request))
            await entered.wait()
            task.cancel()
            with self.assertRaises(DetectionCancelled):
                await task
        with self.runtime(agent.ScriptedClient([])) as runtime:
            self.assertEqual(runtime.memory.observations.snapshot(ACCESS, request.boundary).observed_count, 1)
            self.assertEqual(runtime.memory.detector.snapshot(ACCESS, request.boundary).version, 0)

    async def test_deadline_does_not_commit_or_return_a_benign_assessment(self):
        async def slow(binding, request):
            await asyncio.sleep(10)
        limits = demo_limits()
        limits = replace(limits, execution=replace(limits.execution, timeout_seconds=0.01))
        with self.runtime(agent.ScriptedClient([slow]), limits=limits) as runtime:
            request = self.record(runtime)
            result = await runtime.detection.run(request)
            self.assertEqual(result.status, "timeout")
            self.assertIsNone(result.to_dict()["assessment"])
            self.assertEqual(runtime.memory.detector.snapshot(ACCESS, request.boundary).records, ())
