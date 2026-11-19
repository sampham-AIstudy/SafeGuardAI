"""Warning decisions use committed scoped assessments and durable history."""

from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from test_agent_controller import SETTINGS, ScriptedClient

from safeguard.adapters.demo import create_demo_adapter
from safeguard.demo import demo_limits
from safeguard.detection.assessment import SCAM_PROFILE
from safeguard.detection.model_contract import encoded
from safeguard.detection.tools.readers import Utf8TextReader
from safeguard.ingress import AccessContext
from safeguard.memory.conversation_status import HistoryError, StateError
from safeguard.runtime import open_agent_runtime
from safeguard.warning import WarningPolicy


def assessment(verdict, number):
    reference = {"observation_number": number, "part_index": 0}
    return dict(kind="structured_result", profile=SCAM_PROFILE.identity(),
                payload=dict(verdict=verdict, rationale=f"Authored policy fixture {number}."),
                supporting=[reference] if verdict == "scam" else [], counter=[],
                unresolved=[reference] if verdict == "insufficient_evidence" else [])


class WarningPolicyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.access = AccessContext("policy-check-account", frozenset({"workshop"}))

    def runtime(self, *replies):
        return open_agent_runtime(root=self.root, limits=demo_limits(), client=ScriptedClient(replies),
            settings=SETTINGS, input_fit=lambda binding, request: True, reader=Utf8TextReader(8192, 8192))

    def record(self, runtime, number):
        native = dict(thread="workshop", id=f"message-{number}", author="contact", body=f"Workshop note {number}.")
        message = create_demo_adapter().receive(native, account_id=self.access.account_id, conversation_id="workshop")
        return runtime.detection.host.intake.record(message, self.access)

    async def test_warn_update_and_preserve_active_notice_across_reopen(self):
        with self.runtime(assessment("no_scam_evidence", 1), assessment("scam", 2), assessment("scam", 2),
                          assessment("scam", 4), assessment("insufficient_evidence", 5)) as runtime:
            policy = WarningPolicy(runtime.memory, warn_on_scam=True)
            first = self.record(runtime, 1)
            self.assertIsNone(policy.apply(first, await runtime.detection.run(first)).active)

            second = self.record(runtime, 2)
            result = await runtime.detection.run(second)
            first_warning = policy.apply(second, result)
            self.assertEqual(first_warning.action, "warn")
            self.assertEqual(first_warning.active.supporting[0].observation_number, 2)
            duplicate = policy.apply(second, result)
            self.assertEqual((duplicate.action, duplicate.reason), ("no_action", "duplicate_assessment"))
            self.assertEqual(runtime.memory.warning_history.snapshot(self.access, second.boundary).version, 2)

            third = self.record(runtime, 3)
            self.assertEqual(policy.apply(second, result).reason, "stale_boundary")
            same = policy.apply(third, await runtime.detection.run(third))
            self.assertEqual((same.reason, same.active), ("same_evidence", first_warning.active))

            fourth = self.record(runtime, 4)
            revised = policy.apply(fourth, await runtime.detection.run(fourth))
            self.assertEqual(revised.action, "update")
            self.assertEqual(revised.active.supporting[0].observation_number, 4)

            fifth = self.record(runtime, 5)
            uncertain = policy.apply(fifth, await runtime.detection.run(fifth))
            self.assertEqual((uncertain.action, uncertain.reason, uncertain.active),
                             ("no_action", "insufficient_evidence", revised.active))
        with self.runtime() as runtime:
            policy = WarningPolicy(runtime.memory, warn_on_scam=True)
            self.assertEqual(policy.current(self.access, fifth.boundary.key), revised.active)
            self.assertEqual(runtime.memory.warning_history.snapshot(self.access, fifth.boundary).version, 5)
            self.assertEqual(runtime.memory.detector.snapshot(self.access, fifth.boundary).version, 5)

    async def test_failure_and_cross_account_input_cannot_create_or_replace_a_warning(self):
        with self.runtime(assessment("scam", 1), RuntimeError("private-provider-error")) as runtime:
            policy = WarningPolicy(runtime.memory, warn_on_scam=True)
            request = self.record(runtime, 1)
            result = await runtime.detection.run(request)
            changed = result.to_dict()
            changed["assessment"]["rationale"] = "Altered assessment."
            self.assertEqual(policy.apply(request, replace(result, json_bytes=encoded(changed))).reason,
                             "uncommitted_assessment")
            with self.assertRaises(HistoryError):
                policy.apply(replace(request, context=AccessContext("other-account", frozenset({"workshop"}))), result)
            self.assertEqual(runtime.memory.warning_history.snapshot(self.access, request.boundary).version, 0)

            with patch.object(runtime.memory.warning_history, "commit", side_effect=StateError("test_failure")):
                self.assertEqual(policy.apply(request, result).reason, "warning_storage_failed")
            self.assertEqual(runtime.memory.warning_history.snapshot(self.access, request.boundary).version, 0)
            previous = policy.apply(request, result).active
            later = self.record(runtime, 2)
            failed = policy.apply(later, await runtime.detection.run(later))
            self.assertEqual((failed.action, failed.reason, failed.active), ("unavailable", "detection_failed", previous))
            self.assertEqual(runtime.memory.warning_history.snapshot(self.access, later.boundary).version, 1)

    async def test_warnings_can_be_disabled_explicitly(self):
        with self.runtime(assessment("scam", 1)) as runtime:
            request = self.record(runtime, 1)
            decision = WarningPolicy(runtime.memory, warn_on_scam=False).apply(request, await runtime.detection.run(request))
            self.assertEqual((decision.action, decision.reason, decision.active), ("no_action", "warnings_disabled", None))
