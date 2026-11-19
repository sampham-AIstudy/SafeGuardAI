"""Independently authored profile and complete-result boundary checks."""

from dataclasses import replace
import inspect
import json
import unittest

import test_agent_controller as agent
import test_execution_host as fixtures
from safeguard.detection.agent_controller import AgentController
from safeguard.detection.assessment import SCAM_INSTRUCTIONS, SCAM_PROFILE
from safeguard.detection.execution_host import (
    AssessmentProfile, ControllerReply, ControllerSpec, ExecutionError,
)
from safeguard.detection.model_contract import encoded
from safeguard.detection.tools.evidence import PartReference


REFERENCE = PartReference(1, 0)
RATIONALE = "Independent structural test result, not a content judgment."


def payload(verdict="scam", rationale=RATIONALE):
    return dict(verdict=verdict, rationale=rationale)


INVALID_PAYLOADS = (
    None, [], {}, dict(verdict="scam"), dict(rationale=RATIONALE),
    dict(payload(), score=1), payload("unknown"), payload(rationale=7),
    payload(rationale=""), payload(rationale=" \n\t"),
    payload(rationale="x" * 2001), payload(rationale="\ud800"),
)


class ScamProfileTests(unittest.TestCase):
    def test_three_verdicts_validate_without_changing_payload(self):
        for verdict in ("scam", "no_scam_evidence", "insufficient_evidence"):
            with self.subTest(verdict=verdict):
                value = payload(verdict)
                before = encoded(value)
                SCAM_PROFILE.validate(value)
                SCAM_PROFILE.assessment.validate(value)
                self.assertEqual(encoded(value), before)

    def test_invalid_payloads_are_rejected_by_both_public_validation_paths(self):
        for value in INVALID_PAYLOADS:
            for validate in (SCAM_PROFILE.validate, SCAM_PROFILE.assessment.validate):
                with self.subTest(value=value, validator=validate):
                    with self.assertRaises(ValueError):
                        validate(value)

    def test_async_or_noncallable_result_validator_is_configuration_error(self):
        async def asynchronous(result):
            pass

        for validator in (True, asynchronous):
            with self.subTest(validator=validator):
                with self.assertRaises(ExecutionError) as caught:
                    AssessmentProfile("invalid-result-validator", "1.0", lambda value: None,
                                      validate_result=validator)
                self.assertEqual(caught.exception.code, "invalid_profile")

    def test_existing_three_argument_profile_retains_optional_hook_default(self):
        profile = AssessmentProfile("existing-profile", "1.0", lambda value: None)
        self.assertIsNone(profile.validate_result)


class ScamAssessmentHostTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture = fixtures.ExecutionHostTests(
            methodName="test_two_controllers_use_same_caller_input_profile_and_envelope")
        await self.fixture.asyncSetUp()
        self.addCleanup(self.fixture.doCleanups)

    async def run_reply(self, reply, *, profile=SCAM_PROFILE.assessment, finalizer=None):
        async def execute(invocation, broker):
            return reply

        host = self.fixture.host(capabilities=(), profile=profile)
        return await host.run(self.fixture.request,
            strategy=ControllerSpec("independent-assessment-controller", "1.0", execute),
            allowed_capabilities=frozenset(), initial_state_json=b"{}", finalizer=finalizer)

    async def test_valid_verdicts_finalize_with_the_same_scoped_envelope(self):
        for verdict in ("scam", "no_scam_evidence", "insufficient_evidence"):
            with self.subTest(verdict=verdict):
                saved = []

                async def finalize(invocation, outcome):
                    saved.append(outcome)

                reply = ControllerReply(encoded(payload(verdict)),
                    supporting=(REFERENCE,) if verdict == "scam" else (),
                    unresolved=(REFERENCE,) if verdict == "insufficient_evidence" else ())
                outcome = await self.run_reply(reply, finalizer=finalize)
                self.assertEqual((outcome.status, outcome.code), ("completed", "ok"))
                self.assertEqual(outcome.to_dict()["assessment"], payload(verdict))
                self.assertEqual(saved, [outcome])
                self.assertEqual(outcome.to_dict()["observed_count"], 1)

    async def test_invalid_payloads_never_reach_finalization(self):
        for value in INVALID_PAYLOADS:
            with self.subTest(value=value):
                saved = []

                async def finalize(invocation, outcome):
                    saved.append(outcome)

                raw = json.dumps(value, ensure_ascii=True).encode("ascii")
                outcome = await self.run_reply(ControllerReply(raw, supporting=(REFERENCE,)),
                                               finalizer=finalize)
                self.assertEqual((outcome.status, outcome.code), ("failed", "invalid_assessment"))
                self.assertIsNone(outcome.to_dict()["assessment"])
                self.assertEqual(saved, [])

    async def test_required_grounding_and_future_references_fail_before_finalization(self):
        cases = (
            (ControllerReply(encoded(payload())), "invalid_assessment"),
            (ControllerReply(encoded(payload("insufficient_evidence"))), "invalid_assessment"),
            (ControllerReply(encoded(payload()), supporting=(PartReference(2, 0),)), "invalid_reference"),
            (ControllerReply(encoded(payload()), supporting=(PartReference(1, 9),)), "invalid_reference"),
        )
        for reply, code in cases:
            with self.subTest(code=code, reply=reply):
                saved = []

                async def finalize(invocation, outcome):
                    saved.append(outcome)

                outcome = await self.run_reply(reply, finalizer=finalize)
                self.assertEqual((outcome.status, outcome.code), ("failed", code))
                self.assertIsNone(outcome.to_dict()["assessment"])
                self.assertEqual(saved, [])

    async def test_unavailable_result_bypasses_completed_assessment_rule(self):
        for reason in ("no_usable_input", "unsupported_input", "incomplete"):
            with self.subTest(reason=reason):
                outcome = await self.run_reply(ControllerReply(None, unavailable_code=reason))
                self.assertEqual((outcome.status, outcome.code), ("unavailable", reason))
                self.assertIsNone(outcome.to_dict()["assessment"])

    async def test_rejected_mutating_and_non_none_result_validators_cannot_finalize(self):
        def mutate_assessment(result):
            result["assessment"]["verdict"] = "no_scam_evidence"

        def mutate_reference_type(result):
            result["supporting"][0]["observation_number"] = 1.0

        for validate in (mutate_assessment, mutate_reference_type, lambda value: True):
            with self.subTest(validate=validate):
                saved = []

                async def finalize(invocation, outcome):
                    saved.append(outcome)

                profile = replace(SCAM_PROFILE.assessment, validate_result=validate)
                outcome = await self.run_reply(ControllerReply(encoded(payload()), supporting=(REFERENCE,)),
                                               profile=profile, finalizer=finalize)
                self.assertEqual((outcome.status, outcome.code), ("failed", "invalid_assessment"))
                self.assertEqual(saved, [])

    async def test_accidental_async_result_validator_is_closed_and_rejected(self):
        pending = []

        async def asynchronous():
            pass

        def validate(result):
            coroutine = asynchronous()
            pending.append(coroutine)
            return coroutine

        outcome = await self.run_reply(ControllerReply(encoded(payload()), supporting=(REFERENCE,)),
            profile=replace(SCAM_PROFILE.assessment, validate_result=validate))
        self.assertEqual((outcome.status, outcome.code), ("failed", "invalid_assessment"))
        self.assertEqual(len(pending), 1)
        self.assertEqual(inspect.getcoroutinestate(pending[0]), inspect.CORO_CLOSED)

    async def test_existing_profile_without_hook_keeps_its_result_behavior(self):
        outcome = await self.run_reply(ControllerReply(encoded(dict(summary="Independent neutral result."))),
                                       profile=fixtures.PROFILE)
        self.assertEqual((outcome.status, outcome.code), ("completed", "ok"))

    async def test_agent_and_independent_controller_share_the_grounding_rule(self):
        outcomes = []
        for supporting in ([], [dict(observation_number=1, part_index=0)]):
            with self.subTest(supporting=supporting):
                output = dict(kind="structured_result", profile=SCAM_PROFILE.identity(), payload=payload(),
                              supporting=supporting, counter=[], unresolved=[])
                model = agent.AgentControllerTests.model(self, agent.ScriptedClient([output]),
                    profile=SCAM_PROFILE, instructions=SCAM_INSTRUCTIONS)
                host = self.fixture.host(capabilities=(model.capability(),), profile=SCAM_PROFILE.assessment)
                via_agent = await host.run(self.fixture.request, strategy=AgentController(model=model).spec,
                    allowed_capabilities=frozenset((model.name,)), initial_state_json=b"{}")
                via_independent = await self.run_reply(ControllerReply(encoded(payload()),
                    supporting=(REFERENCE,) if supporting else ()))
                self.assertEqual((via_agent.status, via_agent.code),
                                 (via_independent.status, via_independent.code))
                outcomes.append(via_agent.status)
        self.assertEqual(outcomes, ["failed", "completed"])


if __name__ == "__main__":
    unittest.main()
