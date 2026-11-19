"""ICFD adapter behavior on newly authored toy rows, without corpus access."""

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import unittest
from unittest.mock import patch

from safeguard.evaluation.icfd import (
    IcfdAdapterError, IcfdCase, IcfdLimits, IcfdProvenance,
    adapt_static, adapt_streaming,
)


PROVENANCE = IcfdProvenance(hashlib.sha256(b"independent release declaration").hexdigest(),
    hashlib.sha256(b"independent shard declaration").hexdigest(), 7, "toy-split")
LIMITS = IcfdLimits(16, 2048, 16384, 32768, 64)
CASE_ID = "opaque-case"
TEXT = "\ufeffSổ quan sát sao tự tạo.\r\n a\u0301  🔭\t"


def turns():
    return [dict(speaker="", text=TEXT, timestamp_end=0),
            dict(speaker="independent-observer", text="", timestamp_end=2.0)]


def static_row():
    return dict(release_metadata=dict(conversation_uid="withheld-source-identity", split="toy-split", domain="PRIVATE_DOMAIN"),
        transcript=turns(), final_verdict="YES", scenario=dict(private="PRIVATE_SCENARIO"),
        chunk_level_analysis=[dict(private="PRIVATE_ANNOTATION")])


def streaming_row():
    return dict(conversation_uid="withheld-source-identity", split="toy-split", chunk_timestamp=2,
        cumulative_transcript_json=json.dumps(turns(), ensure_ascii=False), final_verdict="NO",
        domain="PRIVATE_DOMAIN", transcript=[dict(text="PRIVATE_FUTURE_SOURCE")],
        conversation_final_verdict="YES", scenario=dict(fraud_start=-1))


def model_bytes(messages):
    return json.dumps(dict(messages=messages), ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


class IcfdAdapterTests(unittest.TestCase):
    def adapt(self, row=None, *, streaming=False, limits=LIMITS, provenance=PROVENANCE, case_id=CASE_ID):
        function = adapt_streaming if streaming else adapt_static
        return function(row if row is not None else (streaming_row() if streaming else static_row()),
            case_id=case_id, provenance=provenance, limits=limits)

    def assert_error(self, action, code):
        with self.assertRaises(IcfdAdapterError) as caught:
            action()
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(caught.exception.args, (code,))
        self.assertNotIn("PRIVATE", str(caught.exception))

    def test_explicit_positive_limits(self):
        self.assertEqual(IcfdLimits(4, 1024, 4096, 8192, 64).max_turns, 4)
        for field in ("max_turns", "max_text_chars", "max_input_bytes", "max_prefix_json_bytes", "max_identifier_chars"):
            for value in (0, -1, True, 1.0, "4", None):
                with self.subTest(field=field, value=value):
                    self.assert_error(lambda: replace(LIMITS, **{field: value}), "invalid_limits")
        self.assert_error(lambda: self.adapt(limits=object()), "invalid_limits")

    def test_static_projection_preserves_exact_data_and_reference_binding(self):
        row = static_row()
        before = deepcopy(row)
        case = self.adapt(row)
        expected = model_bytes(turns())
        self.assertEqual(case.input.model_json(), expected)
        self.assertEqual(row, before)
        self.assertEqual(case.input.task, "icfd-static")
        self.assertIsNone(case.input.observation_time)
        self.assertEqual([type(turn.timestamp_end) for turn in case.input.turns], [int, float])
        self.assertEqual(case.input.turns[0].text.encode("utf-8"), TEXT.encode("utf-8"))
        self.assertEqual((case.reference.case_id, case.reference.task, case.reference.label), (CASE_ID, "icfd-static", 1))
        self.assertEqual(case.reference.source_uid, "withheld-source-identity")
        self.assertEqual(case.reference.split, "toy-split")
        self.assertIs(case.reference.provenance, PROVENANCE)
        self.assertEqual(case.reference.input_sha256, hashlib.sha256(expected).hexdigest())
        self.assertNotIn("PRIVATE", expected.decode())

    def test_streaming_uses_its_released_reference_and_observed_projection(self):
        row = streaming_row()
        before = deepcopy(row)
        case = self.adapt(row, streaming=True)
        self.assertEqual(case.input.model_json(), model_bytes(turns()))
        self.assertEqual((case.input.task, case.reference.task, case.reference.label), ("icfd-streaming", "icfd-streaming", 0))
        self.assertEqual(case.input.observation_time, 2)
        self.assertIs(type(case.input.observation_time), int)
        self.assertEqual(row, before)
        self.assertNotIn("PRIVATE", case.input.model_json().decode())
        self.assertNotIn("conversation_final_verdict", case.input.model_json().decode())

    def test_withheld_metadata_and_labels_do_not_change_model_input(self):
        for streaming in (False, True):
            with self.subTest(streaming=streaming):
                row = streaming_row() if streaming else static_row()
                baseline = self.adapt(row, streaming=streaming)
                row["final_verdict"] = "YES" if streaming else "NO"
                row["domain"] = "PRIVATE_CHANGED_DOMAIN"
                row["scenario"] = dict(private="PRIVATE_CHANGED_SCENARIO")
                row["annotations"] = ["PRIVATE_CHANGED_ANNOTATION"]
                row["full_transcript"] = [dict(text="PRIVATE_NEW_FUTURE")]
                metadata = row if streaming else row["release_metadata"]
                metadata["conversation_uid"] = "PRIVATE_CHANGED_UID"
                metadata["split"] = "different-toy-split"
                changed = self.adapt(row, streaming=streaming,
                    provenance=replace(PROVENANCE, expected_split="different-toy-split"))
                self.assertEqual(baseline.input.model_json(), changed.input.model_json())
                self.assertEqual(baseline.reference.input_sha256, changed.reference.input_sha256)
                self.assertNotEqual(baseline.reference.label, changed.reference.label)
                self.assertNotEqual(baseline.reference.source_uid, changed.reference.source_uid)
                self.assertEqual(changed.reference.split, "different-toy-split")

    def test_unknown_fields_are_not_traversed_or_serialized(self):
        class Unselected:
            def __str__(self):
                raise AssertionError("Unselected data must not be converted")
            def __repr__(self):
                raise AssertionError("Unselected data must not be displayed")
            def __deepcopy__(self, memo):
                raise AssertionError("Unselected data must not be copied")
        row = static_row()
        row["unselected"] = Unselected()
        row["release_metadata"]["unselected"] = Unselected()
        row["transcript"][0]["unselected"] = Unselected()
        self.assertEqual(self.adapt(row).input.model_json(), model_bytes(turns()))
        row = streaming_row()
        row["unselected"] = Unselected()
        self.assertEqual(self.adapt(row, streaming=True).input.model_json(), model_bytes(turns()))

    def test_immutable_records_do_not_retain_mutable_source_views_or_expose_data_in_repr(self):
        row = static_row()
        case = self.adapt(row)
        original = case.input.model_json()
        row["transcript"][0]["text"] = "changed after adaptation"
        row["release_metadata"]["conversation_uid"] = "changed UID"
        row["transcript"].clear()
        self.assertEqual(case.input.model_json(), original)
        self.assertEqual(case.reference.source_uid, "withheld-source-identity")
        view = json.loads(original)
        view["messages"][0]["text"] = "changed detached view"
        self.assertEqual(case.input.model_json(), original)
        for record, field, value in ((case, "input", None), (case.input, "case_id", "changed"),
                (case.input.turns[0], "text", "changed"), (case.reference, "label", 0), (PROVENANCE, "row_index", 0)):
            with self.subTest(record_type=type(record)), self.assertRaises(FrozenInstanceError):
                setattr(record, field, value)
        for value in (case, case.input, case.input.turns[0], case.reference, PROVENANCE):
            self.assertNotIn(TEXT, repr(value))
            self.assertNotIn("withheld-source-identity", repr(value))
            self.assertNotIn("toy-split", repr(value))

    def test_empty_inputs_keep_their_reference_and_task_without_fabricating_a_turn(self):
        row = static_row()
        row["transcript"] = []
        complete = self.adapt(row)
        row = streaming_row()
        row["cumulative_transcript_json"] = "[]"
        row["chunk_timestamp"] = 0
        prefix = self.adapt(row, streaming=True)
        for case, label in ((complete, 1), (prefix, 0)):
            with self.subTest(task=case.input.task):
                self.assertEqual(case.input.turns, ())
                self.assertEqual(case.input.model_json(), b'{"messages":[]}')
                self.assertEqual(case.reference.label, label)
        self.assertNotEqual(complete.input.task, prefix.input.task)

    def test_all_limits_accept_exact_values_and_reject_one_short(self):
        row = streaming_row()
        expected = model_bytes(turns())
        exact = IcfdLimits(len(turns()), sum(len(t["speaker"]) + len(t["text"]) for t in turns()),
            len(expected), len(row["cumulative_transcript_json"].encode("utf-8")), len("withheld-source-identity"))
        self.assertEqual(self.adapt(row, streaming=True, limits=exact).input.model_json(), expected)
        for field, code in (("max_turns", "turn_limit"), ("max_text_chars", "text_limit"),
                ("max_input_bytes", "input_byte_limit"), ("max_prefix_json_bytes", "prefix_byte_limit"),
                ("max_identifier_chars", "identifier_limit")):
            with self.subTest(field=field):
                self.assert_error(lambda: self.adapt(row, streaming=True,
                    limits=replace(exact, **{field: getattr(exact, field) - 1})), code)
        static = static_row()
        self.assert_error(lambda: self.adapt(static, limits=replace(LIMITS, max_input_bytes=len(expected) - 1)), "input_byte_limit")
        self.assert_error(lambda: self.adapt(static, limits=replace(LIMITS, max_identifier_chars=3)), "identifier_limit")

    def test_resource_preflight_rejects_before_validating_oversized_payloads(self):
        row = static_row()
        row["transcript"] = [object(), object()]
        self.assert_error(lambda: self.adapt(row, limits=replace(LIMITS, max_turns=1)), "turn_limit")
        row["transcript"] = [dict(speaker="", text="PRIVATE_LONG_TEXT\ud800", timestamp_end=0)]
        self.assert_error(lambda: self.adapt(row, limits=replace(LIMITS, max_text_chars=1)), "text_limit")
        row = streaming_row()
        row["cumulative_transcript_json"] = "PRIVATE_MALFORMED_JSON"
        self.assert_error(lambda: self.adapt(row, streaming=True, limits=replace(LIMITS, max_prefix_json_bytes=1)), "prefix_byte_limit")

    def test_prefix_parser_rejects_duplicate_nonfinite_malformed_or_nonlist_json(self):
        invalid = ["", "[", "[] trailing PRIVATE", '{"PRIVATE":1}', "null", "[true]",
            '[{"speaker":"x","text":"a","text":"b","timestamp_end":0}]',
            '[{"speaker":"x","text":"a","timestamp_end":0,"extra":1,"extra":2}]',
            '[{"speaker":"x","text":"a","timestamp_end":NaN}]',
            '[{"speaker":"x","text":"a","timestamp_end":Infinity}]',
            '[{"speaker":"x","text":"a","timestamp_end":-Infinity}]',
            '[{"speaker":"x","text":"a","timestamp_end":1e999}]',
            '[{"speaker":"x","text":"a","timestamp_end":0,"extra":1e999}]',
            "\ud800", "[" * 1100 + "0" + "]" * 1100]
        for raw in invalid:
            row = streaming_row()
            row["cumulative_transcript_json"] = raw
            with self.subTest(raw_length=len(raw)), self.assertRaises(IcfdAdapterError) as caught:
                self.adapt(row, streaming=True)
            self.assertIn(caught.exception.code, ("invalid_prefix_json", "invalid_transcript"))
            self.assertNotIn("PRIVATE", str(caught.exception))
        for raw in (None, b"[]", [], {}, True):
            row = streaming_row()
            row["cumulative_transcript_json"] = raw
            with self.subTest(raw_type=type(raw)):
                self.assert_error(lambda: self.adapt(row, streaming=True), "invalid_prefix_json")

    def test_time_boundaries_order_numeric_types_and_large_values_are_explicit(self):
        for streaming in (False, True):
            for end in (True, None, "0", -1, float("nan"), float("inf"), -float("inf"), 10 ** 400):
                row = streaming_row() if streaming else static_row()
                values = [dict(speaker="", text="", timestamp_end=end)]
                row["cumulative_transcript_json" if streaming else "transcript"] = json.dumps(values) if streaming else values
                with self.subTest(streaming=streaming, end_type=type(end)), self.assertRaises(IcfdAdapterError):
                    self.adapt(row, streaming=streaming)
        row = static_row()
        row["transcript"] = [dict(speaker="", text="", timestamp_end=2), dict(speaker="", text="", timestamp_end=1)]
        self.assert_error(lambda: self.adapt(row), "unordered_turn")
        row = streaming_row()
        row["chunk_timestamp"] = 1.999
        self.assert_error(lambda: self.adapt(row, streaming=True), "future_turn")
        for end in (2, 2.0, -0.0):
            row["chunk_timestamp"] = 2
            row["cumulative_transcript_json"] = json.dumps([dict(speaker="", text="", timestamp_end=end)] * 2)
            case = self.adapt(row, streaming=True)
            self.assertIs(type(case.input.turns[0].timestamp_end), type(end))
            self.assertEqual(len(case.input.turns), 2)
            if end == 0:
                self.assertIn(b"-0.0", case.input.model_json())
        for value in (True, None, "2", -1, float("nan"), float("inf"), 10 ** 400):
            row["chunk_timestamp"] = value
            with self.subTest(observation_type=type(value)):
                self.assert_error(lambda: self.adapt(row, streaming=True), "invalid_timestamp")

    def test_missing_bad_fields_labels_unicode_and_split_do_not_get_repaired(self):
        for verdict in (None, True, 0, "yes", "NO ", "PRIVATE_INVALID_LABEL"):
            row = static_row()
            row["final_verdict"] = verdict
            with self.subTest(verdict_type=type(verdict)):
                self.assert_error(lambda: self.adapt(row), "invalid_reference")
        for bad in (None, [], object()):
            with self.subTest(row_type=type(bad)):
                self.assert_error(lambda: adapt_static(bad, case_id=CASE_ID, provenance=PROVENANCE, limits=LIMITS), "invalid_row")
        for changes in ({"release_metadata": None}, {"transcript": None}, {"transcript": [dict(speaker="x", text="y")]},
                {"transcript": [dict(speaker=1, text="x", timestamp_end=0)]},
                {"transcript": [dict(speaker="x", text="\ud800", timestamp_end=0)]}):
            row = static_row()
            row.update(changes)
            with self.subTest(field=next(iter(changes))), self.assertRaises(IcfdAdapterError):
                self.adapt(row)
        row = static_row()
        row["release_metadata"]["split"] = "different-split"
        self.assert_error(lambda: self.adapt(row), "split_mismatch")
        for value in (None, "", "  ", True, "\ud800"):
            with self.subTest(identity_type=type(value)):
                self.assert_error(lambda: self.adapt(case_id=value), "invalid_identity")
            row = static_row()
            row["release_metadata"]["conversation_uid"] = value
            self.assert_error(lambda: self.adapt(row), "invalid_identity")

    def test_provenance_and_public_record_invariants_are_explicit(self):
        for field in ("release_sha256", "shard_sha256"):
            for value in ("0" * 63, "A" * 64, "PRIVATE", None, 64):
                with self.subTest(field=field, value_type=type(value)):
                    self.assert_error(lambda: replace(PROVENANCE, **{field: value}), "invalid_provenance")
        for value in (-1, True, 1.0, None):
            self.assert_error(lambda: replace(PROVENANCE, row_index=value), "invalid_provenance")
        self.assert_error(lambda: self.adapt(provenance=object()), "invalid_provenance")
        case = self.adapt()
        self.assert_error(lambda: replace(case.input, task="unknown"), "invalid_case")
        self.assert_error(lambda: replace(case.input, observation_time=0), "invalid_timestamp")
        self.assert_error(lambda: replace(case.input, turns=list(case.input.turns)), "invalid_transcript")
        self.assert_error(lambda: replace(case.reference, label=True), "invalid_reference")
        self.assert_error(lambda: IcfdCase(case.input, replace(case.reference, case_id="different-case")), "invalid_case")
        self.assert_error(lambda: IcfdCase(case.input, replace(case.reference, input_sha256="0" * 64)), "invalid_case")

    def test_conversion_performs_no_file_or_network_io_and_keeps_scorer_compatibility(self):
        from safeguard.evaluation.audits.icfd.audit_core import observed_input, score_binary
        row = streaming_row()
        with patch("builtins.open", side_effect=AssertionError("No file IO during conversion")), \
             patch("io.open", side_effect=AssertionError("No path IO during conversion")):
            prefix = self.adapt(row, streaming=True)
            complete = self.adapt()
            self.assertEqual(json.loads(prefix.input.model_json()), observed_input(row))
        scored = score_binary([complete.reference.label, prefix.reference.label], [1, 0])
        self.assertEqual(scored["metrics"]["accuracy"], 1)
        self.assertEqual(score_binary([prefix.reference.label], [None]), dict(complete=False, metrics=None))
