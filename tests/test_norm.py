"""One-message Norm checks with independent neutral inputs only."""

from copy import deepcopy
from datetime import datetime, timezone
import json
import unittest
from unittest.mock import patch

from safeguard.adapters.gateways.demo import DemoGateway
from safeguard.adapters.norm import NormalizationError, normalize


def envelope():
    # Vietnamese text below is independently authored neutral fixture content.
    return {
        "schema_version": "1.0", "source": "demo", "account_id": "toy-account",
        "conversation_id": "toy-reading-room", "message_id": "toy-note", "sender_id": "toy-reader",
        "event_type": "message.created", "observed_at": "2026-01-02T03:04:05Z",
        "payload": {"thread": "toy-reading-room", "id": "toy-note", "author": "toy-reader",
                    "body": "  Sách ở trên bàn.\n  ", "sent_at": None,
                    "extension": {"values": [False, 1, 1.5, None, {"note": "Toy detail"}]}},
    }


class NormalizerTests(unittest.TestCase):
    def rejected(self, value, field, code=None):
        with self.assertRaises(NormalizationError) as caught:
            normalize(value)
        self.assertEqual(caught.exception.field, field)
        if code is not None:
            self.assertEqual(caught.exception.code, code)
        self.assertEqual(set(caught.exception.as_dict()), {"field", "code"})
        return caught.exception

    def test_complete_provisional_output_matches_the_contract(self):
        source = envelope()
        before = deepcopy(source)
        self.assertEqual(normalize(source), {
            "message_schema_version": "2.0", "source": "demo", "account_id": "toy-account",
            "conversation_id": "toy-reading-room", "message_id": "toy-note", "sender_id": "toy-reader",
            "content_parts": [{"kind": "text", "text": "  Sách ở trên bàn.\n  "}], "assets": [],
            "is_from_observed_account": False,
            "observed_at": "2026-01-02T03:04:05Z", "sent_at": None, "raw_payload": before["payload"],
        })
        self.assertEqual(source, before)

    def test_actual_demo_adapter_single_event_is_accepted(self):
        native = envelope()["payload"]
        adapter = DemoGateway("toy-account", clock=lambda: datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc))
        received = adapter.receive(native)
        self.assertEqual(received, envelope())
        self.assertEqual(normalize(received), normalize(envelope()))

    def test_sender_flag_uses_ids_instead_of_message_prose(self):
        source = envelope()
        source["payload"]["body"] = "A neutral note mentioning toy-account."
        self.assertFalse(normalize(source)["is_from_observed_account"])
        source["sender_id"] = source["payload"]["author"] = "toy-account"
        source["payload"]["body"] = "A neutral note mentioning toy-reader."
        self.assertTrue(normalize(source)["is_from_observed_account"])

    def test_text_code_points_and_whitespace_are_unchanged(self):
        # All strings below are newly authored neutral preservation fixtures.
        for body in ["  Chào bạn!\n\t", "Cafe\u0301", "Café", " \n ", "<b>Toy book</b>\u200b", "\x00"]:
            with self.subTest(body=body):
                source = envelope()
                source["payload"]["body"] = body
                result = normalize(source)
                self.assertEqual(result["content_parts"][0]["text"], body)
                self.assertEqual(result["raw_payload"]["body"], body)

    def test_missing_or_null_sent_at_remains_distinct_in_raw_payload(self):
        source = envelope()
        self.assertIsNone(normalize(source)["sent_at"])
        self.assertIn("sent_at", normalize(source)["raw_payload"])
        del source["payload"]["sent_at"]
        result = normalize(source)
        self.assertIsNone(result["sent_at"])
        self.assertNotIn("sent_at", result["raw_payload"])
        self.assertEqual(result["observed_at"], source["observed_at"])

    def test_source_times_convert_to_utc_without_fractional_truncation(self):
        cases = [
            ("2026-01-02T10:04:05+07:00", "2026-01-02T03:04:05Z"),
            ("2026-01-01T23:00:00-02:00", "2026-01-02T01:00:00Z"),
            ("2024-03-01T00:30:00+01:00", "2024-02-29T23:30:00Z"),
            ("2026-01-02T03:04:05+00:00", "2026-01-02T03:04:05Z"),
            ("2026-01-02T03:04:05-00:00", "2026-01-02T03:04:05Z"),
            ("2026-01-02t03:04:05z", "2026-01-02T03:04:05Z"),
            ("2026-01-02T10:04:05.123456789012+07:00", "2026-01-02T03:04:05.123456789012Z"),
            ("2026-01-02T03:04:05.0000Z", "2026-01-02T03:04:05.0000Z"),
            ("0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z"),
            ("9999-12-31T23:59:59Z", "9999-12-31T23:59:59Z"),
        ]
        for original, expected in cases:
            with self.subTest(original=original):
                source = envelope()
                source["payload"]["sent_at"] = original
                result = normalize(source)
                self.assertEqual(result["sent_at"], expected)
                self.assertEqual(result["raw_payload"]["sent_at"], original)

    def test_invalid_source_times_have_explicit_errors(self):
        cases = ["", "2026-01-02", "2026-01-02T03:04:05", "2026-02-30T03:04:05Z",
                 "2023-02-29T00:00:00Z", "0000-01-01T00:00:00Z", "2026-13-01T00:00:00Z",
                 "2026-01-02T24:00:00Z", "2026-01-02T03:60:00Z", "2026-01-02T03:04:60Z", "2026-01-02T03:04:05+24:00",
                 "2026-01-02T03:04:05+01:60", "2026-01-02T03:04:05+07",
                 "2026-01-02T03:04:05+07:00:30", "20260102T030405Z", "2026-01-02T03:04:05,1Z",
                 "2026-01-02T03:04:05Z trailing", 0, False, [], {}, datetime(2026, 1, 2)]
        for sent in cases:
            with self.subTest(sent=sent):
                source = envelope()
                source["payload"]["sent_at"] = sent
                self.rejected(source, "payload.sent_at")

    def test_utc_conversion_overflow_is_a_structured_error(self):
        for sent in ["0001-01-01T00:00:00+00:01", "9999-12-31T23:59:59-00:01"]:
            with self.subTest(sent=sent):
                source = envelope()
                source["payload"]["sent_at"] = sent
                self.rejected(source, "payload.sent_at", "invalid_datetime")

    def test_observation_time_is_validated_but_retained_exactly(self):
        source = envelope()
        source["observed_at"] = "2026-01-02T03:04:05.000123456789Z"
        source["payload"]["sent_at"] = "2027-01-01T00:00:00Z"
        result = normalize(source)
        self.assertEqual(result["observed_at"], source["observed_at"])
        self.assertEqual(result["sent_at"], "2027-01-01T00:00:00Z")

    def test_invalid_observation_times_are_rejected(self):
        for observed in [None, 1, "", "2026-99-01T00:00:00Z", "2026-01-02T030405Z",
                         "2026-01-02T03:04:05+00:00", "2026-01-02T03:04:05", "2026-01-02t03:04:05z",
                         "2026-01-02T24:00:00Z", "2026-01-02T03:60:00Z", "2026-01-02T03:04:60Z"]:
            with self.subTest(observed=observed):
                source = envelope()
                source["observed_at"] = observed
                self.rejected(source, "observed_at")

    def test_all_native_header_identity_conflicts_are_rejected(self):
        for native in ["thread", "id", "author"]:
            with self.subTest(native=native):
                source = envelope()
                source["payload"][native] = "different-toy-identity"
                self.rejected(source, "payload."+native, "identity_mismatch")

    def test_required_outer_fields(self):
        for field in envelope():
            with self.subTest(field=field):
                source = envelope()
                del source[field]
                self.rejected(source, field, "required")

    def test_outer_and_payload_container_types(self):
        for value in [None, [], "Toy event", 1, False]:
            with self.subTest(event=value):
                self.rejected(value, "event", "expected_object")
        for value in [None, [], "Toy payload", 1, False, {}]:
            with self.subTest(payload=value):
                source = envelope()
                source["payload"] = value
                self.rejected(source, "payload", "expected_nonempty_object")

    def test_unknown_outer_keys_are_not_echoed_in_errors(self):
        source = envelope()
        source["PRIVATE_KEY_CANARY"] = "PRIVATE_VALUE_CANARY"
        error = self.rejected(source, "event", "unexpected_fields")
        rendered = str(error)+json.dumps(error.as_dict())
        self.assertNotIn("PRIVATE_KEY_CANARY", rendered)
        self.assertNotIn("PRIVATE_VALUE_CANARY", rendered)

    def test_invalid_header_identifiers(self):
        for field in ["account_id", "conversation_id", "message_id", "sender_id"]:
            for value in [None, 1, False, [], {}, "", "  \t"]:
                with self.subTest(field=field, value=value):
                    source = envelope()
                    source[field] = value
                    self.rejected(source, field, "expected_nonblank_string")

    def test_unsupported_versions_sources_and_events(self):
        for field, value, code in [
            ("schema_version", "2.0", "unsupported_version"),
            ("schema_version", 1.0, "unsupported_version"),
            ("source", "another.source", "unsupported_source"),
            ("source", "Invalid Source", "invalid_source_identifier"),
            ("source", None, "invalid_source_identifier"),
            ("event_type", "message.updated", "unsupported_event_type"),
            ("event_type", None, "unsupported_event_type"),
        ]:
            with self.subTest(field=field, value=value):
                source = envelope()
                source[field] = value
                self.rejected(source, field, code)

    def test_required_native_fields(self):
        for field in ["thread", "id", "author", "body"]:
            with self.subTest(field=field):
                source = envelope()
                del source["payload"][field]
                self.rejected(source, "payload."+field, "required")

    def test_invalid_native_identifiers(self):
        for field in ["thread", "id", "author"]:
            for value in [None, 1, False, [], {}, "", "  "]:
                with self.subTest(field=field, value=value):
                    source = envelope()
                    source["payload"][field] = value
                    self.rejected(source, "payload."+field, "expected_nonblank_string")

    def test_invalid_body_is_not_replaced_by_other_native_fields(self):
        for value in [None, False, 1, [], {}, ""]:
            with self.subTest(body=value):
                source = envelope()
                source["payload"]["body"] = value
                source["payload"]["text"] = "Toy fallback must not be used"
                self.rejected(source, "payload.body", "expected_nonempty_string")

    def test_invalid_json_extensions_have_structured_errors(self):
        for value in [float("nan"), float("inf"), (1, 2), {"toy-set"}, {1: "Toy key"}, object()]:
            with self.subTest(value_type=type(value).__name__):
                source = envelope()
                source["payload"]["extension"] = value
                self.rejected(source, "payload")

    def test_cycles_are_rejected_but_shared_json_values_are_allowed(self):
        source = envelope()
        source["payload"]["extension"] = source["payload"]
        self.rejected(source, "payload", "cyclic_payload")
        shared = {"items": ["Toy detail"]}
        source = envelope()
        source["payload"]["left"] = source["payload"]["right"] = shared
        result = normalize(source)
        self.assertEqual(result["raw_payload"], source["payload"])
        self.assertIsNot(result["raw_payload"]["left"], shared)

    def test_deep_nesting_is_rejected_without_partial_output(self):
        nested = []
        for _ in range(2000):
            nested = [nested]
        source = envelope()
        source["payload"]["extension"] = nested
        self.rejected(source, "payload", "nesting_too_deep")
        self.assertIs(source["payload"]["extension"], nested)

    def test_source_output_mutations_and_independent_calls_are_isolated(self):
        source = envelope()
        before = deepcopy(source)
        first = normalize(source)
        second = normalize(source)
        first["raw_payload"]["extension"]["values"].append("output-change")
        self.assertEqual(source, before)
        self.assertEqual(second["raw_payload"], before["payload"])
        source["payload"]["extension"]["values"].append("source-change")
        source["message_id"] = source["payload"]["id"] = "changed-source-id"
        self.assertEqual(second["message_id"], "toy-note")
        self.assertEqual(second["raw_payload"], before["payload"])

    def test_errors_do_not_echo_malformed_time_or_native_values(self):
        source = envelope()
        source["payload"]["sent_at"] = "PRIVATE_TIME_CANARY"
        error = self.rejected(source, "payload.sent_at")
        self.assertNotIn("PRIVATE_TIME_CANARY", str(error)+json.dumps(error.as_dict()))
        source = envelope()
        source["payload"]["PRIVATE_NATIVE_KEY_CANARY"] = object()
        error = self.rejected(source, "payload")
        self.assertNotIn("PRIVATE_NATIVE_KEY_CANARY", str(error)+json.dumps(error.as_dict()))

    def test_single_message_normalization_uses_no_file_network_or_clock(self):
        source = envelope()
        with patch("builtins.open", side_effect=AssertionError("File access prohibited")), \
                patch("pathlib.Path.open", side_effect=AssertionError("File access prohibited")), \
                patch("socket.socket", side_effect=AssertionError("Network access prohibited")), \
                patch("time.time", side_effect=AssertionError("Clock access prohibited")):
            result = normalize(source)
        self.assertEqual(result["content_parts"][0]["text"], source["payload"]["body"])
        self.assertIsNone(result["sent_at"])


if __name__ == "__main__":
    unittest.main()
