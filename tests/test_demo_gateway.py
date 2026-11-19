"""New neutral toy inputs only; no benchmark records, labels or corpus loaders."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from importlib.resources import files
import json
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator, FormatChecker

from safeguard.adapters.gateways.demo import GatewayInputError, DemoGateway


NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
SCHEMA = json.loads(files("safeguard.adapters").joinpath("contract.schema.json").read_text())
FORMATS = FormatChecker()


@FORMATS.checks("date-time", raises=ValueError)
def valid_datetime(value):
    if not isinstance(value, str):
        return True
    datetime.fromisoformat(value.replace("Z", "+00:00"))
    return True


VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FORMATS)


def toy_event():
    # Vietnamese text below is an independently authored neutral test input.
    return {"thread": "toy-chat", "id": "toy-note", "author": "toy-contact",
            "body": "  Chào bạn!\nHẹn gặp ở thư viện.  ", "sent_at": None}


class DemoGatewayTests(unittest.TestCase):
    def setUp(self):
        self.adapter = DemoGateway("toy-account", clock=lambda: NOW)

    def checked_receive(self, event, adapter=None):
        result = (adapter or self.adapter).receive(event)
        VALIDATOR.validate(result)
        return result

    def rejected(self, operation, field, code=None):
        with self.assertRaises(GatewayInputError) as caught:
            operation()
        self.assertEqual(caught.exception.field, field)
        if code:
            self.assertEqual(caught.exception.code, code)
        self.assertEqual(set(caught.exception.as_dict()), {"field", "code"})

    def test_exact_complete_envelope_for_contact(self):
        event = toy_event()
        self.assertEqual(self.checked_receive(event), {
            "schema_version": "1.0", "source": "demo", "account_id": "toy-account",
            "conversation_id": "toy-chat", "message_id": "toy-note", "sender_id": "toy-contact",
            "event_type": "message.created", "observed_at": "2026-01-02T03:04:05Z",
            "payload": event,
        })

    def test_observed_account_can_send_without_role_inference(self):
        event = toy_event()
        event["author"] = "toy-account"
        result = self.checked_receive(event)
        self.assertEqual(result["sender_id"], "toy-account")
        self.assertNotIn("role", result)
        self.assertNotIn("role", result["payload"])

    def test_text_and_identifiers_are_not_cleaned(self):
        event = toy_event()
        event["id"] = "  toy-note  "
        result = self.checked_receive(event)
        self.assertEqual(result["payload"], event)
        self.assertEqual(result["message_id"], "  toy-note  ")
        self.assertEqual(result["payload"]["body"], "  Chào bạn!\nHẹn gặp ở thư viện.  ")

    def test_whitespace_body_is_preserved_as_nonempty(self):
        event = toy_event()
        event["body"] = "  \n "
        self.assertEqual(self.checked_receive(event)["payload"]["body"], event["body"])

    def test_extra_native_json_fields_are_preserved(self):
        event = toy_event()
        event["native_extension"] = {"items": [False, None, 1, 1.5, {"note": "Toy detail"}]}
        event["source"] = "native-source-field"
        event["account_id"] = "native-account-field"
        result = self.checked_receive(event)
        self.assertEqual(result["payload"], event)
        self.assertEqual(result["source"], "demo")
        self.assertEqual(result["account_id"], "toy-account")

    def test_missing_null_or_native_send_time_not_replaced(self):
        for value in [None, "2025-12-01T09:00:00+07:00", "opaque source time"]:
            with self.subTest(sent_at=value):
                event = toy_event()
                event["sent_at"] = value
                self.assertEqual(self.checked_receive(event)["payload"], event)
        event = toy_event()
        del event["sent_at"]
        self.assertNotIn("sent_at", self.checked_receive(event)["payload"])

    def test_mutation_isolation_in_both_directions(self):
        event = toy_event()
        event["extra"] = {"list": ["before"]}
        before = deepcopy(event)
        result = self.checked_receive(event)
        self.assertEqual(event, before)
        event["extra"]["list"].append("source-change")
        self.assertEqual(result["payload"], before)
        result["payload"]["extra"]["list"].append("consumer-change")
        self.assertEqual(event["extra"]["list"], ["before", "source-change"])

    def test_required_native_fields(self):
        for key in ["thread", "id", "author", "body"]:
            with self.subTest(missing=key):
                event = toy_event()
                del event[key]
                self.rejected(lambda: self.adapter.receive(event), "payload." + key, "required")

    def test_invalid_native_identifiers(self):
        for key in ["thread", "id", "author"]:
            for value in [None, 1, True, [], {}, "", "  \t"]:
                with self.subTest(field=key, value=value):
                    event = toy_event()
                    event[key] = value
                    self.rejected(lambda: self.adapter.receive(event), "payload." + key)

    def test_invalid_body_and_nonobject_event(self):
        for value in [None, 1, True, [], {}, ""]:
            with self.subTest(body=value):
                event = toy_event()
                event["body"] = value
                self.rejected(lambda: self.adapter.receive(event), "payload.body")
        for value in [None, [], "Toy text"]:
            with self.subTest(event=value):
                self.rejected(lambda: self.adapter.receive(value), "payload", "expected_object")

    def test_invalid_account_context(self):
        for value in [None, 1, False, "", "  "]:
            with self.subTest(account=value):
                self.rejected(lambda: DemoGateway(value), "account_id")

    def test_invalid_clock_context(self):
        self.rejected(lambda: DemoGateway("toy-account", clock=None), "observed_at", "clock_not_callable")
        for value in [None, "2026-01-02T03:04:05Z", NOW.replace(tzinfo=None)]:
            with self.subTest(clock_return=value):
                adapter = DemoGateway("toy-account", clock=lambda: value)
                self.rejected(lambda: adapter.receive(toy_event()), "observed_at", "expected_aware_datetime")

    def test_clock_failure_does_not_echo_private_exception(self):
        def broken_clock():
            raise RuntimeError("PRIVATE_ERROR_CANARY")

        adapter = DemoGateway("toy-account", clock=broken_clock)
        with self.assertRaises(GatewayInputError) as caught:
            adapter.receive(toy_event())
        self.assertEqual(caught.exception.code, "clock_failed")
        self.assertNotIn("PRIVATE_ERROR_CANARY", str(caught.exception))

    def test_observation_clock_is_converted_to_utc(self):
        value = datetime(2026, 1, 2, 10, 4, 5, 125000, tzinfo=timezone(timedelta(hours=7)))
        adapter = DemoGateway("toy-account", clock=lambda: value)
        self.assertEqual(self.checked_receive(toy_event(), adapter)["observed_at"], "2026-01-02T03:04:05.125000Z")

    def test_default_clock_is_real_aware_utc(self):
        before = datetime.now(timezone.utc)
        result = self.checked_receive(toy_event(), DemoGateway("toy-account"))
        after = datetime.now(timezone.utc)
        timestamp = datetime.fromisoformat(result["observed_at"].replace("Z", "+00:00"))
        self.assertLessEqual(before, timestamp)
        self.assertLessEqual(timestamp, after)

    def test_non_json_payload_extensions_are_rejected(self):
        for value in [float("nan"), float("inf"), {"set-member"}, (1, 2), {1: "numeric key"}]:
            with self.subTest(invalid_json_type=type(value).__name__):
                event = toy_event()
                event["extra"] = value
                self.rejected(lambda: self.adapter.receive(event), "payload")

    def test_cycle_rejected_but_shared_values_are_copied(self):
        event = toy_event()
        event["extra"] = event
        self.rejected(lambda: self.adapter.receive(event), "payload", "cyclic_payload")
        shared = {"toy": []}
        event = toy_event()
        event["first"] = shared
        event["second"] = shared
        self.assertEqual(self.checked_receive(event)["payload"], event)

    def test_excessive_nesting_returns_a_field_error(self):
        nested = []
        for _ in range(2000):
            nested = [nested]
        event = toy_event()
        event["extra"] = nested
        self.rejected(lambda: self.adapter.receive(event), "payload", "nesting_too_deep")

    def test_invalid_event_does_not_call_observation_clock(self):
        def unexpected_clock():
            self.fail("Invalid native input should fail before reading the clock")

        adapter = DemoGateway("toy-account", clock=unexpected_clock)
        self.rejected(lambda: adapter.receive({}), "payload.thread", "required")

    def test_receive_uses_no_file_or_network_access(self):
        with patch("builtins.open", side_effect=AssertionError("File access prohibited")), \
                patch("pathlib.Path.open", side_effect=AssertionError("File access prohibited")), \
                patch("socket.socket", side_effect=AssertionError("Network access prohibited")):
            result = self.adapter.receive(toy_event())
        VALIDATOR.validate(result)


if __name__ == "__main__":
    unittest.main()
