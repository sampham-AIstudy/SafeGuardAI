"""Exercise actual demo handoff with a recorder and independent neutral inputs."""

from copy import deepcopy
from datetime import timedelta
import unittest
from unittest.mock import patch

from jsonschema import ValidationError

from safeguard.adapters.gateways.demo import GatewayInputError, DemoGateway
from test_demo_gateway import NOW, VALIDATOR


def native_event(thread="toy-study", message="toy-note", author="toy-reader"):
    # Vietnamese text below is independently authored neutral fixture content.
    return {"thread": thread, "id": message, "author": author,
            "body": "  Cuốn sách đang ở bàn đọc.\n  ", "sent_at": None,
            "extension": {"items": [False, 2, None, {"title": "Toy book"}]}}


class RecordingNormalizer:
    """Check the envelope and record it; perform no content normalization."""

    def __init__(self):
        self.events = []

    def __call__(self, envelope):
        VALIDATOR.validate(envelope)
        self.events.append(deepcopy(envelope))


class GatewayHandoffTests(unittest.TestCase):
    def setUp(self):
        self.clock_calls = 0

        def clock():
            self.clock_calls += 1
            return NOW

        self.adapter = DemoGateway("toy-account", clock=clock)
        self.receiver = RecordingNormalizer()

    def check_recorded(self, native, recorded, account="toy-account"):
        self.assertEqual(len(native), len(recorded))
        for event, envelope in zip(native, recorded):
            self.assertEqual(envelope, {
                "schema_version": "1.0", "source": "demo", "account_id": account,
                "conversation_id": event["thread"], "message_id": event["id"],
                "sender_id": event["author"], "event_type": "message.created",
                "observed_at": "2026-01-02T03:04:05Z", "payload": event,
            })

    def test_interleaved_handoff_preserves_every_field_in_arrival_order(self):
        native = [native_event("toy-study", "note-2"), native_event("toy-park", "note-1", "toy-account"),
                  native_event("toy-study", "note-1", "toy-account"), native_event("toy-park", "note-2")]
        before = deepcopy(native)
        self.assertEqual(self.adapter.deliver_stream(iter(native), self.receiver), 4)
        self.check_recorded(before, self.receiver.events)
        self.assertEqual(native, before)
        self.assertEqual(self.clock_calls, 4)

    def test_empty_and_singleton_handoff(self):
        self.assertEqual(self.adapter.deliver_stream([], self.receiver), 0)
        self.assertEqual((self.receiver.events, self.clock_calls), ([], 0))
        native = [native_event()]
        self.assertEqual(self.adapter.deliver_stream(native, self.receiver), 1)
        self.check_recorded(native, self.receiver.events)
        self.assertEqual(self.clock_calls, 1)

    def test_longer_generator_reaches_the_receiver_without_losses(self):
        native = [native_event("toy-room-"+str(i % 2), str(i)) for i in range(1000)]
        self.assertEqual(self.adapter.deliver_stream((x for x in native), self.receiver), 1000)
        self.check_recorded(native, self.receiver.events)
        self.assertEqual(self.clock_calls, 1000)

    def test_receiver_finishes_before_the_next_source_read(self):
        timeline = []

        def source():
            for i in range(3):
                timeline.append(("source", i))
                yield native_event(message=str(i))

        def receiver(envelope):
            i = int(envelope["message_id"])
            self.assertEqual(timeline[-1], ("source", i))
            self.receiver(envelope)
            timeline.append(("accepted", i))

        self.assertEqual(self.adapter.deliver_stream(source(), receiver), 3)
        self.assertEqual(timeline, [("source", 0), ("accepted", 0), ("source", 1),
                                    ("accepted", 1), ("source", 2), ("accepted", 2)])

    def test_scoped_and_repeated_ids_and_source_times_are_preserved(self):
        for account in ["toy-account", "toy-other-account"]:
            native = [native_event("toy-study", "same-id"), native_event("toy-park", "same-id"),
                      native_event("toy-study", "same-id")]
            for value, seconds in zip(native, [20, -10, 0]):
                value["sent_at"] = (NOW+timedelta(seconds=seconds)).isoformat()
            receiver = RecordingNormalizer()
            adapter = DemoGateway(account, clock=lambda: NOW)
            self.assertEqual(adapter.deliver_stream(native, receiver), 3)
            self.check_recorded(native, receiver.events, account)

    def test_receiver_mutation_cannot_modify_native_or_later_envelopes(self):
        shared = native_event()
        before = deepcopy(shared)

        def receiver(envelope):
            self.receiver(envelope)
            envelope["payload"]["extension"]["items"].append("receiver-change")
            envelope["conversation_id"] = "receiver-local-edit"

        self.assertEqual(self.adapter.deliver_stream([shared, shared], receiver), 2)
        self.assertEqual(shared, before)
        self.check_recorded([before, before], self.receiver.events)

    def test_noncallable_receiver_is_rejected_before_source_consumption(self):
        consumed = []

        def source():
            consumed.append(True)
            yield native_event()

        for receiver in [None, 1, [], {}]:
            with self.subTest(receiver=type(receiver).__name__), self.assertRaises(GatewayInputError) as caught:
                self.adapter.deliver_stream(source(), receiver)
            self.assertEqual(caught.exception.as_dict(), {"field": "receiver", "code": "expected_callable"})
        self.assertEqual((consumed, self.clock_calls), ([], 0))

    def test_non_none_receiver_return_is_not_silent_acceptance(self):
        for returned in [False, True, 0, {}, "rejected"]:
            with self.subTest(returned=returned):
                consumed = []
                attempted = []

                def source():
                    for i in range(3):
                        consumed.append(i)
                        yield native_event(message=str(i))

                def receiver(envelope):
                    attempted.append(envelope["message_id"])
                    return returned

                with self.assertRaises(GatewayInputError) as caught:
                    self.adapter.deliver_stream(source(), receiver)
                self.assertEqual(caught.exception.as_dict(),
                                 {"field": "receiver", "code": "expected_none_return"})
                self.assertEqual((consumed, attempted), ([0], ["0"]))

    def test_receiver_failure_before_or_after_recording_stops_without_retry(self):
        for record_failed in [False, True]:
            with self.subTest(record_failed=record_failed):
                consumed = []
                attempted = []
                receiver = RecordingNormalizer()
                failure = RuntimeError("Toy receiver unavailable")

                def source():
                    for i in range(3):
                        consumed.append(i)
                        yield native_event(message=str(i))

                def failing_receiver(envelope):
                    attempted.append(envelope["message_id"])
                    if envelope["message_id"] == "1":
                        if record_failed:
                            receiver(envelope)
                        raise failure
                    receiver(envelope)

                native = source()
                with self.assertRaises(RuntimeError) as caught:
                    self.adapter.deliver_stream(native, failing_receiver)
                self.assertIs(caught.exception, failure)
                self.assertEqual((consumed, attempted), ([0, 1], ["0", "1"]))
                self.assertEqual([x["message_id"] for x in receiver.events],
                                 ["0", "1"] if record_failed else ["0"])
                self.assertEqual(next(native)["id"], "2")
                native.close()

    def test_receiver_can_explicitly_reject_an_envelope(self):
        failure = ValueError("Toy receiver does not accept this event")

        def rejecting_receiver(envelope):
            VALIDATOR.validate(envelope)
            raise failure

        with self.assertRaises(ValueError) as caught:
            self.adapter.deliver_stream([native_event()], rejecting_receiver)
        self.assertIs(caught.exception, failure)
        self.assertEqual(self.receiver.events, [])

    def test_recording_receiver_rejects_malformed_envelopes_before_recording(self):
        class MalformedAdapter(DemoGateway):
            def receive(self, event):
                result = super().receive(event)
                del result["conversation_id"]
                return result

        adapter = MalformedAdapter("toy-account", clock=lambda: NOW)
        with self.assertRaises(ValidationError):
            adapter.deliver_stream([native_event()], self.receiver)
        self.assertEqual(self.receiver.events, [])

    def test_bad_middle_native_event_never_reaches_receiver(self):
        consumed = []

        def source():
            for i, value in enumerate([native_event(), {}, native_event(message="unread")]):
                consumed.append(i)
                yield value

        with self.assertRaises(GatewayInputError) as caught:
            self.adapter.deliver_stream(source(), self.receiver)
        self.assertEqual(caught.exception.as_dict(), {"field": "payload.thread", "code": "required"})
        self.assertEqual((consumed, self.clock_calls), ([0, 1], 1))
        self.check_recorded([native_event()], self.receiver.events)

    def test_clock_failure_does_not_deliver_bad_or_later_events(self):
        consumed = []
        times = iter([NOW, None, NOW])
        adapter = DemoGateway("toy-account", clock=lambda: next(times))

        def source():
            for i in range(3):
                consumed.append(i)
                yield native_event(message=str(i))

        with self.assertRaises(GatewayInputError) as caught:
            adapter.deliver_stream(source(), self.receiver)
        self.assertEqual(caught.exception.field, "observed_at")
        self.assertEqual(consumed, [0, 1])
        self.check_recorded([native_event(message="0")], self.receiver.events)

    def test_source_failure_is_not_masked_or_counted_as_success(self):
        failure = OSError("Toy source unavailable")

        def source():
            yield native_event()
            raise failure

        with self.assertRaises(OSError) as caught:
            self.adapter.deliver_stream(source(), self.receiver)
        self.assertIs(caught.exception, failure)
        self.check_recorded([native_event()], self.receiver.events)

    def test_handoff_uses_no_file_or_network_access(self):
        native = [native_event(), native_event("toy-park")]
        with patch("builtins.open", side_effect=AssertionError("File access prohibited")), \
                patch("pathlib.Path.open", side_effect=AssertionError("File access prohibited")), \
                patch("socket.socket", side_effect=AssertionError("Network access prohibited")):
            completed = self.adapter.deliver_stream(native, self.receiver)
        self.assertEqual(completed, 2)
        self.check_recorded(native, self.receiver.events)


if __name__ == "__main__":
    unittest.main()
