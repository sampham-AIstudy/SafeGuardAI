"""Stream checks use independently authored neutral inputs, never benchmark data."""

from copy import deepcopy
from datetime import timedelta
from itertools import islice
import unittest
from unittest.mock import patch

from safeguard.adapters.gateways.demo import GatewayInputError, DemoGateway
from test_demo_gateway import NOW, VALIDATOR


def event(thread="toy-library", message="toy-note", author="toy-reader"):
    # Vietnamese text below is independently authored neutral fixture content.
    return {"thread": thread, "id": message, "author": author,
            "body": "  Hôm nay thư viện mở cửa.\n  ", "extra": {"items": [1, None, False]}}


class DemoStreamTests(unittest.TestCase):
    def setUp(self):
        self.clock_calls = 0

        def clock():
            self.clock_calls += 1
            return NOW + timedelta(seconds=self.clock_calls)

        self.adapter = DemoGateway("toy-account", clock=clock)

    def check_outputs(self, inputs, outputs, account="toy-account"):
        self.assertEqual(len(outputs), len(inputs))
        for native, envelope in zip(inputs, outputs):
            VALIDATOR.validate(envelope)
            self.assertEqual(envelope["payload"], native)
            self.assertEqual(envelope["conversation_id"], native["thread"])
            self.assertEqual(envelope["message_id"], native["id"])
            self.assertEqual(envelope["sender_id"], native["author"])
            self.assertEqual(envelope["account_id"], account)

    def test_interleaved_conversations_preserve_exact_order_and_payload(self):
        inputs = [event("toy-library", "note-2"), event("toy-garden", "note-1", "toy-account"),
                  event("toy-library", "note-1", "toy-account"), event("toy-garden", "note-2")]
        before = deepcopy(inputs)
        outputs = list(self.adapter.receive_stream(inputs))
        self.check_outputs(before, outputs)
        self.assertEqual(inputs, before)
        self.assertEqual(self.clock_calls, 4)

    def test_empty_and_singleton_streams(self):
        for empty in [[], (), iter(())]:
            with self.subTest(container=type(empty).__name__):
                self.assertEqual(list(self.adapter.receive_stream(empty)), [])
        self.assertEqual(self.clock_calls, 0)
        for container in [list, tuple, iter]:
            with self.subTest(container=container.__name__):
                inputs = [event()]
                self.check_outputs(inputs, list(self.adapter.receive_stream(container(inputs))))
        self.assertEqual(self.clock_calls, 3)

    def test_lazy_single_pass_source_reads_only_requested_items(self):
        seen = []

        class SinglePass:
            iterations = 0

            def __iter__(inner):
                inner.iterations += 1
                if inner.iterations > 1:
                    raise AssertionError("Source must not be iterated twice")
                for index in range(3):
                    seen.append(index)
                    yield event(message=str(index))

        source = SinglePass()
        stream = self.adapter.receive_stream(source)
        self.assertEqual(seen, [])
        self.assertEqual(self.clock_calls, 0)
        first = next(stream)
        self.assertEqual((seen, self.clock_calls), ([0], 1))
        self.assertEqual(first["message_id"], "0")
        second = next(stream)
        self.assertEqual((seen, self.clock_calls), ([0, 1], 2))
        self.assertEqual(second["message_id"], "1")
        stream.close()
        self.assertEqual(seen, [0, 1])

    def test_unbounded_source_can_be_consumed_as_a_finite_prefix(self):
        requested = []

        def source():
            index = 0
            while True:
                requested.append(index)
                yield event(message=str(index))
                index += 1

        stream = self.adapter.receive_stream(source())
        outputs = list(islice(stream, 5))
        self.assertEqual([x["message_id"] for x in outputs], ["0", "1", "2", "3", "4"])
        self.assertEqual(requested, [0, 1, 2, 3, 4])
        self.assertEqual(self.clock_calls, 5)
        stream.close()

    def test_longer_interleaved_generator_has_no_missing_or_extra_events(self):
        inputs = [event("toy-room-"+str(index % 2), str(index), "toy-person-"+str(index % 3))
                  for index in range(1000)]
        self.check_outputs(inputs, list(self.adapter.receive_stream(x for x in inputs)))
        self.assertEqual(self.clock_calls, 1000)

    def test_clocks_and_local_message_ids_do_not_reorder_or_merge_events(self):
        inputs = [event("toy-library", "same-id"), event("toy-garden", "same-id"),
                  event("toy-library", "same-id")]
        for native, seconds in zip(inputs, [30, -10, 20]):
            native["sent_at"] = (NOW + timedelta(seconds=seconds)).isoformat()
        times = iter([NOW + timedelta(seconds=20), NOW, NOW])
        adapter = DemoGateway("toy-account", clock=lambda: next(times))
        outputs = list(adapter.receive_stream(inputs))
        self.check_outputs(inputs, outputs)
        self.assertEqual([x["observed_at"] for x in outputs],
                         ["2026-01-02T03:04:25Z", "2026-01-02T03:04:05Z", "2026-01-02T03:04:05Z"])

    def test_reused_source_object_is_snapshotted_per_yield(self):
        shared = event()

        def source():
            yield shared
            shared["id"] = "second-note"
            shared["extra"]["items"].append("source-change")
            yield shared

        stream = self.adapter.receive_stream(source())
        first = next(stream)
        second = next(stream)
        self.assertEqual(first["message_id"], "toy-note")
        self.assertEqual(first["payload"]["extra"]["items"], [1, None, False])
        self.assertEqual(second["message_id"], "second-note")
        second["payload"]["extra"]["items"].append("consumer-change")
        self.assertEqual(shared["extra"]["items"], [1, None, False, "source-change"])
        self.assertEqual(first["payload"]["extra"]["items"], [1, None, False])

    def test_consumer_mutation_does_not_affect_later_shared_payload(self):
        shared = event()
        stream = self.adapter.receive_stream([shared, shared])
        first = next(stream)
        first["payload"]["extra"]["items"].append("consumer-change")
        second = next(stream)
        self.assertEqual(second["payload"], shared)
        self.assertEqual(shared["extra"]["items"], [1, None, False])

    def test_independent_streams_and_accounts_do_not_mix_context(self):
        other = DemoGateway("toy-other-account", clock=lambda: NOW)
        first = self.adapter.receive_stream([event(message="first"), event(message="second")])
        second = self.adapter.receive_stream([event("toy-garden", "garden-note")])
        third = other.receive_stream([event()])
        self.assertEqual(next(first)["message_id"], "first")
        self.assertEqual(next(second)["conversation_id"], "toy-garden")
        self.assertEqual(next(third)["account_id"], "toy-other-account")
        self.assertEqual(next(first)["message_id"], "second")

    def test_invalid_stream_containers_have_structured_errors(self):
        for value in [None, 1, True, "", "toy-text", b"", bytearray(), {}, event()]:
            with self.subTest(container=type(value).__name__), self.assertRaises(GatewayInputError) as caught:
                list(self.adapter.receive_stream(value))
            self.assertEqual(caught.exception.as_dict(),
                             {"field": "events", "code": "expected_event_iterable"})
        self.assertEqual(self.clock_calls, 0)

    def test_invalid_middle_event_stops_without_consuming_later_events(self):
        consumed = []

        def source():
            for index, value in enumerate([event(), {}, event(message="unread")]):
                consumed.append(index)
                yield value

        stream = self.adapter.receive_stream(source())
        first = next(stream)
        before = deepcopy(first)
        with self.assertRaises(GatewayInputError) as caught:
            next(stream)
        self.assertEqual(caught.exception.as_dict(), {"field": "payload.thread", "code": "required"})
        self.assertEqual((consumed, self.clock_calls), ([0, 1], 1))
        self.assertEqual(list(stream), [])
        self.assertEqual(first, before)

    def test_clock_failure_stops_without_prefetch_or_content_leak(self):
        consumed = []

        def source():
            for index in range(3):
                consumed.append(index)
                yield event(message=str(index))

        calls = 0

        def clock():
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("PRIVATE_CLOCK_CANARY")
            return NOW

        stream = DemoGateway("toy-account", clock=clock).receive_stream(source())
        first = next(stream)
        with self.assertRaises(GatewayInputError) as caught:
            next(stream)
        self.assertEqual(caught.exception.code, "clock_failed")
        self.assertNotIn("PRIVATE_CLOCK_CANARY", str(caught.exception))
        self.assertEqual(consumed, [0, 1])
        self.assertEqual(first["message_id"], "0")
        self.assertEqual(list(stream), [])

    def test_source_failure_propagates_without_retry_or_rollback(self):
        for failure_type in [RuntimeError, TypeError, ValueError]:
            with self.subTest(error=failure_type.__name__):
                failure = failure_type("Toy source unavailable")
                consumed = []
                clock_before = self.clock_calls

                def source():
                    consumed.append(0)
                    yield event()
                    consumed.append(1)
                    raise failure

                stream = self.adapter.receive_stream(source())
                first = next(stream)
                with self.assertRaises(failure_type) as caught:
                    next(stream)
                self.assertIs(caught.exception, failure)
                self.assertEqual((consumed, self.clock_calls-clock_before), ([0, 1], 1))
                self.assertEqual(first["message_id"], "toy-note")
                self.assertEqual(list(stream), [])

    def test_close_does_not_close_the_caller_owned_source(self):
        closed = []

        def source():
            try:
                yield event(message="first-note")
                yield event(message="second-note")
            finally:
                closed.append(True)

        native = source()
        stream = self.adapter.receive_stream(native)
        self.assertEqual(next(stream)["message_id"], "first-note")
        stream.close()
        self.assertEqual(closed, [])
        self.assertEqual(self.clock_calls, 1)
        self.assertEqual(next(native)["id"], "second-note")
        native.close()
        self.assertEqual(closed, [True])

    def test_close_before_first_read_never_consumes_input(self):
        def unread_source():
            self.fail("Closing before first read must not consume source")
            yield event()

        stream = self.adapter.receive_stream(unread_source())
        stream.close()
        self.assertEqual(list(stream), [])
        self.assertEqual(self.clock_calls, 0)

    def test_stream_uses_no_file_or_network_access(self):
        with patch("builtins.open", side_effect=AssertionError("File access prohibited")), \
                patch("pathlib.Path.open", side_effect=AssertionError("File access prohibited")), \
                patch("socket.socket", side_effect=AssertionError("Network access prohibited")):
            outputs = list(self.adapter.receive_stream([event(), event("toy-garden")]))
        self.check_outputs([event(), event("toy-garden")], outputs)


if __name__ == "__main__":
    unittest.main()
