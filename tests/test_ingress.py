"""Independent neutral inputs; toy limits are not deployment defaults."""

import asyncio
from dataclasses import replace
import json
import unittest

from safeguard.adapters.demo import create_demo_adapter
from unittest.mock import patch

from safeguard.ingress import AccessContext, ConversationIngress, IngressError, InputLimits, InputViolation, ProcessingLimits


INPUT = InputLimits(65536, 4096, 16, 4096, 16, 8)
PROCESSING = ProcessingLimits(2, 16, 262144, 16, 16, 1.0)


def native(room="toy-study", message="toy-note"):
    return {"thread": room, "id": message, "author": "toy-reader", "body": "Toy library note.", "sent_at": None}


def access(account="toy-account", rooms=("toy-study", "toy-garden")):
    return AccessContext(account, frozenset(rooms))


class InputLimitTests(unittest.TestCase):
    def violation(self, operation, code):
        with self.assertRaises(InputViolation) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)

    def test_size_matches_canonical_utf8_and_exact_boundary(self):
        value = {"body": "Toy \"book\"\n", "items": [None, False, 1, 1.5]}
        size = len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode())
        self.assertEqual(replace(INPUT, max_bytes=size).inspect(value), size)

    def test_encoded_size_limit_accounts_for_escaping(self):
        self.violation(lambda: replace(INPUT, max_bytes=10).inspect({"x": "\x01"*3}), "too_many_bytes")

    def test_wire_size_and_depth_reject_before_json_parser(self):
        with patch("safeguard.ingress.limits.json.loads", side_effect=AssertionError("Parser must not run")):
            self.violation(lambda: replace(INPUT, max_bytes=3).decode(b"[1,2]"), "too_many_bytes")
            self.violation(lambda: replace(INPUT, max_depth=2).decode(b"[[[1]]]"), "too_deep")

    def test_quotes_and_escaped_brackets_are_not_container_depth(self):
        value = {"body": 'Toy "book" [[[[ { } ]]]'}
        raw = json.dumps(value).encode()
        self.assertEqual(replace(INPUT, max_depth=1).decode(raw), value)

    def test_decoded_depth_nodes_text_unicode_and_cycles(self):
        self.violation(lambda: replace(INPUT, max_depth=1).inspect({"items": []}), "too_deep")
        self.violation(lambda: replace(INPUT, max_nodes=2).inspect([1, 2]), "too_many_nodes")
        self.violation(lambda: replace(INPUT, max_text_chars=2).inspect({"body": "Toy"}), "text_too_long")
        self.violation(lambda: INPUT.inspect({"body": "\ud800"}), "invalid_unicode")
        self.violation(lambda: INPUT.inspect({1: "Toy"}), "nonstring_key")
        value = []
        value.append(value)
        self.violation(lambda: INPUT.inspect(value), "cyclic_input")
        shared = {"note": "Toy"}
        self.assertGreater(INPUT.inspect([shared, shared]), 0)

    def test_json_rejects_duplicates_nonfinite_malformed_and_wrong_encoding(self):
        for raw, code in [(b'{"body":1,"body":2}', "duplicate_key"), (b'{"x":NaN}', "nonfinite_number"),
                          (b"{", "invalid_json"), (b"\xff", "invalid_utf8")]:
            with self.subTest(code=code):
                self.violation(lambda: INPUT.decode(raw), code)
        self.violation(lambda: INPUT.inspect(INPUT.decode(b'{"x":1e999}')), "nonfinite_number")

    def test_limits_require_explicit_positive_values(self):
        for name in ("max_bytes", "max_text_chars", "max_depth", "max_nodes", "max_content_parts", "max_assets"):
            for value in (0, -1, True):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    replace(INPUT, **{name: value})
        for changes in ({"workers": 0}, {"max_pending": True}, {"consumer_timeout": float("inf")}, {"consumer_timeout": 0}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(PROCESSING, **changes)


class IngressTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_adapter_norm_json_and_native_integration_and_isolation(self):
        received = []

        async def consume(message):
            received.append(message)

        async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING) as pipe:
            value = native()
            first = pipe.submit(value, access())
            value["body"] = "Changed after admission"
            second = pipe.submit_json(json.dumps(native("toy-garden")).encode(), access())
            outcomes = await asyncio.gather(first.wait(), second.wait())
            self.assertTrue(all(x.status == "completed" for x in outcomes))
            self.assertTrue(all(x["content_parts"][0]["text"] == "Toy library note." for x in received))
            self.assertTrue(all(x["raw_payload"]["body"] == "Toy library note." for x in received))
            self.assertEqual(pipe.stats["pending"], 0)
            self.assertEqual(pipe.stats["pending_bytes"], 0)

    async def test_same_conversation_fifo_and_cross_conversation_concurrency(self):
        gate, both = asyncio.Event(), asyncio.Event()
        active = set()
        order = {"toy-study": [], "toy-garden": []}

        async def consume(message):
            key = message["conversation_id"]
            self.assertNotIn(key, active)
            active.add(key)
            order[key].append(message["message_id"])
            if len(active) == 2:
                both.set()
            await gate.wait()
            active.remove(key)

        async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING) as pipe:
            tickets = [pipe.submit(native(room, str(i)), access()) for i in range(3) for room in order]
            await asyncio.wait_for(both.wait(), 1)
            self.assertEqual(order, {"toy-study": ["0"], "toy-garden": ["0"]})
            self.assertEqual(pipe.stats["active"], 2)
            gate.set()
            await asyncio.gather(*(x.wait() for x in tickets))
            self.assertEqual(order, {"toy-study": ["0", "1", "2"], "toy-garden": ["0", "1", "2"]})
            self.assertEqual(pipe.stats["peak_active"], 2)

    async def test_worker_cap_applies_with_more_keys_than_workers(self):
        gate, started = asyncio.Event(), asyncio.Event()
        active = 0
        peak = 0

        async def consume(_):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            if active == 2:
                started.set()
            await gate.wait()
            active -= 1

        rooms = tuple("toy-room-"+str(i) for i in range(8))
        async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING) as pipe:
            tickets = [pipe.submit(native(room), access(rooms=rooms)) for room in rooms]
            await asyncio.wait_for(started.wait(), 1)
            self.assertEqual(active, 2)
            gate.set()
            await asyncio.gather(*(x.wait() for x in tickets))
            self.assertEqual((peak, pipe.stats["peak_active"]), (2, 2))

    async def test_ingestion_and_other_key_progress_while_first_key_waits(self):
        gate, started = asyncio.Event(), asyncio.Event()

        async def consume(message):
            if message["conversation_id"] == "toy-study":
                started.set()
                await gate.wait()

        async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING) as pipe:
            first = pipe.submit(native(), access())
            await started.wait()
            follower = pipe.submit(native(message="second"), access())
            other = pipe.submit(native("toy-garden"), access())
            self.assertEqual((await asyncio.wait_for(other.wait(), 1)).status, "completed")
            self.assertEqual(pipe.stats["pending"], 2)
            gate.set()
            await asyncio.gather(first.wait(), follower.wait())

    async def test_global_account_conversation_and_byte_capacity(self):
        gate = asyncio.Event()

        async def consume(_):
            await gate.wait()

        configs = [(replace(PROCESSING, max_pending=1), native("toy-garden"), access(), "busy"),
                   (replace(PROCESSING, per_account=1), native("toy-garden"), access(), "scope_busy"),
                   (replace(PROCESSING, per_conversation=1), native(), access(), "scope_busy"),
                   (replace(PROCESSING, max_pending_bytes=INPUT.inspect(native())), native(), access(), "byte_capacity")]
        for limits, value, context, code in configs:
            with self.subTest(code=code):
                gate.clear()
                async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=limits) as pipe:
                    ticket = pipe.submit(native(), access())
                    with self.assertRaises(IngressError) as caught:
                        pipe.submit(value, context)
                    self.assertEqual(caught.exception.code, code)
                    self.assertEqual(pipe.stats["admitted"], 1)
                    gate.set()
                    self.assertEqual((await ticket.wait()).status, "completed")
                    self.assertEqual(pipe.stats["pending"], 0)

    async def test_authorization_and_bound_account_before_copy(self):
        received = []

        async def consume(message):
            received.append(message)

        async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING) as pipe:
            with patch("safeguard.adapters.gateways.demo.DemoGateway.receive", side_effect=AssertionError("Must not copy")):
                for value, context in [(native("unauthorized-room"), access()), (native(), {"account_id": "toy-account"})]:
                    with self.assertRaises(IngressError) as caught:
                        pipe.submit(value, context)
                    self.assertEqual(caught.exception.stage, "authorization")
            value = native()
            value["account_id"] = "spoofed-native-account"
            await pipe.submit(value, access("trusted-account")).wait()
            self.assertEqual(received[0]["account_id"], "trusted-account")
            self.assertEqual(pipe.stats["admitted"], 1)

    async def test_resource_rejections_happen_before_copy(self):
        async def consume(_):
            self.fail("Rejected input must never reach consumer")

        async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=replace(INPUT, max_text_chars=3), processing_limits=PROCESSING) as pipe:
            with patch("safeguard.adapters.gateways.demo.DemoGateway.receive", side_effect=AssertionError("Must not copy")):
                with self.assertRaises(IngressError) as caught:
                    pipe.submit(native(), access())
            self.assertEqual((caught.exception.stage, caught.exception.code), ("input", "text_too_long"))
            self.assertEqual(pipe.stats["admitted"], 0)

    async def test_account_scope_separation_with_matching_conversation_ids(self):
        gate, both = asyncio.Event(), asyncio.Event()
        started = []

        async def consume(message):
            started.append(message["account_id"])
            if len(started) == 2:
                both.set()
            await gate.wait()

        async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=replace(PROCESSING, per_account=1)) as pipe:
            tickets = [pipe.submit(native(), access(account)) for account in ("toy-one", "toy-two")]
            await asyncio.wait_for(both.wait(), 1)
            gate.set()
            await asyncio.gather(*(x.wait() for x in tickets))
            self.assertEqual(set(started), {"toy-one", "toy-two"})

    async def test_failure_pauses_only_its_key_and_requires_explicit_ack(self):
        seen = []

        async def consume(message):
            seen.append(message["message_id"])
            if message["message_id"] == "fail":
                raise RuntimeError("PRIVATE_EXCEPTION_CANARY")

        with self.assertRaises(IngressError) as aggregate:
            async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING) as pipe:
                tickets = [pipe.submit(native(message="fail"), access()),
                           pipe.submit(native(message="blocked"), access()),
                           pipe.submit(native("toy-garden", "other"), access())]
                results = await asyncio.gather(*(x.wait() for x in tickets))
                self.assertEqual([x.status for x in results], ["failed", "blocked", "completed"])
                self.assertNotIn("blocked", seen)
                with self.assertRaises(IngressError) as caught:
                    pipe.submit(native(), access())
                self.assertEqual(caught.exception.code, "conversation_failed")
                pipe.acknowledge_failure(access(), "toy-study")
                self.assertEqual((await pipe.submit(native(message="explicit-new-event"), access()).wait()).status, "completed")
        self.assertEqual(aggregate.exception.code, "run_failed")

    async def test_retained_failed_keys_are_bounded(self):
        async def consume(_):
            raise ValueError("Toy failure")

        context = access(rooms=("toy-one", "toy-two", "toy-three"))
        with self.assertRaises(IngressError):
            async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=replace(PROCESSING, max_pending=2)) as pipe:
                for room in ("toy-one", "toy-two"):
                    self.assertEqual((await pipe.submit(native(room), context).wait()).status, "failed")
                with self.assertRaises(IngressError) as caught:
                    pipe.submit(native("toy-three"), context)
                self.assertEqual(caught.exception.code, "conversation_capacity")
                self.assertEqual(pipe.stats["tracked_conversations"], 2)

    async def test_timeout_and_invalid_consumer_return_are_explicit(self):
        async def timeout(_):
            await asyncio.Event().wait()

        async def invalid(_):
            return False

        async def cancelled(_):
            raise asyncio.CancelledError

        for consume, code in [(timeout, "consumer_timeout"), (invalid, "invalid_consumer_return"), (cancelled, "consumer_cancelled")]:
            with self.subTest(code=code), self.assertRaises(IngressError):
                async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=replace(PROCESSING, consumer_timeout=0.01)) as pipe:
                    result = await asyncio.wait_for(pipe.submit(native(), access()).wait(), 1)
                    self.assertEqual((result.status, result.code), ("failed", code))

    async def test_cancelling_waiter_does_not_cancel_admitted_work(self):
        gate = asyncio.Event()

        async def consume(_):
            await gate.wait()

        async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING) as pipe:
            ticket = pipe.submit(native(), access())
            waiter = asyncio.create_task(ticket.wait())
            await asyncio.sleep(0)
            waiter.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await waiter
            gate.set()
            self.assertEqual((await ticket.wait()).status, "completed")

    async def test_abort_settles_active_and_waiting_tickets_and_workers(self):
        started = asyncio.Event()

        async def consume(_):
            started.set()
            await asyncio.Event().wait()

        pipe = ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=replace(PROCESSING, workers=1))
        await pipe.__aenter__()
        tickets = [pipe.submit(native(room), access()) for room in ("toy-study", "toy-garden")]
        await started.wait()
        await asyncio.wait_for(pipe.__aexit__(RuntimeError, RuntimeError("Toy abort"), None), 0.2)
        results = await asyncio.wait_for(asyncio.gather(*(x.wait() for x in tickets)), 1)
        self.assertTrue(all(x.status in ("cancelled", "blocked") for x in results))
        self.assertEqual(pipe.stats["pending"], 0)
        self.assertEqual(pipe.stats["active"], 0)
        self.assertTrue(all(x.done() for x in pipe._workers))

    async def test_logs_and_outcomes_do_not_echo_chat_ids_or_exceptions(self):
        async def consume(_):
            raise RuntimeError("PRIVATE_EXCEPTION_CANARY")

        with self.assertLogs("safeguard.ingress", level="INFO") as captured:
            with self.assertRaises(IngressError):
                async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING) as pipe:
                    value = native("PRIVATE_ROOM_CANARY", "PRIVATE_ID_CANARY")
                    value["body"] = "PRIVATE_BODY_CANARY"
                    context = access("PRIVATE_ACCOUNT_CANARY", ("PRIVATE_ROOM_CANARY",))
                    result = await pipe.submit(value, context).wait()
        rendered = "\n".join(captured.output)+repr(result)
        self.assertNotIn("PRIVATE_", rendered)
        self.assertIn("bytes=", rendered)
        self.assertIn("elapsed_seconds=", rendered)
        self.assertEqual(len(result.trace_id), 32)
        self.assertEqual(result.code, "consumer_failed")

    async def test_bad_native_and_norm_input_never_reach_consumer(self):
        async def consume(_):
            self.fail("Invalid input must not be processed")

        async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING) as pipe:
            for changes, stage in [({"body": ""}, "gateway"), ({"sent_at": "invalid-time"}, "normalizer")]:
                with self.subTest(stage=stage):
                    value = native()
                    value.update(changes)
                    with self.assertRaises(IngressError) as caught:
                        pipe.submit(value, access())
                    self.assertEqual(caught.exception.stage, stage)

    async def test_runtime_does_not_open_files_or_network_connections(self):
        async def consume(_):
            return None

        async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING) as pipe:
            with patch("builtins.open", side_effect=AssertionError("File access prohibited")), \
                    patch("pathlib.Path.open", side_effect=AssertionError("File access prohibited")), \
                    patch("socket.socket", side_effect=AssertionError("Network access prohibited")):
                result = await pipe.submit_json(json.dumps(native()).encode(), access()).wait()
            self.assertEqual(result.status, "completed")

    async def test_configuration_and_lifecycle_are_explicit(self):
        async def consume(_):
            return None

        for kwargs in [dict(input_limits=None, processing_limits=PROCESSING),
                       dict(input_limits=INPUT, processing_limits=None)]:
            with self.subTest(kwargs=kwargs), self.assertRaises(IngressError):
                ConversationIngress(consume, adapter=create_demo_adapter(), **kwargs)
        with self.assertRaises(IngressError):
            ConversationIngress(lambda _: None, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING)
        pipe = ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING)
        with self.assertRaises(IngressError):
            pipe.submit(native(), access())
        async with pipe:
            for context, room in [(access(), []), ({}, "toy-study"), (access(), "unauthorized")]:
                with self.subTest(room=room), self.assertRaises(IngressError):
                    pipe.acknowledge_failure(context, room)
        with self.assertRaises(IngressError):
            pipe.submit(native(), access())

    async def test_cancelling_close_still_settles_every_ticket(self):
        started = asyncio.Event()

        async def consume(_):
            started.set()
            await asyncio.Event().wait()

        pipe = ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING)
        await pipe.__aenter__()
        tickets = [pipe.submit(native(room), access()) for room in ("toy-study", "toy-garden")]
        await started.wait()
        closing = asyncio.create_task(pipe.__aexit__(None, None, None))
        await asyncio.sleep(0)
        closing.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(closing, 1)
        results = await asyncio.wait_for(asyncio.gather(*(x.wait() for x in tickets)), 1)
        self.assertTrue(all(x.status == "cancelled" for x in results))
        self.assertEqual(pipe.stats["pending"], 0)

    async def test_graceful_close_stops_new_admission_before_draining(self):
        gate, started = asyncio.Event(), asyncio.Event()

        async def consume(_):
            started.set()
            await gate.wait()

        pipe = ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING)
        await pipe.__aenter__()
        ticket = pipe.submit(native(), access())
        await started.wait()
        closing = asyncio.create_task(pipe.__aexit__(None, None, None))
        await asyncio.sleep(0)
        try:
            with self.assertRaises(IngressError) as caught:
                pipe.submit(native("toy-garden"), access())
            self.assertEqual(caught.exception.code, "not_open")
        finally:
            gate.set()
            await asyncio.wait_for(closing, 1)
        self.assertEqual((await ticket.wait()).status, "completed")


if __name__ == "__main__":
    unittest.main()
