"""New neutral input-contract fixtures; no benchmark or content-reader input."""

from copy import deepcopy
from datetime import datetime, timezone
from dataclasses import replace
import asyncio
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from safeguard.adapters.demo import create_demo_adapter
from unittest.mock import patch
import wave

from safeguard.adapters.gateways.demo import GatewayInputError, DemoGateway
from safeguard.ingress import AccessContext, ConversationIngress, IngressError, InputLimits, InputViolation, ProcessingLimits
from safeguard.adapters.norm import NormalizationError, normalize
from test_demo_gateway import VALIDATOR


def asset_event():
    return {
        "thread": "toy-reading-room", "id": "toy-attachment", "author": "toy-reader",
        "content_parts": [{"kind": "file", "asset_id": "toy-document"}],
        "assets": [{"asset_id": "toy-document", "filename": "reading-list.txt",
                    "declared_media_type": "text/plain", "declared_size_bytes": 12,
                    "source_status": "available"}],
    }


def convert(native):
    return normalize(DemoGateway("toy-account", clock=lambda: datetime(2026, 1, 2, tzinfo=timezone.utc)).receive(native))


class MessageAssetTests(unittest.TestCase):
    def reject_both(self, native, code):
        # Exercise independent entry paths, including bypassing the adapter.
        for boundary in ("adapter", "normalizer"):
            with self.subTest(boundary=boundary):
                with self.assertRaises((GatewayInputError, NormalizationError)) as caught:
                    if boundary == "adapter":
                        DemoGateway("toy-account").receive(native)
                    else:
                        event = DemoGateway("toy-account").receive({"thread": native["thread"],
                            "id": native["id"], "author": native["author"], "body": "Toy baseline"})
                        event["payload"] = native
                        normalize(event)
                self.assertEqual(caught.exception.code, code)

    def test_attachment_only_message_is_normalized_without_invented_text(self):
        native = asset_event()
        before = deepcopy(native)
        message = convert(native)
        self.assertEqual(message["message_schema_version"], "2.0")
        self.assertEqual(message["content_parts"], before["content_parts"])
        self.assertNotIn("text", message)
        self.assertEqual(message["assets"], [dict(before["assets"][0], processing_status="not_requested")])
        self.assertEqual(message["raw_payload"], before)
        self.assertEqual(native, before)

    def test_all_media_kinds_and_mixed_order_preserve_exact_content(self):
        native = asset_event()
        native["content_parts"] = [{"kind": "text", "text": "  Café\n"}]
        native["assets"] = []
        for kind in ("image", "audio", "video", "file"):
            native["content_parts"].extend([{"kind": kind, "asset_id": "toy-"+kind},
                                            {"kind": "text", "text": "Cafe\u0301\t"}])
            native["assets"].append({"asset_id": "toy-"+kind})
        event = DemoGateway("toy-account").receive(native)
        VALIDATOR.validate(event)
        result = normalize(event)
        self.assertEqual(result["content_parts"], native["content_parts"])
        self.assertTrue(all(a["filename"] is None and a["source_status"] == "unknown"
                            and a["processing_status"] == "not_requested" for a in result["assets"]))

    def test_legacy_text_becomes_one_exact_part(self):
        for text in (" \n ", "\x00", "Café", "Cafe\u0301"):
            with self.subTest(text=text):
                result = convert({"thread": "toy-room", "id": "toy-note", "author": "toy-reader", "body": text})
                self.assertEqual(result["content_parts"], [{"kind": "text", "text": text}])
                self.assertEqual(result["assets"], [])

    def test_text_only_parts_do_not_require_an_asset_catalog(self):
        native = asset_event()
        native["content_parts"] = [{"kind": "text", "text": "Toy note"}]
        del native["assets"]
        self.assertEqual(convert(native)["assets"], [])

    def test_reported_availability_is_not_extraction_or_byte_verification(self):
        for status in ("unknown", "available", "pending", "unavailable", "failed"):
            with self.subTest(status=status):
                native = asset_event()
                native["assets"][0]["source_status"] = status
                result = convert(native)
                self.assertEqual(result["assets"][0]["source_status"], status)
                self.assertEqual(result["assets"][0]["processing_status"], "not_requested")
                self.assertNotIn("evidence", result)
                self.assertNotIn("risk", result)

    def test_empty_and_ambiguous_content_is_rejected(self):
        native = asset_event()
        native["body"] = ""
        self.reject_both(native, "ambiguous_content")
        native["body"] = "Toy conflicting text"
        self.reject_both(native, "ambiguous_content")
        for parts in (None, {}, "Toy", [], [None]):
            with self.subTest(parts=parts):
                native = asset_event()
                native["content_parts"] = parts
                self.reject_both(native, "expected_part_object" if parts == [None] else "expected_nonempty_array")

    def test_unsupported_malformed_and_derived_parts_fail_explicitly(self):
        cases = [({"kind": "sticker"}, "unsupported_kind"), ({"kind": []}, "unsupported_kind"),
                 ({"kind": "text", "text": ""}, "invalid_part_value"),
                 ({"kind": "text", "text": None}, "invalid_part_value"),
                 ({"kind": "file", "asset_id": "  "}, "invalid_part_value"),
                 ({"kind": "file", "asset_id": 12}, "invalid_part_value"),
                 ({"kind": "text"}, "invalid_part_fields"),
                 ({"kind": "file", "asset_id": "toy-document", "url": "PRIVATE_URL_CANARY"}, "invalid_part_fields"),
                 ({"kind": "text", "text": "Toy OCR", "derived_from": "toy-document"}, "invalid_part_fields")]
        for part, code in cases:
            with self.subTest(code=code):
                native = asset_event()
                native["content_parts"] = [part]
                self.reject_both(native, code)

    def test_missing_duplicate_unreferenced_and_conflicting_assets(self):
        native = asset_event()
        del native["assets"]
        self.reject_both(native, "missing_asset_descriptor")
        native = asset_event()
        native["assets"].append(deepcopy(native["assets"][0]))
        self.reject_both(native, "duplicate_asset_id")
        native = asset_event()
        native["assets"].append({"asset_id": "toy-unreferenced"})
        self.reject_both(native, "unreferenced_asset")
        native = asset_event()
        native["content_parts"].append({"kind": "audio", "asset_id": "toy-document"})
        self.reject_both(native, "conflicting_asset_kind")

    def test_repeated_reference_with_same_kind_retains_part_order(self):
        native = asset_event()
        native["content_parts"] *= 2
        result = convert(native)
        self.assertEqual(result["content_parts"], native["content_parts"])
        self.assertEqual(len(result["assets"]), 1)

    def test_malformed_asset_metadata_and_fake_processing_cannot_be_promoted(self):
        cases = [("asset_id", "", "invalid_asset_id"), ("filename", [], "invalid_asset_metadata"),
                 ("declared_media_type", " ", "invalid_asset_metadata"),
                 ("declared_size_bytes", -1, "invalid_declared_size"),
                 ("declared_size_bytes", True, "invalid_declared_size"),
                 ("declared_size_bytes", 1.5, "invalid_declared_size"),
                 ("source_status", "processed", "invalid_source_status"),
                 ("source_status", None, "invalid_source_status"),
                 ("processing_status", "completed", "invalid_asset_fields"),
                 ("url", "PRIVATE_URL_CANARY", "invalid_asset_fields"),
                 ("data", "PRIVATE_BINARY_CANARY", "invalid_asset_fields")]
        for key, value, code in cases:
            with self.subTest(key=key, code=code):
                native = asset_event()
                native["assets"][0][key] = value
                self.reject_both(native, code)
        for assets in (None, {}, "Toy"):
            native = asset_event()
            native["assets"] = assets
            self.reject_both(native, "expected_array")

    def test_explicit_null_metadata_and_zero_size_remain_distinct_from_raw_absence(self):
        native = asset_event()
        native["assets"][0] = {"asset_id": "toy-document", "filename": None,
                               "declared_media_type": None, "declared_size_bytes": 0}
        result = convert(native)
        self.assertIsNone(result["assets"][0]["filename"])
        self.assertEqual(result["assets"][0]["declared_size_bytes"], 0)
        self.assertNotIn("source_status", result["raw_payload"]["assets"][0])

    def test_descriptors_are_detached_from_source_raw_payload_and_each_other(self):
        native = asset_event()
        before = deepcopy(native)
        first, second = convert(native), convert(native)
        first["assets"][0]["filename"] = "changed.txt"
        first["content_parts"][0]["asset_id"] = "changed"
        self.assertEqual(first["raw_payload"], before)
        self.assertEqual(second["raw_payload"], before)
        self.assertEqual(native, before)
        native["assets"][0]["filename"] = "source-change.txt"
        self.assertEqual(second["assets"][0]["filename"], "reading-list.txt")

    def test_errors_never_echo_private_keys_or_values(self):
        native = asset_event()
        native["assets"][0]["PRIVATE_KEY_CANARY"] = "PRIVATE_VALUE_CANARY"
        for operation in (lambda: DemoGateway("toy-account").receive(native),):
            with self.assertRaises(GatewayInputError) as caught:
                operation()
            self.assertNotIn("PRIVATE", str(caught.exception)+json.dumps(caught.exception.as_dict()))

    def test_asset_identifiers_and_names_are_never_used_as_paths_or_urls(self):
        native = asset_event()
        native["content_parts"][0]["asset_id"] = "https://invalid.example/toy"
        native["assets"][0]["asset_id"] = "https://invalid.example/toy"
        native["assets"][0]["filename"] = "../../toy.txt"
        with patch("builtins.open", side_effect=AssertionError("No file reader")), \
                patch("pathlib.Path.open", side_effect=AssertionError("No file reader")), \
                patch("socket.socket", side_effect=AssertionError("No network")):
            result = convert(native)
        self.assertEqual(result["assets"][0]["filename"], "../../toy.txt")

    def test_self_created_text_and_wave_files_remain_external_to_messages(self):
        audio = io.BytesIO()
        with wave.open(audio, "wb") as stream:
            stream.setparams((1, 2, 8000, 0, "NONE", "not compressed"))
            stream.writeframes(b"\x00\x00"*80)
        with tempfile.TemporaryDirectory() as folder:
            for name, data, kind, mime in [("toy-list.txt", b"Toy books.\n", "file", "text/plain"),
                                            ("toy-tone.wav", audio.getvalue(), "audio", "audio/wav")]:
                with self.subTest(kind=kind):
                    path = Path(folder)/name
                    path.write_bytes(data)
                    before = hashlib.sha256(path.read_bytes()).hexdigest()
                    native = asset_event()
                    native["content_parts"][0]["kind"] = kind
                    native["assets"][0].update(filename=name, declared_media_type=mime, declared_size_bytes=len(data))
                    result = convert(native)
                    self.assertEqual(result["assets"][0]["declared_size_bytes"], len(data))
                    self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)
                    self.assertNotIn("data", result["assets"][0])
                    self.assertNotIn("transcript", result)


INPUT = InputLimits(65536, 100, 16, 4096, 16, 8)
PROCESSING = ProcessingLimits(2, 16, 262144, 16, 16, 1.0)
ACCESS = AccessContext("toy-account", frozenset(("toy-reading-room", "toy-garden")))


class RichInputLimitTests(unittest.TestCase):
    def test_text_limit_is_aggregate_across_all_parts(self):
        native = {"content_parts": [{"kind": "text", "text": "Book"}, {"kind": "text", "text": "Desk"}]}
        replace(INPUT, max_text_chars=8).inspect(native)
        with self.assertRaises(InputViolation) as caught:
            replace(INPUT, max_text_chars=7).inspect(native)
        self.assertEqual(caught.exception.code, "text_too_long")

    def test_part_and_asset_limits_and_boundaries(self):
        native = asset_event()
        replace(INPUT, max_content_parts=1, max_assets=1).inspect(native)
        for field, key, code in (("max_content_parts", "content_parts", "too_many_content_parts"),
                                 ("max_assets", "assets", "too_many_assets")):
            with self.subTest(field=field):
                native = asset_event()
                native[key] *= 2
                with self.assertRaises(InputViolation) as caught:
                    replace(INPUT, **{field: 1}).inspect(native)
                self.assertEqual(caught.exception.code, code)


class RichIngressTests(unittest.IsolatedAsyncioTestCase):
    async def test_native_json_mixed_media_fifo_and_mutation_isolation(self):
        received = []
        async def consume(message):
            await asyncio.sleep(0)
            received.append(message)
        async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING) as pipe:
            tickets = []
            for i, kind in enumerate(("image", "audio", "video", "file")):
                native = asset_event()
                native["id"] = str(i)
                native["content_parts"][0]["kind"] = kind
                native["content_parts"].append({"kind": "text", "text": "  Toy caption\n"})
                tickets.append(pipe.submit_json(json.dumps(native).encode(), ACCESS) if i % 2 else pipe.submit(native, ACCESS))
                native["assets"][0]["filename"] = "source-mutated"
            outcomes = await asyncio.gather(*(t.wait() for t in tickets))
        self.assertTrue(all(r.status == "completed" for r in outcomes))
        self.assertEqual([m["message_id"] for m in received], ["0", "1", "2", "3"])
        self.assertEqual([m["content_parts"][0]["kind"] for m in received], ["image", "audio", "video", "file"])
        self.assertTrue(all(m["assets"][0]["filename"] == "reading-list.txt" for m in received))

    async def test_references_remain_scoped_across_accounts_and_conversations(self):
        received = []
        async def consume(message):
            received.append(message)
        async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING) as pipe:
            tickets = []
            for account in ("toy-account", "toy-other-account"):
                for room in ("toy-reading-room", "toy-garden"):
                    native = asset_event()
                    native["thread"] = room
                    native["assets"][0]["filename"] = account+room
                    tickets.append(pipe.submit(native, AccessContext(account, frozenset((room,)))))
            await asyncio.gather(*(t.wait() for t in tickets))
        self.assertEqual(len(received), 4)
        for m in received:
            self.assertEqual(m["assets"][0]["filename"], m["account_id"]+m["conversation_id"])
            self.assertEqual(m["assets"][0]["asset_id"], "toy-document")

    async def test_unauthorized_rich_message_never_reaches_consumer(self):
        async def consume(message):
            self.fail("Rejected input reached consumer")
        async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING) as pipe:
            native = asset_event()
            native["account_id"] = "spoofed-account"
            with self.assertRaises(IngressError) as caught:
                pipe.submit(native, AccessContext("toy-account", frozenset()))
            self.assertEqual(caught.exception.code, "conversation_not_allowed")
            self.assertEqual(pipe.stats["admitted"], 0)

    async def test_malformed_or_over_limit_rich_message_is_explicitly_rejected(self):
        async def consume(message):
            self.fail("Rejected input reached consumer")
        async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=replace(INPUT, max_content_parts=1), processing_limits=PROCESSING) as pipe:
            for case, stage, code in (("limit", "input", "too_many_content_parts"),
                                       ("dangling", "gateway", "invalid_message")):
                native = asset_event()
                if case == "limit":
                    native["content_parts"] *= 2
                else:
                    native["assets"] = []
                with self.assertRaises(IngressError) as caught:
                    pipe.submit(native, ACCESS)
                self.assertEqual((caught.exception.stage, caught.exception.code), (stage, code))
            self.assertEqual(pipe.stats["admitted"], 0)

    async def test_logs_do_not_contain_asset_metadata_or_caption(self):
        async def consume(message):
            raise RuntimeError("PRIVATE_READER_ERROR")
        native = asset_event()
        native["assets"][0]["filename"] = "PRIVATE_FILENAME_CANARY"
        native["content_parts"].append({"kind": "text", "text": "PRIVATE_CAPTION_CANARY"})
        with self.assertLogs("safeguard.ingress", level="INFO") as logs:
            with self.assertRaises(IngressError):
                async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING) as pipe:
                    await pipe.submit(native, ACCESS).wait()
        self.assertNotIn("PRIVATE", "\n".join(logs.output))


if __name__ == "__main__":
    unittest.main()
