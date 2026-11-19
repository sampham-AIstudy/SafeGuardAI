"""Real original-byte handoff using newly authored neutral files only."""

import io
from contextlib import ExitStack
from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
import unittest

from safeguard.adapters.demo import create_demo_adapter

from safeguard.memory.original_assets import AssetError, AssetKey, AssetLimits, LocalAssetStore
from safeguard.ingress import AccessContext, ConversationIngress, IngressError, InputLimits, ProcessingLimits

INPUT = InputLimits(65536, 4096, 16, 4096, 16, 8)
PROCESSING = ProcessingLimits(1, 8, 65536, 8, 8, 1.)
LIMITS = AssetLimits(4096, 16384, 8, 16384, 8, 64)
CONTEXT = AccessContext("toy-account", frozenset(("toy-room", "toy-garden")))


def native(message="toy-note"):
    return {"thread": "toy-room", "id": message, "author": "toy-reader",
            "content_parts": [{"kind": "file", "asset_id": "toy-document"}],
            "assets": [{"asset_id": "toy-document", "filename": "toy-list.txt"}]}


class RecordingReader(io.BytesIO):
    reads = 0
    def read(self, n):
        self.reads += 1
        return super().read(n)


class FileIngressTests(unittest.IsolatedAsyncioTestCase):
    async def test_self_created_files_of_all_declared_kinds_and_mixed_message(self):
        received = []
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent, limits=LIMITS) as store:
            event = native()
            event["content_parts"] = [{"kind": "text", "text": "  Toy attachments\n"}]
            event["assets"] = []
            expected = {}
            with ExitStack() as stack:
                uploads = {}
                for kind in ("image", "audio", "video", "file"):
                    # This tests original bytes, not whether bytes decode as a media format.
                    asset_id = "toy-"+kind
                    data = ("Newly authored toy "+kind+" bytes.\n").encode()+b"\x00\xff"
                    expected[asset_id] = data
                    path = Path(parent)/(kind+".bin");path.write_bytes(data)
                    uploads[asset_id] = stack.enter_context(path.open("rb"))
                    event["content_parts"].append({"kind": kind, "asset_id": asset_id})
                    event["assets"].append({"asset_id": asset_id, "filename": "../../"+kind+".bin",
                                            "declared_size_bytes": 1, "source_status": "pending"})
                async def consume(message):
                    received.append(message)
                    for asset in message["assets"]:
                        identity = AssetKey.from_message(message, asset["asset_id"])
                        self.assertEqual(store.read(CONTEXT, identity), expected[asset["asset_id"]])
                        receipt = store.describe(CONTEXT, identity)
                        self.assertEqual(receipt.size_bytes, len(expected[asset["asset_id"]]))
                        self.assertEqual(receipt.sha256, hashlib.sha256(expected[asset["asset_id"]]).hexdigest())
                        self.assertEqual(asset["declared_size_bytes"], 1)
                        self.assertEqual(asset["source_status"], "pending")
                        self.assertEqual(asset["processing_status"], "not_requested")
                async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING) as pipe:
                    outcome = await pipe.submit_files(event, uploads, CONTEXT, store=store).wait()
                    self.assertEqual(outcome.status, "completed")
                self.assertTrue(all(not stream.closed for stream in uploads.values()))
            self.assertEqual(received[0]["content_parts"], event["content_parts"])

    async def test_metadata_permissions_capacity_and_matching_reject_before_source_read(self):
        async def consume(message):
            pass
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent, limits=LIMITS) as store:
            async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=replace(PROCESSING, max_pending=1)) as pipe:
                for fault, stage, code in (("permissions", "authorization", "conversation_not_allowed"),
                                           ("metadata", "gateway", "invalid_message"),
                                           ("time", "normalizer", "invalid_message"),
                                           ("matching", "assets", "upload_reference_mismatch")):
                    with self.subTest(fault=fault):
                        event, context, reader = native(), CONTEXT, RecordingReader(b"Toy")
                        uploads = {"toy-document": reader}
                        if fault == "permissions": context = AccessContext("toy-account", frozenset())
                        if fault == "metadata": event["content_parts"][0]["kind"] = "unsupported"
                        if fault == "time": event["sent_at"] = "invalid"
                        if fault == "matching": uploads = {"toy-wrong": reader}
                        with self.assertRaises(IngressError) as caught:
                            pipe.submit_files(event, uploads, context, store=store)
                        self.assertEqual((caught.exception.stage, caught.exception.code), (stage, code))
                        self.assertEqual(reader.reads, 0)
                        self.assertEqual(store.stats["files"], 0)
                ticket = pipe.submit_files(native(), {"toy-document": io.BytesIO(b"Toy")}, CONTEXT, store=store)
                reader = RecordingReader(b"Other")
                with self.assertRaises(IngressError) as caught:
                    pipe.submit_files(native("second"), {"toy-document": reader}, CONTEXT, store=store)
                self.assertEqual(caught.exception.code, "busy")
                self.assertEqual(reader.reads, 0)
                await ticket.wait()

    async def test_failed_batch_leaves_no_admitted_message_or_partial_files(self):
        class FailedReader:
            def read(self, n): raise RuntimeError("PRIVATE_UPLOAD_ERROR")
        async def consume(message): self.fail("Failed upload was admitted")
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent, limits=LIMITS) as store:
            async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING) as pipe:
                event = native()
                event["content_parts"].append({"kind": "audio", "asset_id": "toy-audio"})
                event["assets"].append({"asset_id": "toy-audio"})
                with self.assertLogs("safeguard.ingress", level="INFO") as logs, self.assertRaises(IngressError) as caught:
                    pipe.submit_files(event, {"toy-document": io.BytesIO(b"Toy"), "toy-audio": FailedReader()}, CONTEXT, store=store)
                self.assertEqual(caught.exception.code, "source_failed")
                self.assertNotIn("PRIVATE", str(caught.exception)+"\n".join(logs.output))
                self.assertEqual(pipe.stats["admitted"], 0)
                self.assertEqual(store.stats["files"], 0)
                self.assertEqual(list(store._directory.iterdir()), [])

    async def test_consumer_failure_retains_original_until_explicit_delete(self):
        async def consume(message): raise RuntimeError("PRIVATE_CONSUMER_ERROR")
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent, limits=LIMITS) as store:
            with self.assertRaises(IngressError):
                async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING) as pipe:
                    outcome = await pipe.submit_files(native(), {"toy-document": io.BytesIO(b"Keep")}, CONTEXT, store=store).wait()
                    self.assertEqual(outcome.status, "failed")
            identity = AssetKey("demo", "toy-account", "toy-room", "toy-note", "toy-document")
            self.assertEqual(store.read(CONTEXT, identity), b"Keep")
            store.delete(CONTEXT, identity)
            self.assertEqual(store.stats["files"], 0)

    async def test_store_scope_conflict_and_quota_failure_do_not_admit(self):
        async def consume(message): pass
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent, limits=replace(LIMITS, max_file_bytes=3)) as store:
            async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=INPUT, processing_limits=PROCESSING) as pipe:
                with self.assertRaises(IngressError) as caught:
                    pipe.submit_files(native(), {"toy-document": io.BytesIO(b"Too much")}, CONTEXT, store=store)
                self.assertEqual(caught.exception.code, "file_byte_limit")
                first = await pipe.submit_files(native(), {"toy-document": io.BytesIO(b"Toy")}, CONTEXT, store=store).wait()
                self.assertEqual(first.status, "completed")
                reader = RecordingReader(b"New")
                with self.assertRaises(IngressError) as caught:
                    pipe.submit_files(native(), {"toy-document": reader}, CONTEXT, store=store)
                self.assertEqual(caught.exception.code, "asset_exists")
                self.assertEqual(reader.reads, 0)
                event = native();event["thread"] = "toy-garden"
                second = await pipe.submit_files(event, {"toy-document": io.BytesIO(b"New")}, CONTEXT, store=store).wait()
                self.assertEqual(second.status, "completed")
                self.assertEqual(store.stats["files"], 2)

    async def test_file_entry_requires_a_store_and_uploads(self):
        async def consume(message):
            self.fail("Invalid file entry reached consumer")
        async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=InputLimits(65536, 4096, 16, 4096, 16, 8),
                                       processing_limits=ProcessingLimits(1, 8, 65536, 8, 8, 1.)) as pipe:
            with self.assertRaises(IngressError):
                pipe.submit_files({"thread": "toy-room", "id": "toy-note", "author": "toy-reader", "body": "Toy"},
                                  None, AccessContext("toy-account", frozenset(("toy-room",))), store=None)

    async def test_original_bytes_can_be_retrieved_from_normalized_reference(self):
        # Capability check before implementation; the existing entry does not take streams.
        from safeguard.memory.original_assets import AssetKey, AssetLimits, LocalAssetStore
        data = b"Independently authored toy reading list.\n"
        context = AccessContext("toy-account", frozenset(("toy-room",)))
        native = {"thread": "toy-room", "id": "toy-note", "author": "toy-reader",
                  "content_parts": [{"kind": "file", "asset_id": "toy-document"}],
                  "assets": [{"asset_id": "toy-document", "filename": "toy-list.txt"}]}
        with tempfile.TemporaryDirectory() as parent:
            with LocalAssetStore(parent=parent, limits=AssetLimits(4096, 16384, 8, 16384, 8, 64)) as store:
                async def consume(message):
                    self.assertEqual(store.read(context, AssetKey.from_message(message, "toy-document")), data)
                async with ConversationIngress(consume, adapter=create_demo_adapter(), input_limits=InputLimits(65536, 4096, 16, 4096, 16, 8),
                                               processing_limits=ProcessingLimits(1, 8, 65536, 8, 8, 1.)) as pipe:
                    outcome = await pipe.submit_files(native, {"toy-document": io.BytesIO(data)}, context, store=store).wait()
                    self.assertEqual(outcome.status, "completed")


if __name__ == "__main__":
    unittest.main()
