"""Reader-boundary tests with independently authored originals and stub readers."""

import asyncio
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from safeguard.adapters.demo import create_demo_adapter
from unittest.mock import patch

from safeguard.adapters.gateways.demo import DemoGateway
from safeguard.original_assets import AssetKey, AssetLimits, LocalAssetStore
from safeguard.conversation_memory import ConversationKey, HistoryLimits, HistorySnapshot, InMemoryConversationMemory
from safeguard.scam_detection.context import ContextLimits, ContextPreparer
from safeguard.scam_detection.tools.evidence import (EvidenceError, EvidenceLimits, EvidenceLocation, EvidencePreparer,
    EvidenceSegment, PartReference, ReaderInput, ReaderOutput, ReaderSpec)
from safeguard.scam_detection.intake import DetectionIntake
from safeguard.ingress import AccessContext, ConversationIngress, InputLimits, ProcessingLimits
from safeguard.adapters.norm import normalize


INPUT = InputLimits(131072, 16384, 24, 16384, 64, 32)
CONTEXT_LIMITS = ContextLimits(64, 1048576, 1048576, 65536, 256, 128)
LIMITS = EvidenceLimits(1048576, 4096, 8, 4096, 32768, 256)
ACCESS = AccessContext("evidence-account", frozenset(("evidence-room", "evidence-garden")))
KEY = ConversationKey("demo", "evidence-account", "evidence-room")
ASSET = AssetKey("demo", "evidence-account", "evidence-room", "repeated-id", "toy-original")
SPEC = ReaderSpec("neutral-test-reader", "1.0", hashlib.sha256(b"{}").hexdigest(),
                  frozenset(("image", "audio", "video", "file")), frozenset(("whole_asset", "page", "time_range_ms")))
DATA = b"Independently authored neutral original.\n"
NOW = datetime(2026, 1, 6, tzinfo=timezone.utc)


def native(*, kind="file", status="unknown", room="evidence-room"):
    return dict(thread=room, id="repeated-id", author="evidence-reader",
                content_parts=[dict(kind="text", text="A fresh neutral note."),
                               dict(kind=kind, asset_id="toy-original"), dict(kind=kind, asset_id="toy-original")],
                assets=[dict(asset_id="toy-original", filename="source-name.txt", declared_media_type="unverified/example",
                             declared_size_bytes=999999, source_status=status)])


def make_context(*, kind="file", status="unknown", room="evidence-room", count=1):
    adapter = DemoGateway(account_id=ACCESS.account_id, clock=lambda: NOW)
    records = tuple(normalize(adapter.receive(native(kind=kind, status=status, room=room))) for _ in range(count))
    key = replace(KEY, conversation_id=room)
    return ContextPreparer(message_limits=INPUT, limits=CONTEXT_LIMITS).prepare(HistorySnapshot(key, count, records), ACCESS)


def output(text="A neutral stub extraction.", location=None):
    return ReaderOutput((EvidenceSegment(text, location or EvidenceLocation("whole_asset")),))


class EvidenceBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.parent = tempfile.TemporaryDirectory()
        self.addCleanup(self.parent.cleanup)
        self.store = LocalAssetStore(parent=self.parent.name, limits=AssetLimits(16384, 131072, 32, 131072, 32, 64))
        self.store.__enter__()
        self.addCleanup(self.store.close)
        self.bridge = EvidencePreparer(store=self.store, limits=LIMITS)

    def put(self, key=ASSET, data=DATA):
        return self.store.put(ACCESS, key, io.BytesIO(data))

    def process(self, *, prepared=None, ref=None, spec=SPEC, reader=None, access=ACCESS, expected=None, limits=LIMITS):
        bridge = self.bridge if limits == LIMITS else EvidencePreparer(store=self.store, limits=limits)
        return bridge.process(prepared or make_context(), access, ref or PartReference(1, 1), spec=spec,
                              reader=reader or (lambda request: output()), expected_original=expected)

    def rejected(self, action, code):
        with self.assertRaises(EvidenceError) as caught:
            action()
        self.assertEqual((caught.exception.code, str(caught.exception)), (code, code))

    def test_each_kind_reads_exact_scoped_bytes_and_produces_anchored_immutable_evidence(self):
        receipt = self.put()
        for kind in ("image", "audio", "video", "file"):
            with self.subTest(kind=kind):
                context = make_context(kind=kind)
                seen = []

                def reader(request):
                    self.assertIs(type(request), ReaderInput)
                    self.assertEqual({f.name for f in fields(request)}, {"kind", "data", "filename", "declared_media_type"})
                    self.assertEqual((request.kind, request.data), (kind, DATA))
                    self.assertEqual(request.declared_media_type, "unverified/example")
                    self.assertEqual(request.filename, "source-name.txt")
                    seen.append(request)
                    return output(DATA.hex())

                result = self.process(prepared=context, reader=reader, expected=receipt)
                self.assertEqual((result.status, result.code), ("extracted", "ok"))
                self.assertEqual(result.original, receipt)
                self.assertEqual(result.context_sha256, hashlib.sha256(context.json_bytes).hexdigest())
                self.assertEqual(result.segments[0].text, DATA.hex())
                view = result.to_dict()
                self.assertEqual(view["observed_count"], 1)
                self.assertEqual(view["source_ref"], dict(observation_number=1, part_index=1))
                self.assertEqual(view["original"], dict(size_bytes=len(DATA), sha256=hashlib.sha256(DATA).hexdigest()))
                self.assertEqual(view["reader"]["configuration_sha256"], SPEC.configuration_sha256)
                view["segments"][0]["text"] = "Receiver edit"
                self.assertEqual(result.to_dict()["segments"][0]["text"], DATA.hex())
                with self.assertRaises(FrozenInstanceError):
                    result.status = "changed"
                with self.assertRaises(FrozenInstanceError):
                    seen[0].data = b"changed"
                self.assertEqual(self.store.read(ACCESS, ASSET), DATA)

    def test_source_status_and_declared_size_do_not_override_actual_original_facts(self):
        self.put()
        for status in ("unknown", "available", "pending", "unavailable", "failed"):
            with self.subTest(status=status):
                context = make_context(status=status)
                before = context.json_bytes
                result = self.process(prepared=context)
                self.assertEqual(result.status, "extracted")
                self.assertEqual(result.original.size_bytes, len(DATA))
                self.assertEqual(context.json_bytes, before)
                self.assertEqual(context.to_dict()["messages"][0]["assets"][0]["source_status"], status)

    def test_repeated_native_ids_and_repeated_parts_keep_distinct_anchors(self):
        self.put()
        context = make_context(count=2)
        results = [self.process(prepared=context, ref=PartReference(n, p)) for n in (1, 2) for p in (1, 2)]
        self.assertEqual(len({r.source_ref for r in results}), 4)
        self.assertEqual(len({r.context_sha256 for r in results}), 1)
        self.assertTrue(all(r.asset_key == ASSET and r.status == "extracted" for r in results))

    def test_scope_and_invalid_positions_reject_before_original_access(self):
        with patch.object(self.store, "describe", side_effect=AssertionError("No original access")):
            for access in (AccessContext("different-account", ACCESS.conversations), AccessContext(ACCESS.account_id, frozenset())):
                with self.subTest(access=access):
                    self.rejected(lambda: self.process(access=access), "conversation_not_allowed")
            self.rejected(lambda: self.process(access={}), "trusted_context_required")
            self.rejected(lambda: self.process(ref=PartReference(2, 1)), "invalid_reference")
            self.rejected(lambda: self.process(ref=PartReference(1, 9)), "invalid_reference")
            self.rejected(lambda: self.process(ref=PartReference(1, 0)), "attachment_required")

    def test_part_reference_requires_exact_integer_positions(self):
        for number, index in ((0, 0), (-1, 0), (True, 0), (1, True), (1, -1), (1.0, 0)):
            with self.subTest(number=number, index=index):
                self.rejected(lambda: PartReference(number, index), "invalid_reference")

    def test_unsupported_kind_and_missing_original_do_not_call_reader(self):
        def forbidden(request):
            self.fail("Reader must not run")
        with patch.object(self.store, "describe", side_effect=AssertionError("Unsupported must precede original IO")):
            result = self.process(spec=replace(SPEC, supported_kinds=frozenset(("audio",))), reader=forbidden)
            self.assertEqual((result.status, result.code, result.original, result.segments), ("unsupported", "unsupported_kind", None, ()))
        result = self.process(reader=forbidden)
        self.assertEqual((result.status, result.code, result.segments), ("unavailable", "original_unavailable", ()))

    def test_actual_original_byte_limit_checks_before_reading(self):
        self.put()
        exact = replace(LIMITS, max_original_bytes=len(DATA))
        self.assertEqual(self.process(limits=exact).status, "extracted")
        with patch.object(self.store, "read", side_effect=AssertionError("Oversize must precede read")):
            result = self.process(limits=replace(exact, max_original_bytes=len(DATA) - 1))
        self.assertEqual((result.status, result.code), ("limited", "original_byte_limit"))

    def test_expected_original_detects_replacement_before_processing(self):
        receipt = self.put()
        self.store.delete(ACCESS, ASSET)
        self.put(data=b"Different neutral original.")
        with patch.object(self.store, "read", side_effect=AssertionError("Stale binding must precede read")):
            result = self.process(expected=receipt)
        self.assertEqual((result.status, result.code, result.segments), ("failed", "original_changed", ()))
        self.rejected(lambda: self.process(expected=replace(receipt, key=replace(ASSET, message_id="another-id"))), "invalid_original_binding")

    def test_replacement_between_describe_and_read_is_rejected_before_reader(self):
        self.put()
        actual_read = self.store.read

        def changed(access, key):
            self.store.delete(access, key)
            self.put(data=b"A replacement during the test.")
            return actual_read(access, key)

        with patch.object(self.store, "read", side_effect=changed):
            result = self.process(reader=lambda request: self.fail("Changed original must not reach reader"))
        self.assertEqual((result.status, result.code), ("failed", "original_changed"))

    def test_corrupt_and_physically_missing_originals_are_explicit(self):
        self.put()
        original_path = self.store._directory / self.store._entries[ASSET][0]
        original_path.chmod(0o600)
        original_path.write_bytes(b"X" * len(DATA))
        result = self.process(reader=lambda request: self.fail("Corrupt original must not reach reader"))
        self.assertEqual((result.status, result.code), ("failed", "original_integrity_failed"))
        original_path.unlink()
        result = self.process()
        self.assertEqual((result.status, result.code), ("unavailable", "original_unavailable"))

    def test_closed_store_and_callback_errors_do_not_leak_private_details(self):
        self.put()

        def failed(request):
            raise RuntimeError("PRIVATE_READER_VALUE /private/source/path")

        result = self.process(reader=failed)
        self.assertEqual((result.status, result.code), ("failed", "reader_failed"))
        self.assertNotIn(b"PRIVATE_READER_VALUE", result.json_bytes)
        self.assertNotIn(b"/private/source/path", result.json_bytes)
        self.assertEqual(self.store.read(ACCESS, ASSET), DATA)
        self.store.close()
        result = self.process()
        self.assertEqual((result.status, result.code), ("failed", "original_unreadable"))

    def test_control_exceptions_propagate_without_deleting_original(self):
        self.put()

        def cancelled(request):
            raise asyncio.CancelledError()

        with self.assertRaises(asyncio.CancelledError):
            self.process(reader=cancelled)
        self.assertEqual(self.store.read(ACCESS, ASSET), DATA)

    def test_empty_extraction_is_distinct_from_successful_text_and_failure(self):
        self.put()
        result = self.process(reader=lambda request: ReaderOutput(()))
        self.assertEqual((result.status, result.code, result.segments), ("empty", "no_content_extracted", ()))
        self.assertNotIn("assessment", result.to_dict())

    def test_invalid_reader_outputs_are_not_partially_accepted(self):
        self.put()
        values = [None, {}, ReaderOutput([]), ReaderOutput((object(),)), output(""), output("\ud800"),
                  ReaderOutput((EvidenceSegment("Valid first segment", EvidenceLocation("whole_asset")), object()))]
        for value in values:
            with self.subTest(value=type(value)):
                result = self.process(reader=lambda request: value)
                self.assertEqual((result.status, result.code, result.segments), ("failed", "invalid_reader_output", ()))

    def test_location_shape_kind_and_reader_declared_capabilities_are_checked(self):
        self.put()
        for kind, good in (("file", EvidenceLocation("page", page=1)), ("image", EvidenceLocation("page", page=2)),
                           ("audio", EvidenceLocation("time_range_ms", start_ms=0, end_ms=100)),
                           ("video", EvidenceLocation("time_range_ms", start_ms=10, end_ms=20))):
            with self.subTest(kind=kind):
                self.assertEqual(self.process(prepared=make_context(kind=kind), reader=lambda request: output(location=good)).status, "extracted")
        invalid = [EvidenceLocation("page", page=0), EvidenceLocation("page", page=True),
                   EvidenceLocation("page", page=1, start_ms=0), EvidenceLocation("whole_asset", page=1),
                   EvidenceLocation("time_range_ms", start_ms=0, end_ms=0), EvidenceLocation("unknown"), None]
        for location in invalid:
            with self.subTest(location=location):
                result = self.process(reader=lambda request: ReaderOutput((EvidenceSegment("Neutral text", location),)))
                self.assertEqual((result.status, result.code, result.segments), ("failed", "invalid_location", ()))
        result = self.process(spec=replace(SPEC, location_kinds=frozenset(("whole_asset",))),
                              reader=lambda request: output(location=EvidenceLocation("page", page=1)))
        self.assertEqual(result.code, "invalid_location")
        result = self.process(prepared=make_context(kind="audio"), reader=lambda request: output(location=EvidenceLocation("page", page=1)))
        self.assertEqual(result.code, "invalid_location")

    def test_segment_text_and_result_byte_limits_have_no_partial_success(self):
        self.put()
        two = ReaderOutput((EvidenceSegment("á🙂", EvidenceLocation("whole_asset")),) * 2)
        self.assertEqual(self.process(reader=lambda request: two, limits=replace(LIMITS, max_segments=2, max_text_chars=4)).status, "extracted")
        for limits, code in ((replace(LIMITS, max_segments=1), "segment_limit"), (replace(LIMITS, max_text_chars=3), "text_limit")):
            with self.subTest(code=code):
                result = self.process(reader=lambda request: two, limits=limits)
                self.assertEqual((result.status, result.code, result.segments), ("limited", code, ()))
        large = lambda request: output("A" * 2048)
        baseline = self.process(reader=large)
        exact = replace(LIMITS, max_result_bytes=len(baseline.json_bytes))
        self.assertEqual(self.process(reader=large, limits=exact).json_bytes, baseline.json_bytes)
        result = self.process(reader=large, limits=replace(exact, max_result_bytes=len(baseline.json_bytes) - 1))
        self.assertEqual((result.status, result.code, result.segments), ("limited", "result_byte_limit", ()))
        self.rejected(lambda: self.process(limits=replace(LIMITS, max_result_bytes=1)), "result_byte_limit")

    def test_context_size_and_malformed_contexts_reject_before_storage(self):
        context = make_context()
        with patch.object(self.store, "describe", side_effect=AssertionError("No storage access")):
            self.rejected(lambda: self.process(prepared=context, limits=replace(LIMITS, max_context_bytes=len(context.json_bytes) - 1)), "context_byte_limit")
            values = [replace(context, observed_count=2), replace(context, json_bytes=b"{}"),
                      replace(context, json_bytes=b"["), replace(context, key=replace(KEY, conversation_id="evidence-garden"))]
            for value in values:
                with self.subTest(value=value.observed_count):
                    self.rejected(lambda: self.process(prepared=value), "invalid_context")
        self.assertEqual(self.process(prepared=context, limits=replace(LIMITS, max_context_bytes=len(context.json_bytes))).status, "unavailable")

    def test_configuration_validation_and_reader_metadata_limits(self):
        for item in fields(LIMITS):
            for value in (0, -1, True, 1.5, None):
                with self.subTest(field=item.name, value=value), self.assertRaises(ValueError):
                    replace(LIMITS, **{item.name: value})
        invalid = [dict(name=""), dict(version=None), dict(configuration_sha256="X" * 64),
                   dict(supported_kinds=frozenset(("text",))), dict(supported_kinds=set(("file",))),
                   dict(location_kinds=frozenset(("line",)))]
        for changes in invalid:
            with self.subTest(changes=changes):
                self.rejected(lambda: replace(SPEC, **changes), "invalid_reader_spec")
        self.rejected(lambda: EvidencePreparer(store=None, limits=LIMITS), "invalid_configuration")
        self.rejected(lambda: self.process(spec=replace(SPEC, name="a" * 300)), "reader_metadata_limit")
        self.rejected(lambda: self.process(spec=replace(SPEC, name="\ud800")), "invalid_reader_spec")

    def test_async_readers_are_rejected_without_running_them(self):
        async def reader(request):
            self.fail("Async reader must not run")
        self.rejected(lambda: self.process(reader=reader), "invalid_reader")
        self.put()
        result = self.process(reader=lambda request: reader(request))
        self.assertEqual(result.code, "invalid_reader_output")


class EvidenceIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_input_store_context_and_reader_handoff_retains_history_on_reader_failure(self):
        with tempfile.TemporaryDirectory() as parent, \
                LocalAssetStore(parent=parent, limits=AssetLimits(4096, 16384, 8, 16384, 8, 64)) as store, \
                InMemoryConversationMemory(message_limits=INPUT, limits=HistoryLimits(8, 16, 1048576, 16, 1048576, 16, 1048576)) as history:
            preparer = ContextPreparer(message_limits=INPUT, limits=CONTEXT_LIMITS)
            bridge = EvidencePreparer(store=store, limits=LIMITS)
            results = []

            def stub(request):
                self.assertEqual(request.data, DATA)
                return output(request.data.hex())

            async def consumer(value):
                context = preparer.prepare(value, ACCESS)
                reader = stub if value.key.conversation_id == "evidence-room" else lambda request: (_ for _ in ()).throw(RuntimeError("PRIVATE_FAILURE"))
                results.append(bridge.process(context, ACCESS, PartReference(1, 1), spec=SPEC, reader=reader))

            async with ConversationIngress(consumer, adapter=create_demo_adapter(), input_limits=INPUT,
                    processing_limits=ProcessingLimits(2, 8, 1048576, 8, 8, 2.), intake=DetectionIntake(history)) as pipe:
                tickets = [pipe.submit_files(native(room=room), {"toy-original": io.BytesIO(DATA)}, ACCESS, store=store)
                           for room in ("evidence-room", "evidence-garden")]
                outcomes = await asyncio.gather(*(ticket.wait() for ticket in tickets))
            self.assertTrue(all(item.status == "completed" for item in outcomes))
            self.assertEqual({(r.asset_key.conversation_id, r.status) for r in results},
                             {("evidence-room", "extracted"), ("evidence-garden", "failed")})
            self.assertEqual(history.stats["messages"], 2)
            self.assertEqual(store.stats["files"], 2)
            self.assertEqual(store.read(ACCESS, ASSET), DATA)
            # A completed consumer is not proof of successful extraction/assessment.
            self.assertEqual(next(r for r in results if r.status == "failed").segments, ())
