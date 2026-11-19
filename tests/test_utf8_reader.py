"""UTF-8 decoder/evidence checks with independent text originals."""

import asyncio
from dataclasses import FrozenInstanceError, replace
import hashlib
import io
import json
import tempfile
import unittest
from unittest.mock import patch

import test_evidence_boundary as fixtures
from safeguard.adapters.demo import create_demo_adapter
from safeguard.detection.tools.evidence import (
    EvidenceError, EvidenceLimits, EvidencePreparer, PartReference, ReaderInput, ReaderRejection,
)
from safeguard.detection.tools.readers import Utf8TextReader
from safeguard.memory.original_assets import AssetKey, AssetLimits, LocalAssetStore


TEXT = "\ufeffHồ sơ thư viện độc lập.\r\nDòng a\u0301 và hình 🙂.\n  Kết thúc\t"
READER = Utf8TextReader(8192, 4096)
LIMITS = EvidenceLimits(1048576, 8192, 4, 8192, 65536, 256)


def populate_text_file(intake, store, *, access, room, now, data):
    native = dict(thread=room, id="independent-utf8-file", author="independent-text-author",
        content_parts=[dict(kind="file", asset_id="text-original")],
        assets=[dict(asset_id="text-original", filename="untrusted-name.bin",
                     declared_media_type="application/incorrect-claim", declared_size_bytes=999999)])
    message = create_demo_adapter(clock=lambda: now).receive(native,
        account_id=access.account_id, conversation_id=room)
    request = intake.record(message, access)
    key = AssetKey("demo", access.account_id, room, native["id"], "text-original")
    return request, store.put(access, key, io.BytesIO(data))


class Utf8ReaderTests(unittest.TestCase):
    def test_decodes_exact_original_text(self):
        for text in (TEXT, "", " \t\r\n", "\ufeff", "<note>Raw UTF-8 syntax.</note>"):
            with self.subTest(text=text):
                output = READER(ReaderInput("file", text.encode("utf-8"), None, None))
                self.assertEqual(tuple(segment.text for segment in output.segments), (text,) if text else ())
                if text:
                    self.assertEqual(output.segments[0].text.encode("utf-8"), text.encode("utf-8"))
                    self.assertEqual(output.segments[0].location.kind, "whole_asset")

    def test_exact_input_and_code_point_limits_without_partial_text(self):
        text = "á🙂a\u0301"
        data = text.encode("utf-8")
        exact = Utf8TextReader(len(data), len(text))
        self.assertEqual(exact(ReaderInput("file", data, None, None)).segments[0].text, text)
        for reader, raw, code in ((replace(exact, max_input_bytes=len(data) - 1), data, "input_byte_limit"),
                                  (replace(exact, max_text_chars=len(text) - 1), data, "text_limit"),
                                  (Utf8TextReader(3, 100), b"\xff" * 4, "input_byte_limit")):
            with self.subTest(code=code), self.assertRaises(ReaderRejection) as caught:
                reader(ReaderInput("file", raw, None, None))
            self.assertEqual(caught.exception.code, code)

    def test_invalid_encoding_nul_and_non_file_kinds_are_explicit(self):
        for raw in (b"\xff", b"\xc0\x80", b"\xed\xa0\x80", b"\xe1\xba"):
            with self.subTest(raw=raw), self.assertRaises(ReaderRejection) as caught:
                READER(ReaderInput("file", raw, None, None))
            self.assertEqual(caught.exception.code, "unsupported_encoding")
        for raw in (b"\0", b"visible\0tail", b"A\0B\0"):
            with self.subTest(raw=raw), self.assertRaises(ReaderRejection) as caught:
                READER(ReaderInput("file", raw, None, None))
            self.assertEqual(caught.exception.code, "nul_content")
        for kind in ("image", "audio", "video", "text", None):
            with self.subTest(kind=kind), self.assertRaises(ReaderRejection) as caught:
                READER(ReaderInput(kind, b"plain", None, None))
            self.assertEqual(caught.exception.code, "unsupported_kind")

    def test_malformed_callback_input_is_a_fixed_programmer_error(self):
        for request in (object(), {}, ReaderInput("file", bytearray(b"text"), None, None),
                        ReaderInput("file", "text", None, None), ReaderInput("file", memoryview(b"text"), None, None)):
            with self.subTest(kind=type(request)), self.assertRaises(ValueError) as caught:
                READER(request)
            self.assertIsNot(type(caught.exception), ReaderRejection)
            self.assertEqual(str(caught.exception), "invalid_utf8_reader_input")

    def test_configuration_is_immutable_and_spec_identity_tracks_limits(self):
        for value in (0, -1, True, 1.0, "4", None):
            for field in ("max_input_bytes", "max_text_chars"):
                with self.subTest(value=value, field=field), self.assertRaises(ValueError):
                    replace(READER, **{field: value})
        with self.assertRaises(FrozenInstanceError):
            READER.max_input_bytes = 1
        self.assertEqual(READER.spec, Utf8TextReader(8192, 4096).spec)
        self.assertEqual((READER.spec.name, READER.spec.version), ("utf8-text", "1.0"))
        self.assertEqual(READER.spec.supported_kinds, frozenset(("file",)))
        self.assertEqual(READER.spec.location_kinds, frozenset(("whole_asset",)))
        self.assertRegex(READER.spec.configuration_sha256, "^[0-9a-f]{64}$")
        for reader in (replace(READER, max_input_bytes=8191), replace(READER, max_text_chars=4095)):
            self.assertNotEqual(reader.spec.configuration_sha256, READER.spec.configuration_sha256)

    def test_filename_and_media_claims_are_data_without_io(self):
        with patch("builtins.open", side_effect=AssertionError("Reader must not open metadata")):
            output = READER(ReaderInput("file", TEXT.encode("utf-8"),
                "/untrusted/path/never-opened", "https://unselected.invalid/never-fetched"))
        self.assertEqual(output.segments[0].text, TEXT)


class Utf8EvidenceTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.store = self.enterContext(LocalAssetStore(parent=directory,
            limits=AssetLimits(16384, 131072, 16, 131072, 16, 64)))
        self.prepared = fixtures.make_context()
        self.receipt = None

    def put(self, data):
        if self.receipt is not None:
            self.store.delete(fixtures.ACCESS, fixtures.ASSET)
        self.receipt = self.store.put(fixtures.ACCESS, fixtures.ASSET, io.BytesIO(data))
        return self.receipt

    def process(self, *, reader=READER, limits=LIMITS, access=fixtures.ACCESS, ref=PartReference(1, 1)):
        return EvidencePreparer(store=self.store, limits=limits).process(self.prepared, access,
            ref, spec=READER.spec if not isinstance(reader, Utf8TextReader) else reader.spec,
            reader=reader, expected_original=self.receipt)

    def test_real_original_provenance_and_exact_text_are_bound_to_whole_asset(self):
        receipt = self.put(TEXT.encode("utf-8"))
        result = self.process()
        document = result.to_dict()
        self.assertEqual((result.status, result.code, result.original), ("extracted", "ok", receipt))
        self.assertEqual(document["source_ref"], dict(observation_number=1, part_index=1))
        self.assertEqual(document["asset_key"]["message_id"], fixtures.ASSET.message_id)
        self.assertEqual(document["context_sha256"], hashlib.sha256(self.prepared.json_bytes).hexdigest())
        self.assertEqual(document["original"], dict(size_bytes=len(TEXT.encode("utf-8")), sha256=hashlib.sha256(TEXT.encode("utf-8")).hexdigest()))
        self.assertEqual(document["reader"]["configuration_sha256"], READER.spec.configuration_sha256)
        self.assertEqual(document["segments"], [dict(text=TEXT, location=dict(kind="whole_asset"))])
        self.assertEqual(self.store.read(fixtures.ACCESS, fixtures.ASSET), TEXT.encode("utf-8"))

    def test_empty_and_whitespace_files_do_not_become_the_same_outcome(self):
        self.put(b"")
        result = self.process()
        self.assertEqual((result.status, result.code, result.segments), ("empty", "no_content_extracted", ()))
        self.put(b" \t\r\n")
        result = self.process()
        self.assertEqual((result.status, result.code), ("extracted", "ok"))
        self.assertEqual(result.segments[0].text, " \t\r\n")

    def test_actual_decoder_rejections_preserve_receipt_and_emit_no_partial_segments(self):
        for raw, reader, status, code in (
                (b"valid-prefix\xff", READER, "unsupported", "unsupported_encoding"),
                (b"valid-prefix\0tail", READER, "unsupported", "nul_content"),
                (b"four", Utf8TextReader(3, 100), "limited", "input_byte_limit"),
                ("á🙂a\u0301".encode("utf-8"), Utf8TextReader(100, 3), "limited", "text_limit")):
            with self.subTest(code=code):
                receipt = self.put(raw)
                result = self.process(reader=reader)
                self.assertEqual((result.status, result.code, result.segments, result.original), (status, code, (), receipt))
                self.assertEqual(result.to_dict()["segments"], [])

    def test_all_fixed_rejections_and_forged_state_are_sanitized(self):
        self.put(b"independent original")
        for code, status in (("unsupported_kind", "unsupported"), ("unsupported_encoding", "unsupported"),
                             ("nul_content", "unsupported"), ("input_byte_limit", "limited"), ("text_limit", "limited")):
            error = ReaderRejection(code)
            def reject(request, error=error):
                raise error
            with self.subTest(code=code):
                result = self.process(reader=reject)
                self.assertEqual((result.status, result.code, result.segments), (status, code, ()))
        for invalid in ("PRIVATE_UNKNOWN_CODE", None, [], True):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                ReaderRejection(invalid)
        errors = []
        for code in ("PRIVATE_UNKNOWN_CODE", None, [], True):
            error = ReaderRejection("text_limit")
            error.code = code
            errors.append(error)
        error = ReaderRejection("text_limit")
        del error.code
        errors.append(error)
        error = ReaderRejection("text_limit")
        error.args = ("PRIVATE_CALLBACK_MESSAGE",)
        errors.append(error)
        class RejectionSubclass(ReaderRejection):
            pass
        errors.append(RejectionSubclass("text_limit"))
        for error in errors:
            def reject(request, error=error):
                raise error
            with self.subTest(error_type=type(error)):
                result = self.process(reader=reject)
                self.assertEqual((result.status, result.code, result.segments), ("failed", "invalid_reader_output", ()))
                self.assertNotIn("PRIVATE_", result.json_bytes.decode("utf-8"))

    def test_exception_details_cannot_override_fixed_outcome(self):
        self.put(b"independent original")
        error = ReaderRejection("text_limit")
        error.status = "extracted"
        error.details = "PRIVATE_CALLBACK_DETAILS"
        def reject(request):
            raise error
        result = self.process(reader=reject)
        self.assertEqual((result.status, result.code, result.segments), ("limited", "text_limit", ()))
        self.assertNotIn("PRIVATE_", result.json_bytes.decode())

    def test_generic_exceptions_and_control_signals_retain_prior_behavior(self):
        self.put(b"independent original")
        def broken(request):
            raise RuntimeError("PRIVATE_LEGACY_EXCEPTION")
        result = self.process(reader=broken)
        self.assertEqual((result.status, result.code, result.segments), ("failed", "reader_failed", ()))
        self.assertNotIn("PRIVATE_", result.json_bytes.decode())
        for exception in (KeyboardInterrupt, SystemExit, asyncio.CancelledError):
            def signal(request):
                raise exception()
            with self.subTest(exception=exception), self.assertRaises(exception):
                self.process(reader=signal)
        self.assertEqual(self.store.read(fixtures.ACCESS, fixtures.ASSET), b"independent original")

    def test_rejections_still_obey_result_and_bridge_limits(self):
        self.put(b"unsupported-encoding\xff")
        with self.assertRaises(EvidenceError) as caught:
            self.process(limits=replace(LIMITS, max_result_bytes=1))
        self.assertEqual(caught.exception.code, "result_byte_limit")
        self.put(b"longer original")
        with patch.object(self.store, "read") as read:
            result = self.process(limits=replace(LIMITS, max_original_bytes=1))
        self.assertEqual((result.status, result.code), ("limited", "original_byte_limit"))
        read.assert_not_called()

    def test_foreign_scope_and_future_reference_precede_original_access(self):
        self.put(b"independent original")
        foreign = replace(fixtures.ACCESS, account_id="foreign-utf8-account")
        for access, ref in ((foreign, PartReference(1, 1)), (fixtures.ACCESS, PartReference(2, 1))):
            with self.subTest(access=access, ref=ref), patch.object(self.store, "read") as read, self.assertRaises(EvidenceError):
                self.process(access=access, ref=ref)
            read.assert_not_called()
