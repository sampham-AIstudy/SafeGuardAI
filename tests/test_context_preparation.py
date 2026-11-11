"""Analysis-context checks using independently authored neutral messages only."""

import asyncio
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from safeguard.adapters.demo import create_demo_adapter
from unittest.mock import patch

from safeguard.adapters.gateways.demo import DemoGateway
from safeguard.memory.original_assets import AssetLimits, LocalAssetStore
from safeguard.memory.conversation_status import ConversationKey, HistoryLimits, HistorySnapshot, InMemoryConversationStatus
from safeguard.scam_detection.context import ContextError, ContextLimits, ContextPreparer
from safeguard.scam_detection.intake import DetectionIntake
from safeguard.ingress import AccessContext, ConversationIngress, IngressError, InputLimits, ProcessingLimits
from safeguard.adapters.norm import normalize


INPUT = InputLimits(131072, 16384, 24, 16384, 64, 32)
LIMITS = ContextLimits(64, 1048576, 1048576, 65536, 256, 128)
HISTORY = HistoryLimits(16, 64, 2097152, 64, 2097152, 64, 2097152)
ACCESS = AccessContext("toy-account", frozenset(("toy-room", "toy-garden")))
KEY = ConversationKey("demo", "toy-account", "toy-room")
NOW = datetime(2026, 1, 5, tzinfo=timezone.utc)


def native(index=0, *, room="toy-room", mixed=False):
    event = dict(thread=room, id=str(index), author="toy-reader", body="A newly authored library note. " + str(index))
    if mixed:
        event.pop("body")
        event.update(content_parts=[dict(kind="text", text="An independently authored file note."),
                                    dict(kind="file", asset_id="toy-file"), dict(kind="file", asset_id="toy-file")],
                     assets=[dict(asset_id="toy-file", filename="note.txt", declared_size_bytes=999,
                                  declared_media_type="text/plain", source_status="available")])
    return event


def message(index=0, *, account="toy-account", **options):
    return normalize(DemoGateway(account_id=account, clock=lambda: NOW).receive(native(index, **options)))


def snapshot(*records, key=KEY):
    return HistorySnapshot(key, len(records), tuple(records))


def prepare(value, *, limits=LIMITS, message_limits=INPUT, access=ACCESS):
    return ContextPreparer(message_limits=message_limits, limits=limits).prepare(value, access)


class ContextPreparationTests(unittest.TestCase):
    def rejected(self, action, code):
        with self.assertRaises(ContextError) as caught:
            action()
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)

    def test_exact_text_metadata_order_and_no_implicit_native_extras(self):
        event = native()
        event.update(body="  A neutral note: café, cây, 🙂\n", sent_at="2026-01-04T03:00:00.123456789+03:00",
                     extra={"private_note": "Not assessment content"})
        first = normalize(DemoGateway(account_id="toy-account", clock=lambda: NOW).receive(event))
        second = message(1)
        second["raw_payload"]["sent_at"] = "2026-01-01T00:00:00Z"
        second = normalize(dict(schema_version="1.0", source="demo", account_id="toy-account",
                                conversation_id="toy-room", message_id="1", sender_id="toy-reader",
                                event_type="message.created", observed_at=first["observed_at"], payload=second["raw_payload"]))
        result = prepare(snapshot(first, second))
        document = result.to_dict()
        self.assertEqual(document["context_schema_version"], "1.0")
        self.assertEqual((result.key, result.observed_count), (KEY, 2))
        self.assertEqual([m["message_id"] for m in document["messages"]], ["0", "1"])
        for number, (source, output) in enumerate(zip((first, second), document["messages"]), 1):
            self.assertEqual(output["observation_number"], number)
            for name in ("message_id", "sender_id", "observed_at", "sent_at", "is_from_observed_account", "assets"):
                self.assertEqual(output[name], source[name])
            self.assertEqual(output["content_parts"], [dict(source["content_parts"][0],
                source_ref=dict(observation_number=number, part_index=0))])
        self.assertNotIn("raw_payload", document["messages"][0])
        self.assertNotIn(b"Not assessment content", result.json_bytes)
        self.assertIn("extra", first["raw_payload"])
        self.assertEqual(document["coverage"]["attachments"], [])

    def test_duplicate_native_ids_and_repeated_assets_have_distinct_positional_references(self):
        result = prepare(snapshot(message(0, mixed=True), message(0, mixed=True)))
        document = result.to_dict()
        refs = [item["source_ref"] for item in document["coverage"]["attachments"]]
        self.assertEqual(refs, [dict(observation_number=n, part_index=i) for n in (1, 2) for i in (1, 2)])
        self.assertEqual(result.stats.assets, 2)
        self.assertEqual(result.stats.content_parts, 6)
        for ref in refs:
            self.assertEqual(result.resolve_part(ref)["asset_id"], "toy-file")
        self.assertEqual([m["message_id"] for m in document["messages"]], ["0", "0"])

    def test_every_attachment_kind_and_source_status_remains_unprocessed(self):
        for kind in ("image", "audio", "video", "file"):
            for status in ("unknown", "available", "pending", "unavailable", "failed"):
                with self.subTest(kind=kind, status=status):
                    event = dict(thread="toy-room", id="toy-media", author="toy-reader",
                                 content_parts=[dict(kind=kind, asset_id="toy-asset")],
                                 assets=[dict(asset_id="toy-asset", source_status=status)])
                    record = normalize(DemoGateway(account_id="toy-account", clock=lambda: NOW).receive(event))
                    result = prepare(snapshot(record))
                    coverage = result.to_dict()["coverage"]
                    expected = "source_reported_" + status if status in ("pending", "unavailable", "failed") else "reader_not_run"
                    self.assertEqual(coverage, dict(attachment_parts=1, unprocessed_attachment_parts=1,
                        attachments=[dict(source_ref=dict(observation_number=1, part_index=0), kind=kind,
                                          asset_id="toy-asset", source_status=status,
                                          processing_status="not_requested", gap_reason=expected)]))

    def test_bytes_and_metadata_are_immutable_and_every_view_is_detached(self):
        record = message(mixed=True)
        value = snapshot(record)
        result = prepare(value)
        original = result.json_bytes
        view = result.to_dict()
        view["messages"][0]["content_parts"][0]["text"] = "Receiver edit"
        view["coverage"]["attachments"][0]["source_ref"]["part_index"] = 99
        record["assets"][0]["filename"] = "Snapshot edit"
        record["content_parts"][0]["text"] = "Snapshot edit"
        self.assertEqual(result.json_bytes, original)
        self.assertEqual(result.to_dict()["messages"][0]["assets"][0]["filename"], "note.txt")
        self.assertEqual(result.resolve_part(dict(observation_number=1, part_index=1))["kind"], "file")
        with self.assertRaises(FrozenInstanceError):
            result.observed_count = 0
        with self.assertRaises(FrozenInstanceError):
            result.stats.assets = 0

    def test_empty_context_is_representable_without_claiming_assessment(self):
        result = prepare(snapshot())
        self.assertEqual(result.observed_count, 0)
        self.assertEqual(result.to_dict()["messages"], [])
        self.assertEqual(result.stats.input_json_bytes, 0)
        self.assertNotIn("assessment", result.to_dict())

    def test_trusted_scope_is_required_even_for_an_empty_prefix(self):
        self.rejected(lambda: prepare(snapshot(), access={"account_id": "toy-account"}), "trusted_context_required")
        for access in (AccessContext("toy-other", ACCESS.conversations), AccessContext("toy-account", frozenset())):
            with self.subTest(access=access):
                self.rejected(lambda: prepare(snapshot(), access=access), "conversation_not_allowed")
        for key, record in ((KEY, message(room="toy-garden")), (KEY, message(account="toy-other"))):
            with self.subTest(record=record["conversation_id"]):
                self.rejected(lambda: prepare(snapshot(record, key=key)), "scope_mismatch")

    def test_invalid_snapshot_boundary_and_membership_are_rejected(self):
        self.rejected(lambda: prepare({}), "invalid_snapshot")
        self.rejected(lambda: prepare(HistorySnapshot("toy-room", 0, ())), "invalid_snapshot")
        for count, records in ((True, (message(),)), (-1, ()), (0, (message(),)), (2, (message(),)),
                               (1, [message()]), (1.0, (message(),))):
            with self.subTest(count=count, membership=type(records)):
                self.rejected(lambda: prepare(HistorySnapshot(KEY, count, records)), "invalid_boundary")

    def test_all_configured_limits_accept_exact_boundaries_and_reject_one_less(self):
        value = snapshot(message(0, mixed=True), message(1, mixed=True))
        baseline = prepare(value)
        exact = ContextLimits(2, baseline.stats.input_json_bytes, len(baseline.json_bytes),
                              baseline.stats.text_chars, baseline.stats.content_parts, baseline.stats.assets)
        self.assertEqual(prepare(value, limits=exact).json_bytes, baseline.json_bytes)
        codes = dict(max_messages="message_limit", max_input_bytes="input_byte_limit",
                     max_output_bytes="output_byte_limit", max_text_chars="text_limit",
                     max_content_parts="part_limit", max_assets="asset_limit")
        for name, code in codes.items():
            with self.subTest(limit=name):
                self.rejected(lambda: prepare(value, limits=replace(exact, **{name: getattr(exact, name) - 1})), code)

    def test_input_and_output_accounting_uses_actual_compact_utf8_json(self):
        record = message()
        record["raw_payload"]["body"] = "Unicode note 🙂 é e\u0301"
        record = normalize(dict(schema_version="1.0", source="demo", account_id="toy-account",
                                conversation_id="toy-room", message_id="0", sender_id="toy-reader",
                                event_type="message.created", observed_at=record["observed_at"], payload=record["raw_payload"]))
        result = prepare(snapshot(record))
        options = dict(ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        self.assertEqual(result.stats.input_json_bytes, len(json.dumps(record, **options).encode("utf-8")))
        self.assertEqual(result.stats.output_json_bytes, len(result.json_bytes))
        self.assertEqual(result.json_bytes, json.dumps(result.to_dict(), **options).encode("utf-8"))
        self.assertEqual(result.stats.text_chars, len(record["content_parts"][0]["text"]))

    def test_limits_require_positive_integers_and_explicit_configuration(self):
        for item in fields(LIMITS):
            for invalid in (0, -1, True, 1.5, "2", None):
                with self.subTest(field=item.name, value=invalid), self.assertRaises(ValueError):
                    replace(LIMITS, **{item.name: invalid})
        for kwargs in (dict(message_limits=None, limits=LIMITS), dict(message_limits=INPUT, limits=None)):
            self.rejected(lambda: ContextPreparer(**kwargs), "invalid_configuration")

    def test_preflight_budget_rejection_precedes_normalization_or_partial_output(self):
        with patch("safeguard.scam_detection.context.normalize", side_effect=AssertionError("Must not normalize")):
            self.rejected(lambda: prepare(snapshot(message(), message(1)), limits=replace(LIMITS, max_messages=1)), "message_limit")
            self.rejected(lambda: prepare(snapshot(message()), limits=replace(LIMITS, max_input_bytes=1)), "input_byte_limit")

    def test_invalid_normalized_records_and_dangling_references_are_rejected(self):
        mutations = [lambda m: m.update(message_schema_version="1.0"),
                     lambda m: m.update(is_from_observed_account=0),
                     lambda m: m.update(private_extra="PRIVATE_VALUE_CANARY"),
                     lambda m: m["content_parts"][0].update(text="Forged text"),
                     lambda m: m["raw_payload"].update(id="PRIVATE_ID_CANARY"),
                     lambda m: m["assets"].clear(),
                     lambda m: m["raw_payload"]["assets"].clear(),
                     lambda m: m["content_parts"][1].update(asset_id="PRIVATE_ASSET_CANARY")]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                record = message(mixed=True)
                mutate(record)
                self.rejected(lambda: prepare(snapshot(record)), "invalid_normalized_message")

    def test_per_message_resources_reject_malformed_json_without_private_values(self):
        cases = [(lambda m: m["raw_payload"].update(private=float("nan")), "message_nonfinite_number"),
                 (lambda m: m["raw_payload"].update(private="\ud800"), "message_invalid_unicode"),
                 (lambda m: m["raw_payload"].update(private=m), "message_cyclic_input"),
                 (lambda m: m["raw_payload"].update(private=object()), "message_unsupported_json_value")]
        for mutate, code in cases:
            with self.subTest(code=code):
                record = message()
                mutate(record)
                self.rejected(lambda: prepare(snapshot(record)), code)
        self.rejected(lambda: prepare(snapshot(message()), message_limits=replace(INPUT, max_depth=1)), "message_too_deep")
        self.rejected(lambda: prepare(snapshot(message()), message_limits=replace(INPUT, max_bytes=1)), "message_too_many_bytes")

    def test_reference_resolution_rejects_invalid_positions_and_returns_detached_parts(self):
        result = prepare(snapshot(message(mixed=True)))
        invalid = [None, {}, dict(observation_number=True, part_index=0), dict(observation_number=0, part_index=0),
                   dict(observation_number=2, part_index=0), dict(observation_number=1, part_index=-1),
                   dict(observation_number=1, part_index=True), dict(observation_number=1, part_index=3),
                   dict(observation_number=1, part_index=0, private="PRIVATE_VALUE_CANARY")]
        for ref in invalid:
            with self.subTest(ref=ref):
                self.rejected(lambda: result.resolve_part(ref), "invalid_source_ref")
        ref = dict(observation_number=1, part_index=0)
        result.resolve_part(ref)["text"] = "Changed receiver copy"
        self.assertEqual(result.resolve_part(ref)["text"], "An independently authored file note.")

    def test_direct_import_in_a_fresh_process(self):
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
        result = subprocess.run([sys.executable, "-c", "from safeguard.scam_detection.context import ContextPreparer"],
                                env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


class ContextIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_ingress_scoped_prefixes_exclude_future_arrivals_and_preserve_history(self):
        seen = {}
        with InMemoryConversationStatus(message_limits=INPUT, limits=HISTORY) as history:
            preparer = ContextPreparer(message_limits=INPUT, limits=LIMITS)

            async def analyzer(value):
                prepared = preparer.prepare(value, ACCESS)
                document = prepared.to_dict()
                seen.setdefault(value.key, []).append(document)
                self.assertEqual([m["message_id"] for m in document["messages"]], [str(i) for i in range(value.observed_count)])
                document["messages"][0]["content_parts"][0]["text"] = "Only receiver's copy"

            async with ConversationIngress(analyzer, adapter=create_demo_adapter(), input_limits=INPUT,
                    processing_limits=ProcessingLimits(2, 16, 1048576, 16, 16, 2.), intake=DetectionIntake(history)) as pipe:
                tickets = [pipe.submit(native(i, room=room), ACCESS) for i in range(3) for room in ("toy-room", "toy-garden")]
                outcomes = await asyncio.gather(*(ticket.wait() for ticket in tickets))
            self.assertTrue(all(outcome.status == "completed" for outcome in outcomes))
            self.assertEqual(len(seen), 2)
            for key, documents in seen.items():
                self.assertEqual([d["observed_count"] for d in documents], [1, 2, 3])
                self.assertTrue(all(d["conversation_id"] == key.conversation_id for d in documents))
                original = history.snapshot(ACCESS, history.head(ACCESS, key))
                self.assertEqual(original.messages[0]["content_parts"][0]["text"], native()["body"])

    async def test_context_failure_retains_accepted_history_and_is_not_a_benign_result(self):
        with InMemoryConversationStatus(message_limits=INPUT, limits=HISTORY) as history:
            preparer = ContextPreparer(message_limits=INPUT, limits=replace(LIMITS, max_output_bytes=1))

            async def analyzer(value):
                preparer.prepare(value, ACCESS)

            with self.assertRaises(IngressError):
                async with ConversationIngress(analyzer, adapter=create_demo_adapter(), input_limits=INPUT,
                        processing_limits=ProcessingLimits(1, 8, 1048576, 8, 8, 2.), intake=DetectionIntake(history)) as pipe:
                    tickets = [pipe.submit(native(i), ACCESS) for i in range(2)]
                    outcomes = await asyncio.gather(*(ticket.wait() for ticket in tickets))
            self.assertEqual((outcomes[0].status, outcomes[0].code), ("failed", "consumer_failed"))
            self.assertEqual(outcomes[1].status, "blocked")
            self.assertEqual(history.head(ACCESS, KEY).observed_count, 2)

    async def test_uploaded_original_is_not_read_or_treated_as_interpreted_evidence(self):
        with tempfile.TemporaryDirectory() as parent, \
                LocalAssetStore(parent=parent, limits=AssetLimits(4096, 16384, 8, 16384, 8, 64)) as store, \
                InMemoryConversationStatus(message_limits=INPUT, limits=HISTORY) as history:
            seen = []

            async def analyzer(value):
                with patch.object(store, "read", side_effect=AssertionError("No reader selected")):
                    seen.append(prepare(value))

            async with ConversationIngress(analyzer, adapter=create_demo_adapter(), input_limits=INPUT,
                    processing_limits=ProcessingLimits(1, 8, 1048576, 8, 8, 2.), intake=DetectionIntake(history)) as pipe:
                outcome = await pipe.submit_files(native(mixed=True), {"toy-file": io.BytesIO(b"New neutral toy file.\n")},
                                                  ACCESS, store=store).wait()
            self.assertEqual(outcome.status, "completed")
            coverage = seen[0].to_dict()["coverage"]
            self.assertEqual(coverage["unprocessed_attachment_parts"], 2)
            self.assertTrue(all(item["gap_reason"] == "reader_not_run" for item in coverage["attachments"]))
