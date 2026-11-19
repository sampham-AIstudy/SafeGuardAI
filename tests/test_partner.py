"""Bounded partner ingestion, file identity, warning return, and replay."""

import asyncio
from base64 import b64encode
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from test_agent_controller import SETTINGS, ScriptedClient, envelope
from test_native_media import toy_jpeg
from test_warning import assessment

from safeguard.adapters.demo import create_demo_adapter
from safeguard.demo import demo_limits
from safeguard.detection.context import ContextError
from safeguard.detection.model_contract import encoded
from safeguard.detection.tools.readers import Utf8TextReader
from safeguard.ingress import AccessContext, ProcessingLimits
from safeguard.memory.conversation_status import StateError
from safeguard.memory.original_assets import AssetKey
from safeguard.partner import PartnerError, PartnerService
from safeguard.partner_demo import partner_demo_limits
from safeguard.partner.live import native_media_options
from safeguard.partner.rooms import DemoRooms
from safeguard.runtime import open_agent_runtime
from safeguard.warning import WarningPolicy


CONVERSATION = "library"
ACCESS = AccessContext("library-partner", frozenset({CONVERSATION}))
OTHER = AccessContext("other-partner", frozenset({CONVERSATION}))
BYTES = b"Newly authored reading list for the workshop.\n"


def event(number, *, data=None, body="Workshop message", author="reader", filename="list.txt"):
    value = {"id": f"msg-{number}", "author": author, "body": body}
    if data is not None:
        value["attachment"] = {"id": "note", "filename": filename, "base64": b64encode(data).decode("ascii")}
    return encoded(value)


class PartnerServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.limits = demo_limits()

    def runtime(self, client):
        return open_agent_runtime(root=self.root, limits=self.limits, client=client, settings=SETTINGS,
            input_fit=lambda binding, request: True, reader=Utf8TextReader(8192, 8192))

    def service(self, runtime):
        return PartnerService(runtime, adapter=create_demo_adapter(), limits=self.limits,
            processing_limits=ProcessingLimits(1, 1, 32768, 1, 1, 15),
            policy=WarningPolicy(runtime.memory, warn_on_scam=True))

    async def test_ordered_history_upload_duplicate_conflict_and_scope_survive_reopen(self):
        client = ScriptedClient([assessment("no_scam_evidence", 1), assessment("scam", 2)])
        with self.runtime(client) as runtime:
            service = self.service(runtime)
            with self.assertRaisesRegex(PartnerError, "conversation_not_allowed"):
                await service.submit(ACCESS, "unselected", event(1))
            self.assertEqual(service.conversation(ACCESS, CONVERSATION)["messages"], [])
            first = await service.submit(ACCESS, CONVERSATION, event(1))
            self.assertEqual((first.observed_count, first.warning.action), (1, "no_action"))

            request = event(2, data=BYTES)
            second, repeated = await asyncio.gather(service.submit(ACCESS, CONVERSATION, request),
                                                    service.submit(ACCESS, CONVERSATION, request))
            self.assertEqual((second.observed_count, second.warning.action, second.duplicate), (2, "warn", False))
            self.assertEqual((repeated.observed_count, repeated.warning.action, repeated.duplicate), (2, "no_action", True))
            self.assertEqual(second.warning.active, repeated.warning.active)
            asset = AssetKey("demo", ACCESS.account_id, CONVERSATION, "msg-2", "note")
            self.assertEqual(runtime.originals.read(ACCESS, asset), BYTES)
            self.assertEqual(len(client.requests), 2)
            self.assertIsNone(service.conversation(OTHER, CONVERSATION)["active_warning"])
            with self.assertRaisesRegex(PartnerError, "event_conflict"):
                await service.submit(ACCESS, CONVERSATION, event(2, data=b"Other bytes."))

        with self.runtime(client) as runtime:
            service = self.service(runtime)
            view = service.conversation(ACCESS, CONVERSATION)
            self.assertEqual([item["id"] for item in view["messages"]], ["msg-1", "msg-2"])
            self.assertEqual(view["messages"][1]["attachments"], [{"id": "note", "filename": "list.txt"}])
            self.assertEqual(view["active_warning"]["supporting"][0]["observation_number"], 2)
            duplicate = await service.submit(ACCESS, CONVERSATION, event(1))
            self.assertEqual((duplicate.warning.reason, duplicate.duplicate), ("duplicate_event", True))
            self.assertEqual(len(client.requests), 2)

    async def test_recover_committed_analysis_after_warning_write_failure(self):
        client = ScriptedClient([assessment("scam", 1)])
        with self.runtime(client) as runtime:
            service = self.service(runtime)
            with patch.object(runtime.memory.warning_history, "commit", side_effect=StateError("fixture")):
                failed = await service.submit(ACCESS, CONVERSATION, event(1))
            self.assertEqual((failed.warning.action, failed.warning.reason), ("unavailable", "warning_storage_failed"))
        with self.runtime(client) as runtime:
            service = self.service(runtime)
            retried = await service.submit(ACCESS, CONVERSATION, event(1))
            self.assertEqual((retried.duplicate, retried.warning.action), (True, "warn"))
            self.assertEqual(len(client.requests), 1)

    async def test_detection_failure_preserves_observation_and_retry_does_not_call_again(self):
        client = ScriptedClient([RuntimeError("private-fixture-error")])
        with self.runtime(client) as runtime:
            service = self.service(runtime)
            failed = await service.submit(ACCESS, CONVERSATION, event(1))
            self.assertEqual((failed.observed_count, failed.warning.reason), (1, "detection_failed"))
            retry = await service.submit(ACCESS, CONVERSATION, event(1))
            self.assertEqual((retry.warning.reason, retry.duplicate), ("assessment_not_committed", True))
            self.assertIsNone(service.conversation(ACCESS, CONVERSATION)["active_warning"])
            self.assertEqual(len(client.requests), 1)

    async def test_invalid_upload_and_untrusted_route_do_not_admit_messages(self):
        client = ScriptedClient([])
        with self.runtime(client) as runtime:
            service = self.service(runtime)
            with self.assertRaisesRegex(PartnerError, "conversation_not_allowed"):
                await service.submit({"account_id": ACCESS.account_id}, CONVERSATION, event(1))
            with self.assertRaisesRegex(PartnerError, "invalid_event"):
                await service.submit(ACCESS, CONVERSATION, b'{"id":"one", "id":"two"}')
            with self.assertRaisesRegex(PartnerError, "attachment_too_large"):
                await service.submit(ACCESS, CONVERSATION, event(1, data=b"x" * (self.limits.assets.max_file_bytes + 1)))
            self.assertEqual(service.conversation(ACCESS, CONVERSATION)["messages"], [])
            self.assertEqual(runtime.originals.stats["files"], 0)
            self.assertEqual(client.requests, [])

    async def test_clear_only_the_bound_conversation_and_reject_an_old_revision(self):
        access = AccessContext("demo-owner", frozenset({"library", "marketplace"}))
        limits = replace(self.limits, assets=replace(self.limits.assets, max_file_bytes=10485760,
            max_total_bytes=41943040, max_account_bytes=41943040))
        client = ScriptedClient([assessment("scam", 1)] * 3)
        service = DemoRooms(root=self.root, context=access, limits=limits, client=client, settings=SETTINGS,
                            text_file_bytes=16384)
        large = b"x" * (1024 * 1024)
        first = await service.submit(access, "library", event(1, data=large, body=""))
        self.assertEqual(first.warning.action, "warn")
        revision = service.conversation(access, "library")["revision"]
        self.assertEqual(sum(path.stat().st_size for path in (self.root / "room-library/originals").iterdir()
                             if len(path.name) == 32), len(large))
        await service.submit(access, "marketplace", event(1))
        with self.assertRaisesRegex(PartnerError, "conversation_not_allowed"):
            service.clear(OTHER, "library", revision)
        with self.assertRaisesRegex(PartnerError, "conversation_changed"):
            service.clear(access, "marketplace", revision)
        self.assertTrue(service.conversation(access, "marketplace")["active_warning"])

        cleared = service.clear(access, "library", revision)
        self.assertEqual(cleared, {"messages": [], "active_warning": None, "revision": None})
        self.assertFalse((self.root / "room-library").exists())
        self.assertEqual(service.conversation(access, "library"), cleared)
        fresh = await service.submit(access, "library", event(1))
        self.assertEqual((fresh.observed_count, fresh.duplicate, fresh.warning.action), (1, False, "warn"))
        with self.assertRaisesRegex(PartnerError, "conversation_changed"):
            service.clear(access, "library", revision)
        self.assertEqual(len(service.conversation(access, "library")["messages"]), 1)
        self.assertEqual(len(service.conversation(access, "marketplace")["messages"]), 1)

    async def test_reopen_finishes_only_an_already_requested_clear(self):
        access = AccessContext("demo-owner", frozenset({"library", "marketplace"}))
        service = DemoRooms(root=self.root, context=access, limits=self.limits,
            client=ScriptedClient([assessment("scam", 1)] * 2), settings=SETTINGS, text_file_bytes=8192)
        await service.submit(access, "library", event(1))
        await service.submit(access, "marketplace", event(1))
        tomb = self.root / ".clearing-room-library"
        (self.root / "room-library").rename(tomb)
        self.assertEqual(service.conversation(access, "library")["messages"], [])
        self.assertFalse(tomb.exists())
        self.assertEqual(len(service.conversation(access, "marketplace")["messages"]), 1)

    async def test_demo_outgoing_stays_in_chat_and_out_of_the_next_model_request(self):
        room = self.root / "room-library"
        room.mkdir(mode=0o700)
        historical = event(1, body="Private legacy outgoing text", author="You")
        with open_agent_runtime(root=room, limits=self.limits, client=ScriptedClient([assessment("scam", 1)]),
                settings=SETTINGS, input_fit=lambda binding, request: True, reader=Utf8TextReader(8192, 8192)) as runtime:
            # Reproduce the previous MVP's direction and active warning in a private fixture.
            await self.service(runtime).submit(ACCESS, CONVERSATION, historical)

        def assess(binding, request):
            document = binding.prepared.to_dict()
            self.assertEqual(document["observed_count"], 3)
            for message in document["messages"][:2]:
                self.assertTrue(message["is_from_observed_account"])
                self.assertEqual((message["content_parts"], message["assets"]), ([], []))
            self.assertNotIn(b"Private", binding.presentation_json)
            self.assertNotIn(b"list.txt", binding.presentation_json)
            self.assertEqual(binding.media, ())
            with self.assertRaises(ContextError):
                binding.prepared.resolve_part({"observation_number": 2, "part_index": 1})
            visible = binding.prepared.resolve_part({"observation_number": 3, "part_index": 0})
            self.assertEqual(visible["text"], "Observed incoming text")
            return envelope(request, assessment("scam", 3))

        client = ScriptedClient([assess])
        demo = DemoRooms(root=self.root, context=ACCESS, limits=self.limits, client=client, settings=SETTINGS,
                         text_file_bytes=8192, native_media=native_media_options())
        self.assertIsNone(demo.conversation(ACCESS, CONVERSATION)["active_warning"])
        duplicate = await demo.submit(ACCESS, CONVERSATION, historical)
        self.assertTrue(duplicate.duplicate)
        self.assertEqual(duplicate.warning.reason, "outgoing_message")
        sent = await demo.submit(ACCESS, CONVERSATION,
            event(2, data=b"Private outgoing file", body="Private outgoing text", author="You"))
        self.assertEqual(sent.warning.reason, "outgoing_message")
        self.assertEqual(client.requests, [])
        own = demo.conversation(ACCESS, CONVERSATION)["messages"][1]
        self.assertEqual((own["author"], own["parts"][0]["text"]), ("You", "Private outgoing text"))
        self.assertEqual(own["attachments"][0]["filename"], "list.txt")

        incoming = await demo.submit(ACCESS, CONVERSATION, event(3, body="Observed incoming text"))
        self.assertEqual(len(client.requests), 1)
        self.assertEqual(incoming.warning.active.supporting[0].observation_number, 3)
        self.assertEqual(demo.conversation(ACCESS, CONVERSATION)["active_warning"]["observed_count"], 3)

    async def test_jpeg_preview_and_engine_use_the_same_scoped_original(self):
        original = toy_jpeg()

        def assess_image(binding, request):
            self.assertEqual([(item.media_type, item.data) for item in binding.media],
                             [("image/jpeg", original)])
            return envelope(request, assessment("scam", 1))

        def assess_without_image(binding, request):
            self.assertEqual(binding.media, ())
            return envelope(request, assessment("insufficient_evidence", 3))

        client = ScriptedClient([assess_image, assess_without_image])
        access = AccessContext(ACCESS.account_id, frozenset({CONVERSATION, "other"}))
        demo = DemoRooms(root=self.root, context=access, limits=self.limits, client=client,
                         settings=SETTINGS, text_file_bytes=8192, native_media=native_media_options())
        photo = await demo.submit(access, CONVERSATION, event(1, data=original, filename="payment.JPG", body=""))
        self.assertEqual(photo.warning.action, "warn")
        self.assertEqual(photo.warning.active.supporting[0].observation_number, 1)
        await demo.submit(access, CONVERSATION,
                          event(2, data=original, filename="private.jpeg", body="", author="You"))
        invalid = await demo.submit(access, CONVERSATION,
                                    event(3, data=b"<html></html>", filename="invalid.jpg", body=""))
        self.assertEqual(invalid.warning.reason, "insufficient_evidence")
        self.assertEqual(invalid.warning.active, photo.warning.active)
        view = demo.conversation(access, CONVERSATION)
        images = [message["attachments"][0]["preview_url"] for message in view["messages"]]
        for url in images[:2]:
            _, _, _, room, _, store_id, number, attachment = url.split("/")
            self.assertEqual(demo.image_preview(access, room, store_id, int(number), int(attachment)),
                             ("image/jpeg", original))
        _, _, _, _, _, store_id, _, _ = images[0].split("/")
        for room, number in (("other", 1), (CONVERSATION, 3)):
            with self.assertRaisesRegex(PartnerError, "image_not_found"):
                demo.image_preview(access, room, store_id, number, 1)
        demo.clear(access, CONVERSATION, view["revision"])
        with self.assertRaisesRegex(PartnerError, "image_not_found"):
            demo.image_preview(access, CONVERSATION, store_id, 1, 1)

    async def test_private_outgoing_text_does_not_use_the_model_context_text_budget(self):
        client = ScriptedClient([assessment("scam", 6)])
        demo = DemoRooms(root=self.root, context=ACCESS, limits=self.limits, client=client, settings=SETTINGS,
                         text_file_bytes=8192)
        for number in range(1, 6):
            sent = await demo.submit(ACCESS, CONVERSATION, event(number, body="x" * 7000, author="You"))
            self.assertEqual(sent.warning.reason, "outgoing_message")
        self.assertEqual(client.requests, [])

        incoming = await demo.submit(ACCESS, CONVERSATION, event(6, body="New incoming message."))
        self.assertEqual(incoming.warning.action, "warn")
        self.assertEqual(incoming.warning.active.supporting[0].observation_number, 6)

    async def test_admitted_message_reports_unavailable_after_context_rejection(self):
        limits = replace(self.limits, context=replace(self.limits.context, max_text_chars=12))
        client = ScriptedClient([])
        demo = DemoRooms(root=self.root, context=ACCESS, limits=limits, client=client, settings=SETTINGS,
                         text_file_bytes=8192)
        received = await demo.submit(ACCESS, CONVERSATION, event(1, body="This exceeds the test context limit."))
        self.assertEqual((received.observed_count, received.warning.action, received.warning.reason),
                         (1, "unavailable", "processing_failed"))
        self.assertEqual(len(demo.conversation(ACCESS, CONVERSATION)["messages"]), 1)
        self.assertEqual(client.requests, [])

    async def test_demo_state_holds_assessments_through_the_history_limit(self):
        limits = partner_demo_limits(live=False)
        maximum = limits.history.max_conversation_messages
        client = ScriptedClient([assessment("no_scam_evidence", 1)] * maximum)
        demo = DemoRooms(root=self.root, context=ACCESS, limits=limits, client=client, settings=SETTINGS,
                         text_file_bytes=8192)
        for number in range(1, maximum + 1):
            received = await demo.submit(ACCESS, CONVERSATION, event(number))
            self.assertEqual((received.observed_count, received.warning.reason), (number, "no_scam_evidence"))
        self.assertEqual(len(client.requests), maximum)
        self.assertEqual(len(demo.conversation(ACCESS, CONVERSATION)["messages"]), maximum)
