"""Norm-to-Engine history checks; independently authored neutral fixtures only."""

import asyncio
from dataclasses import replace
import io
import json
import tempfile
import unittest

from safeguard.adapters.demo import create_demo_adapter

from safeguard.adapters.gateways.demo import DemoGateway
from safeguard.original_assets import AssetKey, AssetLimits, LocalAssetStore
from safeguard.conversation_memory import ConversationKey, HistoryError, HistoryLimits, InMemoryConversationMemory
from safeguard.scam_detection.intake import DetectionIntake
from safeguard.ingress import AccessContext, ConversationIngress, IngressError, InputLimits, ProcessingLimits
from safeguard.adapters.norm import normalize


INPUT = InputLimits(65536,4096,16,4096,16,8)
PROCESSING = ProcessingLimits(1,16,262144,16,16,1.)
CONTEXT = AccessContext("toy-account",frozenset(("toy-room","toy-garden")))
LIMITS = HistoryLimits(16,64,1048576,32,524288,64,1048576)
KEY = ConversationKey("demo","toy-account","toy-room")


def native(index,room="toy-room"):
    return dict(thread=room,id=str(index),author="toy-reader",body="Newly authored toy library note "+str(index))


class DetectionIntakeTests(unittest.IsolatedAsyncioTestCase):
    async def test_analyzer_history_error_is_not_a_snapshot_failure(self):
        with InMemoryConversationMemory(message_limits=INPUT,limits=LIMITS) as history:
            async def analyzer(snapshot):raise HistoryError("PRIVATE_ANALYZER_ERROR")
            with self.assertRaises(IngressError):
                async with ConversationIngress(analyzer, adapter=create_demo_adapter(),input_limits=INPUT,processing_limits=PROCESSING,intake=DetectionIntake(history)) as pipe:
                    outcome=await pipe.submit(native(0),CONTEXT).wait()
                    self.assertEqual((outcome.stage,outcome.code),("consumer","consumer_failed"))

    async def test_real_norm_handoff_preserves_every_boundary_and_source_isolation(self):
        seen=[]
        with InMemoryConversationMemory(message_limits=INPUT,limits=LIMITS) as history:
            async def analyzer(snapshot):
                seen.append((snapshot.observed_count,[m["message_id"] for m in snapshot.messages]))
                snapshot.messages[0]["content_parts"][0]["text"]="Analyzer changed its copy"
            async with ConversationIngress(analyzer, adapter=create_demo_adapter(),input_limits=INPUT,processing_limits=PROCESSING,intake=DetectionIntake(history)) as pipe:
                source=native(0)
                tickets=[pipe.submit(source,CONTEXT)]
                source["body"]="Changed after admission"
                tickets.extend(pipe.submit_json(json.dumps(native(i)).encode(),CONTEXT) for i in range(1,4))
                outcomes=await asyncio.gather(*(t.wait() for t in tickets))
            self.assertTrue(all(r.status=="completed" for r in outcomes))
            self.assertEqual(seen,[(i,[str(n) for n in range(i)]) for i in range(1,5)])
            latest=history.snapshot(CONTEXT,history.head(CONTEXT,KEY))
            self.assertEqual(latest.messages[0]["content_parts"][0]["text"],native(0)["body"])

    async def test_interleaved_accounts_and_keys_use_scoped_fifo_with_bounded_overlap(self):
        entered,release=asyncio.Event(),asyncio.Event()
        active=set();seen={}
        with InMemoryConversationMemory(message_limits=INPUT,limits=LIMITS) as history:
            async def analyzer(snapshot):
                self.assertNotIn(snapshot.key,active);active.add(snapshot.key)
                if len(active)==4:entered.set()
                await release.wait()
                seen.setdefault(snapshot.key,[]).append(snapshot.observed_count)
                self.assertEqual([m["message_id"] for m in snapshot.messages],[str(i) for i in range(snapshot.observed_count)])
                active.remove(snapshot.key)
            async with ConversationIngress(analyzer, adapter=create_demo_adapter(),input_limits=INPUT,processing_limits=replace(PROCESSING,workers=4),intake=DetectionIntake(history)) as pipe:
                tickets=[]
                for i in range(3):
                    for account in ("toy-account","toy-other"):
                        for room in ("toy-room","toy-garden"):
                            tickets.append(pipe.submit(native(i,room),AccessContext(account,CONTEXT.conversations)))
                await asyncio.wait_for(entered.wait(),1);release.set()
                await asyncio.gather(*(t.wait() for t in tickets))
            self.assertEqual(len(seen),4)
            self.assertTrue(all(counts==[1,2,3] for counts in seen.values()))
            self.assertEqual(history.stats["messages"],12)

    async def test_timeout_retains_registered_history(self):
        with InMemoryConversationMemory(message_limits=INPUT,limits=LIMITS) as history:
            async def analyzer(snapshot):await asyncio.Event().wait()
            with self.assertRaises(IngressError):
                async with ConversationIngress(analyzer, adapter=create_demo_adapter(),input_limits=INPUT,processing_limits=replace(PROCESSING,consumer_timeout=.005),intake=DetectionIntake(history)) as pipe:
                    tickets=[pipe.submit(native(i),CONTEXT) for i in range(2)]
                    outcomes=await asyncio.gather(*(t.wait() for t in tickets))
            self.assertEqual(outcomes[0].code,"consumer_timeout")
            self.assertEqual(outcomes[1].status,"blocked")
            self.assertEqual(history.head(CONTEXT,KEY).observed_count,2)

    async def test_abort_keeps_all_admitted_observations_even_before_dispatch(self):
        with InMemoryConversationMemory(message_limits=INPUT,limits=LIMITS) as history:
            async def analyzer(snapshot):await asyncio.Event().wait()
            with self.assertRaisesRegex(RuntimeError,"Host shutdown"):
                async with ConversationIngress(analyzer, adapter=create_demo_adapter(),input_limits=INPUT,processing_limits=PROCESSING,intake=DetectionIntake(history)) as pipe:
                    tickets=[pipe.submit(native(i),CONTEXT) for i in range(3)]
                    raise RuntimeError("Host shutdown")
            self.assertTrue(all(r.status=="cancelled" for r in await asyncio.gather(*(t.wait() for t in tickets))))
            self.assertEqual(history.head(CONTEXT,KEY).observed_count,3)

    async def test_failed_key_rejects_new_input_without_history_change(self):
        with InMemoryConversationMemory(message_limits=INPUT,limits=LIMITS) as history:
            async def analyzer(snapshot):raise RuntimeError("PRIVATE_ANALYZER_ERROR")
            with self.assertRaises(IngressError):
                async with ConversationIngress(analyzer, adapter=create_demo_adapter(),input_limits=INPUT,processing_limits=PROCESSING,intake=DetectionIntake(history)) as pipe:
                    await pipe.submit(native(0),CONTEXT).wait()
                    with self.assertRaises(IngressError) as caught:pipe.submit(native(1),CONTEXT)
                    self.assertEqual(caught.exception.code,"conversation_failed")
                    self.assertEqual(history.head(CONTEXT,KEY).observed_count,1)

    async def test_snapshot_failure_is_explicit_without_stranding_tickets(self):
        with InMemoryConversationMemory(message_limits=INPUT,limits=LIMITS) as history:
            async def analyzer(snapshot):self.fail("Closed state must not reach analyzer")
            with self.assertRaises(IngressError):
                async with ConversationIngress(analyzer, adapter=create_demo_adapter(),input_limits=INPUT,processing_limits=PROCESSING,intake=DetectionIntake(history)) as pipe:
                    ticket=pipe.submit(native(0),CONTEXT);history.close()
                    outcome=await ticket.wait()
                    self.assertEqual((outcome.status,outcome.code),("failed","snapshot_failed"))

    async def test_history_limit_and_unauthorized_inputs_do_not_change_state(self):
        with InMemoryConversationMemory(message_limits=INPUT,limits=replace(LIMITS,max_messages=1)) as history:
            async def analyzer(snapshot):pass
            async with ConversationIngress(analyzer, adapter=create_demo_adapter(),input_limits=INPUT,processing_limits=PROCESSING,intake=DetectionIntake(history)) as pipe:
                with self.assertRaises(IngressError):pipe.submit(native(0),AccessContext("toy-account",frozenset()))
                self.assertEqual(history.stats["messages"],0)
                await pipe.submit(native(0),CONTEXT).wait()
                with self.assertRaises(IngressError) as caught:pipe.submit(native(1),CONTEXT)
                self.assertEqual((caught.exception.stage,caught.exception.code),("engine_intake","message_limit"))
                self.assertEqual(history.stats["messages"],1)

    async def test_file_reference_survives_history_snapshots_and_retrieves_original(self):
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent,limits=AssetLimits(4096,16384,8,16384,8,64)) as store, \
             InMemoryConversationMemory(message_limits=INPUT,limits=LIMITS) as history:
            event=dict(thread="toy-room",id="0",author="toy-reader",content_parts=[dict(kind="file",asset_id="toy-file")],assets=[dict(asset_id="toy-file")])
            async def analyzer(snapshot):
                identity=AssetKey.from_message(snapshot.messages[-1],"toy-file")
                self.assertEqual(store.read(CONTEXT,identity),b"New neutral toy original.\n")
            async with ConversationIngress(analyzer, adapter=create_demo_adapter(),input_limits=INPUT,processing_limits=PROCESSING,intake=DetectionIntake(history)) as pipe:
                outcome=await pipe.submit_files(event,{"toy-file":io.BytesIO(b"New neutral toy original.\n")},CONTEXT,store=store).wait()
                self.assertEqual(outcome.status,"completed")
            self.assertEqual(history.stats["messages"],1)

    async def test_history_preflight_prevents_upload_and_failed_upload_leaves_no_history(self):
        class NoRead:
            def read(self,n):raise AssertionError("History rejection must precede upload")
        class FailedRead:
            def read(self,n):raise RuntimeError("PRIVATE_UPLOAD_ERROR")
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent,limits=AssetLimits(4096,16384,8,16384,8,64)) as store, \
             InMemoryConversationMemory(message_limits=INPUT,limits=replace(LIMITS,max_messages=1)) as history:
            event=dict(thread="toy-room",id="1",author="toy-reader",content_parts=[dict(kind="file",asset_id="toy-file")],assets=[dict(asset_id="toy-file")])
            async def analyzer(snapshot):pass
            async with ConversationIngress(analyzer, adapter=create_demo_adapter(),input_limits=INPUT,processing_limits=PROCESSING,intake=DetectionIntake(history)) as pipe:
                with self.assertRaises(IngressError) as caught:pipe.submit_files(event,{"toy-file":FailedRead()},CONTEXT,store=store)
                self.assertEqual(caught.exception.code,"source_failed");self.assertEqual(history.stats["messages"],0)
                await pipe.submit(native(0),CONTEXT).wait()
                with self.assertRaises(IngressError) as caught:pipe.submit_files(event,{"toy-file":NoRead()},CONTEXT,store=store)
                self.assertEqual(caught.exception.code,"message_limit");self.assertEqual(store.stats["files"],0)

    async def test_post_upload_history_rejection_rolls_back_new_originals(self):
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent,limits=AssetLimits(4096,16384,8,16384,8,64)) as store, \
             InMemoryConversationMemory(message_limits=INPUT,limits=replace(LIMITS,max_messages=1)) as history:
            class ReentrantHostReader(io.BytesIO):
                added=False
                def read(reader,n):
                    if not reader.added:
                        history.append(CONTEXT,normalize(DemoGateway("toy-account").receive(native("host-observation"))))
                        reader.added=True
                    return super().read(n)
            event=dict(thread="toy-room",id="0",author="toy-reader",content_parts=[dict(kind="file",asset_id="toy-file")],assets=[dict(asset_id="toy-file")])
            async def analyzer(snapshot):self.fail("Rejected arrival reached analyzer")
            async with ConversationIngress(analyzer, adapter=create_demo_adapter(),input_limits=INPUT,processing_limits=PROCESSING,intake=DetectionIntake(history)) as pipe:
                with self.assertRaises(IngressError) as caught:pipe.submit_files(event,{"toy-file":ReentrantHostReader(b"Toy")},CONTEXT,store=store)
                self.assertEqual(caught.exception.code,"message_limit")
                self.assertEqual(store.stats["files"],0);self.assertEqual(pipe.stats["admitted"],0)
                snapshot=history.snapshot(CONTEXT,history.head(CONTEXT,KEY))
                self.assertEqual([m["message_id"] for m in snapshot.messages],["host-observation"])

    async def test_configuration_and_failure_logs_do_not_expose_history(self):
        with self.assertRaises(IngressError):ConversationIngress(lambda value:None,adapter=create_demo_adapter(),input_limits=INPUT,processing_limits=PROCESSING,intake={})
        with self.assertRaises(HistoryError):DetectionIntake({})
        with InMemoryConversationMemory(message_limits=INPUT,limits=LIMITS) as history:
            async def analyzer(snapshot):raise RuntimeError("PRIVATE_ANALYSIS_CANARY")
            event=native(0);event["body"]="PRIVATE_BODY_CANARY"
            with self.assertLogs("safeguard.ingress",level="INFO") as logs,self.assertRaises(IngressError):
                async with ConversationIngress(analyzer, adapter=create_demo_adapter(),input_limits=INPUT,processing_limits=PROCESSING,intake=DetectionIntake(history)) as pipe:
                    await pipe.submit(event,CONTEXT).wait()
            self.assertNotIn("PRIVATE","\n".join(logs.output))

    async def test_queued_observations_survive_analyzer_failure(self):
        from safeguard.conversation_memory import ConversationKey, HistoryLimits, InMemoryConversationMemory
        from safeguard.scam_detection.intake import DetectionIntake
        with InMemoryConversationMemory(message_limits=INPUT,limits=HistoryLimits(16,64,1048576,32,524288,64,1048576)) as history:
            seen=[]
            async def analyzer(snapshot):
                seen.append(snapshot)
                raise RuntimeError("PRIVATE_ANALYZER_ERROR")
            with self.assertRaises(IngressError):
                async with ConversationIngress(analyzer, adapter=create_demo_adapter(),input_limits=INPUT,processing_limits=PROCESSING,intake=DetectionIntake(history)) as pipe:
                    tickets=[pipe.submit(native(i),CONTEXT) for i in range(3)]
                    outcomes=await asyncio.gather(*(t.wait() for t in tickets))
            self.assertEqual([r.status for r in outcomes],["failed","blocked","blocked"])
            key=ConversationKey("demo","toy-account","toy-room")
            snapshot=history.snapshot(CONTEXT,history.head(CONTEXT,key))
            self.assertEqual([m["message_id"] for m in snapshot.messages],["0","1","2"])
            self.assertEqual([m["message_id"] for m in seen[0].messages],["0"])
