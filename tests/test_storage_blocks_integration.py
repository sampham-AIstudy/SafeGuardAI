"""Real input/storage/Host arrows with self-authored messages, files and test controllers."""

from dataclasses import asdict
import asyncio
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from safeguard.adapters.demo import create_demo_adapter
from safeguard.memory.conversation_status import (ConversationStatus, HistoryBoundary, HistoryLimits, InMemoryConversationStatus, InMemoryDerivedState,
    SqliteConversationStatus, SqliteDerivedState, StateLimits, StateProfile, StateWrite, SourceReference)
from safeguard.ingress import AccessContext, ConversationIngress, IngressError, InputLimits, ProcessingLimits
from safeguard.memory.original_assets import AssetKey, AssetLimits, LocalAssetStore, PersistentAssetStore
from safeguard.scam_detection.context import ContextLimits, ContextPreparer
from safeguard.scam_detection.intake import DetectionIntake, DetectionRequest
from safeguard.scam_detection.execution_host import (AssessmentProfile, CapabilityReply, CapabilitySpec,
    ControllerReply, ControllerSpec, ExecutionHost, ExecutionLimits)
from safeguard.scam_detection.tools.evidence import (EvidenceLimits, EvidenceLocation, EvidencePreparer,
    EvidenceSegment, PartReference, ReaderOutput, ReaderSpec)
from safeguard.storage.local import StorageLimits

INPUT=InputLimits(131072,16384,24,16384,64,32)
HISTORY=HistoryLimits(16,64,2097152,32,1048576,64,2097152)
STATE=StateLimits(64,2097152,32,1048576,64,2097152,65536,24,16384,32)
FILES=AssetLimits(8192,65536,16,65536,16,128)
DISK=StorageLimits(8388608,0.1)
ACCESS=AccessContext('integration-account',frozenset(('reading-room',)))
CONTEXT=ContextLimits(64,2097152,2097152,65536,256,128)
RUN=ExecutionLimits(2097152,4096,4096,8192,8192,131072,8,2,2,32,24,16384,1.)
DATA=b'Fresh independent opening-hours attachment: nine to five.\n'

def encoded(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()

def event(kind='file'):
    return dict(thread='reading-room',id='opening-hours',author='librarian',
        content_parts=[dict(kind='text',text='The attachment lists the opening hours.'),dict(kind=kind,asset_id='hours')],
        assets=[dict(asset_id='hours',filename='hours.bin')])

def profile(document):
    if set(document)!={'summary'} or type(document['summary']) is not str:raise ValueError('invalid neutral assessment')

def analysis_profile(doc):
    if doc.get('engine_result_schema_version')!='1.0' or doc.get('status') not in ('completed','unavailable','failed','limited','timeout','cancelled'):
        raise ValueError('invalid result envelope')
    if (doc['status']=='completed')!=(type(doc.get('assessment')) is dict):raise ValueError('invalid result status')

def evidence_profile(doc):
    if doc.get('evidence_schema_version')!='1.0' or type(doc.get('source_ref')) is not dict:raise ValueError('invalid evidence envelope')

PROFILES={'analysis':StateProfile('neutral-detection-envelope','1.0',analysis_profile),
          'evidence':StateProfile('neutral-evidence-envelope','1.0',evidence_profile)}


class StorageBlocksIntegrationTests(unittest.IsolatedAsyncioTestCase):
    def resources(self,parent,durable):
        if durable:
            history=SqliteConversationStatus(root=parent/'memory',message_limits=INPUT,limits=HISTORY,storage_limits=DISK).__enter__()
            assets=PersistentAssetStore(root=parent/'originals',limits=FILES,storage_limits=DISK).__enter__()
            derived=SqliteDerivedState(history=history,limits=STATE,profiles=PROFILES)
        else:
            history=InMemoryConversationStatus(message_limits=INPUT,limits=HISTORY).__enter__()
            assets=LocalAssetStore(parent=parent,limits=FILES).__enter__()
            derived=InMemoryDerivedState(history=history,limits=STATE,profiles=PROFILES)
        return ConversationStatus(observations=history,derived=derived),assets,derived

    async def test_real_arrows_and_controller_substitution_for_both_backends(self):
        logical=[]
        for durable in (False,True):
            for use_tool in (False,True):
                with self.subTest(durable=durable,use_tool=use_tool), tempfile.TemporaryDirectory() as folder:
                    parent=Path(folder);memory,assets,_=self.resources(parent,durable)
                    self.addCleanup(memory.close);self.addCleanup(assets.close)
                    intake=DetectionIntake(memory.observations);preparer=ContextPreparer(message_limits=INPUT,limits=CONTEXT)
                    async def echo(scope,args):return CapabilityReply(encoded(dict(summary='Reading-room opening hours are recorded.')))
                    async def controller(invocation,broker):
                        payload=await broker.call('neutral_summary',b'{}') if use_tool else encoded(dict(summary='Reading-room opening hours are recorded.'))
                        return ControllerReply(payload,supporting=(PartReference(1,0),PartReference(1,1)))
                    host=ExecutionHost(intake=intake,preparer=preparer,limits=RUN,
                        capabilities=(CapabilitySpec('neutral_summary','1.0','tool',echo),),profile=AssessmentProfile('neutral-summary','1.0',profile))
                    captures=[]
                    async def consumer(snapshot):
                        boundary=HistoryBoundary(snapshot.key,snapshot.observed_count,
                            memory.observations.head(ACCESS,snapshot.key).store_id)
                        prepared=preparer.prepare(snapshot,ACCESS)
                        spec=ReaderSpec('independent-hours-reader','1.0',hashlib.sha256(b'{}').hexdigest(),frozenset(('file',)),frozenset(('whole_asset',)))
                        bridge=EvidencePreparer(store=assets,limits=EvidenceLimits(2097152,8192,8,8192,32768,256))
                        receipt=assets.describe(ACCESS,AssetKey('demo',ACCESS.account_id,'reading-room','opening-hours','hours'))
                        def reader(request):
                            self.assertEqual(request.data,DATA)
                            return ReaderOutput((EvidenceSegment('Opening hours: nine to five.',EvidenceLocation('whole_asset')),))
                        evidence=bridge.process(prepared,ACCESS,PartReference(1,1),spec=spec,reader=reader,expected_original=receipt)
                        self.assertEqual(evidence.status,'extracted')
                        initial=memory.detector.snapshot(ACCESS,boundary)
                        outcome=await host.run(DetectionRequest(boundary,ACCESS),strategy=ControllerSpec('tool-controller' if use_tool else 'direct-controller','1.0',controller),
                            allowed_capabilities=frozenset(('neutral_summary',)),initial_state_json=encoded(dict(memory_version=initial.version)))
                        self.assertEqual(outcome.status,'completed')
                        self.assertEqual(outcome.to_dict()['observed_count'],snapshot.observed_count)
                        self.assertEqual(outcome.to_dict()['context_sha256'],hashlib.sha256(prepared.json_bytes).hexdigest())
                        saved=memory.detector.commit(ACCESS,boundary,expected_version=initial.version,operation_id=outcome.to_dict()['run_id'],writes=(
                            StateWrite('evidence','hours',evidence.json_bytes,(SourceReference(1,1),)),
                            StateWrite('analysis','latest',outcome.json_bytes,(SourceReference(1,0),SourceReference(1,1)))))
                        captures.append((boundary,saved,outcome.to_dict()))
                    async with ConversationIngress(consumer,input_limits=INPUT,processing_limits=ProcessingLimits(1,8,131072,8,8,1.),
                            adapter=create_demo_adapter(clock=lambda:datetime(2026,11,11,tzinfo=timezone.utc)),intake=intake) as ingress:
                        first=ingress.submit_files(event(),{'hours':io.BytesIO(DATA)},ACCESS,store=assets)
                        later=event();later['id']='later-opening-hours'
                        second=ingress.submit_files(later,{'hours':io.BytesIO(DATA)},ACCESS,store=assets)
                        completed=await asyncio.gather(first.wait(),second.wait())
                        self.assertTrue(all(item.status=='completed' for item in completed))
                    self.assertEqual([item[0].observed_count for item in captures],[1,2])
                    boundary,saved,outcome=captures[0]
                    snapshot=memory.detector.reader().snapshot(ACCESS,boundary)
                    self.assertEqual(snapshot.version,1);self.assertEqual(len(snapshot.records),2)
                    logical.append((outcome['assessment'],outcome['supporting']))
                    self.assertEqual(outcome['usage']['capability_calls'],int(use_tool))
                    if durable:
                        memory.close();assets.close()
                        memory,assets,_=self.resources(parent,True)
                        self.addCleanup(memory.close);self.addCleanup(assets.close)
                        self.assertEqual(memory.detector.snapshot(ACCESS,boundary),snapshot)
                        self.assertEqual(assets.read(ACCESS,AssetKey('demo',ACCESS.account_id,'reading-room','opening-hours','hours')),DATA)
                    memory.close();assets.close()
        self.assertTrue(all(x==logical[0] for x in logical))

    async def test_sqlite_admission_failure_rolls_back_only_new_originals(self):
        with tempfile.TemporaryDirectory() as folder:
            memory,assets,_=self.resources(Path(folder),True)
            self.addCleanup(memory.close);self.addCleanup(assets.close)
            async def consumer(snapshot):self.fail('Rejected observation reached consumer')
            intake=DetectionIntake(memory.observations)
            async with ConversationIngress(consumer,input_limits=INPUT,processing_limits=ProcessingLimits(1,8,131072,8,8,1.),adapter=create_demo_adapter(),intake=intake) as ingress:
                with patch.object(memory.observations._database,'transaction',side_effect=OSError('PRIVATE_HISTORY_WRITE')):
                    with self.assertRaises(ValueError):ingress.submit_files(event(),{'hours':io.BytesIO(DATA)},ACCESS,store=assets)
            self.assertEqual(assets.stats['files'],0);self.assertEqual(memory.observations.stats['messages'],0)
            memory.close();assets.close()
            memory,assets,_=self.resources(Path(folder),True)
            self.addCleanup(memory.close);self.addCleanup(assets.close)
            self.assertEqual(assets.stats['files'],0);self.assertEqual(memory.observations.stats['messages'],0)

    async def test_failed_derived_commit_keeps_observations_and_originals(self):
        with tempfile.TemporaryDirectory() as folder:
            memory,assets,state=self.resources(Path(folder),True)
            self.addCleanup(memory.close);self.addCleanup(assets.close)
            intake=DetectionIntake(memory.observations)
            async def consumer(snapshot):
                boundary=memory.observations.head(ACCESS,snapshot.key)
                with patch.object(state,'_publish',side_effect=OSError('PRIVATE_STATE_WRITE')):
                    memory.detector.commit(ACCESS,boundary,expected_version=0,operation_id='failed-analysis',writes=(StateWrite('evidence','hours',encoded(dict(evidence_schema_version='1.0',source_ref=dict(observation_number=1,part_index=1))), (SourceReference(1,1),)),))
            with self.assertRaises(IngressError):
                async with ConversationIngress(consumer,input_limits=INPUT,processing_limits=ProcessingLimits(1,8,131072,8,8,1.),adapter=create_demo_adapter(),intake=intake) as ingress:
                    completed=await ingress.submit_files(event(),{'hours':io.BytesIO(DATA)},ACCESS,store=assets).wait()
                    self.assertEqual(completed.status,'failed')
            self.assertEqual(memory.observations.stats['messages'],1);self.assertEqual(state.stats['records'],0)
            self.assertEqual(assets.stats['files'],1)
            memory.close();assets.close()
            memory,assets,state=self.resources(Path(folder),True)
            self.addCleanup(memory.close);self.addCleanup(assets.close)
            self.assertEqual(memory.observations.stats['messages'],1);self.assertEqual(state.stats['records'],0)
            self.assertEqual(assets.stats['files'],1)
            memory.close();assets.close()

    async def test_uncertain_history_commit_preserves_originals_until_reopen(self):
        with tempfile.TemporaryDirectory() as folder:
            memory,assets,_=self.resources(Path(folder),True)
            self.addCleanup(memory.close);self.addCleanup(assets.close)
            history=memory.observations;database=history._database
            original_transaction=database.transaction;original_connection=database.db
            class ReadbackFailure:
                def execute(self,sql,*args):
                    if sql.startswith('SELECT payload FROM observations WHERE seq='):
                        import sqlite3
                        raise sqlite3.OperationalError('PRIVATE_READBACK_ERROR')
                    return original_connection.execute(sql,*args)
                @property
                def in_transaction(self):return original_connection.in_transaction
                def close(self):return original_connection.close()
            @contextmanager
            def after_commit():
                with original_transaction() as db:yield db
                raise OSError('PRIVATE_AFTER_COMMIT')
            async def consumer(snapshot):self.fail('Uncertain append was not acknowledged')
            async with ConversationIngress(consumer,input_limits=INPUT,processing_limits=ProcessingLimits(1,8,131072,8,8,1.),adapter=create_demo_adapter(),intake=DetectionIntake(history)) as ingress:
                with patch.object(database,'db',ReadbackFailure()),patch.object(database,'transaction',after_commit):
                    with self.assertRaises(IngressError) as caught:
                        ingress.submit_files(event(),{'hours':io.BytesIO(DATA)},ACCESS,store=assets)
                    self.assertEqual(caught.exception.code,'history_commit_uncertain')
            self.assertEqual(assets.stats['files'],1)
            memory.close();assets.close()
            memory,assets,_=self.resources(Path(folder),True)
            self.addCleanup(memory.close);self.addCleanup(assets.close)
            self.assertEqual(memory.observations.stats['messages'],1)
            self.assertEqual(assets.read(ACCESS,AssetKey('demo',ACCESS.account_id,'reading-room','opening-hours','hours')),DATA)
            memory.close();assets.close()
