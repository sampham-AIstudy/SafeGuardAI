"""Storage replacement through declared ports, using independently authored input."""

from datetime import datetime, timezone
import hashlib
import io
import tempfile
import unittest

from safeguard.adapters.demo import create_demo_adapter
from safeguard.conversation_memory import (ConversationKey, HistoryError, HistoryLimits,
    InMemoryConversationMemory, ObservedHistory)
from safeguard.ingress import AccessContext, ConversationIngress, InputLimits, ProcessingLimits
from safeguard.original_assets import AssetError, AssetKey, AssetLimits, LocalAssetStore, OriginalAssets
from safeguard.scam_detection.context import ContextLimits, ContextPreparer
from safeguard.scam_detection.intake import DetectionIntake
from safeguard.scam_detection.tools.evidence import (EvidenceLimits, EvidenceLocation, EvidencePreparer,
    EvidenceSegment, PartReference, ReaderOutput, ReaderSpec)

INPUT = InputLimits(65536, 4096, 20, 8192, 32, 16)
HISTORY = HistoryLimits(16, 64, 1048576, 32, 524288, 64, 1048576)
ASSETS = AssetLimits(4096, 16384, 8, 16384, 8, 64)
ACCESS = AccessContext('port-account', frozenset(('port-room',)))
DATA = b'Freshly authored catalogue entry for the reading room.\n'


class ForwardAssets(OriginalAssets):
    """Different trusted implementation identity, delegating the chosen byte backend."""
    def __init__(self, backend): self.backend, self.limits = backend, backend.limits
    def put_batch(self, context, uploads): return self.backend.put_batch(context, uploads)
    def describe(self, context, key): return self.backend.describe(context, key)
    def read(self, context, key): return self.backend.read(context, key)
    def copy_to(self, context, key, sink): return self.backend.copy_to(context, key, sink)
    def delete(self, context, key): return self.backend.delete(context, key)
    def close(self): return self.backend.close()


class ForwardHistory(ObservedHistory):
    def __init__(self, backend): self.backend, self.limits = backend, backend.limits
    def check(self, context, message): return self.backend.check(context, message)
    def append(self, context, message): return self.backend.append(context, message)
    def head(self, context, key): return self.backend.head(context, key)
    def snapshot(self, context, boundary): return self.backend.snapshot(context, boundary)
    def close(self): return self.backend.close()


class StoragePortTests(unittest.IsolatedAsyncioTestCase):
    def test_ports_are_explicit_and_incomplete_implementations_reject(self):
        for port in (OriginalAssets, ObservedHistory):
            with self.subTest(port=port.__name__), self.assertRaises(TypeError): port()
        with self.assertRaises(HistoryError): DetectionIntake(object())
        with self.assertRaises(ValueError):
            EvidencePreparer(store=object(), limits=EvidenceLimits(65536,4096,8,4096,16384,256))

    async def test_ingress_intake_and_reader_accept_independent_port_implementations(self):
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent,limits=ASSETS) as raw_assets, \
                InMemoryConversationMemory(message_limits=INPUT,limits=HISTORY) as raw_history:
            assets, history = ForwardAssets(raw_assets), ForwardHistory(raw_history)
            intake=DetectionIntake(history); seen=[]
            event=dict(thread='port-room',id='catalogue-entry',author='librarian',
                content_parts=[dict(kind='text',text='Please find the reading-room catalogue.'),dict(kind='file',asset_id='catalogue')],
                assets=[dict(asset_id='catalogue',filename='catalogue.txt')])
            async def consumer(snapshot):
                prepared=ContextPreparer(message_limits=INPUT,limits=ContextLimits(64,1048576,1048576,65536,256,128)).prepare(snapshot,ACCESS)
                bridge=EvidencePreparer(store=assets,limits=EvidenceLimits(1048576,4096,8,4096,16384,256))
                spec=ReaderSpec('independent-port-reader','1.0',hashlib.sha256(b'{}').hexdigest(),frozenset(('file',)),frozenset(('whole_asset',)))
                def reader(request):
                    self.assertEqual(request.data,DATA)
                    return ReaderOutput((EvidenceSegment('Reading-room catalogue.',EvidenceLocation('whole_asset')),))
                result=bridge.process(prepared,ACCESS,PartReference(1,1),spec=spec,reader=reader)
                seen.append((snapshot.observed_count,result.status))
            adapter=create_demo_adapter(clock=lambda:datetime(2026,11,11,tzinfo=timezone.utc))
            async with ConversationIngress(consumer,input_limits=INPUT,processing_limits=ProcessingLimits(1,8,65536,8,8,1.),adapter=adapter,intake=intake) as ingress:
                ticket=ingress.submit_files(event,{'catalogue':io.BytesIO(DATA)},ACCESS,store=assets)
                outcome=await ticket.wait()
                self.assertEqual(outcome.status,'completed')
            self.assertEqual(seen,[(1,'extracted')])
            key=AssetKey('demo','port-account','port-room','catalogue-entry','catalogue')
            self.assertEqual(assets.read(ACCESS,key),DATA)
            bad=AccessContext('other-account',frozenset(('port-room',)))
            with self.assertRaises(AssetError): assets.read(bad,key)
            with self.assertRaises(HistoryError): history.head(bad,ConversationKey('demo','port-account','port-room'))
            snapshot=intake.snapshot(intake.record(adapter.receive(dict(thread='port-room',id='later',author='librarian',body='A later catalogue note.'),account_id='port-account',conversation_id='port-room'),ACCESS))
            self.assertEqual(snapshot.observed_count,2)
