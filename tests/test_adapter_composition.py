"""Adapter boundary checks using separately authored neutral inputs only."""

import unittest


class AdapterCompositionTests(unittest.TestCase):
    def test_public_adapter_composes_gateway_and_norm(self):
        from safeguard.adapters import Adapter
        from safeguard.adapters.gateways.demo import DemoGateway
        from safeguard.adapters.norm import normalize
        adapter = Adapter(gateway_factory=DemoGateway, norm=normalize)
        native = {"thread": "toy-room", "id": "toy-note", "author": "toy-reader", "body": "Toy reading note."}
        key = adapter.conversation_key(native, "toy-account")
        result = adapter.receive(native, account_id="toy-account", conversation_id=key[2])
        self.assertEqual(key, ("demo", "toy-account", "toy-room"))
        self.assertEqual(result["message_schema_version"], "2.0")
        self.assertEqual(result["content_parts"], [{"kind": "text", "text": "Toy reading note."}])

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
import asyncio
import gc
import warnings
from unittest.mock import patch

from safeguard.adapters import Adapter, AdapterError
from safeguard.adapters.demo import create_demo_adapter
from safeguard.adapters.gateways.demo import DemoGateway
from safeguard.adapters.norm import normalize
from safeguard.ingress import AccessContext, ConversationIngress, IngressError, InputLimits, ProcessingLimits

NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)
INPUT = InputLimits(65536, 4096, 16, 4096, 16, 8)
PROCESSING = ProcessingLimits(2, 16, 262144, 16, 16, 1.0)
ACCESS = AccessContext('toy-account', frozenset({'toy-room', 'toy-other'}))


def native(index=0):
    return dict(thread='toy-room', id=str(index), author='toy-reader', body='Toy reading note.', sent_at=None)


class ToyGateway:
    """Independent test source with different native field names; no real transport."""
    source = 'toy_source'

    @staticmethod
    def conversation_id(event):
        return event['room']

    def __init__(self, account_id, *, clock=lambda: NOW):
        self.account_id, self.clock = account_id, clock

    def receive(self, event):
        return dict(schema_version='1.0', source=self.source, account_id=self.account_id,
                    conversation_id=event['room'], message_id=event['note_id'], sender_id=event['writer'],
                    event_type='message.created', observed_at=self.clock().isoformat().replace('+00:00','Z'),
                    payload=deepcopy(event))


def toy_norm(envelope):
    return dict(message_schema_version='2.0', source=envelope['source'], account_id=envelope['account_id'],
                conversation_id=envelope['conversation_id'], message_id=envelope['message_id'],
                sender_id=envelope['sender_id'], content_parts=[dict(kind='text',text=envelope['payload']['note'])],
                assets=[], is_from_observed_account=envelope['sender_id']==envelope['account_id'],
                observed_at=envelope['observed_at'], sent_at=None, raw_payload=deepcopy(envelope['payload']))


def toy_event(index=0, room='toy-room'):
    return dict(room=room, note_id=str(index), writer='toy-reader', note='Independent toy source note.')


class AdapterBoundaryTests(unittest.TestCase):
    def receive(self, adapter=None, event=None):
        return (adapter or create_demo_adapter(clock=lambda:NOW)).receive(
            native() if event is None else event, account_id=ACCESS.account_id, conversation_id='toy-room')

    def rejected(self, adapter, stage, event=None):
        with self.assertRaises(AdapterError) as caught:
            self.receive(adapter,event)
        self.assertEqual(caught.exception.stage,stage)
        self.assertNotIn('PRIVATE_CANARY',str(caught.exception))

    def test_exact_legacy_output_and_detachment(self):
        value=native(); value['extension']={'items':[False,1,None]}
        before=deepcopy(value)
        expected=normalize(DemoGateway(ACCESS.account_id,clock=lambda:NOW).receive(value))
        result=self.receive(event=value)
        self.assertEqual(result,expected)
        self.assertEqual(value,before)
        value['extension']['items'].append('caller change')
        self.assertEqual(result['raw_payload'],before)
        result['raw_payload']['extension']['items'].append('receiver change')
        self.assertNotIn('receiver change',value['extension']['items'])

    def test_all_content_kinds_remain_exact(self):
        for kind in ('image','audio','video','file'):
            with self.subTest(kind=kind):
                value=native(); del value['body']
                value['content_parts']=[dict(kind=kind,asset_id='toy-asset'),dict(kind='text',text='Toy caption.')]
                value['assets']=[dict(asset_id='toy-asset',filename='toy.dat')]
                expected=normalize(DemoGateway(ACCESS.account_id,clock=lambda:NOW).receive(value))
                self.assertEqual(self.receive(event=value),expected)

    def test_injected_gateway_and_norm_support_different_native_shape(self):
        adapter=Adapter(gateway_factory=ToyGateway,norm=toy_norm)
        value=toy_event(); value['source']='demo'; value['account_id']='spoofed'
        self.assertEqual(adapter.conversation_key(value,ACCESS.account_id),('toy_source','toy-account','toy-room'))
        result=self.receive(adapter,value)
        self.assertEqual(result['source'],'toy_source')
        self.assertEqual(result['account_id'],ACCESS.account_id)
        self.assertEqual(result['raw_payload'],value)
        self.assertEqual(result['content_parts'],[dict(kind='text',text=value['note'])])

    def test_binding_is_immutable(self):
        adapter=create_demo_adapter()
        with self.assertRaises(FrozenInstanceError): adapter.source='other'

    def test_configuration_rejects_invalid_or_async_components(self):
        async def async_component(*args,**kwargs): return None
        for kwargs in (dict(gateway_factory=None,norm=normalize),dict(gateway_factory=DemoGateway,norm=None),
                       dict(gateway_factory=DemoGateway,norm=async_component),
                       dict(gateway_factory=DemoGateway,norm=normalize,clock=async_component)):
            with self.subTest(kwargs=kwargs),self.assertRaises(AdapterError): Adapter(**kwargs)

    def test_scope_errors_and_changed_conversation_are_rejected(self):
        adapter=create_demo_adapter()
        for value in ({},None,dict(native(),thread=''),dict(native(),thread=[])):
            with self.subTest(value=value), self.assertRaises(AdapterError): adapter.conversation_key(value,ACCESS.account_id)
        with self.assertRaises(AdapterError): adapter.conversation_key(native(),'')
        with self.assertRaises(AdapterError): adapter.receive(native(),account_id=ACCESS.account_id,conversation_id='toy-other')

    def test_gateway_envelope_contract_and_identity_drift(self):
        for field,value in (('schema_version','2.0'),('source','other'),('account_id','other'),
                            ('conversation_id','other'),('message_id',1),('sender_id',None),
                            ('event_type','message.updated'),('observed_at','invalid'),('payload',{}),('extra','PRIVATE_CANARY')):
            with self.subTest(field=field):
                class Changed(DemoGateway):
                    def receive(self,event):
                        result=super().receive(event); result[field]=value; return result
                self.rejected(Adapter(gateway_factory=Changed,norm=normalize),'gateway')

    def test_norm_cannot_change_provenance_or_self_justify_input_mutation(self):
        for field,value in (('source','other'),('account_id','other'),('conversation_id','other'),
                            ('message_id','other'),('sender_id','other'),('observed_at','2026-01-03T00:00:00Z'),
                            ('raw_payload',{'PRIVATE_CANARY':1}),('is_from_observed_account',1)):
            with self.subTest(field=field):
                def changed(envelope):
                    result=normalize(envelope); result[field]=value; return result
                self.rejected(Adapter(gateway_factory=DemoGateway,norm=changed),'normalizer')
        def mutating(envelope):
            envelope['payload']['body']='PRIVATE_CANARY'
            return normalize(envelope)
        self.rejected(Adapter(gateway_factory=DemoGateway,norm=mutating),'normalizer')

    def test_norm_must_return_common_message_and_valid_parts(self):
        for field,value in (('message_schema_version','3.0'),('content_parts',[]),('content_parts',[dict(kind='file',asset_id='missing')]),
                            ('assets',[{}]),('sent_at','2026-01-01T01:00:00+01:00'),('extra','PRIVATE_CANARY')):
            with self.subTest(field=field):
                def changed(envelope):
                    result=normalize(envelope); result[field]=value; return result
                self.rejected(Adapter(gateway_factory=DemoGateway,norm=changed),'normalizer')
        for value in (None,[],42):
            self.rejected(Adapter(gateway_factory=DemoGateway,norm=lambda e:value),'normalizer')

    def test_norm_cannot_introduce_invalid_utf8_text(self):
        def changed(envelope):
            result=normalize(envelope)
            result['content_parts'][0]['text']='\ud800'
            return result
        self.rejected(Adapter(gateway_factory=DemoGateway,norm=changed),'normalizer')

    def test_raw_provenance_distinguishes_bool_from_int(self):
        value=native(); value['extension']=False
        def changed(envelope):
            result=normalize(envelope); result['raw_payload']['extension']=0; return result
        self.rejected(Adapter(gateway_factory=DemoGateway,norm=changed),'normalizer',value)

    def test_callback_exceptions_are_sanitized(self):
        def failed(*args,**kwargs): raise RuntimeError('PRIVATE_CANARY')
        class Failed(DemoGateway):
            def receive(self,event): return failed()
        self.rejected(Adapter(gateway_factory=Failed,norm=normalize),'gateway')
        self.rejected(Adapter(gateway_factory=DemoGateway,norm=failed),'normalizer')

    def test_unexpected_coroutine_is_closed_without_warning(self):
        async def operation(): return None
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            self.rejected(Adapter(gateway_factory=DemoGateway,norm=lambda e:operation()),'normalizer')
            gc.collect()
        self.assertFalse([w for w in caught if 'never awaited' in str(w.message)])

    def test_stream_lazy_order_fail_stop_and_caller_ownership(self):
        visited=[]; closed=[]
        def source():
            try:
                for i in range(4):
                    visited.append(i); yield native(i) if i!=2 else {}
            finally: closed.append(True)
        events=source(); stream=create_demo_adapter(clock=lambda:NOW).receive_stream(events,account_id=ACCESS.account_id)
        self.assertEqual(visited,[])
        self.assertEqual(next(stream)['message_id'],'0')
        self.assertEqual(visited,[0])
        self.assertEqual(next(stream)['message_id'],'1')
        with self.assertRaises(AdapterError): next(stream)
        self.assertEqual(visited,[0,1,2]); self.assertEqual(closed,[])
        events.close(); self.assertEqual(closed,[True])

    def test_stream_delivery_completes_before_next_read(self):
        seen=[]
        def source():
            for i in range(3):
                self.assertEqual(len(seen),i); yield native(i)
        adapter=create_demo_adapter()
        count=adapter.deliver_stream(source(),lambda m:seen.append(m['message_id']),account_id=ACCESS.account_id)
        self.assertEqual((count,seen),(3,['0','1','2']))

    def test_awaitable_receiver_is_a_structured_contract_error(self):
        async def result(): return None
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            with self.assertRaises(AdapterError) as error:
                create_demo_adapter().deliver_stream([native()],lambda m:result(),account_id=ACCESS.account_id)
            self.assertEqual(error.exception.stage,'receiver')
            gc.collect()
        self.assertFalse([w for w in caught if 'never awaited' in str(w.message)])


class AdapterIngressTests(unittest.IsolatedAsyncioTestCase):
    async def test_non_demo_gateway_no_native_field_dependency(self):
        seen=[]
        async def consume(message): seen.append(message)
        adapter=Adapter(gateway_factory=ToyGateway,norm=toy_norm)
        async with ConversationIngress(consume,adapter=adapter,input_limits=INPUT,processing_limits=PROCESSING) as pipe:
            tickets=[pipe.submit(toy_event(i,room),ACCESS) for i in range(3) for room in ('toy-room','toy-other')]
            self.assertTrue(all(r.status=='completed' for r in await asyncio.gather(*(t.wait() for t in tickets))))
        for room in ('toy-room','toy-other'):
            self.assertEqual([m['message_id'] for m in seen if m['conversation_id']==room],['0','1','2'])
        self.assertTrue(all(m['source']=='toy_source' for m in seen))

    async def test_authorization_and_capacity_precede_gateway_receipt(self):
        gate=asyncio.Event()
        async def consume(_): await gate.wait()
        adapter=Adapter(gateway_factory=ToyGateway,norm=toy_norm)
        async with ConversationIngress(consume,adapter=adapter,input_limits=INPUT,processing_limits=replace(PROCESSING,max_pending=1)) as pipe:
            with patch.object(ToyGateway,'receive',side_effect=AssertionError('Must not receive')):
                with self.assertRaises(IngressError) as caught: pipe.submit(toy_event(room='denied'),ACCESS)
                self.assertEqual(caught.exception.stage,'authorization')
            ticket=pipe.submit(toy_event(),ACCESS)
            with patch.object(ToyGateway,'receive',side_effect=AssertionError('Must not receive')):
                with self.assertRaises(IngressError) as caught: pipe.submit(toy_event(),ACCESS)
                self.assertEqual(caught.exception.code,'busy')
            gate.set(); await ticket.wait()

    async def test_failure_acknowledgement_uses_configured_source(self):
        async def consume(message):
            if message['message_id']=='0': raise RuntimeError('PRIVATE_CANARY')
        adapter=Adapter(gateway_factory=ToyGateway,norm=toy_norm)
        with self.assertRaises(IngressError):
            async with ConversationIngress(consume,adapter=adapter,input_limits=INPUT,processing_limits=PROCESSING) as pipe:
                first=pipe.submit(toy_event(),ACCESS); follower=pipe.submit(toy_event(1),ACCESS)
                self.assertEqual((await first.wait()).status,'failed')
                self.assertEqual((await follower.wait()).status,'blocked')
                with self.assertRaises(IngressError): pipe.submit(toy_event(2),ACCESS)
                pipe.acknowledge_failure(ACCESS,'toy-room')
                self.assertEqual((await pipe.submit(toy_event(3),ACCESS).wait()).status,'completed')

    async def test_configured_adapter_required(self):
        async def consume(_): pass
        for value in (None,{},DemoGateway):
            with self.subTest(value=value),self.assertRaises(IngressError):
                ConversationIngress(consume,adapter=value,input_limits=INPUT,processing_limits=PROCESSING)

class NormalizedContentLimitTests(unittest.IsolatedAsyncioTestCase):
    async def test_source_specific_field_names_cannot_bypass_common_text_limit(self):
        seen=[]
        async def consume(message): seen.append(message)
        adapter=Adapter(gateway_factory=ToyGateway,norm=toy_norm)
        async with ConversationIngress(consume,adapter=adapter,input_limits=replace(INPUT,max_text_chars=3),processing_limits=PROCESSING) as pipe:
            with self.assertRaises(IngressError) as caught:
                pipe.submit(toy_event(),ACCESS)
            self.assertEqual((caught.exception.stage,caught.exception.code),('normalizer','text_too_long'))
            self.assertEqual((pipe.stats['admitted'],seen),(0,[]))

    async def test_normalized_part_and_asset_limits_apply_to_other_source_shapes(self):
        async def consume(_): self.fail('Limited content must not be admitted')
        for dimension in ('parts','assets'):
            with self.subTest(dimension=dimension):
                def expanded(envelope):
                    message=toy_norm(envelope)
                    if dimension=='parts':
                        message['content_parts']*=2
                    else:
                        message['content_parts']=[dict(kind='file',asset_id=str(i)) for i in range(2)]
                        message['assets']=[dict(asset_id=str(i),filename=None,declared_media_type=None,
                            declared_size_bytes=None,source_status='unknown',processing_status='not_requested') for i in range(2)]
                    return message
                limits=replace(INPUT,**({'max_content_parts':1} if dimension=='parts' else {'max_assets':1}))
                adapter=Adapter(gateway_factory=ToyGateway,norm=expanded)
                async with ConversationIngress(consume,adapter=adapter,input_limits=limits,processing_limits=PROCESSING) as pipe:
                    with self.assertRaises(IngressError) as caught: pipe.submit(toy_event(),ACCESS)
                    self.assertEqual(caught.exception.code,'too_many_content_parts' if dimension=='parts' else 'too_many_assets')
                    self.assertEqual(pipe.stats['admitted'],0)
