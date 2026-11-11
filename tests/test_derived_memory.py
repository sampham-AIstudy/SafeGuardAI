"""Derived state ownership, prefix isolation, CAS and atomic retry behavior."""

import asyncio
from dataclasses import replace
from datetime import datetime, timezone
import json
import threading
import unittest
from unittest.mock import patch

from safeguard.adapters.demo import create_demo_adapter
from safeguard.conversation_memory import (ConversationMemory, HistoryLimits, InMemoryConversationMemory,
    InMemoryDerivedState, SourceReference, StateError, StateLimits, StateProfile, StateWrite)
from safeguard.ingress import AccessContext, InputLimits

INPUT=InputLimits(65536,4096,20,8192,32,16)
HISTORY=HistoryLimits(16,64,1048576,32,524288,64,1048576)
LIMITS=StateLimits(64,1048576,32,524288,64,1048576,4096,16,8192,16)
ACCESS=AccessContext('state-account',frozenset(('state-room','state-garden')))

def validate(document):
    if set(document)!={'summary'} or type(document['summary']) is not str: raise ValueError('PRIVATE_PROFILE_ERROR')

PROFILE=StateProfile('neutral-state','1.0',validate)

def write(summary='A neutral reading-room result.',namespace='analysis',record_id='current'):
    return StateWrite(namespace,record_id,json.dumps(dict(summary=summary)).encode(),(SourceReference(1,0),))


class DerivedMemoryTests(unittest.TestCase):
    def setUp(self):
        self.history=InMemoryConversationMemory(message_limits=INPUT,limits=HISTORY).__enter__()
        self.addCleanup(self.history.close)
        self.adapter=create_demo_adapter(clock=lambda:datetime(2026,11,11,tzinfo=timezone.utc))
        self.boundary=self.append()
        self.state=InMemoryDerivedState(history=self.history,limits=LIMITS,profiles={n:PROFILE for n in ('analysis','evidence','warnings')})
        self.addCleanup(self.state.close)
        self.memory=ConversationMemory(observations=self.history,derived=self.state)

    def append(self,index='first',room='state-room'):
        event=dict(thread=room,id=index,author='librarian',body='A newly authored reading-room observation.')
        message=self.adapter.receive(event,account_id=ACCESS.account_id,conversation_id=room)
        return self.history.append(ACCESS,message)

    def commit(self,*,boundary=None,expected=0,operation='analysis-operation',writes=None,view=None):
        return (view or self.memory.detector).commit(ACCESS,boundary or self.boundary,expected_version=expected,
            operation_id=operation,writes=(write(),) if writes is None else writes)

    def rejected(self,call,code):
        with self.assertRaises(StateError) as caught:call()
        self.assertEqual((caught.exception.code,str(caught.exception)),(code,code))
        self.assertNotIn('PRIVATE',str(caught.exception))

    def test_detached_immutable_records_and_observed_history_are_separate(self):
        receipt=self.commit();self.assertEqual(receipt.version,1)
        state=self.memory.detector.snapshot(ACCESS,self.boundary)
        self.assertEqual(state.version,1);record=state.records[0]
        self.assertEqual(record.boundary,self.boundary)
        self.assertEqual(record.profile_name,'neutral-state')
        document=record.payload();document['summary']='Receiver mutation.'
        self.assertEqual(record.payload(),write().payload_json and dict(summary='A neutral reading-room result.'))
        self.assertEqual(self.history.stats['messages'],1)
        reader=self.memory.detector.reader()
        self.assertFalse(hasattr(reader,'commit'))
        self.assertEqual(reader.snapshot(ACCESS,self.boundary),state)

    def test_atomic_batch_and_channel_ownership(self):
        self.commit(writes=(write(),write('Derived neutral text.',namespace='evidence',record_id='page')))
        self.assertEqual(len(self.memory.detector.snapshot(ACCESS,self.boundary).records),2)
        self.assertEqual(self.memory.warning_history.snapshot(ACCESS,self.boundary).records,())
        self.rejected(lambda:self.commit(expected=1,operation='forbidden',writes=(write(namespace='warnings'),)),'namespace_not_allowed')
        self.commit(view=self.memory.warning_history,operation='warning-record',writes=(write(namespace='warnings'),))
        self.assertEqual(self.memory.warning_history.snapshot(ACCESS,self.boundary).version,1)
        self.rejected(lambda:self.commit(view=self.memory.warning_history,expected=1,operation='forbidden-analysis'),'namespace_not_allowed')

    def test_invalid_second_write_leaves_no_first_write_or_retry_entry(self):
        before=self.state.stats.copy()
        bad=replace(write(record_id='second'),payload_json=b'{"wrong":true}')
        self.rejected(lambda:self.commit(writes=(write(),bad)),'invalid_state_profile_payload')
        self.assertEqual(self.state.stats,before)
        self.assertEqual(self.memory.detector.snapshot(ACCESS,self.boundary).version,0)
        self.commit() # Failed operation did not consume its ID.

    def test_idempotent_retry_and_conflicting_reuse(self):
        first=self.commit();before=self.state.stats.copy()
        self.assertEqual(self.commit(),first);self.assertEqual(self.state.stats,before)
        equivalent=replace(write(),payload_json=b'{ "summary" : "A neutral reading-room result." }')
        self.assertEqual(self.commit(writes=(equivalent,)),first)
        self.rejected(lambda:self.commit(writes=(write('Different result.'),)),'operation_conflict')
        self.commit(expected=1,operation='second')
        self.assertEqual(self.commit(),first) # Original retry receipt survives a newer revision.

    def test_compare_and_swap_preserves_current_state(self):
        self.commit();before=self.state.stats.copy()
        self.rejected(lambda:self.commit(operation='stale-version'),'state_conflict')
        self.assertEqual(self.state.stats,before)
        for value in (-1,True,1.0,'1'):
            with self.subTest(value=value):
                self.rejected(lambda:self.commit(expected=value,operation='bad-version'),'invalid_state_version')

    def test_old_prefix_reads_old_revision_and_late_result_does_not_replace_newer(self):
        self.commit()
        later=self.append('second')
        self.commit(boundary=later,expected=1,operation='later-analysis',writes=(write('Later analysis.'),))
        old=self.memory.detector.snapshot(ACCESS,self.boundary)
        new=self.memory.detector.snapshot(ACCESS,later)
        self.assertEqual(old.version,1);self.assertEqual(new.version,2)
        self.assertEqual(old.records[0].payload()['summary'],'A neutral reading-room result.')
        self.assertEqual(new.records[0].payload()['summary'],'Later analysis.')
        self.rejected(lambda:self.commit(expected=2,operation='late-analysis'),'stale_state_boundary')

    def test_future_and_cross_scope_references_fail_before_publication(self):
        for refs in ((SourceReference(2,0),),(SourceReference(1,1),),(SourceReference(1,0),)*2,[],({'observation_number':1,'part_index':0},)):
            with self.subTest(refs=refs):
                self.rejected(lambda:self.commit(writes=(replace(write(),references=refs),)),'invalid_source_reference')
        garden=self.append('garden','state-garden')
        self.commit(boundary=garden)
        self.assertEqual(self.memory.detector.snapshot(ACCESS,self.boundary).records,())
        bad=AccessContext('other-account',ACCESS.conversations)
        self.rejected(lambda:self.memory.detector.snapshot(bad,self.boundary),'invalid_observed_scope')
        self.rejected(lambda:self.memory.detector.commit(bad,self.boundary,expected_version=0,operation_id='foreign',writes=(write(),)),'invalid_observed_scope')
        foreign=replace(self.boundary,store_id='foreign-store')
        self.rejected(lambda:self.memory.detector.snapshot(ACCESS,foreign),'invalid_observed_scope')

    def test_payload_structure_and_identity_errors_are_sanitized(self):
        for raw in (b'[]',b'{"summary":"a","summary":"b"}',b'{"summary":NaN}',b'\xff',b'{',b'{"summary":"\\ud800"}'):
            with self.subTest(raw=raw):
                self.rejected(lambda:self.commit(writes=(replace(write(),payload_json=raw),)),'invalid_state_payload')
        for value in ('','  ',None,'\ud800'):
            with self.subTest(value=value):self.rejected(lambda:self.commit(operation=value),'invalid_state_identity')
        self.rejected(lambda:self.commit(writes=(write(),write())),'duplicate_state_record')
        self.rejected(lambda:self.commit(writes=[]),'invalid_state_writes')

    def test_profile_cannot_mutate_result_or_return_awaitable(self):
        def mutation(doc):doc['summary']=7
        def number_mutation(doc):doc['summary']=True
        def returns_value(doc):return {}
        async def coroutine():pass
        def returns_coroutine(doc):return coroutine()
        for callback in (mutation,number_mutation,returns_value,returns_coroutine):
            with self.subTest(callback=callback.__name__):
                state=InMemoryDerivedState(history=self.history,limits=LIMITS,profiles={'analysis':StateProfile('profile','1',callback)})
                self.addCleanup(state.close)
                self.rejected(lambda:state.commit(ACCESS,self.boundary,channel='detector',expected_version=0,operation_id='invalid',writes=(write(),)),'invalid_state_profile_payload')
                self.assertEqual(state.stats['records'],0)

    def test_capacity_failure_and_exact_byte_boundary(self):
        self.commit();charge=self.state.stats['bytes']
        for limit,expected in ((charge,None),(charge-1,'state_byte_limit')):
            state=InMemoryDerivedState(history=self.history,limits=replace(LIMITS,max_bytes=limit),profiles={'analysis':PROFILE})
            self.addCleanup(state.close)
            call=lambda:state.commit(ACCESS,self.boundary,channel='detector',expected_version=0,operation_id='analysis-operation',writes=(write(),))
            if expected:self.rejected(call,expected);self.assertEqual(state.stats['records'],0)
            else:call();self.assertEqual(state.stats['bytes'],charge)
        small=InMemoryDerivedState(history=self.history,limits=replace(LIMITS,max_records=1),profiles={'analysis':PROFILE})
        self.addCleanup(small.close)
        small.commit(ACCESS,self.boundary,channel='detector',expected_version=0,operation_id='first',writes=(write(),))
        self.rejected(lambda:small.commit(ACCESS,self.boundary,channel='detector',expected_version=1,operation_id='second',writes=(write(),)),'state_record_count_limit')

    def test_wrong_thread_and_closed_views_reject(self):
        errors=[]
        def other():
            try:self.memory.detector.snapshot(ACCESS,self.boundary)
            except StateError as error:errors.append(error.code)
        thread=threading.Thread(target=other);thread.start();thread.join(2)
        self.assertFalse(thread.is_alive());self.assertEqual(errors,['wrong_thread'])
        self.memory.close()
        self.rejected(lambda:self.memory.detector.snapshot(ACCESS,self.boundary),'state_closed')

    def test_failed_publication_does_not_change_state_and_hides_backend_detail(self):
        before=self.state.stats.copy()
        with patch.object(self.state,'_publish',side_effect=OSError('PRIVATE_DISK_DETAIL')):
            self.rejected(lambda:self.commit(),'state_storage_failed')
        self.assertEqual(self.state.stats,before)
        self.commit()
