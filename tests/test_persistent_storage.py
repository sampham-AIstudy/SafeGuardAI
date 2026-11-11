"""Restart/crash/fault checks over self-authored local data, without model inference."""

from contextlib import contextmanager
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from safeguard.memory.conversation_status import (ConversationStatus, HistoryError, SqliteConversationStatus,
    SqliteDerivedState, StateError, StateProfile)
from safeguard.memory.original_assets import AssetError, AssetKey, AssetLimits, PersistentAssetStore
from safeguard.storage.local import LocalDatabase, StorageError, StorageLimits
from test_derived_state import ACCESS, HISTORY, INPUT, LIMITS, PROFILE, write
from test_storage_ports import DATA
from safeguard.adapters.demo import create_demo_adapter

DISK=StorageLimits(4194304,0.1)
ASSETS=AssetLimits(4096,16384,8,16384,8,64)
KEY=AssetKey('demo','state-account','state-room','persistent-note','original')


def append(history):
    event=dict(thread='state-room',id='persistent-note',author='librarian',body='An independently authored durable library note.')
    message=create_demo_adapter().receive(event,account_id=ACCESS.account_id,conversation_id='state-room')
    return history.append(ACCESS,message)


class PersistentStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def assets(self,**kwargs):
        return PersistentAssetStore(root=self.root/'originals',limits=kwargs.get('limits',ASSETS),storage_limits=kwargs.get('storage_limits',DISK))

    def history(self,**kwargs):
        return SqliteConversationStatus(root=self.root/'memory',message_limits=INPUT,limits=kwargs.get('limits',HISTORY),storage_limits=kwargs.get('storage_limits',DISK))

    def child(self,code):
        root=Path(__file__).resolve().parents[1]
        guard='''import sys, pathlib
project=pathlib.Path.cwd()
def deny(event,args):
    if event in ('open','os.listdir','os.scandir') and args and isinstance(args[0],(str,bytes)):
        p=pathlib.Path(args[0].decode() if isinstance(args[0],bytes) else args[0]).resolve()
        if any(p==project/x or project/x in p.parents for x in ('data/benchmarks','evaluation','testset','devset','.audit-private')):
            raise RuntimeError('Benchmark access forbidden in crash fixture')
sys.addaudithook(deny)
'''
        result=subprocess.run([sys.executable,'-c',guard+code],cwd=root,
            env=dict(os.environ,PYTHONPATH=str(root/'src')+os.pathsep+str(root/'tests')),
            capture_output=True,text=True,timeout=15)
        return result

    def test_originals_survive_close_reopen_and_preserve_receipts_and_quotas(self):
        with self.assets() as store:
            first=store.put(ACCESS,KEY,io.BytesIO(DATA))
            self.assertEqual(store.stats['files'],1)
        with self.assets() as store:
            self.assertEqual(store.describe(ACCESS,KEY),first)
            self.assertEqual(store.read(ACCESS,KEY),DATA)
            self.assertEqual(store.stats['bytes'],len(DATA))
            with self.assertRaises(AssetError):store.put(ACCESS,KEY,io.BytesIO(DATA))
            store.delete(ACCESS,KEY)
        with self.assets() as store:self.assertEqual(store.stats['files'],0)

    def test_observed_boundary_and_derived_revisions_survive_reopen(self):
        with self.history() as history:
            boundary=append(history)
            derived=SqliteDerivedState(history=history,limits=LIMITS,profiles={'analysis':PROFILE})
            memory=ConversationStatus(observations=history,derived=derived)
            receipt=memory.detector.commit(ACCESS,boundary,expected_version=0,operation_id='durable-analysis',writes=(write(),))
            derived.close()
        with self.history() as history:
            self.assertEqual(history.snapshot(ACCESS,boundary).observed_count,1)
            derived=SqliteDerivedState(history=history,limits=LIMITS,profiles={'analysis':PROFILE})
            self.addCleanup(derived.close)
            memory=ConversationStatus(observations=history,derived=derived)
            snapshot=memory.detector.snapshot(ACCESS,boundary)
            self.assertEqual(snapshot.version,1)
            self.assertEqual(snapshot.records[0].payload(),dict(summary='A neutral reading-room result.'))
            self.assertEqual(memory.detector.commit(ACCESS,boundary,expected_version=0,operation_id='durable-analysis',writes=(write(),)),receipt)
            self.assertEqual(derived.stats['records'],1)

    def test_reopen_with_smaller_quotas_rejects_without_deleting_data(self):
        with self.assets() as store:store.put(ACCESS,KEY,io.BytesIO(DATA))
        with self.assertRaises(AssetError):
            with self.assets(limits=replace(ASSETS,max_file_bytes=len(DATA)-1)):pass
        with self.assets() as store:self.assertEqual(store.read(ACCESS,KEY),DATA)
        with self.history() as history:append(history);append(history)
        with self.assertRaises(HistoryError):
            with self.history(limits=replace(HISTORY,max_messages=1)):pass
        with self.history() as history:self.assertEqual(history.stats['messages'],2)

    def test_second_open_is_rejected_until_owner_closes(self):
        with self.assets():
            with self.assertRaises(AssetError):
                with self.assets():pass
        with self.assets():pass
        with self.history():
            with self.assertRaises(HistoryError):
                with self.history():pass
        with self.history():pass

    def test_failed_catalog_publish_rolls_back_new_files_and_counters(self):
        with self.assets() as store:
            before=store.stats.copy()
            with patch.object(store,'_commit_receipts',side_effect=OSError('PRIVATE_CATALOG_FAILURE')):
                with self.assertRaises(AssetError) as caught:store.put(ACCESS,KEY,io.BytesIO(DATA))
            self.assertEqual(str(caught.exception),'storage_failed')
            self.assertEqual(store.stats,before)
        with self.assets() as store:self.assertEqual(store.stats['files'],0)

    def test_committed_catalog_is_not_rolled_back_on_uncertain_return(self):
        with self.assets() as store:
            publish=store._commit_receipts
            def fail_after_commit(receipts):publish(receipts);raise OSError('PRIVATE_AFTER_COMMIT')
            with patch.object(store,'_commit_receipts',side_effect=fail_after_commit):
                with self.assertRaises(AssetError) as caught:store.put(ACCESS,KEY,io.BytesIO(DATA))
            self.assertEqual(str(caught.exception),'storage_commit_uncertain')
        with self.assets() as store:self.assertEqual(store.read(ACCESS,KEY),DATA)

    def test_generated_orphans_recover_but_unknown_files_are_not_deleted(self):
        with self.assets():pass
        root=self.root/'originals';orphan=root/('e'*32);orphan.write_bytes(b'incomplete self-authored upload');orphan.chmod(0o600)
        with self.assets() as store:self.assertEqual(store.stats['files'],0)
        self.assertFalse(orphan.exists())
        unknown=root/'host-owned-note';unknown.write_text('A neutral host file.');unknown.chmod(0o600)
        with self.assertRaises(AssetError):
            with self.assets():pass
        self.assertTrue(unknown.exists())

    def test_corrupt_original_and_symlink_root_fail_closed(self):
        with self.assets() as store:
            store.put(ACCESS,KEY,io.BytesIO(DATA));name=store._entries[KEY][0]
        original=self.root/'originals'/name;original.chmod(0o600);original.write_bytes(b'tampered')
        with self.assertRaises(AssetError):
            with self.assets():pass
        target=self.root/'other';target.mkdir(mode=0o700)
        link=self.root/'linked';link.symlink_to(target,target_is_directory=True)
        with self.assertRaises(AssetError):
            with PersistentAssetStore(root=link,limits=ASSETS,storage_limits=DISK):pass

    def test_crash_before_and_after_original_catalog_commit(self):
        for phase,expected in (('before',0),('after',1)):
            with self.subTest(phase=phase):
                directory=self.root/phase
                code=f'''import os,io
from safeguard.memory.original_assets import PersistentAssetStore
from test_persistent_storage import ASSETS,DISK,ACCESS,KEY,DATA
store=PersistentAssetStore(root={str(directory)!r},limits=ASSETS,storage_limits=DISK).__enter__()
publish=store._commit_receipts
def crash(receipts):
    if {phase!r}=='after':publish(receipts)
    os._exit(19)
store._commit_receipts=crash
store.put(ACCESS,KEY,io.BytesIO(DATA))
'''
                result=self.child(code);self.assertEqual(result.returncode,19,result.stderr)
                with PersistentAssetStore(root=directory,limits=ASSETS,storage_limits=DISK) as store:
                    self.assertEqual(store.stats['files'],expected)
                    if expected:self.assertEqual(store.read(ACCESS,KEY),DATA)

    def test_crash_after_observation_commit_retains_exact_history(self):
        directory=self.root/'memory'
        code=f'''import os
from safeguard.memory.conversation_status import SqliteConversationStatus
from test_persistent_storage import INPUT,HISTORY,DISK,append
history=SqliteConversationStatus(root={str(directory)!r},message_limits=INPUT,limits=HISTORY,storage_limits=DISK).__enter__()
history._append_prepared=lambda *args:os._exit(23)
append(history)
'''
        result=self.child(code);self.assertEqual(result.returncode,23,result.stderr)
        with self.history() as history:self.assertEqual(history.stats['messages'],1)

    def test_changed_profile_is_not_silently_attributed_to_old_records(self):
        with self.history() as history:
            boundary=append(history)
            state=SqliteDerivedState(history=history,limits=LIMITS,profiles={'analysis':PROFILE})
            state.commit(ACCESS,boundary,channel='detector',expected_version=0,operation_id='profile-check',writes=(write(),))
            state.close()
        with self.history() as history:
            with self.assertRaises(StateError):
                SqliteDerivedState(history=history,limits=LIMITS,profiles={'analysis':StateProfile('different-profile','2.0',PROFILE.validate)})

    def test_interrupted_empty_database_initialization_can_resume(self):
        directory=self.root/'new';directory.mkdir(mode=0o700)
        empty=directory/'metadata.sqlite';empty.touch(mode=0o600)
        db=LocalDatabase(root=directory,kind='initialization-fixture',limits=DISK)
        db.close()
        again=LocalDatabase(root=directory,kind='initialization-fixture',limits=DISK);again.close()

    def test_crash_before_and_after_derived_sqlite_commit(self):
        for phase,expected in (('before',0),('after',1)):
            with self.subTest(phase=phase):
                directory=self.root/('derived-'+phase)
                code=f'''import os
from contextlib import contextmanager
from safeguard.memory.conversation_status import SqliteConversationStatus,SqliteDerivedState
from test_persistent_storage import INPUT,HISTORY,DISK,LIMITS,PROFILE,ACCESS,append,write
history=SqliteConversationStatus(root={str(directory)!r},message_limits=INPUT,limits=HISTORY,storage_limits=DISK).__enter__()
boundary=append(history)
state=SqliteDerivedState(history=history,limits=LIMITS,profiles={{'analysis':PROFILE}})
transaction=history._database.transaction
@contextmanager
def interrupted():
    with transaction() as db:
        yield db
        if {phase!r}=='before':os._exit(29)
    os._exit(29)
history._database.transaction=interrupted
state.commit(ACCESS,boundary,channel='detector',expected_version=0,operation_id='interrupted-derived',writes=(write(),))
'''
                result=self.child(code);self.assertEqual(result.returncode,29,result.stderr)
                with SqliteConversationStatus(root=directory,message_limits=INPUT,limits=HISTORY,storage_limits=DISK) as history:
                    state=SqliteDerivedState(history=history,limits=LIMITS,profiles={'analysis':PROFILE})
                    self.assertEqual(history.stats['messages'],1)
                    self.assertEqual(state.stats['records'],expected)
                    state.close()
