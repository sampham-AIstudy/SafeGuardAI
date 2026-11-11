"""Focused fault review of storage identity, ownership and persistent derived writes."""

from contextlib import contextmanager
import io
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from safeguard.conversation_memory import (ConversationKey, HistoryError, SqliteConversationMemory,
    SqliteDerivedState, StateError, StateProfile)
from safeguard.original_assets import AssetError, AssetKey, PersistentAssetStore
from safeguard.storage.local import LocalDatabase, StorageError
from test_persistent_storage import DISK, ASSETS, ACCESS, HISTORY, INPUT, LIMITS, PROFILE, write, append


class StorageHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def history(self):
        return SqliteConversationMemory(root=self.root/'memory',message_limits=INPUT,limits=HISTORY,storage_limits=DISK)

    def test_history_startup_on_wrong_thread_rejects_before_opening_storage(self):
        history=self.history();errors=[]
        def other_thread():
            try:history.__enter__()
            except HistoryError as error:errors.append(error.code)
            finally:
                # The pre-fix implementation can open SQLite on the wrong thread.
                # Release that fixture connection on its creating thread.
                if history._database is not None:
                    history._database.close();history._database=None
        thread=threading.Thread(target=other_thread);thread.start();thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors,['wrong_thread'])
        self.assertFalse((self.root/'memory').exists())

    def test_initialization_never_treats_existing_host_files_as_upload_orphans(self):
        directory=self.root/'host-data';directory.mkdir(mode=0o700)
        original=directory/('f'*32);original.write_bytes(b'Preexisting independently authored host data.');original.chmod(0o600)
        for attempt in range(2):
            with self.subTest(attempt=attempt),self.assertRaises(AssetError):
                with PersistentAssetStore(root=directory,limits=ASSETS,storage_limits=DISK):pass
            self.assertEqual(original.read_bytes(),b'Preexisting independently authored host data.')

    def test_invalid_unicode_identifiers_reject_at_contract_boundary(self):
        for construct,error in ((lambda:AssetKey('demo','\ud800','room','message','asset'),AssetError),
                                (lambda:ConversationKey('demo','account','\ud800'),HistoryError),
                                (lambda:StateProfile('\ud800','1',lambda doc:None),StateError)):
            with self.subTest(error=error.__name__),self.assertRaises(error):construct()

    def test_second_derived_writer_for_same_sqlite_history_is_rejected(self):
        with self.history() as history:
            append(history)
            first=SqliteDerivedState(history=history,limits=LIMITS,profiles={'analysis':PROFILE})
            self.addCleanup(first.close)
            with self.assertRaises(StateError):
                duplicate=SqliteDerivedState(history=history,limits=LIMITS,profiles={'analysis':PROFILE})
                duplicate.close()
            first.close()
            replacement=SqliteDerivedState(history=history,limits=LIMITS,profiles={'analysis':PROFILE})
            replacement.close()

    def test_persisted_store_identity_must_be_canonical_hex(self):
        directory=self.root/'identity'
        database=LocalDatabase(root=directory,kind='identity-fixture',limits=DISK);database.close()
        with sqlite3.connect(directory/'metadata.sqlite') as db:
            db.execute('UPDATE storage_identity SET store_id=?',('z'*32,))
        with self.assertRaises(StorageError):
            database=LocalDatabase(root=directory,kind='identity-fixture',limits=DISK)
            database.close()

    def test_derived_database_failure_leaves_no_visible_or_replayed_state(self):
        with self.history() as history:
            boundary=append(history)
            state=SqliteDerivedState(history=history,limits=LIMITS,profiles={'analysis':PROFILE})
            with patch.object(history._database,'transaction',side_effect=OSError('PRIVATE_STATE_COMMIT')):
                with self.assertRaises(StateError) as caught:
                    state.commit(ACCESS,boundary,channel='detector',expected_version=0,operation_id='retry',writes=(write(),))
            self.assertEqual(str(caught.exception),'state_storage_failed')
            self.assertEqual(state.stats['records'],0);state.close()
        with self.history() as history:
            state=SqliteDerivedState(history=history,limits=LIMITS,profiles={'analysis':PROFILE})
            self.assertEqual(state.stats['records'],0)
            state.commit(ACCESS,boundary,channel='detector',expected_version=0,operation_id='retry',writes=(write(),))
            state.close()

    def test_duplicate_json_keys_in_persisted_transaction_fail_closed(self):
        with self.history() as history:
            boundary=append(history)
            state=SqliteDerivedState(history=history,limits=LIMITS,profiles={'analysis':PROFILE})
            state.commit(ACCESS,boundary,channel='detector',expected_version=0,operation_id='duplicate-check',writes=(write(),))
            state.close()
        import json
        path=self.root/'memory'/'metadata.sqlite'
        with sqlite3.connect(path) as db:
            original=db.execute('SELECT payload FROM derived_transactions').fetchone()[0]
            corrupted=b'{"channel":"detector",'+original[1:]
            db.execute('UPDATE derived_transactions SET payload=?',(corrupted,))
        with self.history() as history:
            with self.assertRaises(StateError):
                state=SqliteDerivedState(history=history,limits=LIMITS,profiles={'analysis':PROFILE})
                state.close()

    def test_observation_commit_is_reconciled_after_post_commit_error(self):
        with self.history() as history:
            original=history._database.transaction
            @contextmanager
            def after_commit():
                with original() as db:yield db
                raise OSError('PRIVATE_AFTER_COMMIT')
            with patch.object(history._database,'transaction',after_commit):
                boundary=append(history)
            self.assertEqual(history.snapshot(ACCESS,boundary).observed_count,1)
        with self.history() as history:self.assertEqual(history.stats['messages'],1)

    def test_derived_commit_is_reconciled_after_post_commit_error(self):
        with self.history() as history:
            boundary=append(history)
            state=SqliteDerivedState(history=history,limits=LIMITS,profiles={'analysis':PROFILE})
            self.addCleanup(state.close)
            original=history._database.transaction
            @contextmanager
            def after_commit():
                with original() as db:yield db
                raise OSError('PRIVATE_AFTER_COMMIT')
            with patch.object(history._database,'transaction',after_commit):
                receipt=state.commit(ACCESS,boundary,channel='detector',expected_version=0,operation_id='reconciled',writes=(write(),))
            self.assertEqual(receipt.version,1)
            self.assertEqual(state.commit(ACCESS,boundary,channel='detector',expected_version=0,operation_id='reconciled',writes=(write(),)),receipt)
            state.close()
        with self.history() as history:
            state=SqliteDerivedState(history=history,limits=LIMITS,profiles={'analysis':PROFILE})
            self.assertEqual(state.stats['records'],1);state.close()
