"""Durable observed history and replayable derived transactions in one local database."""

from dataclasses import asdict
import sqlite3

from safeguard.storage.local import LocalDatabase, StorageError
from .contracts import ConversationKey, HistoryBoundary, HistoryError
from .in_memory import InMemoryConversationStatus
from .derived import (InMemoryDerivedState, SourceReference, StateError, StateWrite, encoded)


class SqliteConversationStatus(InMemoryConversationStatus):
    """Bounded RAM working set backed by SQLite; close preserves observations.

    One open owner per directory and one host thread. Persistent boundary identity
    survives reopen. Each append is committed before it is exposed in RAM.
    """
    def __init__(self, *, root, message_limits, limits, storage_limits):
        super().__init__(message_limits=message_limits,limits=limits)
        self._root,self._storage_limits=root,storage_limits
        self._database=None

    def __enter__(self):
        from safeguard.ingress import AccessContext
        super().__enter__()
        try:
            self._database=LocalDatabase(root=self._root,kind='conversation-memory',limits=self._storage_limits)
            self._id=self._database.store_id
            with self._database.transaction() as db:
                db.execute('CREATE TABLE IF NOT EXISTS observations (seq INTEGER PRIMARY KEY, payload BLOB NOT NULL)')
                db.execute('CREATE TABLE IF NOT EXISTS derived_transactions (seq INTEGER PRIMARY KEY, payload BLOB NOT NULL)')
            count=self._database.db.execute('SELECT count(*) FROM observations').fetchone()[0]
            if count>self.limits.max_messages:raise HistoryError('message_limit')
            invalid=self._database.db.execute('SELECT count(*) FROM observations WHERE typeof(payload)!=? OR length(payload)>?',
                ('blob',self.message_limits.max_bytes)).fetchone()[0]
            if invalid:raise HistoryError('invalid_stored_history')
            for length,payload in self._database.db.execute('SELECT length(payload),payload FROM observations ORDER BY seq'):
                if type(length) is not int or length>self.message_limits.max_bytes or type(payload) is not bytes:
                    raise HistoryError('invalid_stored_history')
                document=self.message_limits.decode(payload)
                context=AccessContext(document['account_id'],frozenset((document['conversation_id'],)))
                InMemoryConversationStatus.append(self,context,document)
            return self
        except BaseException as error:
            self.close()
            if isinstance(error,HistoryError):raise
            if isinstance(error,(StorageError,sqlite3.Error,OSError,ValueError,KeyError,TypeError)):
                raise HistoryError('history_storage_failed') from None
            raise

    def append(self, context, message):
        key,canonical,size=self._prepare(context,message)
        try:
            self._database.append_blob('observations',encoded(canonical))
        except StorageError as error:
            if error.code=='storage_commit_uncertain':
                self._state='broken'
                raise HistoryError('history_commit_uncertain') from None
            raise HistoryError('history_storage_failed') from None
        try:return self._append_prepared(key,canonical,size)
        except Exception:
            self._state='broken'
            raise HistoryError('history_commit_uncertain') from None

    def close(self):
        # Enforce thread ownership before closing the database/lock.
        super().close()
        if self._database is not None:
            self._database.close();self._database=None


class SqliteDerivedState(InMemoryDerivedState):
    """Replay canonical transactions; persistence precedes each RAM publication."""
    def __init__(self, *, history, limits, profiles):
        if not isinstance(history,SqliteConversationStatus) or history._database is None:
            raise StateError('open_sqlite_history_required')
        if getattr(history,'_derived_owner',None) is not None:
            raise StateError('derived_store_busy')
        super().__init__(history=history,limits=limits,profiles=profiles)
        history._derived_owner=self
        from safeguard.ingress import AccessContext
        from safeguard.ingress.limits import InputLimits
        self._replaying=True
        try:
            count=history._database.db.execute('SELECT count(*) FROM derived_transactions').fetchone()[0]
            if count>limits.max_records:raise StateError('state_record_count_limit')
            for length,raw in history._database.db.execute('SELECT length(payload),payload FROM derived_transactions ORDER BY seq'):
                if type(length) is not int or length>history._storage_limits.max_database_bytes or type(raw) is not bytes:
                    raise StateError('invalid_stored_state')
                # Local metadata is still parsed as data, never unpickled or executed.
                ceiling=history._storage_limits.max_database_bytes
                policy=InputLimits(ceiling,ceiling,limits.max_json_depth+8,
                    (limits.max_json_nodes+128)*limits.max_records,limits.max_records,limits.max_records)
                doc=policy.decode(raw)
                policy.inspect(doc)
                if set(doc)!={'boundary','channel','expected_version','operation_id','writes'}:raise StateError('invalid_stored_state')
                boundary_doc=doc['boundary'];key=ConversationKey(**boundary_doc['key'])
                boundary=HistoryBoundary(key,boundary_doc['observed_count'],boundary_doc['store_id'])
                for w in doc['writes']:
                    if set(w)!={'namespace','record_id','payload','references','profile'}:
                        raise StateError('invalid_stored_state')
                    profile=self.profiles.get(w['namespace'])
                    if profile is None or w['profile']!={'name':profile.name,'version':profile.version}:
                        raise StateError('stored_profile_mismatch')
                writes=tuple(StateWrite(w['namespace'],w['record_id'],encoded(w['payload']),tuple(SourceReference(**r) for r in w['references'])) for w in doc['writes'])
                before=len(self._data['operations'])
                self.commit(AccessContext(key.account_id,frozenset((key.conversation_id,))),boundary,
                    channel=doc['channel'],expected_version=doc['expected_version'],operation_id=doc['operation_id'],writes=writes)
                if len(self._data['operations'])!=before+1:raise StateError('invalid_stored_state')
        except BaseException as error:
            self.close()
            if isinstance(error,StateError):raise
            if isinstance(error,(sqlite3.Error,OSError,ValueError,KeyError,TypeError)):
                raise StateError('state_storage_failed') from None
            raise
        finally:self._replaying=False

    def _publish(self, data):
        if not self._replaying:
            added=set(data['operations'])-set(self._data['operations'])
            if len(added)!=1:raise StateError('invalid_state_transaction')
            identity=added.pop();_,channel,operation_id=identity
            receipt=data['operations'][identity][1]
            records=data['records'][len(self._data['records']):]
            document=dict(boundary=asdict(receipt.boundary),channel=channel,expected_version=receipt.version-1,
                operation_id=operation_id,writes=[dict(namespace=r.namespace,record_id=r.record_id,payload=r.payload(),
                    profile=dict(name=r.profile_name,version=r.profile_version),
                    references=[asdict(ref) for ref in r.references]) for r in records])
            try:
                self.history._database.append_blob('derived_transactions',encoded(document))
            except StorageError as error:
                if error.code=='storage_commit_uncertain':
                    self._broken=True
                    raise StateError('state_commit_uncertain') from None
                raise OSError('state_storage_failed') from None
        try:super()._publish(data)
        except Exception:
            self._broken=True
            raise StateError('state_commit_uncertain') from None

    def close(self):
        super().close()
        if getattr(self.history,'_derived_owner',None) is self:
            self.history._derived_owner=None
