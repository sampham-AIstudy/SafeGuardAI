"""Durable originals: fsynced object files followed by atomic SQLite publication."""

import os
import re
import sqlite3
import stat
import threading

from safeguard.storage.local import LocalDatabase, StorageError
from .contracts import AssetError, AssetKey, StoredAsset
from .store import LocalAssetStore


class PersistentAssetStore(LocalAssetStore):
    """Single-owner Linux backend. Root is private and supplied by trusted assembly.

    Close preserves data. Startup validates every catalogued file and removes only
    unreferenced generated objects left by interrupted receipt/deletion. Missing or
    corrupt referenced originals fail closed. No retention/eviction is automatic.
    """
    def __init__(self, *, root, limits, storage_limits):
        super().__init__(parent=root,limits=limits)
        self._storage_limits=storage_limits
        self._database=None

    def __enter__(self):
        if self._state!='new':raise AssetError('already_started')
        try:
            self._database=LocalDatabase(root=self._parent,kind='original-assets',limits=self._storage_limits)
            self._dirfd=self._database.fd
            self._directory=self._database.directory
            self._owner,self._state=threading.get_ident(),'open'
            with self._database.transaction() as db:
                db.execute('''CREATE TABLE IF NOT EXISTS originals (
                    source TEXT NOT NULL, account TEXT NOT NULL, conversation TEXT NOT NULL,
                    message TEXT NOT NULL, asset TEXT NOT NULL, object_name TEXT NOT NULL UNIQUE,
                    size INTEGER NOT NULL, sha256 TEXT NOT NULL,
                    PRIMARY KEY(source,account,conversation,message,asset))''')
            rows=self._database.db.execute('SELECT source,account,conversation,message,asset,object_name,size,sha256 FROM originals')
            for row in rows:
                key=AssetKey(*row[:5]);name,size,digest=row[5:]
                if type(name) is not str or re.fullmatch('[0-9a-f]{32}',name) is None or type(size) is not int or size<0 or type(digest) is not str or re.fullmatch('[0-9a-f]{64}',digest) is None:
                    raise AssetError('invalid_catalog')
                self._entries[key]=(name,StoredAsset(key,size,digest))
                self._bytes+=size;self._account_bytes[key.account_id]+=size;self._account_files[key.account_id]+=1
                if size>self.limits.max_file_bytes or self._bytes>self.limits.max_total_bytes or len(self._entries)>self.limits.max_files or self._account_bytes[key.account_id]>self.limits.max_account_bytes or self._account_files[key.account_id]>self.limits.max_account_files:
                    raise AssetError('stored_asset_limit')
                fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self._dirfd)
                with self._wrap(fd,'rb') as stream:
                    info=os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size!=size:raise AssetError('integrity_failed')
                    self._verify(stream,self._entries[key][1])
            referenced={name for name,_ in self._entries.values()}
            for name in os.listdir(self._dirfd):
                if name in {'.owner.lock','metadata.sqlite','metadata.sqlite-journal','metadata.sqlite-wal','metadata.sqlite-shm'} or name in referenced:continue
                if re.fullmatch('[0-9a-f]{32}',name) is None:raise AssetError('unexpected_storage_entry')
                info=os.stat(name,dir_fd=self._dirfd,follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise AssetError('integrity_failed')
                os.unlink(name,dir_fd=self._dirfd)
            os.fsync(self._dirfd)
            return self
        except BaseException as error:
            self.close()
            if isinstance(error,AssetError):raise
            if isinstance(error,(StorageError,sqlite3.Error,OSError,ValueError,TypeError)):
                raise AssetError('storage_failed') from None
            raise

    def _commit_receipts(self, receipts):
        with self._database.transaction() as db:
            for receipt in receipts:
                name,_=self._entries[receipt.key]
                key=receipt.key
                db.execute('INSERT INTO originals VALUES (?,?,?,?,?,?,?,?)',
                    (key.source,key.account_id,key.conversation_id,key.message_id,key.asset_id,name,receipt.size_bytes,receipt.sha256))
            os.fsync(self._dirfd)

    def put_batch(self, context, uploads):
        receipts=super().put_batch(context,uploads)
        try:
            self._commit_receipts(receipts)
            return receipts
        except BaseException as error:
            # A commit error is not assumed to mean rollback. Check actual catalog
            # visibility before removing any original that might be committed.
            try:
                count=0
                for receipt in receipts:
                    k=receipt.key
                    count+=self._database.db.execute('SELECT count(*) FROM originals WHERE source=? AND account=? AND conversation=? AND message=? AND asset=?',
                        (k.source,k.account_id,k.conversation_id,k.message_id,k.asset_id)).fetchone()[0]
                if count:
                    self._state='broken'
                    raise AssetError('storage_commit_uncertain')
                for receipt in reversed(receipts):self._remove(receipt.key)
                os.fsync(self._dirfd)
            except (sqlite3.Error,OSError):
                self._state='broken'
                raise AssetError('storage_commit_uncertain') from None
            if isinstance(error,AssetError):raise
            if isinstance(error,(sqlite3.Error,StorageError,OSError)):raise AssetError('storage_failed') from None
            raise

    def delete(self, context, key):
        self._entry(context,key)
        try:
            with self._database.transaction() as db:
                db.execute('DELETE FROM originals WHERE source=? AND account=? AND conversation=? AND message=? AND asset=?',
                    (key.source,key.account_id,key.conversation_id,key.message_id,key.asset_id))
        except (sqlite3.Error,StorageError,OSError):
            self._state='broken'
            raise AssetError('storage_commit_uncertain') from None
        self._remove(key)
        try:os.fsync(self._dirfd)
        except OSError:
            self._state='broken';raise AssetError('cleanup_failed') from None

    def close(self):
        if self._busy:raise AssetError('store_busy')
        if hasattr(self,'_owner') and threading.get_ident()!=self._owner:raise AssetError('wrong_thread')
        if self._database is not None:
            self._database.close();self._database=None
        if hasattr(self,'_dirfd'):del self._dirfd
        self._entries.clear();self._account_bytes.clear();self._account_files.clear()
        self._bytes,self._state=0,'closed'
