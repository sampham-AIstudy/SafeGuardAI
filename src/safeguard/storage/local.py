"""Private Linux directory, exclusive owner and explicit SQLite transactions."""

from contextlib import contextmanager
from dataclasses import dataclass
try:
    import fcntl
except ImportError:
    fcntl=None
import math
import os
import re
from pathlib import Path
import sqlite3
import stat
from uuid import uuid4


class StorageError(ValueError):
    def __init__(self, code):
        self.code=code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class StorageLimits:
    max_database_bytes: int
    busy_timeout_seconds: float

    def __post_init__(self):
        if type(self.max_database_bytes) is not int or self.max_database_bytes<4096 or type(self.busy_timeout_seconds) not in (int,float) or not math.isfinite(self.busy_timeout_seconds) or self.busy_timeout_seconds<0:
            raise StorageError('invalid_storage_limits')


class LocalDatabase:
    """One open owner per private directory; not a multi-process service backend.

    SQLite commits metadata atomically. External asset bytes need their own
    ordered file/fsync/catalog protocol. Close preserves all committed data.
    """
    def __init__(self, *, root, kind, limits):
        if type(limits) is not StorageLimits: raise StorageError('invalid_storage_limits')
        if os.name!='posix' or fcntl is None or not Path('/proc/self/fd').is_dir(): raise StorageError('unsupported_platform')
        self.directory=Path(root);self.db=None;self.fd=None;self.lock=None
        try:
            try:os.mkdir(self.directory,0o700)
            except FileExistsError:pass
            self.fd=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            info=os.fstat(self.fd)
            if info.st_uid!=os.getuid() or info.st_mode&0o077: raise StorageError('unsafe_storage_directory')
            self.lock=os.open('.owner.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=self.fd)
            self._regular(self.lock)
            try:fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise StorageError('storage_busy') from None
            fresh=False
            try:
                fd=os.open('metadata.sqlite',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
                fresh=True
            except FileExistsError:
                fd=os.open('metadata.sqlite',os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.fd)
            try:self._regular(fd)
            finally:os.close(fd)
            for name in ('metadata.sqlite-journal','metadata.sqlite-wal','metadata.sqlite-shm'):
                try:
                    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.fd)
                except FileNotFoundError:continue
                try:self._regular(fd)
                finally:os.close(fd)
            self.db=sqlite3.connect(f'/proc/self/fd/{self.fd}/metadata.sqlite',timeout=limits.busy_timeout_seconds,isolation_level=None)
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA foreign_keys=ON')
            page=self.db.execute('PRAGMA page_size').fetchone()[0]
            if self.db.execute('PRAGMA page_count').fetchone()[0]*page>limits.max_database_bytes:raise StorageError('storage_limit')
            self.db.execute(f'PRAGMA max_page_count={limits.max_database_bytes//page}')
            # A crash before the first schema transaction can leave an empty,
            # private SQLite file. Only an entirely empty schema is initialized.
            empty_schema=not self.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            if fresh or empty_schema:
                # A new store has never issued upload object names. Do not adopt
                # or delete preexisting host files just because a name looks like
                # a generated object. A dedicated root is required on every retry.
                allowed={'.owner.lock','metadata.sqlite','metadata.sqlite-journal','metadata.sqlite-wal','metadata.sqlite-shm'}
                with os.scandir(self.fd) as entries:
                    if any(entry.name not in allowed for entry in entries):
                        raise StorageError('unexpected_storage_entry')
                with self.transaction():
                    self.db.execute('CREATE TABLE storage_identity (kind TEXT NOT NULL, version INTEGER NOT NULL, store_id TEXT NOT NULL)')
                    self.db.execute('INSERT INTO storage_identity VALUES (?,1,?)',(kind,uuid4().hex))
            identity=self.db.execute('SELECT kind,version,store_id FROM storage_identity').fetchall()
            if len(identity)!=1 or identity[0][0]!=kind or identity[0][1]!=1 or type(identity[0][2]) is not str or re.fullmatch('[0-9a-f]{32}',identity[0][2]) is None:
                raise StorageError('invalid_storage_identity')
            self.store_id=identity[0][2]
            if self.db.execute('PRAGMA quick_check').fetchone()!=('ok',):raise StorageError('storage_integrity_failed')
            os.fsync(self.fd)
        except BaseException as error:
            self.close()
            if isinstance(error,StorageError):raise
            if isinstance(error,(OSError,sqlite3.Error)):raise StorageError('storage_failed') from None
            raise

    @staticmethod
    def _regular(fd):
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.getuid() or info.st_mode&0o077:
            raise StorageError('unsafe_storage_file')

    @contextmanager
    def transaction(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield self.db
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise

    def append_blob(self, table, payload):
        """Reconcile a known row after an exception near commit acknowledgement.

        A missing row is a confirmed failed append; a matching row is committed.
        Failed readback is explicitly uncertain and must stop cached writers.
        """
        if table not in ('observations','derived_transactions'):
            raise StorageError('invalid_storage_table')
        sequence=None
        try:
            with self.transaction() as db:
                sequence=db.execute(f'INSERT INTO {table}(payload) VALUES (?)',(payload,)).lastrowid
            return sequence
        except (sqlite3.Error,OSError,StorageError):
            if sequence is None:raise StorageError('storage_failed') from None
            try:row=self.db.execute(f'SELECT payload FROM {table} WHERE seq=?',(sequence,)).fetchone()
            except (sqlite3.Error,OSError):raise StorageError('storage_commit_uncertain') from None
            if row is None:raise StorageError('storage_failed') from None
            if row==(payload,):return sequence
            raise StorageError('storage_commit_uncertain') from None

    def close(self):
        if self.db is not None:
            self.db.close();self.db=None
        if self.lock is not None:
            os.close(self.lock);self.lock=None
        if self.fd is not None:
            os.close(self.fd);self.fd=None
