"""Temporary POSIX disk backend, owned by one host thread and store context."""

from collections import Counter
import hashlib
import io
import os
from pathlib import Path
import shutil
import stat
import tempfile
import threading
from uuid import uuid4


from .contracts import AssetError, AssetKey, AssetLimits, StoredAsset
from .ports import OriginalAssets


class LocalAssetStore(OriginalAssets):
    """Private temporary originals; explicit quotas, no eviction or network.

    Streams are caller-owned cooperative binary readers/writers. IO is synchronous;
    blocking callbacks cannot be preempted. The host supplies fresh AccessContext.
    Close removes this store's temporary directory; no restart persistence exists.
    """

    def __init__(self, *, parent, limits: AssetLimits):
        if type(limits) is not AssetLimits:
            raise AssetError("invalid_limits")
        self.limits, self._parent = limits, Path(parent)
        self._state, self._busy = "new", False
        self._entries, self._bytes = {}, 0
        self._account_bytes, self._account_files = Counter(), Counter()

    def __enter__(self):
        if self._state != "new":
            raise AssetError("already_started")
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise AssetError("unsupported_platform")
        try:
            self._directory = Path(tempfile.mkdtemp(prefix="safeguard-assets-", dir=self._parent))
            self._dirfd = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            self._state = "broken"
            if hasattr(self, "_directory"):
                try:
                    # No object was created before the directory handle opened.
                    # Removing this empty directory needs no second os.open.
                    os.rmdir(self._directory)
                    del self._directory
                except OSError:
                    raise AssetError("cleanup_failed") from None
            raise AssetError("storage_failed") from None
        self._owner, self._state = threading.get_ident(), "open"
        return self

    def _check(self):
        if self._state != "open":
            raise AssetError("store_not_open" if self._state != "broken" else "storage_broken")
        if threading.get_ident() != self._owner:
            raise AssetError("wrong_thread")
        if self._busy:
            raise AssetError("store_busy")

    def _authorize(self, context, key):
        self._check()
        # Lazy import reuses the existing trusted-host contract without a module
        # initialization cycle between assets and ingress.
        from safeguard.ingress.pipeline import AccessContext
        if type(context) is not AccessContext:
            raise AssetError("trusted_context_required")
        if type(key) is not AssetKey:
            raise AssetError("invalid_reference")
        if key.account_id != context.account_id or key.conversation_id not in context.conversations:
            raise AssetError("asset_not_allowed")

    @property
    def stats(self):
        return dict(state=self._state, files=len(self._entries), bytes=self._bytes)

    def _entry(self, context, key):
        self._authorize(context, key)
        if key not in self._entries:
            raise AssetError("asset_not_found")
        return self._entries[key]

    def describe(self, context, key) -> StoredAsset:
        """Return recorded size/hash; this does not re-read physical storage."""
        return self._entry(context, key)[1]

    def put(self, context, key, stream) -> StoredAsset:
        return self.put_batch(context, {key: stream})[0]

    def put_batch(self, context, uploads: dict) -> tuple[StoredAsset, ...]:
        """All new originals succeed or are removed; existing objects stay intact."""
        self._check()
        if type(uploads) is not dict or not uploads:
            raise AssetError("invalid_uploads")
        for key, stream in uploads.items():
            self._authorize(context, key)
            if key in self._entries:
                raise AssetError("asset_exists")
            if not callable(getattr(stream, "read", None)):
                raise AssetError("expected_binary_reader")
        if len(self._entries)+len(uploads) > self.limits.max_files:
            raise AssetError("file_count_limit")
        if self._account_files[context.account_id]+len(uploads) > self.limits.max_account_files:
            raise AssetError("account_file_count_limit")
        self._busy = True
        done = []
        try:
            for key, stream in uploads.items():
                receipt = self._write(key, stream)
                done.append(receipt)
            return tuple(done)
        except BaseException:
            for receipt in reversed(done):
                self._remove(receipt.key)
            raise
        finally:
            self._busy = False

    def _write(self, key, stream):
        name, size, digest = uuid4().hex, 0, hashlib.sha256()
        created = False
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self._dirfd)
            created = True
            with self._wrap(fd, "wb") as target:
                while True:
                    room = min(self.limits.max_file_bytes-size, self.limits.max_total_bytes-self._bytes-size,
                               self.limits.max_account_bytes-self._account_bytes[key.account_id]-size)
                    request = min(self.limits.chunk_bytes, room+1)
                    try:
                        chunk = stream.read(request)
                    except Exception:
                        raise AssetError("source_failed") from None
                    if type(chunk) is not bytes or len(chunk) > request:
                        raise AssetError("invalid_binary_reader")
                    if not chunk:
                        break
                    if size+len(chunk) > self.limits.max_file_bytes:
                        raise AssetError("file_byte_limit")
                    if self._bytes+size+len(chunk) > self.limits.max_total_bytes:
                        raise AssetError("total_byte_limit")
                    if self._account_bytes[key.account_id]+size+len(chunk) > self.limits.max_account_bytes:
                        raise AssetError("account_byte_limit")
                    target.write(chunk)
                    size += len(chunk)
                    digest.update(chunk)
                target.flush()
                os.fsync(target.fileno())
                os.fchmod(target.fileno(), 0o400)
            receipt = StoredAsset(key, size, digest.hexdigest())
            self._entries[key] = (name, receipt)
            self._bytes += size
            self._account_bytes[key.account_id] += size
            self._account_files[key.account_id] += 1
            return receipt
        except OSError:
            raise AssetError("storage_failed") from None
        finally:
            if created and key not in self._entries:
                try:
                    os.unlink(name, dir_fd=self._dirfd)
                except OSError:
                    self._state = "broken"
                    raise AssetError("cleanup_failed") from None

    @staticmethod
    def _wrap(fd, mode):
        try:
            return os.fdopen(fd, mode)
        except BaseException:
            os.close(fd)
            raise

    def _verify(self, source, receipt):
        size, digest = 0, hashlib.sha256()
        while True:
            chunk = source.read(min(self.limits.chunk_bytes, receipt.size_bytes-size+1))
            if not chunk:
                break
            size += len(chunk)
            if size > receipt.size_bytes:
                raise AssetError("integrity_failed")
            digest.update(chunk)
        if size != receipt.size_bytes or digest.hexdigest() != receipt.sha256:
            raise AssetError("integrity_failed")

    def copy_to(self, context, key, sink) -> StoredAsset:
        """Verify before output, then stream and recheck. Sink errors can leave partial output."""
        name, receipt = self._entry(context, key)
        if not callable(getattr(sink, "write", None)):
            raise AssetError("expected_binary_writer")
        self._busy = True
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._dirfd)
            with self._wrap(fd, "rb") as source:
                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size != receipt.size_bytes:
                    raise AssetError("integrity_failed")
                self._verify(source, receipt)
                source.seek(0)
                size, digest = 0, hashlib.sha256()
                while True:
                    chunk = source.read(min(self.limits.chunk_bytes, receipt.size_bytes-size+1))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > receipt.size_bytes:
                        raise AssetError("integrity_failed")
                    digest.update(chunk)
                    remaining = memoryview(chunk)
                    while remaining:
                        try:
                            written = sink.write(remaining)
                        except Exception:
                            raise AssetError("sink_failed") from None
                        if type(written) is not int or not 0 < written <= len(remaining):
                            raise AssetError("invalid_binary_writer")
                        remaining = remaining[written:]
                if size != receipt.size_bytes or digest.hexdigest() != receipt.sha256:
                    raise AssetError("integrity_failed")
                return receipt
        except FileNotFoundError:
            raise AssetError("asset_missing") from None
        except OSError:
            raise AssetError("storage_failed") from None
        finally:
            self._busy = False

    def read(self, context, key) -> bytes:
        """Bounded by max_file_bytes; streaming copy_to avoids whole-file allocation."""
        sink = io.BytesIO()
        self.copy_to(context, key, sink)
        return sink.getvalue()

    def _remove(self, key):
        name, receipt = self._entries[key]
        try:
            os.unlink(name, dir_fd=self._dirfd)
        except FileNotFoundError:
            pass
        except OSError:
            self._state = "broken"
            raise AssetError("cleanup_failed") from None
        del self._entries[key]
        self._bytes -= receipt.size_bytes
        self._account_bytes[key.account_id] -= receipt.size_bytes
        self._account_files[key.account_id] -= 1
        if not self._account_files[key.account_id]:
            del self._account_files[key.account_id]
            del self._account_bytes[key.account_id]

    def delete(self, context, key):
        self._entry(context, key)
        self._remove(key)

    def close(self):
        if self._state == "closed":
            return
        if self._busy:
            raise AssetError("store_busy")
        if hasattr(self, "_owner") and threading.get_ident() != self._owner:
            raise AssetError("wrong_thread")
        try:
            if hasattr(self, "_dirfd"):
                os.close(self._dirfd)
                del self._dirfd
            if hasattr(self, "_directory"):
                shutil.rmtree(self._directory)
        except OSError:
            self._state = "broken"
            raise AssetError("cleanup_failed") from None
        self._entries.clear()
        self._account_bytes.clear()
        self._account_files.clear()
        self._bytes, self._state = 0, "closed"

    def __exit__(self, exc_type, exc, tb):
        self.close()
