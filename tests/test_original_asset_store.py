"""Private temporary originals, neutral self-created bytes, no benchmark data."""

from dataclasses import replace
import io
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from safeguard.original_assets import AssetError, AssetKey, AssetLimits, LocalAssetStore
from safeguard.ingress import AccessContext


LIMITS = AssetLimits(4096, 16384, 8, 8192, 4, 64)
CONTEXT = AccessContext("toy-account", frozenset(("toy-room", "toy-garden")))


def key(message="toy-note", account="toy-account", room="toy-room", asset="toy-file"):
    return AssetKey("demo", account, room, message, asset)


class OriginalAssetStoreTests(unittest.TestCase):
    def rejected(self, operation, code):
        with self.assertRaises(AssetError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)
        self.assertNotIn("PRIVATE", str(caught.exception))

    def test_exact_bytes_hash_and_streaming_round_trip(self):
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent, limits=LIMITS) as store:
            for n, data in enumerate((b"", b"Toy\x00\xff\n", bytes(range(256))*8)):
                with self.subTest(size=len(data)):
                    receipt = store.put(CONTEXT, key(str(n)), io.BytesIO(data))
                    self.assertEqual((receipt.size_bytes, receipt.sha256), (len(data), hashlib.sha256(data).hexdigest()))
                    self.assertEqual(store.describe(CONTEXT, key(str(n))), receipt)
                    self.assertEqual(store.read(CONTEXT, key(str(n))), data)
                    sink = io.BytesIO()
                    self.assertEqual(store.copy_to(CONTEXT, key(str(n)), sink), receipt)
                    self.assertEqual(sink.getvalue(), data)

    def test_partial_sink_writes_preserve_complete_output(self):
        class ShortSink(io.BytesIO):
            def write(self, data):
                return super().write(data[:3])
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent, limits=LIMITS) as store:
            data = b"Independently authored toy note."*10
            store.put(CONTEXT, key(), io.BytesIO(data))
            sink = ShortSink()
            store.copy_to(CONTEXT, key(), sink)
            self.assertEqual(sink.getvalue(), data)

    def test_actual_byte_limits_and_exact_boundary(self):
        for field, code in (("max_file_bytes", "file_byte_limit"), ("max_total_bytes", "total_byte_limit"),
                             ("max_account_bytes", "account_byte_limit")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as parent, \
                    LocalAssetStore(parent=parent, limits=replace(LIMITS, **{field: 8})) as store:
                self.rejected(lambda: store.put(CONTEXT, key(), io.BytesIO(b"x"*9)), code)
                self.assertEqual(store.stats["bytes"], 0)
                self.assertEqual(store.stats["files"], 0)
                self.assertEqual(list(store._directory.iterdir()), [])
                receipt = store.put(CONTEXT, key(), io.BytesIO(b"x"*8))
                self.assertEqual(receipt.size_bytes, 8)

    def test_global_and_account_file_counts_fail_before_read(self):
        for field, code in (("max_files", "file_count_limit"), ("max_account_files", "account_file_count_limit")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as parent, \
                    LocalAssetStore(parent=parent, limits=replace(LIMITS, **{field: 1})) as store:
                store.put(CONTEXT, key(), io.BytesIO(b"Toy"))
                stream = io.BytesIO(b"Other")
                self.rejected(lambda: store.put(CONTEXT, key("other"), stream), code)
                self.assertEqual(stream.tell(), 0)

    def test_global_bytes_span_accounts_and_account_budget_is_separate(self):
        limits = replace(LIMITS, max_total_bytes=10, max_account_bytes=6)
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent, limits=limits) as store:
            store.put(CONTEXT, key(), io.BytesIO(b"x"*6))
            other = AccessContext("toy-other", CONTEXT.conversations)
            store.put(other, key(account="toy-other"), io.BytesIO(b"y"*4))
            self.rejected(lambda: store.put(other, key("other", account="toy-other"), io.BytesIO(b"z")), "total_byte_limit")
            store.delete(CONTEXT, key())
            store.put(other, key("other", account="toy-other"), io.BytesIO(b"z"*2))
            self.rejected(lambda: store.put(other, key("third", account="toy-other"), io.BytesIO(b"z")), "account_byte_limit")

    def test_scope_separation_preserves_identical_public_ids(self):
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent, limits=LIMITS) as store:
            for account in ("toy-account", "toy-other"):
                for room in ("toy-room", "toy-garden"):
                    context = AccessContext(account, CONTEXT.conversations)
                    for message in ("one", "two"):
                        identity = key(message, account, room)
                        data = (account+room+message).encode()
                        store.put(context, identity, io.BytesIO(data))
                        self.assertEqual(store.read(context, identity), data)
            self.assertEqual(store.stats["files"], 8)

    def test_authorization_is_rechecked_for_every_operation(self):
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent, limits=LIMITS) as store:
            store.put(CONTEXT, key(), io.BytesIO(b"Toy"))
            for wrong in (AccessContext("toy-other", CONTEXT.conversations), AccessContext("toy-account", frozenset())):
                for operation in (lambda: store.read(wrong, key()), lambda: store.describe(wrong, key()),
                                  lambda: store.delete(wrong, key()), lambda: store.put(wrong, key("new"), io.BytesIO(b"Toy"))):
                    with self.subTest(context=wrong, operation=operation):
                        self.rejected(operation, "asset_not_allowed")
            self.rejected(lambda: store.read({"account_id": "toy-account"}, key()), "trusted_context_required")
            self.assertEqual(store.read(CONTEXT, key()), b"Toy")

    def test_duplicate_batch_preflight_and_rollback_keep_existing_originals(self):
        class FailedReader:
            def read(self, count):
                raise RuntimeError("PRIVATE_SOURCE_ERROR")
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent, limits=LIMITS) as store:
            store.put(CONTEXT, key("existing"), io.BytesIO(b"Keep"))
            untouched = io.BytesIO(b"New")
            self.rejected(lambda: store.put_batch(CONTEXT, {key("new"): untouched, key("existing"): io.BytesIO(b"Overwrite")}), "asset_exists")
            self.assertEqual(untouched.tell(), 0)
            self.rejected(lambda: store.put_batch(CONTEXT, {key("new"): io.BytesIO(b"New"), key("broken"): FailedReader()}), "source_failed")
            self.assertEqual(store.stats["files"], 1)
            self.assertEqual(store.stats["bytes"], 4)
            self.assertEqual(len(list(store._directory.iterdir())), 1)
            self.assertEqual(store.read(CONTEXT, key("existing")), b"Keep")
            store.put(CONTEXT, key("new"), io.BytesIO(b"Retry explicitly"))

    def test_invalid_or_overreturning_readers_and_source_ownership(self):
        class BadReader:
            def __init__(self, value): self.value = value
            def read(self, count): return self.value if self.value != "oversize" else b"x"*(count+1)
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent, limits=LIMITS) as store:
            for value in (None, "Toy", bytearray(b"Toy"), "oversize"):
                with self.subTest(value=value):
                    self.rejected(lambda: store.put(CONTEXT, key(), BadReader(value)), "invalid_binary_reader")
            self.rejected(lambda: store.put(CONTEXT, key(), object()), "expected_binary_reader")
            source = io.BytesIO(b"Toy")
            store.put(CONTEXT, key(), source)
            self.assertFalse(source.closed)

    def test_read_requests_are_bounded_even_at_exhausted_quota(self):
        class Recording(io.BytesIO):
            def __init__(self, data): super().__init__(data); self.requests = []
            def read(self, n): self.requests.append(n); return super().read(n)
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent, limits=replace(LIMITS, max_file_bytes=65)) as store:
            source = Recording(b"x"*1000)
            self.rejected(lambda: store.put(CONTEXT, key(), source), "file_byte_limit")
            self.assertEqual(source.requests, [64, 2])
            self.assertEqual(source.tell(), 66)

    def test_sink_errors_and_invalid_progress_do_not_remove_original(self):
        class Sink:
            def __init__(self, value): self.value=value
            def write(self, chunk):
                if self.value == "fail": raise RuntimeError("PRIVATE_SINK_ERROR")
                return self.value
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent, limits=LIMITS) as store:
            store.put(CONTEXT, key(), io.BytesIO(b"Toy"))
            for value in (None, 0, -1, True, 1000, "fail"):
                with self.subTest(value=value):
                    self.rejected(lambda: store.copy_to(CONTEXT, key(), Sink(value)), "sink_failed" if value == "fail" else "invalid_binary_writer")
            self.rejected(lambda: store.copy_to(CONTEXT, key(), object()), "expected_binary_writer")
            self.assertEqual(store.read(CONTEXT, key()), b"Toy")

    def test_missing_deleted_and_closed_references_are_explicit(self):
        with tempfile.TemporaryDirectory() as parent:
            with LocalAssetStore(parent=parent, limits=LIMITS) as store:
                self.rejected(lambda: store.read(CONTEXT, key()), "asset_not_found")
                store.put(CONTEXT, key(), io.BytesIO(b"Toy"))
                store.delete(CONTEXT, key())
                self.rejected(lambda: store.read(CONTEXT, key()), "asset_not_found")
                self.assertEqual(store.stats["bytes"], 0)
            self.rejected(lambda: store.read(CONTEXT, key()), "store_not_open")
            self.assertEqual(list(Path(parent).iterdir()), [])
            store.close()

    def test_path_like_ids_never_become_filenames_and_permissions_are_private(self):
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent, limits=LIMITS) as store:
            identity = key(message="../../toy", asset="https://invalid.example/../../toy")
            store.put(CONTEXT, identity, io.BytesIO(b"Toy"))
            names = list(store._directory.iterdir())
            self.assertEqual(len(names), 1)
            self.assertRegex(names[0].name, r"^[0-9a-f]{32}$")
            self.assertEqual(store._directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual(names[0].stat().st_mode & 0o777, 0o400)
            self.assertEqual(store.read(CONTEXT, identity), b"Toy")

    def test_missing_same_size_tampered_symlink_and_fifo_are_rejected(self):
        for fault, code in (("missing", "asset_missing"), ("tampered", "integrity_failed"),
                            ("symlink", "storage_failed"), ("fifo", "integrity_failed")):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as parent, \
                    LocalAssetStore(parent=parent, limits=LIMITS) as store:
                store.put(CONTEXT, key(), io.BytesIO(b"Toy"))
                path = next(store._directory.iterdir())
                if fault == "tampered":
                    path.chmod(0o600); path.write_bytes(b"Bad")
                else:
                    path.unlink()
                    if fault == "symlink":
                        target = Path(parent)/"toy-outside"; target.write_bytes(b"Toy");path.symlink_to(target)
                    elif fault == "fifo":
                        os.mkfifo(path)
                sink = io.BytesIO()
                self.rejected(lambda: store.copy_to(CONTEXT, key(), sink), code)
                self.assertEqual(sink.getvalue(), b"")
                store.delete(CONTEXT, key())

    def test_disk_failure_removes_partial_and_does_not_leak_private_error(self):
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent, limits=LIMITS) as store:
            with patch("safeguard.original_assets.store.os.fsync", side_effect=OSError("PRIVATE_DISK_ERROR")):
                self.rejected(lambda: store.put(CONTEXT, key(), io.BytesIO(b"Toy")), "storage_failed")
            self.assertEqual(store.stats["files"], 0)
            self.assertEqual(store.stats["bytes"], 0)
            self.assertEqual(list(store._directory.iterdir()), [])

    def test_failed_cleanup_breaks_store_and_context_close_recovers_own_files(self):
        with tempfile.TemporaryDirectory() as parent:
            with LocalAssetStore(parent=parent, limits=LIMITS) as store:
                with patch("safeguard.original_assets.store.os.fsync", side_effect=OSError("PRIVATE_DISK_ERROR")), \
                     patch("safeguard.original_assets.store.os.unlink", side_effect=OSError("PRIVATE_CLEANUP_ERROR")):
                    self.rejected(lambda: store.put(CONTEXT, key(), io.BytesIO(b"Toy")), "cleanup_failed")
                self.assertEqual(store.stats["state"], "broken")
                self.rejected(lambda: store.put(CONTEXT, key(), io.BytesIO(b"Toy")), "storage_broken")
            self.assertEqual(list(Path(parent).iterdir()), [])

    def test_thread_and_reentrant_operations_are_rejected(self):
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent, limits=LIMITS) as store:
            errors = []
            def foreign():
                try: store.put(CONTEXT, key(), io.BytesIO(b"Toy"))
                except AssetError as error: errors.append(error.code)
            thread = threading.Thread(target=foreign, daemon=True);thread.start();thread.join(1)
            self.assertFalse(thread.is_alive());self.assertEqual(errors, ["wrong_thread"])
            class Reentrant(io.BytesIO):
                def read(inner, n):
                    self.rejected(lambda: store.put(CONTEXT, key("inner"), io.BytesIO(b"Toy")), "store_busy")
                    return super().read(n)
            store.put(CONTEXT, key(), Reentrant(b"Toy"))

    def test_limits_require_explicit_positive_integers(self):
        for field in LIMITS.__dataclass_fields__:
            for value in (0, -1, True, 1.5):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    replace(LIMITS, **{field: value})

    def test_failed_directory_open_removes_new_temporary_directory(self):
        with tempfile.TemporaryDirectory() as parent:
            store = LocalAssetStore(parent=parent, limits=LIMITS)
            try:
                with patch("safeguard.original_assets.store.os.open", side_effect=OSError("PRIVATE_OPEN_ERROR")):
                    with self.assertRaises(AssetError):
                        store.__enter__()
                self.assertEqual(list(Path(parent).iterdir()), [])
            finally:
                store.close()

    def test_failed_file_wrapper_does_not_leak_descriptor(self):
        with tempfile.TemporaryDirectory() as parent, LocalAssetStore(parent=parent, limits=LIMITS) as store:
            opened = []
            real_open = os.open
            def tracked(*args, **kwargs):
                fd = real_open(*args, **kwargs)
                opened.append(fd)
                return fd
            try:
                with patch("safeguard.original_assets.store.os.open", side_effect=tracked), \
                     patch("safeguard.original_assets.store.os.fdopen", side_effect=OSError("PRIVATE_WRAPPER_ERROR")):
                    with self.assertRaises(AssetError):
                        store.put(CONTEXT, key(), io.BytesIO(b"Toy"))
                for fd in opened:
                    with self.assertRaises(OSError):
                        os.fstat(fd)
            finally:
                for fd in opened:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
