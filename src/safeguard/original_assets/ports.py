"""Trusted original-storage port; implementations preserve scoped contract behavior."""

from abc import ABC, abstractmethod

from .contracts import AssetKey, AssetLimits, StoredAsset


class OriginalAssets(ABC):
    """Synchronous trusted backend, not authentication or a Python security sandbox.

    Require current host access on every operation. Batch receipt is all-or-nothing;
    callers own streams. Describe reports a receipt; read/copy verify actual bytes.
    Closing behavior belongs to the selected backend's declared lifecycle.
    """

    limits: AssetLimits

    @abstractmethod
    def put_batch(self, context, uploads: dict) -> tuple[StoredAsset, ...]: ...

    def put(self, context, key: AssetKey, stream) -> StoredAsset:
        return self.put_batch(context, {key: stream})[0]

    @abstractmethod
    def describe(self, context, key: AssetKey) -> StoredAsset: ...

    @abstractmethod
    def read(self, context, key: AssetKey) -> bytes: ...

    @abstractmethod
    def copy_to(self, context, key: AssetKey, sink) -> StoredAsset: ...

    @abstractmethod
    def delete(self, context, key: AssetKey): ...

    @abstractmethod
    def close(self): ...
