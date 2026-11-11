"""Original bytes with trusted scoped access; no media interpretation."""

from .store import AssetError, AssetKey, AssetLimits, LocalAssetStore, StoredAsset
from .ports import OriginalAssets
from .persistent import PersistentAssetStore

__all__ = ["AssetError", "AssetKey", "AssetLimits", "LocalAssetStore", "StoredAsset", "OriginalAssets"]
__all__ += ["PersistentAssetStore"]
