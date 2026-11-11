"""Scoped original identity, receipt and explicit quota contracts."""

from dataclasses import dataclass, fields

class AssetError(ValueError):
    """Fixed public reasons; no source values, paths or exception text."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class AssetKey:
    source: str
    account_id: str
    conversation_id: str
    message_id: str
    asset_id: str

    def __post_init__(self):
        if any(type(getattr(self, f.name)) is not str or not getattr(self, f.name).strip() for f in fields(self)):
            raise AssetError("invalid_reference")
        try:
            for f in fields(self): getattr(self, f.name).encode('utf-8')
        except UnicodeError:
            raise AssetError('invalid_reference') from None
        if self.source != "demo":
            raise AssetError("unsupported_source")

    @classmethod
    def from_message(cls, message, asset_id):
        if type(message) is not dict or message.get("message_schema_version") != "2.0":
            raise AssetError("invalid_reference")
        parts, assets = message.get("content_parts"), message.get("assets")
        if type(parts) is not list or type(assets) is not list or not any(
            type(a) is dict and a.get("asset_id") == asset_id for a in assets
        ) or not any(type(p) is dict and p.get("kind") in ("image", "audio", "video", "file")
                     and p.get("asset_id") == asset_id for p in parts):
            raise AssetError("invalid_reference")
        return cls(*(message.get(n) for n in ("source", "account_id", "conversation_id", "message_id")), asset_id)


@dataclass(frozen=True, slots=True)
class AssetLimits:
    max_file_bytes: int
    max_total_bytes: int
    max_files: int
    max_account_bytes: int
    max_account_files: int
    chunk_bytes: int

    def __post_init__(self):
        if any(type(getattr(self, f.name)) is not int or getattr(self, f.name) <= 0 for f in fields(self)):
            raise ValueError("Asset limits must be positive integers")


@dataclass(frozen=True, slots=True)
class StoredAsset:
    """Observed storage facts, separate from untrusted native declarations."""

    key: AssetKey
    size_bytes: int
    sha256: str
