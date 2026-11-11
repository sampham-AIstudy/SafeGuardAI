"""Provisional v2 message content types; references do not grant byte access."""

from typing import Literal, TypedDict


class TextPart(TypedDict):
    kind: Literal["text"]
    text: str


class AssetPart(TypedDict):
    kind: Literal["image", "audio", "video", "file"]
    asset_id: str


ContentPart = TextPart | AssetPart


class AssetDescriptor(TypedDict):
    """Source claims, scoped by the enclosing message; no verified media type."""

    asset_id: str
    filename: str | None
    declared_media_type: str | None
    declared_size_bytes: int | None
    source_status: Literal["unknown", "available", "pending", "unavailable", "failed"]
    processing_status: Literal["not_requested"]
