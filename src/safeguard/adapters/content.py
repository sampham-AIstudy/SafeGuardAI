"""Declared demo-native mapping, shared by both validating input boundaries."""

from safeguard.messages import AssetDescriptor, ContentPart


ASSET_KINDS = ("image", "audio", "video", "file")
SOURCE_STATUSES = ("unknown", "available", "pending", "unavailable", "failed")
ASSET_FIELDS = {"asset_id", "filename", "declared_media_type", "declared_size_bytes", "source_status"}


def demo_content(payload: dict, error) -> tuple[list[ContentPart], list[AssetDescriptor]]:
    """Validate representation, never fetch, inspect bytes or infer availability.

    `error` constructs the caller's fixed field/code exception. Unknown keys and
    source values are never interpolated into diagnostics. Lists are detached.
    """
    if "content_parts" not in payload:
        if "body" not in payload:
            raise error("payload.body", "required")
        if type(payload["body"]) is not str or not payload["body"]:
            raise error("payload.body", "expected_nonempty_string")
        parts = [{"kind": "text", "text": payload["body"]}]
    else:
        if "body" in payload:
            raise error("payload.content_parts", "ambiguous_content")
        native_parts = payload["content_parts"]
        if type(native_parts) is not list or not native_parts:
            raise error("payload.content_parts", "expected_nonempty_array")
        parts = []
        for part in native_parts:
            field = "payload.content_parts"
            if type(part) is not dict:
                raise error(field, "expected_part_object")
            kind = part.get("kind")
            if type(kind) is not str or kind not in ("text", *ASSET_KINDS):
                raise error(field, "unsupported_kind")
            value_key = "text" if kind == "text" else "asset_id"
            if set(part) != {"kind", value_key}:
                raise error(field, "invalid_part_fields")
            value = part[value_key]
            if type(value) is not str or not value or (value_key == "asset_id" and not value.strip()):
                raise error(field, "invalid_part_value")
            parts.append({"kind": kind, value_key: value})

    native_assets = payload.get("assets", [])
    if type(native_assets) is not list:
        raise error("payload.assets", "expected_array")
    catalog = {}
    for native in native_assets:
        field = "payload.assets"
        if type(native) is not dict or "asset_id" not in native or any(key not in ASSET_FIELDS for key in native):
            raise error(field, "invalid_asset_fields")
        asset_id = native["asset_id"]
        if type(asset_id) is not str or not asset_id.strip():
            raise error(field, "invalid_asset_id")
        if asset_id in catalog:
            raise error(field, "duplicate_asset_id")
        for key in ("filename", "declared_media_type"):
            value = native.get(key)
            if value is not None and (type(value) is not str or not value.strip()):
                raise error(field, "invalid_asset_metadata")
        size = native.get("declared_size_bytes")
        if size is not None and (type(size) is not int or size < 0):
            raise error(field, "invalid_declared_size")
        status = native.get("source_status", "unknown")
        if type(status) is not str or status not in SOURCE_STATUSES:
            raise error(field, "invalid_source_status")
        catalog[asset_id] = {
            "asset_id": asset_id, "filename": native.get("filename"),
            "declared_media_type": native.get("declared_media_type"), "declared_size_bytes": size,
            "source_status": status, "processing_status": "not_requested",
        }
    references = {}
    for part in parts:
        if part["kind"] == "text":
            continue
        asset_id = part["asset_id"]
        if asset_id not in catalog:
            raise error("payload.content_parts", "missing_asset_descriptor")
        if asset_id in references and references[asset_id] != part["kind"]:
            raise error("payload.content_parts", "conflicting_asset_kind")
        references[asset_id] = part["kind"]
    if set(catalog) != set(references):
        raise error("payload.assets", "unreferenced_asset")
    return parts, list(catalog.values())
