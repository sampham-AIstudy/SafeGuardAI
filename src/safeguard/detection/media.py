"""Scoped native-media snapshots. Header recognition does not establish decoding or safety."""

from dataclasses import asdict, dataclass, field, fields
import hashlib
import inspect
import re
import struct

from safeguard.detection.context import PreparedContext
from safeguard.detection.tools.evidence import EvidenceError, PartReference, resolve_original_part
from safeguard.memory.original_assets import AssetKey, OriginalAssets, StoredAsset
from safeguard.memory.conversation_status import ConversationKey


MEDIA_PROTOCOL = "native-inline-1.1-png-jpeg-wav-mp4-pdf"
IMAGE_SUFFIXES = frozenset({".png", ".jpg", ".jpeg"})
_KINDS = {"image/png": "image", "image/jpeg": "image", "audio/wav": "audio",
          "video/mp4": "video", "application/pdf": "file"}


class MediaError(ValueError):
    """Existing model failure codes, without source values or callback exception text."""

    def __init__(self, code):
        if code not in ("invalid_request", "context_limit", "unsupported_request"):
            raise ValueError("invalid_media_error")
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class MediaLimits:
    max_context_bytes: int
    max_attachments: int
    max_original_bytes: int
    max_total_bytes: int

    def __post_init__(self):
        if any(type(getattr(self, f.name)) is not int or getattr(self, f.name) < 1 for f in fields(self)):
            raise ValueError("invalid_media_limits")


def _receipt(original, key):
    if (type(original) is not StoredAsset or type(original.key) is not AssetKey or original.key != key
            or type(original.size_bytes) is not int or original.size_bytes < 1
            or type(original.sha256) is not str or re.fullmatch("[0-9a-f]{64}", original.sha256) is None):
        raise MediaError("invalid_request")


@dataclass(frozen=True, slots=True)
class MediaSelection:
    source_ref: PartReference
    expected_original: StoredAsset | None = None
    skip_unrecognized: bool = False

    def __post_init__(self):
        if type(self.source_ref) is not PartReference or type(self.skip_unrecognized) is not bool:
            raise MediaError("invalid_request")
        if self.expected_original is not None:
            _receipt(self.expected_original, self.expected_original.key if type(self.expected_original) is StoredAsset else None)


def _recognized_jpeg(data):
    if not data.startswith(b"\xff\xd8\xff"):
        return False
    position, has_frame = 2, False
    while position < len(data) and data[position] == 0xff:
        while position < len(data) and data[position] == 0xff:
            position += 1
        if position + 3 > len(data):
            return False
        marker = data[position]
        size = int.from_bytes(data[position + 1:position + 3], "big")
        end = position + 1 + size
        if size < 2 or end > len(data):
            return False
        if marker in (0xc0, 0xc1, 0xc2) and size >= 11:
            height, width, components = struct.unpack_from(">HHB", data, position + 4)
            has_frame = bool(width and height and components and size == 8 + 3 * components)
        if marker == 0xda:
            components = data[position + 3] if size >= 6 else 0
            return bool(has_frame and components and size == 6 + 2 * components
                        and data.find(b"\xff\xd9", end + 1) != -1)
        if marker < 0xc0 or marker in (0xd8, 0xd9) or 0xd0 <= marker <= 0xd7:
            return False
        position = end
    return False


def recognize_media(data):
    """Recognize a bounded structural header, without full decoding or provider validation."""
    if type(data) is not bytes or not data:
        raise MediaError("unsupported_request")
    if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 33:
        width, height = struct.unpack(">II", data[16:24])
        if (data[8:16] == b"\x00\x00\x00\rIHDR" and width and height
                and data[24] in (1, 2, 4, 8, 16) and data[25] in (0, 2, 3, 4, 6)
                and data[26:28] == b"\x00\x00" and data[28] in (0, 1)):
            return "image/png"
    if _recognized_jpeg(data):
        return "image/jpeg"
    if data.startswith(b"RIFF") and len(data) >= 44 and data[8:12] == b"WAVE":
        if int.from_bytes(data[4:8], "little") + 8 == len(data):
            position, pcm, samples = 12, False, False
            while position + 8 <= len(data):
                name, size = data[position:position + 4], int.from_bytes(data[position + 4:position + 8], "little")
                end = position + 8 + size
                if end > len(data):
                    break
                if name == b"fmt " and size >= 16:
                    fmt, channels, rate, byte_rate, align, bits = struct.unpack("<HHIIHH", data[position + 8:position + 24])
                    pcm = (fmt == 1 and channels > 0 and rate > 0 and bits in (8, 16, 24, 32)
                           and align == channels * (bits // 8) and byte_rate == rate * align)
                elif name == b"data":
                    samples = size > 0
                position = end + size % 2
            if pcm and samples and position == len(data):
                return "audio/wav"
    if len(data) >= 24 and data[4:8] == b"ftyp":
        size = int.from_bytes(data[:4], "big")
        if 16 <= size <= len(data) and size % 4 == 0:
            brands = (data[8:12],) + tuple(data[i:i + 4] for i in range(16, size, 4))
            if any(brand in (b"isom", b"iso2", b"mp41", b"mp42", b"avc1") for brand in brands):
                return "video/mp4"
    if re.match(rb"%PDF-(?:1\.[0-7]|2\.0)(?:\r\n|\r|\n)", data[:10]):
        return "application/pdf"
    raise MediaError("unsupported_request")


@dataclass(frozen=True, slots=True)
class NativeMedia:
    source_ref: PartReference
    original: StoredAsset
    media_type: str
    data: bytes = field(repr=False)

    def __post_init__(self):
        if type(self.source_ref) is not PartReference or type(self.original) is not StoredAsset:
            raise MediaError("invalid_request")
        _receipt(self.original, self.original.key)
        if (type(self.data) is not bytes or len(self.data) != self.original.size_bytes
                or hashlib.sha256(self.data).hexdigest() != self.original.sha256):
            raise MediaError("invalid_request")
        if type(self.media_type) is not str or self.media_type != recognize_media(self.data):
            raise MediaError("invalid_request")


def _resolve(prepared, access, ref, limit):
    try:
        if type(ref) is not PartReference:
            raise MediaError("invalid_request")
        ref.__post_init__()
        result = resolve_original_part(prepared, access, ref, max_context_bytes=limit)
        source_ref = result[0]["source_ref"]
        if (type(source_ref) is not dict or set(source_ref) != {"observation_number", "part_index"}
                or any(type(source_ref[name]) is not int for name in source_ref)):
            raise MediaError("invalid_request")
        return result
    except EvidenceError as error:
        raise MediaError("context_limit" if error.code == "context_byte_limit" else "invalid_request") from None


def _context(prepared, access, limit):
    from safeguard.ingress import AccessContext

    if (type(prepared) is not PreparedContext or type(prepared.key) is not ConversationKey
            or type(prepared.json_bytes) is not bytes or type(access) is not AccessContext
            or prepared.key.account_id != access.account_id or prepared.key.conversation_id not in access.conversations):
        raise MediaError("invalid_request")
    if len(prepared.json_bytes) > limit:
        raise MediaError("context_limit")
    try:
        document = prepared.to_dict()
        if (type(document) is not dict or document.get("context_schema_version") != "1.0"
                or type(prepared.observed_count) is not int or prepared.observed_count < 0
                or type(document.get("observed_count")) is not int or document["observed_count"] != prepared.observed_count
                or any(document.get(name) != getattr(prepared.key, name) for name in ("source", "account_id", "conversation_id"))
                or type(document.get("messages")) is not list or len(document["messages"]) != prepared.observed_count):
            raise MediaError("invalid_request")
        return document
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise MediaError("invalid_request") from None


def media_ledger(prepared, access, media, *, max_context_bytes):
    """Validate an immutable binding and describe planned inputs, never remote receipt."""
    if type(media) is not tuple:
        raise MediaError("invalid_request")
    document = _context(prepared, access, max_context_bytes)
    selected = {}
    for item in media:
        if type(item) is not NativeMedia:
            raise MediaError("invalid_request")
        item.__post_init__()
        part, _, key = _resolve(prepared, access, item.source_ref, max_context_bytes)
        if item.original.key != key or (part["kind"] != "file" and part["kind"] != _KINDS[item.media_type]):
            raise MediaError("invalid_request")
        pair = (item.source_ref.observation_number, item.source_ref.part_index)
        if pair in selected:
            raise MediaError("invalid_request")
        selected[pair] = item
    if list(selected) != sorted(selected):
        raise MediaError("invalid_request")
    result = []
    for message in document["messages"]:
        for part in message["content_parts"]:
            if part["kind"] == "text":
                continue
            ref = part["source_ref"]
            item = selected.get((ref["observation_number"], ref["part_index"]))
            if item is None:
                result.append(dict(source_ref=ref, mode="reference_only", processing_status="not_presented"))
            else:
                result.append(dict(source_ref=ref, mode="direct", processing_status="bound_for_request",
                    asset_key=asdict(item.original.key),
                    original=dict(size_bytes=item.original.size_bytes, sha256=item.original.sha256), media_type=item.media_type))
    return result


class MediaPreparer:
    """Trusted synchronous selection and scoped retrieval, with one bounded raw snapshot."""

    def __init__(self, *, store: OriginalAssets, limits: MediaLimits, select_media):
        if (not isinstance(store, OriginalAssets) or type(limits) is not MediaLimits or not callable(select_media)
                or inspect.iscoroutinefunction(select_media) or inspect.iscoroutinefunction(getattr(select_media, "__call__", None))):
            raise MediaError("invalid_request")
        self.store, self.limits, self.select_media = store, limits, select_media

    def prepare(self, prepared, access):
        _context(prepared, access, self.limits.max_context_bytes)
        try:
            selections = self.select_media(prepared)
        except Exception:
            raise MediaError("invalid_request") from None
        if inspect.iscoroutine(selections):
            selections.close()
        if type(selections) is not tuple or any(type(item) is not MediaSelection for item in selections):
            raise MediaError("invalid_request")
        if len(selections) > self.limits.max_attachments:
            raise MediaError("context_limit")
        resolved, seen = [], set()
        for selection in selections:
            selection.__post_init__()
            part, _, key = _resolve(prepared, access, selection.source_ref, self.limits.max_context_bytes)
            if selection.source_ref in seen:
                raise MediaError("invalid_request")
            if selection.expected_original is not None and selection.expected_original.key != key:
                raise MediaError("invalid_request")
            seen.add(selection.source_ref)
            resolved.append((selection, part, key))
        described, total = [], 0
        for selection, part, key in resolved:
            try:
                original = self.store.describe(access, key)
            except Exception:
                raise MediaError("unsupported_request") from None
            _receipt(original, key)
            if selection.expected_original is not None and original != selection.expected_original:
                raise MediaError("unsupported_request")
            total += original.size_bytes
            if original.size_bytes > self.limits.max_original_bytes or total > self.limits.max_total_bytes:
                raise MediaError("context_limit")
            described.append((selection, part, key, original))
        media = []
        for selection, part, key, original in described:
            try:
                data = self.store.read(access, key)
            except Exception:
                raise MediaError("unsupported_request") from None
            if (type(data) is not bytes or len(data) != original.size_bytes
                    or hashlib.sha256(data).hexdigest() != original.sha256):
                raise MediaError("unsupported_request")
            try:
                media_type = recognize_media(data)
            except MediaError:
                if selection.skip_unrecognized:
                    continue
                raise
            if part["kind"] != "file" and part["kind"] != _KINDS[media_type]:
                raise MediaError("unsupported_request")
            media.append(NativeMedia(selection.source_ref, original, media_type, data))
        return tuple(sorted(media, key=lambda item: (item.source_ref.observation_number, item.source_ref.part_index)))
