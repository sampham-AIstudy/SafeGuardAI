"""Scoped original-byte access and validated reader output, without a parser."""

from dataclasses import asdict, dataclass, field, fields
import hashlib
import inspect
import json
import re

from safeguard.memory.original_assets import AssetError, AssetKey, OriginalAssets, StoredAsset
from safeguard.memory.conversation_status import ConversationKey
from safeguard.scam_detection.context import PreparedContext


_KINDS = frozenset(("image", "audio", "video", "file"))
_LOCATIONS = frozenset(("whole_asset", "page", "time_range_ms"))
_SHA256 = re.compile("[0-9a-f]{64}")


class EvidenceError(ValueError):
    """Fixed public reasons, without source values or callback exception text."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class PartReference:
    observation_number: int
    part_index: int

    def __post_init__(self):
        if type(self.observation_number) is not int or self.observation_number < 1 or type(self.part_index) is not int or self.part_index < 0:
            raise EvidenceError("invalid_reference")


@dataclass(frozen=True, slots=True)
class ReaderSpec:
    name: str
    version: str
    configuration_sha256: str
    supported_kinds: frozenset[str]
    location_kinds: frozenset[str]

    def __post_init__(self):
        if any(type(value) is not str or not value.strip() for value in (self.name, self.version)):
            raise EvidenceError("invalid_reader_spec")
        if type(self.configuration_sha256) is not str or not _SHA256.fullmatch(self.configuration_sha256):
            raise EvidenceError("invalid_reader_spec")
        for value, allowed in ((self.supported_kinds, _KINDS), (self.location_kinds, _LOCATIONS)):
            if type(value) is not frozenset or not value or not value <= allowed:
                raise EvidenceError("invalid_reader_spec")


@dataclass(frozen=True, slots=True)
class EvidenceLocation:
    kind: str
    page: int | None = None
    start_ms: int | None = None
    end_ms: int | None = None


@dataclass(frozen=True, slots=True)
class EvidenceSegment:
    text: str = field(repr=False)
    location: EvidenceLocation


@dataclass(frozen=True, slots=True)
class ReaderInput:
    kind: str
    data: bytes = field(repr=False)
    filename: str | None
    declared_media_type: str | None


@dataclass(frozen=True, slots=True)
class ReaderOutput:
    segments: tuple[EvidenceSegment, ...]


@dataclass(frozen=True, slots=True)
class EvidenceLimits:
    max_context_bytes: int
    max_original_bytes: int
    max_segments: int
    max_text_chars: int
    max_result_bytes: int
    max_reader_metadata_chars: int

    def __post_init__(self):
        if any(type(getattr(self, f.name)) is not int or getattr(self, f.name) <= 0 for f in fields(self)):
            raise ValueError("Evidence limits must be positive integers")


@dataclass(frozen=True, slots=True)
class EvidenceResult:
    context_sha256: str
    source_ref: PartReference
    asset_key: AssetKey
    original: StoredAsset | None
    reader: ReaderSpec
    status: str
    code: str
    segments: tuple[EvidenceSegment, ...]
    json_bytes: bytes = field(repr=False)

    def to_dict(self):
        """A decoded view belongs to the receiver, not this record."""
        return json.loads(self.json_bytes)


class EvidencePreparer:
    """A cooperative same-thread bridge, not a hostile-code execution sandbox."""

    def __init__(self, *, store: OriginalAssets, limits: EvidenceLimits):
        if not isinstance(store, OriginalAssets) or type(limits) is not EvidenceLimits:
            raise EvidenceError("invalid_configuration")
        self.store, self.limits = store, limits

    def process(self, prepared: PreparedContext, access, source_ref: PartReference, *, spec: ReaderSpec, reader,
                expected_original: StoredAsset | None = None) -> EvidenceResult:
        part, descriptor, asset_key = self._resolve(prepared, access, source_ref)
        if expected_original is not None and (type(expected_original) is not StoredAsset or expected_original.key != asset_key):
            raise EvidenceError("invalid_original_binding")
        if type(spec) is not ReaderSpec or not callable(reader) or inspect.iscoroutinefunction(reader) or inspect.iscoroutinefunction(getattr(reader, "__call__", None)):
            raise EvidenceError("invalid_reader")
        if sum(len(value) for value in (spec.name, spec.version, spec.configuration_sha256)) > self.limits.max_reader_metadata_chars:
            raise EvidenceError("reader_metadata_limit")
        # Reject invalid Unicode before a callback or result serialization can run.
        try:
            (spec.name + spec.version).encode("utf-8")
        except UnicodeEncodeError:
            raise EvidenceError("invalid_reader_spec") from None

        def emit(status, code, original=None, segments=()):
            return self._emit(prepared, source_ref, asset_key, spec, status, code, original, segments)

        if part["kind"] not in spec.supported_kinds:
            return emit("unsupported", "unsupported_kind")
        try:
            original = self.store.describe(access, asset_key)
        except AssetError as error:
            return emit(*self._asset_failure(error))
        if expected_original is not None and original != expected_original:
            return emit("failed", "original_changed", original)
        if original.size_bytes > self.limits.max_original_bytes:
            return emit("limited", "original_byte_limit", original)
        try:
            data = self.store.read(access, asset_key)
        except AssetError as error:
            return emit(*self._asset_failure(error), original)
        if len(data) != original.size_bytes or hashlib.sha256(data).hexdigest() != original.sha256:
            return emit("failed", "original_changed", original)
        request = ReaderInput(part["kind"], data, descriptor.get("filename"), descriptor.get("declared_media_type"))
        try:
            output = reader(request)
        except Exception:
            return emit("failed", "reader_failed", original)
        if inspect.iscoroutine(output):
            output.close()
        if type(output) is not ReaderOutput or type(output.segments) is not tuple:
            return emit("failed", "invalid_reader_output", original)
        if len(output.segments) > self.limits.max_segments:
            return emit("limited", "segment_limit", original)
        chars = 0
        for segment in output.segments:
            if type(segment) is not EvidenceSegment or type(segment.text) is not str or not segment.text:
                return emit("failed", "invalid_reader_output", original)
            chars += len(segment.text)
            if chars > self.limits.max_text_chars:
                return emit("limited", "text_limit", original)
            try:
                segment.text.encode("utf-8")
            except UnicodeEncodeError:
                return emit("failed", "invalid_reader_output", original)
            if not self._valid_location(segment.location, spec, part["kind"]):
                return emit("failed", "invalid_location", original)
        if not output.segments:
            return emit("empty", "no_content_extracted", original)
        try:
            return emit("extracted", "ok", original, output.segments)
        except EvidenceError as error:
            if error.code != "result_byte_limit":
                raise
            return emit("limited", "result_byte_limit", original)

    def _resolve(self, prepared, access, ref):
        from safeguard.ingress import AccessContext

        if type(access) is not AccessContext:
            raise EvidenceError("trusted_context_required")
        if type(prepared) is not PreparedContext or type(prepared.key) is not ConversationKey or type(prepared.json_bytes) is not bytes:
            raise EvidenceError("invalid_context")
        key = prepared.key
        if key.account_id != access.account_id or key.conversation_id not in access.conversations:
            raise EvidenceError("conversation_not_allowed")
        if type(ref) is not PartReference:
            raise EvidenceError("invalid_reference")
        if len(prepared.json_bytes) > self.limits.max_context_bytes:
            raise EvidenceError("context_byte_limit")
        try:
            document = prepared.to_dict()
            if (type(document) is not dict or document.get("context_schema_version") != "1.0"
                    or type(prepared.observed_count) is not int or type(document.get("observed_count")) is not int
                    or document["observed_count"] != prepared.observed_count
                    or any(document.get(name) != getattr(key, name) for name in ("source", "account_id", "conversation_id"))
                    or type(document.get("messages")) is not list or len(document["messages"]) != prepared.observed_count):
                raise EvidenceError("invalid_context")
            if ref.observation_number > prepared.observed_count:
                raise EvidenceError("invalid_reference")
            message = document["messages"][ref.observation_number - 1]
            if type(message) is not dict or message.get("observation_number") != ref.observation_number or type(message.get("content_parts")) is not list:
                raise EvidenceError("invalid_context")
            if ref.part_index >= len(message["content_parts"]):
                raise EvidenceError("invalid_reference")
            part = message["content_parts"][ref.part_index]
            if type(part) is not dict or part.get("source_ref") != asdict(ref):
                raise EvidenceError("invalid_context")
            if part.get("kind") == "text":
                raise EvidenceError("attachment_required")
            if part.get("kind") not in _KINDS or type(message.get("assets")) is not list:
                raise EvidenceError("invalid_context")
            matches = [a for a in message["assets"] if type(a) is dict and a.get("asset_id") == part.get("asset_id")]
            if len(matches) != 1 or any(matches[0].get(name) is not None and type(matches[0].get(name)) is not str
                                        for name in ("filename", "declared_media_type")):
                raise EvidenceError("invalid_context")
            asset_key = AssetKey(key.source, key.account_id, key.conversation_id, message.get("message_id"), part.get("asset_id"))
        except (KeyError, TypeError, ValueError, RecursionError, UnicodeError) as error:
            if type(error) is EvidenceError:
                raise
            raise EvidenceError("invalid_context") from None
        return part, matches[0], asset_key

    @staticmethod
    def _asset_failure(error):
        if error.code in ("asset_not_found", "asset_missing"):
            return "unavailable", "original_unavailable"
        if error.code == "integrity_failed":
            return "failed", "original_integrity_failed"
        return "failed", "original_unreadable"

    @staticmethod
    def _valid_location(location, spec, kind):
        if type(location) is not EvidenceLocation or type(location.kind) is not str or location.kind not in spec.location_kinds:
            return False
        if location.kind == "whole_asset":
            return location.page is None and location.start_ms is None and location.end_ms is None
        if location.kind == "page":
            return kind in ("file", "image") and type(location.page) is int and location.page > 0 and location.start_ms is None and location.end_ms is None
        return (kind in ("audio", "video") and location.page is None and type(location.start_ms) is int
                and type(location.end_ms) is int and 0 <= location.start_ms < location.end_ms)

    def _emit(self, prepared, ref, key, spec, status, code, original, segments):
        digest = hashlib.sha256(prepared.json_bytes).hexdigest()
        original_info = None if original is None else dict(size_bytes=original.size_bytes, sha256=original.sha256)
        payload = dict(evidence_schema_version="1.0", context_sha256=digest,
                       source=prepared.key.source, account_id=prepared.key.account_id,
                       conversation_id=prepared.key.conversation_id, observed_count=prepared.observed_count,
                       source_ref=asdict(ref), asset_key=asdict(key), original=original_info,
                       reader=dict(name=spec.name, version=spec.version, configuration_sha256=spec.configuration_sha256,
                                   supported_kinds=sorted(spec.supported_kinds), location_kinds=sorted(spec.location_kinds)),
                       status=status, code=code,
                       segments=[dict(text=item.text, location={k: v for k, v in asdict(item.location).items() if v is not None}) for item in segments])
        encoded = bytearray()
        for chunk in json.JSONEncoder(ensure_ascii=False, allow_nan=False, separators=(",", ":")).iterencode(payload):
            chunk_bytes = chunk.encode("utf-8")
            if len(chunk_bytes) > self.limits.max_result_bytes - len(encoded):
                raise EvidenceError("result_byte_limit")
            encoded.extend(chunk_bytes)
        return EvidenceResult(digest, ref, key, original, spec, status, code, segments, bytes(encoded))
