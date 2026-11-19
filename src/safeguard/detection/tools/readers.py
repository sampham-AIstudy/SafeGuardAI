"""Bounded attachment decoders. Decoded syntax is not rendered document content."""

from dataclasses import dataclass
import hashlib
import json

from safeguard.detection.tools.evidence import (
    EvidenceLocation, EvidenceSegment, ReaderInput, ReaderOutput, ReaderRejection, ReaderSpec,
)


@dataclass(frozen=True, slots=True)
class Utf8TextReader:
    """Decode file bytes exactly as strict UTF-8, with no IO or text normalization."""

    max_input_bytes: int
    max_text_chars: int

    def __post_init__(self):
        if any(type(value) is not int or value < 1 for value in (self.max_input_bytes, self.max_text_chars)):
            raise ValueError("invalid_utf8_reader_limits")

    @property
    def spec(self):
        configuration = dict(algorithm_version="1.0", encoding="utf-8", errors="strict",
            preserve_bom=True, preserve_text=True, reject_nul=True,
            max_input_bytes=self.max_input_bytes, max_text_chars=self.max_text_chars)
        digest = hashlib.sha256(json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        return ReaderSpec("utf8-text", "1.0", digest, frozenset(("file",)), frozenset(("whole_asset",)))

    def __call__(self, request):
        if type(request) is not ReaderInput or type(request.data) is not bytes:
            raise ValueError("invalid_utf8_reader_input")
        if request.kind != "file":
            raise ReaderRejection("unsupported_kind")
        if len(request.data) > self.max_input_bytes:
            raise ReaderRejection("input_byte_limit")
        try:
            text = request.data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise ReaderRejection("unsupported_encoding") from None
        if "\x00" in text:
            raise ReaderRejection("nul_content")
        if len(text) > self.max_text_chars:
            raise ReaderRejection("text_limit")
        return ReaderOutput((EvidenceSegment(text, EvidenceLocation("whole_asset")),) if text else ())
