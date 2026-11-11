"""Explicit input limits before decoding/copying; no deployment defaults."""

from dataclasses import dataclass, fields
import json
import math


class InputViolation(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class InputLimits:
    max_bytes: int
    max_text_chars: int
    max_depth: int
    max_nodes: int
    max_content_parts: int
    max_assets: int

    def __post_init__(self):
        if any(type(getattr(self, f.name)) is not int or getattr(self, f.name) <= 0 for f in fields(self)):
            raise ValueError("Input limits must be positive integers")

    def inspect(self, value: object) -> int:
        """Return canonical native UTF-8 JSON bytes after a bounded iterative walk.

        Nodes include keys and values. Depth counts containers, root included.
        Repeated shared objects count on each occurrence; cycles are rejected.
        """
        nodes = 0
        string_bytes = 0
        ancestors = set()
        frames = [(iter((value,)), None, 0)]
        while frames:
            iterator, identity, depth = frames[-1]
            try:
                item = next(iterator)
            except StopIteration:
                frames.pop()
                if identity is not None:
                    ancestors.remove(identity)
                continue
            nodes += 1
            if nodes > self.max_nodes:
                raise InputViolation("too_many_nodes")
            kind = type(item)
            if kind is str:
                if len(item) > self.max_bytes-string_bytes:
                    raise InputViolation("too_many_bytes")
                try:
                    string_bytes += len(item.encode("utf-8"))
                except UnicodeEncodeError:
                    raise InputViolation("invalid_unicode") from None
                if string_bytes > self.max_bytes:
                    raise InputViolation("too_many_bytes")
            elif item is None or kind in (bool, int):
                pass
            elif kind is float:
                if not math.isfinite(item):
                    raise InputViolation("nonfinite_number")
            elif kind in (dict, list):
                if depth+1 > self.max_depth:
                    raise InputViolation("too_deep")
                if id(item) in ancestors:
                    raise InputViolation("cyclic_input")
                if kind is dict:
                    children = self._members(item)
                else:
                    children = iter(item)
                ancestors.add(id(item))
                frames.append((children, id(item), depth+1))
            else:
                raise InputViolation("unsupported_json_value")
        self.inspect_content(value)
        size = 0
        try:
            encoder = json.JSONEncoder(ensure_ascii=False, allow_nan=False, separators=(",", ":"))
            for chunk in encoder.iterencode(value):
                size += len(chunk.encode("utf-8"))
                if size > self.max_bytes:
                    raise InputViolation("too_many_bytes")
        except InputViolation:
            raise
        except (ValueError, RecursionError, UnicodeEncodeError):
            raise InputViolation("invalid_json") from None
        return size

    def inspect_content(self, value: object) -> None:
        """Check content budgets on native input and the common normalized shape."""
        if type(value) is dict:
            chars = len(value["body"]) if type(value.get("body")) is str else 0
            parts = value.get("content_parts")
            if type(parts) is list:
                if len(parts) > self.max_content_parts:
                    raise InputViolation("too_many_content_parts")
                for part in parts:
                    if type(part) is dict and part.get("kind") == "text" and type(part.get("text")) is str:
                        chars += len(part["text"])
            if chars > self.max_text_chars:
                raise InputViolation("text_too_long")
            if type(value.get("assets")) is list and len(value["assets"]) > self.max_assets:
                raise InputViolation("too_many_assets")

    @staticmethod
    def _members(value):
        for key, item in value.items():
            if type(key) is not str:
                raise InputViolation("nonstring_key")
            yield key
            yield item

    def decode(self, raw: bytes):
        """Enforce wire bytes/nesting before parsing strict UTF-8 JSON."""
        if type(raw) is not bytes:
            raise InputViolation("expected_utf8_bytes")
        if len(raw) > self.max_bytes:
            raise InputViolation("too_many_bytes")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise InputViolation("invalid_utf8") from None
        depth = 0
        quoted = escaped = False
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > self.max_depth:
                    raise InputViolation("too_deep")
            elif char in "]}":
                depth -= 1

        def pairs(items):
            result = {}
            for key, item in items:
                if key in result:
                    raise InputViolation("duplicate_key")
                result[key] = item
            return result

        def constant(_):
            raise InputViolation("nonfinite_number")

        try:
            return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
        except InputViolation:
            raise
        except (ValueError, RecursionError):
            raise InputViolation("invalid_json") from None
