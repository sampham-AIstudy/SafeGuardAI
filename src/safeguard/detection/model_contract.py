"""Strict JSON and a deliberately bounded schema vocabulary for model handoffs.

Unsupported schema keywords fail at assembly, rather than being silently ignored.
Trusted semantic validators additionally enforce operation-specific constraints.
"""

from dataclasses import dataclass, field
import inspect
import json
import math
import re

from safeguard.detection.execution_host import (
    AssessmentProfile, CapabilityReply, CapabilitySpec, ExecutionError,
    _async_callable, _identity,
)


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def decode(raw, limits, byte_limit):
    from safeguard.ingress.limits import InputLimits, InputViolation

    if type(raw) is not bytes or len(raw) > byte_limit:
        raise ValueError("invalid_json")
    policy = InputLimits(byte_limit, byte_limit, limits.max_json_depth,
                         limits.max_json_nodes, byte_limit, byte_limit)
    try:
        value = policy.decode(raw)
        policy.inspect(value)
    except InputViolation:
        raise ValueError("invalid_json") from None
    if type(value) is not dict:
        raise ValueError("invalid_json")
    return value


def closed(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError("invalid_fields")


def text(value):
    if type(value) is not str or not value.strip():
        raise ValueError("invalid_text")
    value.encode("utf-8", errors="strict")


def checked_callback(validate, value, *prefix):
    """A validator must be synchronous, return None and leave its input intact."""
    before = encoded(value)
    returned = validate(*prefix, value)
    if inspect.iscoroutine(returned):
        returned.close()
    if returned is not None or encoded(value) != before:
        raise ValueError("invalid_validator")


def schema_document(raw):
    """Check the supported closed-object subset; no remote/local schema retrieval."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_key")
            result[key] = value
        return result

    if type(raw) is not bytes:
        raise ValueError("invalid_schema")
    schema = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                        parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite")))
    encoded(schema)

    def check(node, depth=0):
        if depth > 32 or type(node) is not dict:
            raise ValueError("invalid_schema")
        kind = node.get("type")
        allowed = {"type", "description", "enum", "const"}
        if kind == "object":
            allowed |= {"properties", "required", "additionalProperties"}
            properties, required = node.get("properties"), node.get("required")
            if type(properties) is not dict or node.get("additionalProperties") is not False:
                raise ValueError("open_object_schema")
            if type(required) is not list or any(type(k) is not str for k in required) or len(set(required)) != len(required) or not set(required) <= properties.keys():
                raise ValueError("invalid_required")
            for child in properties.values():
                check(child, depth + 1)
        elif kind == "array":
            allowed |= {"items", "minItems", "maxItems", "uniqueItems"}
            check(node.get("items"), depth + 1)
            if "uniqueItems" in node and type(node["uniqueItems"]) is not bool:
                raise ValueError("invalid_schema")
        elif kind == "string":
            allowed |= {"minLength", "maxLength", "pattern"}
            if "pattern" in node:
                re.compile(node["pattern"])
        elif kind in ("integer", "number"):
            allowed |= {"minimum", "maximum"}
        elif kind not in ("boolean", "null"):
            raise ValueError("unsupported_schema")
        if set(node) - allowed:
            raise ValueError("unsupported_schema")
        for key in ("minItems", "maxItems", "minLength", "maxLength"):
            if key in node and (type(node[key]) is not int or node[key] < 0):
                raise ValueError("invalid_schema")
        for key in ("minimum", "maximum"):
            if key in node and (type(node[key]) not in (int, float) or not math.isfinite(node[key])):
                raise ValueError("invalid_schema")
        if "enum" in node and (type(node["enum"]) is not list or not node["enum"]):
            raise ValueError("invalid_schema")

    check(schema)
    if schema["type"] != "object":
        raise ValueError("invalid_schema_root")
    return schema


def _schema_key(value):
    """Schema equality treats equal numbers alike and keeps booleans distinct."""
    if type(value) is dict:
        return ("object", frozenset((key, _schema_key(child)) for key, child in value.items()))
    if type(value) is list:
        return ("array", tuple(_schema_key(child) for child in value))
    return ("number" if type(value) in (int, float) else type(value).__name__, value)


def validate_schema(value, schema):
    kind = schema["type"]
    types = {"object": (dict,), "array": (list,), "string": (str,),
             "integer": (int,), "number": (int, float), "boolean": (bool,), "null": (type(None),)}
    if type(value) not in types[kind]:
        raise ValueError("schema_type")
    if "const" in schema and _schema_key(value) != _schema_key(schema["const"]):
        raise ValueError("schema_const")
    if "enum" in schema and not any(_schema_key(value) == _schema_key(item) for item in schema["enum"]):
        raise ValueError("schema_enum")
    if kind == "object":
        if set(value) - schema["properties"].keys() or not set(schema["required"]) <= value.keys():
            raise ValueError("schema_fields")
        for key, child in value.items():
            validate_schema(child, schema["properties"][key])
    elif kind == "array":
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", len(value)):
            raise ValueError("schema_length")
        if schema.get("uniqueItems") and len({_schema_key(item) for item in value}) != len(value):
            raise ValueError("schema_unique")
        for item in value:
            validate_schema(item, schema["items"])
    elif kind == "string":
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", len(value)):
            raise ValueError("schema_length")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise ValueError("schema_pattern")
    elif kind in ("integer", "number"):
        if not math.isfinite(value) or value < schema.get("minimum", value) or value > schema.get("maximum", value):
            raise ValueError("schema_number")


@dataclass(frozen=True, slots=True)
class OutputProfile:
    assessment: AssessmentProfile
    schema_json: bytes = field(repr=False)

    def __post_init__(self):
        if type(self.assessment) is not AssessmentProfile:
            raise ValueError("invalid_output_profile")
        schema_document(self.schema_json)

    def identity(self):
        return dict(name=self.assessment.name, version=self.assessment.version)

    def validate(self, value):
        validate_schema(value, schema_document(self.schema_json))
        checked_callback(self.assessment.validate, value)


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    version: str
    description: str
    arguments_schema_json: bytes = field(repr=False)
    validate: object = field(repr=False, compare=False)
    execute: object = field(repr=False, compare=False)

    def __post_init__(self):
        _identity(self.name, self.version)
        text(self.description)
        schema_document(self.arguments_schema_json)
        if not callable(self.validate) or _async_callable(self.validate) or not _async_callable(self.execute):
            raise ValueError("invalid_tool")

    def check(self, prepared, arguments):
        validate_schema(arguments, schema_document(self.arguments_schema_json))
        checked_callback(self.validate, arguments, prepared)

    def capability(self):
        async def execute(scope, arguments):
            self.check(scope.prepared, arguments)
            reply = await self.execute(scope, arguments)
            if type(reply) is not CapabilityReply or reply.tokens is not None:
                raise ExecutionError("invalid_capability_result")
            return reply
        return CapabilitySpec(self.name, self.version, "tool", execute)
