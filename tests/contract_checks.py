"""Check the handoff schema with independent neutral toy envelopes.

Authoring-only dependency: jsonschema. This does not implement an adapter or
normalizer and never loads benchmark data, source accounts or model clients.
"""

import argparse
from copy import deepcopy
from datetime import datetime
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import re
import sys

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent


def cases():
    base = {
        "schema_version": "1.0", "source": "demo", "account_id": "toy-account",
        "conversation_id": "toy-conversation", "message_id": "toy-message",
        "sender_id": "toy-contact", "event_type": "message.created",
        "observed_at": "2026-01-01T00:00:00Z",
        "payload": {"thread": "toy-conversation", "id": "toy-message",
                    "author": "toy-contact", "body": "New neutral toy greeting", "sent_at": None},
    }
    yield "complete_contact_envelope", base, True
    own = deepcopy(base)
    own["sender_id"] = own["account_id"]
    own["payload"]["author"] = own["account_id"]
    yield "own_account_sender", own, True
    extra_native = deepcopy(base)
    extra_native["payload"]["source_extension"] = {"opaque": "toy native field"}
    yield "native_extension_stays_in_payload", extra_native, True
    no_source_time = deepcopy(base)
    del no_source_time["payload"]["sent_at"]
    yield "source_send_time_absent", no_source_time, True
    fractional_time = deepcopy(base)
    fractional_time["observed_at"] = "2026-01-01T00:00:00.125Z"
    yield "fractional_utc_observation_time", fractional_time, True
    unknown_source = deepcopy(base)
    unknown_source["source"] = "another.source"
    yield "registration_is_not_schema_validation", unknown_source, True
    for key in ["account_id", "conversation_id", "message_id", "sender_id", "payload"]:
        missing = deepcopy(base)
        del missing[key]
        yield "missing_" + key, missing, False
    changes = [
        ("blank_identity", "sender_id", "  "),
        ("numeric_identity", "message_id", 3),
        ("unsupported_version", "schema_version", "2.0"),
        ("unsupported_event_type", "event_type", "message.updated"),
        ("payload_is_array", "payload", []),
        ("empty_payload", "payload", {}),
        ("observation_time_has_no_timezone", "observed_at", "2026-01-01T00:00:00"),
        ("observation_time_invalid_calendar_date", "observed_at", "2026-99-01T00:00:00Z"),
        ("observation_time_not_utc", "observed_at", "2026-01-01T01:00:00+01:00"),
        ("observation_time_compact_clock", "observed_at", "2026-01-01T000000Z"),
        ("native_field_outside_payload", "native_body", "Toy content"),
        ("invalid_source_identifier", "source", "Demo With Spaces"),
    ]
    for name, key, value in changes:
        changed = deepcopy(base)
        changed[key] = value
        yield name, changed, False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    schema_path = HERE.parent / "src/safeguard/adapters/contract.schema.json"
    schema = json.loads(schema_path.read_text())
    Draft202012Validator.check_schema(schema)
    # jsonschema's date-time checker depends on optional packages. Register an
    # explicit local checker so a missing optional dependency cannot accept an
    # invalid calendar date. This profile uses UTC observation time with Z.
    format_checker = FormatChecker()

    @format_checker.checks("date-time", raises=ValueError)
    def utc_observation_time(value):
        if not isinstance(value, str):
            return True  # The schema's type check rejects nonstrings.
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z", value):
            return False
        datetime.fromisoformat(value[:-1] + "+00:00")
        return True

    validator = Draft202012Validator(schema, format_checker=format_checker)
    results = []
    for name, instance, expected in cases():
        before = deepcopy(instance)
        actual = validator.is_valid(instance)
        passed = actual == expected and instance == before
        results.append({"case": name, "expected_valid": expected,
                        "actual_valid": actual, "pass": passed})
    report = {
        "scope": "Envelope structure and format checks only; no actual adapter or normalizer behavior",
        "fixture_origin": "Newly authored neutral examples, independent of every benchmark",
        "cases": len(results), "passed": sum(r["pass"] for r in results),
        "failed": sum(not r["pass"] for r in results), "results": results,
        "schema_sha256": hashlib.sha256(schema_path.read_bytes()).hexdigest(),
        "check_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "jsonschema_version": version("jsonschema"), "python_version": sys.version.split()[0],
        "observation_time_validation": "Explicit local UTC/calendar checker; optional date-time packages not required",
        "limits": ["No native payload interpretation or identity-extraction verification",
                   "No delivery, ordering, deduplication or source-account integration verification"],
    }
    if args.out:
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "results"}, sort_keys=True))
    return int(bool(report["failed"]))


if __name__ == "__main__":
    raise SystemExit(main())
