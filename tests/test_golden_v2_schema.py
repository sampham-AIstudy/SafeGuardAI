import json
from pathlib import Path
import pytest


def test_golden_v2_schema_and_integrity():
    root = Path(__file__).resolve().parent.parent
    v2_path = root / "eval" / "golden_set_v2.json"
    v1_path = root / "eval" / "golden_set.json"

    assert v2_path.exists(), f"Missing file: {v2_path}"
    assert v1_path.exists(), f"Missing file: {v1_path}"

    with open(v2_path, "r", encoding="utf-8") as f:
        v2_data = json.load(f)

    with open(v1_path, "r", encoding="utf-8") as f:
        v1_data = json.load(f)

    # 1. Assert _note exists and warns about test domains
    assert "_note" in v2_data, "golden_set_v2.json must have a top-level '_note' key"
    assert isinstance(v2_data["_note"], str) and len(v2_data["_note"]) > 10

    cases = v2_data.get("golden_set", [])
    assert len(cases) >= 72, f"Expected at least 72 cases in golden_set_v2.json, found {len(cases)}"

    # 2. Assert unique IDs
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), f"Duplicate IDs found in golden_set_v2: {[x for x in ids if ids.count(x) > 1]}"

    # 3. Assert required schema fields for each case
    required_fields = [
        "id", "category", "channel", "lang_variant",
        "expected_risk_level", "expected_is_scam",
        "min_expected_score", "max_expected_score",
        "expected_signals", "tags", "source", "split"
    ]

    for c in cases:
        for rf in required_fields:
            assert rf in c, f"Case {c.get('id')} missing required field '{rf}'"
        assert "input_text" in c or "turns" in c, f"Case {c.get('id')} must have 'input_text' or 'turns'"

        # 4. Assert min <= max
        min_score = c["min_expected_score"]
        max_score = c["max_expected_score"]
        assert min_score <= max_score, f"Case {c['id']}: min_expected_score ({min_score}) > max_expected_score ({max_score})"

        # 5. Assert score falls within expected risk level band
        lvl = c["expected_risk_level"]
        if lvl == "LOW":
            assert 0 <= min_score <= max_score <= 39, f"Case {c['id']} (LOW) scores [{min_score}, {max_score}] out of band [0, 39]"
        elif lvl == "MEDIUM":
            assert 40 <= min_score <= max_score <= 74, f"Case {c['id']} (MEDIUM) scores [{min_score}, {max_score}] out of band [40, 74]"
        elif lvl == "HIGH":
            assert 75 <= min_score <= max_score <= 89, f"Case {c['id']} (HIGH) scores [{min_score}, {max_score}] out of band [75, 89]"
        elif lvl == "CRITICAL":
            assert 90 <= min_score <= max_score <= 99, f"Case {c['id']} (CRITICAL) scores [{min_score}, {max_score}] out of band [90, 99]"
        else:
            pytest.fail(f"Unknown risk level: {lvl} in case {c['id']}")

        # 6. Assert lang_variant consistency
        if c["id"] in [f"CASE_{i:02d}" for i in range(56, 61)]:
            assert c["lang_variant"] == "no_accent", f"Case {c['id']} should have lang_variant 'no_accent'"
        else:
            assert c["lang_variant"] == "standard_vi", f"Case {c['id']} should have lang_variant 'standard_vi'"

        # 7. Assert no label-leaking domain names ('fake' or 'evil')
        txt = c.get("input_text", "")
        for word in txt.split():
            for bad in ["fake.", "fake-", "-fake", "evil"]:
                assert bad not in word.lower(), f"Leaked label word '{bad}' found in case {c['id']}: '{word}'"

    # 8. Assert CASE_01 to CASE_20 match golden_set.json identically
    v1_cases = v1_data.get("golden_set", [])
    assert len(v1_cases) == 20
    for idx in range(20):
        c1 = v1_cases[idx]
        c2 = cases[idx]
        assert c2["id"] == c1["id"], f"ID mismatch at index {idx}: {c2['id']} != {c1['id']}"
        assert c2["category"] == c1["category"], f"Category mismatch in {c1['id']}"
        assert c2["input_text"] == c1["input_text"], f"Input text changed in {c1['id']}"
        assert c2["expected_risk_level"] == c1["expected_risk_level"], f"Expected risk level mismatch in {c1['id']}"
        assert c2["min_expected_score"] == c1["min_expected_score"], f"Min expected score mismatch in {c1['id']}"
