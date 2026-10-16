"""
Test to ensure no golden set strings are leaked/hardcoded in codebase/**/*.py.
Rule: For every input_text in golden_set.json and golden_set_v2.json,
no substring of length >= 40 characters appears in any codebase/**/*.py file.
"""

import json
from pathlib import Path
import pytest


def get_golden_texts(eval_dir: Path) -> tuple[list[dict], list[dict], list[str]]:
    """
    Load golden cases from golden_set.json (v1) and golden_set_v2.json (v2).
    Accepts either a raw list or a dict with key 'golden_set'.
    Returns (v1_cases, v2_cases, input_texts).
    """
    golden_files = [
        eval_dir / "golden_set.json",
        eval_dir / "golden_set_v2.json",
    ]

    v1_cases = []
    v2_cases = []
    input_texts = []

    for idx, gfile in enumerate(golden_files):
        if not gfile.exists():
            continue
        with open(gfile, "r", encoding="utf-8") as f:
            data = json.load(f)
            cases = data if isinstance(data, list) else data.get("golden_set", [])
            if idx == 0:
                v1_cases = cases
            else:
                v2_cases = cases

            for case in cases:
                txt = case.get("input_text", "")
                if txt and len(txt) >= 20:
                    input_texts.append(txt)
                if "turns" in case:
                    for turn in case["turns"]:
                        t_txt = turn.get("input_text", "")
                        if t_txt and len(t_txt) >= 20:
                            input_texts.append(t_txt)

    return v1_cases, v2_cases, input_texts


# Cụm từ vựng sản phẩm / URL mẫu có sẵn từ bản gốc (HEAD) trong codebase.
# Không được allowlist cả file hay thư mục.
ALLOWED_PRODUCT_PHRASES = [
    # URL demo Agribank phishing có từ commit khởi tạo (17a520f) trong explainable_agent.py:221
    # từ vựng sản phẩm có từ bản gốc, không thêm để pass case
    "http://www.agribank.com.vn.ebanking.chuyen-tien-nhanh.auth-",
]


def check_golden_leak(
    target_dir: Path,
    golden_input_texts: list[str],
    sub_len: int = 40
) -> list[str]:
    """
    Check if any substring of length >= sub_len from golden_input_texts
    appears in any .py file under target_dir.
    Returns a list of leak descriptions.
    """
    py_files = list(target_dir.rglob("*.py"))
    corpus = {}
    for p in py_files:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            corpus[str(p)] = f.read().lower()

    leaks = []
    for text in golden_input_texts:
        text_clean = text.strip().lower()
        if len(text_clean) < sub_len:
            continue

        for i in range(len(text_clean) - sub_len + 1):
            sub = text_clean[i:i + sub_len]
            # Skip if mostly spaces or punctuation
            if len(sub.strip()) < 15:
                continue

            # Bỏ qua nếu chuỗi con thuộc các cụm sản phẩm có sẵn ở bản gốc HEAD
            if any(sub in phrase.lower() or phrase.lower() in sub for phrase in ALLOWED_PRODUCT_PHRASES):
                continue

            for file_path, content in corpus.items():
                if sub in content:
                    leaks.append(f"Leak in {file_path}: Substring '{sub}' from input '{text}'")
                    break

    return leaks


def test_no_golden_leak():
    """
    Ensure no substring of length >= 40 characters from golden sets appears in codebase/**/*.py.
    """
    repo_root = Path(__file__).resolve().parent.parent
    codebase_dir = repo_root / "codebase"
    eval_dir = repo_root / "eval"

    v1_cases, v2_cases, input_texts = get_golden_texts(eval_dir)

    # Assert correct dataset size requirements
    assert len(v1_cases) == 20, f"Expected 20 cases in golden_set.json, got {len(v1_cases)}"
    assert len(v2_cases) == 72, f"Expected 72 cases in golden_set_v2.json, got {len(v2_cases)}"
    assert len(input_texts) > 0, "Expected non-empty golden input texts"

    leaks = check_golden_leak(codebase_dir, input_texts, sub_len=40)
    assert not leaks, "Golden set text leak detected in codebase:\n" + "\n".join(leaks[:10])


def test_golden_leak_detector_catches_leak(tmp_path):
    """
    Proves that check_golden_leak actively detects leaks by placing CASE_05
    exact input text into a temporary python file with sub_len=40 characters.
    """
    repo_root = Path(__file__).resolve().parent.parent
    eval_dir = repo_root / "eval"

    v1_cases, v2_cases, input_texts = get_golden_texts(eval_dir)

    # Find CASE_05 text
    case_05_text = next(c["input_text"] for c in v1_cases if c.get("id") == "CASE_05")
    assert case_05_text, "CASE_05 must exist in v1"

    # Create dummy .py file in tmp_path with CASE_05 verbatim
    leaked_file = tmp_path / "dummy_agent.py"
    leaked_file.write_text(f'demo_var = "{case_05_text}"\n', encoding="utf-8")

    leaks = check_golden_leak(tmp_path, input_texts, sub_len=40)
    assert len(leaks) > 0, "Detector failed to catch verbatim CASE_05 leak!"
    assert any("dummy_agent.py" in l for l in leaks)
