import pytest
from eval.metrics import (
    accuracy_score,
    accuracy_within_one_step,
    confusion_matrix_4class,
    per_class_metrics,
    macro_f1_score,
    binary_high_plus,
    binary_medium_plus,
    fpr_benign,
    fpr_benign_high_plus,
    critical_recall_strict,
    critical_recall_loose,
    percentile,
    bootstrap_ci,
    compute_all_metrics,
)


def test_hand_calculated_metrics():
    # 8 hand-crafted cases
    y_true = ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"]
    y_pred = ["LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL", "HIGH"]

    # 1. Accuracy
    acc = accuracy_score(y_true, y_pred)
    assert acc == 0.5  # 4 matches out of 8

    # 2. Accuracy within 1 step
    acc_1step = accuracy_within_one_step(y_true, y_pred)
    assert acc_1step == 1.0  # all predictions within 1 rank step

    # 3. Confusion Matrix
    cm = confusion_matrix_4class(y_true, y_pred)
    assert cm["LOW"]["LOW"] == 1
    assert cm["LOW"]["MEDIUM"] == 1
    assert cm["MEDIUM"]["MEDIUM"] == 1
    assert cm["MEDIUM"]["HIGH"] == 1
    assert cm["HIGH"]["HIGH"] == 1
    assert cm["HIGH"]["CRITICAL"] == 1
    assert cm["CRITICAL"]["CRITICAL"] == 1
    assert cm["CRITICAL"]["HIGH"] == 1

    # 4. Per-class metrics
    pcm = per_class_metrics(y_true, y_pred)
    assert pcm["LOW"]["precision"] == 1.0
    assert pcm["LOW"]["recall"] == 0.5
    assert pcm["LOW"]["f1"] == 0.6667
    assert pcm["LOW"]["support"] == 2

    assert pcm["MEDIUM"]["precision"] == 0.5
    assert pcm["MEDIUM"]["recall"] == 0.5
    assert pcm["MEDIUM"]["f1"] == 0.5

    assert pcm["HIGH"]["precision"] == 0.3333
    assert pcm["HIGH"]["recall"] == 0.5
    assert pcm["HIGH"]["f1"] == 0.4

    assert pcm["CRITICAL"]["precision"] == 0.5
    assert pcm["CRITICAL"]["recall"] == 0.5
    assert pcm["CRITICAL"]["f1"] == 0.5

    # 5. Macro-F1
    mf1 = macro_f1_score(y_true, y_pred)
    assert mf1 == round((0.6667 + 0.5 + 0.4 + 0.5) / 4, 4)  # 0.5167

    # 6. Binary HIGH+
    b_high = binary_high_plus(y_true, y_pred)
    assert b_high["precision"] == 0.8
    assert b_high["recall"] == 1.0
    assert b_high["f1"] == 0.8889
    assert b_high["accuracy"] == 0.875

    # 7. Binary >=MEDIUM
    b_med = binary_medium_plus(y_true, y_pred)
    assert b_med["precision"] == 0.8571
    assert b_med["recall"] == 1.0
    assert b_med["f1"] == 0.9231
    assert b_med["accuracy"] == 0.875

    # 8. FPR on Benign (LOW)
    assert fpr_benign(y_true, y_pred) == 0.5  # 1 false alarm (MEDIUM) out of 2 LOW
    assert fpr_benign_high_plus(y_true, y_pred) == 0.0  # 0 high alarms out of 2 LOW

    # 9. Critical recall strict vs loose
    assert critical_recall_strict(y_true, y_pred) == 0.5  # 1 of 2 predicted CRITICAL
    assert critical_recall_loose(y_true, y_pred) == 1.0  # both predicted CRITICAL or HIGH


def test_percentile():
    vals = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0]
    p50 = percentile(vals, 50)
    p95 = percentile(vals, 95)
    assert p50 == 55.0
    assert p95 == 95.5


def test_bootstrap_ci_deterministic():
    y_true = ["LOW", "HIGH", "CRITICAL", "LOW"] * 5
    y_pred = ["LOW", "MEDIUM", "CRITICAL", "LOW"] * 5
    ci1 = bootstrap_ci(y_true, y_pred, accuracy_score, n_resamples=100, seed=42)
    ci2 = bootstrap_ci(y_true, y_pred, accuracy_score, n_resamples=100, seed=42)
    assert ci1 == ci2
    assert ci1[0] <= ci1[1]


def test_compute_all_metrics_structure():
    records = [
        {"expected_risk_level": "LOW", "predicted_risk_level": "LOW", "latency_ms": 12.5, "is_exact_match": True, "is_lenient_match": True},
        {"expected_risk_level": "CRITICAL", "predicted_risk_level": "CRITICAL", "latency_ms": 25.0, "is_exact_match": True, "is_lenient_match": True},
    ]
    res = compute_all_metrics(records)
    assert res["total_cases"] == 2
    assert res["accuracy"] == 1.0
    assert res["accuracy_exact"] == 1.0
    assert res["accuracy_lenient"] == 1.0
    assert res["passed_cases_exact"] == 2
    assert res["passed_cases_lenient"] == 2
    assert "accuracy_ci_95" in res
    assert "confusion_matrix" in res
    assert "latency" in res
    assert res["latency"]["count"] == 2
    assert res["latency"]["p50_ms"] == 18.75


def test_critical_recall_no_critical():
    # Dataset without any CRITICAL cases must return None (not 1.0)
    y_true = ["LOW", "MEDIUM", "HIGH", "LOW"]
    y_pred = ["LOW", "LOW", "HIGH", "MEDIUM"]

    assert critical_recall_strict(y_true, y_pred) is None
    assert critical_recall_loose(y_true, y_pred) is None

    records = [
        {"expected_risk_level": "LOW", "predicted_risk_level": "LOW"},
        {"expected_risk_level": "HIGH", "predicted_risk_level": "HIGH"},
    ]
    res = compute_all_metrics(records)
    assert res["critical_recall_strict"] is None
    assert res["critical_recall_loose"] is None
