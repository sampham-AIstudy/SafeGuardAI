import math
import random
from typing import Callable, Sequence

CLASSES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
LEVEL_MAP = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def accuracy_score(y_true: Sequence[str], y_pred: Sequence[str]) -> float:
    if not y_true:
        return 0.0
    return sum(1 for yt, yp in zip(y_true, y_pred) if yt == yp) / len(y_true)


def accuracy_within_one_step(y_true: Sequence[str], y_pred: Sequence[str]) -> float:
    if not y_true:
        return 0.0
    valid = 0
    for yt, yp in zip(y_true, y_pred):
        diff = abs(LEVEL_MAP.get(yt, -99) - LEVEL_MAP.get(yp, -99))
        if diff <= 1:
            valid += 1
    return valid / len(y_true)


def confusion_matrix_4class(y_true: Sequence[str], y_pred: Sequence[str]) -> dict[str, dict[str, int]]:
    matrix = {t: {p: 0 for p in CLASSES} for t in CLASSES}
    for yt, yp in zip(y_true, y_pred):
        if yt in matrix and yp in matrix[yt]:
            matrix[yt][yp] += 1
    return matrix


def per_class_metrics(y_true: Sequence[str], y_pred: Sequence[str]) -> dict[str, dict[str, float]]:
    res = {}
    for cls in CLASSES:
        tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == cls and yp == cls)
        fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt != cls and yp == cls)
        fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == cls and yp != cls)
        support = sum(1 for yt in y_true if yt == cls)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        res[cls] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": support,
            "tp": tp,
            "fp": fp,
            "fn": fn
        }
    return res


def macro_f1_score(y_true: Sequence[str], y_pred: Sequence[str]) -> float:
    metrics = per_class_metrics(y_true, y_pred)
    f1_sum = sum(m["f1"] for m in metrics.values())
    return round(f1_sum / len(CLASSES), 4)


def _binary_stats(true_pos: Sequence[bool], pred_pos: Sequence[bool]) -> dict[str, float]:
    if not true_pos:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0, "accuracy": 0.0, "support": 0}
    tp = sum(1 for t, p in zip(true_pos, pred_pos) if t and p)
    fp = sum(1 for t, p in zip(true_pos, pred_pos) if not t and p)
    fn = sum(1 for t, p in zip(true_pos, pred_pos) if t and not p)
    tn = sum(1 for t, p in zip(true_pos, pred_pos) if not t and not p)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    acc = (tp + tn) / len(true_pos) if len(true_pos) > 0 else 0.0

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(acc, 4),
        "support": sum(1 for t in true_pos if t)
    }


def binary_high_plus(y_true: Sequence[str], y_pred: Sequence[str]) -> dict[str, float]:
    t = [yt in ("HIGH", "CRITICAL") for yt in y_true]
    p = [yp in ("HIGH", "CRITICAL") for yp in y_pred]
    return _binary_stats(t, p)


def binary_medium_plus(y_true: Sequence[str], y_pred: Sequence[str]) -> dict[str, float]:
    t = [yt in ("MEDIUM", "HIGH", "CRITICAL") for yt in y_true]
    p = [yp in ("MEDIUM", "HIGH", "CRITICAL") for yp in y_pred]
    return _binary_stats(t, p)


def fpr_benign(y_true: Sequence[str], y_pred: Sequence[str]) -> float:
    """FPR on benign cases (expected LOW). False positive = predicted >= MEDIUM."""
    benign_count = sum(1 for yt in y_true if yt == "LOW")
    if benign_count == 0:
        return 0.0
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == "LOW" and yp in ("MEDIUM", "HIGH", "CRITICAL"))
    return round(fp / benign_count, 4)


def fpr_benign_high_plus(y_true: Sequence[str], y_pred: Sequence[str]) -> float:
    """FPR on benign cases (expected LOW) predicted as HIGH or CRITICAL."""
    benign_count = sum(1 for yt in y_true if yt == "LOW")
    if benign_count == 0:
        return 0.0
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == "LOW" and yp in ("HIGH", "CRITICAL"))
    return round(fp / benign_count, 4)


def critical_recall_strict(y_true: Sequence[str], y_pred: Sequence[str]) -> float | None:
    """Recall for CRITICAL cases when predicted is strictly CRITICAL. Returns None if no CRITICAL cases."""
    crit_count = sum(1 for yt in y_true if yt == "CRITICAL")
    if crit_count == 0:
        return None
    hit = sum(1 for yt, yp in zip(y_true, y_pred) if yt == "CRITICAL" and yp == "CRITICAL")
    return round(hit / crit_count, 4)


def critical_recall_loose(y_true: Sequence[str], y_pred: Sequence[str]) -> float | None:
    """Recall for CRITICAL cases when predicted is either CRITICAL or HIGH. Returns None if no CRITICAL cases."""
    crit_count = sum(1 for yt in y_true if yt == "CRITICAL")
    if crit_count == 0:
        return None
    hit = sum(1 for yt, yp in zip(y_true, y_pred) if yt == "CRITICAL" and yp in ("CRITICAL", "HIGH"))
    return round(hit / crit_count, 4)


def percentile(values: Sequence[float], p: float) -> float:
    """Pure Python linear-interpolated percentile."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(sorted_vals[int(k)])
    d0 = sorted_vals[int(f)] * (c - k)
    d1 = sorted_vals[int(c)] * (k - f)
    return round(float(d0 + d1), 2)


def bootstrap_ci(y_true: Sequence[str], y_pred: Sequence[str],
                 metric_fn: Callable[[Sequence[str], Sequence[str]], float],
                 n_resamples: int = 1000, seed: int = 42, alpha: float = 0.05) -> tuple[float, float]:
    """Bootstrap confidence interval calculation with fixed random seed."""
    if not y_true:
        return (0.0, 0.0)
    n = len(y_true)
    rng = random.Random(seed)
    scores = []
    for _ in range(n_resamples):
        indices = [rng.randint(0, n - 1) for _ in range(n)]
        b_true = [y_true[i] for i in indices]
        b_pred = [y_pred[i] for i in indices]
        scores.append(metric_fn(b_true, b_pred))

    sorted_scores = sorted(scores)
    low_idx = int((alpha / 2.0) * n_resamples)
    high_idx = int((1.0 - alpha / 2.0) * n_resamples)
    high_idx = min(high_idx, n_resamples - 1)
    return (round(sorted_scores[low_idx], 4), round(sorted_scores[high_idx], 4))


def compute_all_metrics(records: list[dict]) -> dict:
    """
    Compute comprehensive metrics from a list of case result records.
    Each record must have 'expected_risk_level' and 'predicted_risk_level'.
    Optional: 'latency_ms'.
    """
    y_true = [r["expected_risk_level"] for r in records]
    y_pred = [r["predicted_risk_level"] for r in records]
    latencies = [r["latency_ms"] for r in records if "latency_ms" in r and r["latency_ms"] is not None]

    acc = round(accuracy_score(y_true, y_pred), 4)
    acc_1step = round(accuracy_within_one_step(y_true, y_pred), 4)
    macro_f1 = macro_f1_score(y_true, y_pred)
    per_class = per_class_metrics(y_true, y_pred)
    conf_mat = confusion_matrix_4class(y_true, y_pred)
    b_high = binary_high_plus(y_true, y_pred)
    b_med = binary_medium_plus(y_true, y_pred)
    crit_strict = critical_recall_strict(y_true, y_pred)
    crit_loose = critical_recall_loose(y_true, y_pred)
    fpr_b = fpr_benign(y_true, y_pred)
    fpr_b_high = fpr_benign_high_plus(y_true, y_pred)

    ci_acc = bootstrap_ci(y_true, y_pred, accuracy_score)
    ci_f1 = bootstrap_ci(y_true, y_pred, macro_f1_score)

    latency_stats = {}
    if latencies:
        latency_stats = {
            "p50_ms": percentile(latencies, 50),
            "p95_ms": percentile(latencies, 95),
            "mean_ms": round(sum(latencies) / len(latencies), 2),
            "min_ms": round(min(latencies), 2),
            "max_ms": round(max(latencies), 2),
            "count": len(latencies)
        }

    exact_count = sum(1 for r in records if r.get("is_exact_match", r.get("expected_risk_level") == r.get("predicted_risk_level")))
    lenient_count = sum(1 for r in records if r.get("is_lenient_match", r.get("is_exact_match", r.get("expected_risk_level") == r.get("predicted_risk_level"))))
    total_count = len(records)
    acc_lenient = round(lenient_count / total_count, 4) if total_count > 0 else 0.0

    return {
        "total_cases": len(records),
        "accuracy": acc,
        "accuracy_exact": acc,
        "accuracy_lenient": acc_lenient,
        "passed_cases_exact": exact_count,
        "passed_cases_lenient": lenient_count,
        "accuracy_ci_95": ci_acc,
        "accuracy_within_one_step": acc_1step,
        "macro_f1": macro_f1,
        "macro_f1_ci_95": ci_f1,
        "per_class": per_class,
        "confusion_matrix": conf_mat,
        "binary_high_plus": b_high,
        "binary_medium_plus": b_med,
        "critical_recall_strict": crit_strict,
        "critical_recall_loose": crit_loose,
        "fpr_benign": fpr_b,
        "fpr_benign_high_plus": fpr_b_high,
        "latency": latency_stats
    }
