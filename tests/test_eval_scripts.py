import os
import tempfile
from pathlib import Path

import pytest

from eval.ablation import format_ablation_table, update_results_markdown, MARKER_START, MARKER_END
from eval.url_eval import (
    apply_benign_transform,
    apply_phishing_transform,
    compute_auroc,
    compute_threshold_metrics,
    evaluate_thresholds,
    extract_host,
    predict_url_module,
    select_best_threshold,
)
from codebase.url_analysis import UrlAnalyzer
from codebase.url_analysis.blacklist import PhishBlacklist


@pytest.fixture(scope="module")
def shared_analyzer():
    """Create UrlAnalyzer with blacklist excluding test split for evaluation testing."""
    bl = PhishBlacklist.from_dataset(exclude_splits=["test"])
    return UrlAnalyzer(blacklist=bl)


def test_url_module_predictor_synthetic(shared_analyzer):
    """Predictor url_module achieves >= 10/12 recall on synthetic obfuscated/phishing URLs."""
    synthetic_phish_urls = [
        "https://vcb-verify.xyz/login",
        "http://vietcombank.com.vn@evil-login.com/",
        "http://evil-vcb.top/login",
        "https://www.google.com/url?q=https%3A%2F%2Fevil-phish.xyz",
        "https://v\u0441b-secure.xyz",
        "http://xn--vcb-vrify-k0h.xyz/",
        r"https://evil-phish.top\@vietcombank.com.vn/",
        "http://3232235777/login",
        "http://shopee-hoantien.top/nhanqua",
        "https://track.mail-vn.com/c?u=" + "http://evil-phish.xyz".encode("utf-8").hex(),
        "http://vcb.fake-domain.com.vn/login",
        "http://vcb-verify.xyz/%252F%256C%256F%2567%2569%256E",
    ]

    flagged = 0
    for u in synthetic_phish_urls:
        is_pred, score, signals = predict_url_module(shared_analyzer, u)
        if is_pred:
            flagged += 1

    assert flagged >= 10, f"Expected at least 10/12 synthetic phishing URLs flagged, got {flagged}/{len(synthetic_phish_urls)}"


def test_url_module_benign_synthetic(shared_analyzer):
    """Predictor url_module reports 0/12 false positives on legitimate/official domains."""
    benign_urls = [
        "https://vietcombank.com.vn/",
        "https://bidv.com.vn/",
        "https://chinhphu.vn/",
        "https://dantri.com.vn/",
        "https://google.com/search?q=test",
        "https://zalo.me/",
        "https://facebook.com/",
        "https://github.com/",
        "https://tuoitre.vn/",
        "https://vnexpress.net/",
        "https://gov.vn/",
        "https://vneid.gov.vn/",
    ]

    fps = 0
    for u in benign_urls:
        is_pred, score, signals = predict_url_module(shared_analyzer, u)
        if is_pred:
            fps += 1

    assert fps == 0, f"Expected 0/12 benign URLs flagged, got {fps}"


def test_augmentation_transforms_format():
    """Verify that new and existing augmentation transforms produce valid expected formats."""
    base_url = "http://vietcombank-login.xyz/auth"

    # 1. Homoglyph Cyrillic contains non-ASCII characters
    res_homo = apply_phishing_transform(base_url, "homoglyph_cyrillic")
    assert any(ord(c) > 127 for c in res_homo), "homoglyph_cyrillic must contain non-ASCII character"

    # 2. Punycode IDN starts with xn--
    res_puny = apply_phishing_transform(base_url, "punycode_idn")
    host_puny = extract_host(res_puny)
    assert host_puny.startswith("xn--"), f"punycode_idn host must start with 'xn--', got {host_puny}"

    # 3. Backslash confusion contains '\@'
    res_slash = apply_phishing_transform(base_url, "backslash_confusion")
    assert r"\@" in res_slash, f"backslash_confusion must contain '\\@', got {res_slash}"

    # 4. Nested redirect contains google redirector and encoded parameter
    res_nest = apply_phishing_transform(base_url, "nested_redirect")
    assert "google.com/url?q=" in res_nest, f"nested_redirect must contain google.com/url?q=, got {res_nest}"

    # 5. Double encoding contains '%25'
    res_dbl = apply_phishing_transform(base_url, "double_encoding")
    assert "%25" in res_dbl, f"double_encoding must contain '%25', got {res_dbl}"

    # 6. Hex param contains hex query
    res_hex = apply_phishing_transform(base_url, "hex_param")
    assert "track.mail-vn.com/c?u=" in res_hex, f"hex_param must contain track.mail-vn.com/c?u=, got {res_hex}"

    # 7. IP decimal converts IPv4 address to decimal representation
    ip_url = "http://192.168.1.1/admin"
    res_ip = apply_phishing_transform(ip_url, "ip_decimal")
    assert "3232235777" in res_ip, f"ip_decimal must convert 192.168.1.1 to 3232235777, got {res_ip}"

    # 8. Benign transform trailing punctuation
    benign_punct = apply_benign_transform("https://chinhphu.vn", "trailing_punct")
    assert benign_punct.endswith("."), f"benign trailing_punct must end with '.', got {benign_punct}"


def test_compute_auroc_manual_examples():
    """Verify compute_auroc against hand-calculated examples including ties."""
    # Example 1: Perfect separation
    labels_1 = [1, 1, 0, 0]
    scores_1 = [100.0, 80.0, 20.0, 10.0]
    assert compute_auroc(labels_1, scores_1) == 1.0

    # Example 2: Hand-calculated with ties
    # Sorted: (5,0)->rank 1; (10,1) & (10,0)->avg rank 2.5; (20,1)->rank 4
    # Pos rank sum = 2.5 + 4 = 6.5; U = 6.5 - (2*3)/2 = 3.5; AUROC = 3.5 / (2*2) = 0.875
    labels_2 = [1, 1, 0, 0]
    scores_2 = [20.0, 10.0, 10.0, 5.0]
    assert compute_auroc(labels_2, scores_2) == 0.875

    # Example 3: Complete tie (random guessing baseline)
    labels_3 = [1, 0]
    scores_3 = [50.0, 50.0]
    assert compute_auroc(labels_3, scores_3) == 0.5


def test_ablation_format_table_and_marker_update():
    """Verify ablation table formatting and safe marker update in RESULTS.md."""
    mock_records = [
        {
            "config": "A (Phase 0)",
            "description": "Đo ở Phase 0 (commit 250d938), không chạy lại",
            "formatted": {
                "macro_f1": "—",
                "v1_exact": "65.0% (13/20)",
                "v2_exact": "40.3%",
                "v2_high_recall": "31.7%",
                "v2_fpr_benign": "18.2%",
                "v2_crit_strict": "40.0%",
                "p95_ms": "—",
                "url_id_recall": "22.1%",
                "url_recall_best_f1": "—",
                "url_fpr_best_f1": "—",
                "url_aug_recall_avg": "26.9%",
                "url_aug_recall_no_art": "10.7%",
                "url_benign_fpr": "7.4%",
                "url_auroc": "0.5790",
            },
        },
        {
            "config": "B (URL Off)",
            "description": "SAFEGUARD_URL_MODULE=off (Phase 1 + T1.6)",
            "formatted": {
                "macro_f1": "0.5841",
                "v1_exact": "80.0% (16/20)",
                "v2_exact": "55.6%",
                "v2_high_recall": "46.3%",
                "v2_fpr_benign": "13.6%",
                "v2_crit_strict": "80.0%",
                "p95_ms": "120.5",
                "url_id_recall": "22.1%",
                "url_recall_best_f1": "35.8%",
                "url_fpr_best_f1": "2.5%",
                "url_aug_recall_avg": "26.9%",
                "url_aug_recall_no_art": "10.7%",
                "url_benign_fpr": "7.4%",
                "url_auroc": "0.5790",
            },
            "v2_dev_metrics": {"accuracy_exact": 0.512, "fpr_benign": 0.16, "critical_recall_strict": 0.8},
            "v2_test_metrics": {"accuracy_exact": 0.613, "fpr_benign": 0.10, "critical_recall_strict": 0.8},
        },
        {
            "config": "C (URL On)",
            "description": "Module URL deobfuscation bật (mặc định Phase 2)",
            "formatted": {
                "macro_f1": "0.7812",
                "v1_exact": "85.0% (17/20)",
                "v2_exact": "73.6%",
                "v2_high_recall": "73.2%",
                "v2_fpr_benign": "9.1%",
                "v2_crit_strict": "100.0%",
                "p95_ms": "145.2",
                "url_id_recall": "68.5%",
                "url_recall_best_f1": "74.1%",
                "url_fpr_best_f1": "9.6%",
                "url_aug_recall_avg": "88.2%",
                "url_aug_recall_no_art": "86.1%",
                "url_benign_fpr": "0.5%",
                "url_auroc": "0.9412",
            },
            "v2_dev_metrics": {"accuracy_exact": 0.707, "fpr_benign": 0.12, "critical_recall_strict": 1.0},
            "v2_test_metrics": {"accuracy_exact": 0.774, "fpr_benign": 0.05, "critical_recall_strict": 1.0},
        },
    ]

    table_md = format_ablation_table(mock_records)
    assert "| Cấu hình |" in table_md
    assert "| URL recall@bestF1 |" in table_md
    assert "| URL FPR@bestF1 |" in table_md
    assert "**A (Phase 0)**" in table_md
    assert "**B (URL Off)**" in table_md
    assert "**C (URL On)**" in table_md
    assert "74.1%" in table_md
    assert "Chi tiết v2 B (URL Off)" in table_md
    assert "Chi tiết v2 C (URL On)" in table_md

    # Test updating markdown content with existing markers
    initial_content = (
        "# SAFEGUARD AI\n\n"
        "Some existing text here.\n\n"
        f"{MARKER_START}\nold table content\n{MARKER_END}\n\n"
        "Footer notes that must be preserved."
    )
    updated = update_results_markdown(initial_content, table_md)

    assert "Some existing text here." in updated
    assert "Footer notes that must be preserved." in updated
    assert "old table content" not in updated
    assert MARKER_START in updated
    assert MARKER_END in updated
    assert "**C (URL On)**" in updated

    # Test updating markdown content without existing markers (clean append)
    no_marker_content = "# SAFEGUARD AI\n\nNo markers here."
    appended = update_results_markdown(no_marker_content, table_md)
    assert "# SAFEGUARD AI\n\nNo markers here." in appended
    assert MARKER_START in appended
    assert MARKER_END in appended


def test_threshold_sweep_manual_example():
    """Verify compute_threshold_metrics and select_best_threshold on 6 hand-calculated points."""
    labels = [1, 1, 1, 0, 0, 0]
    scores = [15.0, 30.0, 50.0, 5.0, 20.0, 40.0]

    sweep = compute_threshold_metrics(labels, scores, thresholds=[15, 20, 30, 40, 50])

    # Check metrics at threshold 20:
    # Pos >= 20: 30, 50 (TP=2, FN=1); Neg >= 20: 20, 40 (FP=2, TN=1)
    # Precision = 2/4 = 0.5, Recall = 2/3 ≈ 0.6667, FPR = 2/3 ≈ 0.6667
    m20 = sweep[20]
    assert m20["tp"] == 2
    assert m20["fp"] == 2
    assert m20["fn"] == 1
    assert m20["tn"] == 1
    assert m20["precision"] == 0.5
    assert m20["recall"] == 0.6667
    assert m20["fpr"] == 0.6667
    assert m20["f1"] == 0.5714

    # Check metrics at threshold 30:
    # Pos >= 30: 30, 50 (TP=2, FN=1); Neg >= 30: 40 (FP=1, TN=2)
    # Precision = 2/3 ≈ 0.6667, Recall = 2/3 ≈ 0.6667, FPR = 1/3 ≈ 0.3333, F1 ≈ 0.6667
    m30 = sweep[30]
    assert m30["tp"] == 2
    assert m30["fp"] == 1
    assert m30["fn"] == 1
    assert m30["tn"] == 2
    assert m30["precision"] == 0.6667
    assert m30["recall"] == 0.6667
    assert m30["fpr"] == 0.3333
    assert m30["f1"] == 0.6667

    # Optimal threshold for this hand example is 15 (TP=3, FP=2, FN=0, TN=1, Prec=0.6, Rec=1.0, F1=0.75)
    best = select_best_threshold(sweep)
    assert best["threshold"] == 15
    assert best["f1"] == 0.75


def test_select_best_threshold_tie_breaker():
    """Verify tie breaking: when F1 is tied, select lower FPR; when FPR also tied, higher recall."""
    # Case 1: Same F1, different FPR -> lower FPR wins
    sweep_tie_fpr = {
        10: {"threshold": 10, "f1": 0.8000, "fpr": 0.15, "recall": 0.80, "precision": 0.80},
        20: {"threshold": 20, "f1": 0.8000, "fpr": 0.05, "recall": 0.80, "precision": 0.80},
    }
    best_fpr = select_best_threshold(sweep_tie_fpr)
    assert best_fpr["threshold"] == 20, "Tie breaker must prefer lower FPR"

    # Case 2: Same F1 and same FPR, different Recall -> higher Recall wins
    sweep_tie_rec = {
        15: {"threshold": 15, "f1": 0.7500, "fpr": 0.10, "recall": 0.85, "precision": 0.67},
        25: {"threshold": 25, "f1": 0.7500, "fpr": 0.10, "recall": 0.70, "precision": 0.81},
    }
    best_rec = select_best_threshold(sweep_tie_rec)
    assert best_rec["threshold"] == 15, "Tie breaker must prefer higher Recall when FPR is equal"


def test_evaluate_thresholds_selected_on_val_not_test():
    """
    Verify best_f1 selects optimal threshold on validation set, NOT on test set.
    Synthetic setup:
      - Val set has optimal F1 at t = 20
      - Test set has optimal F1 at t = 40
    evaluate_thresholds must select t = 20, report test metrics at t = 20, and set selected_on = 'val'.
    """
    # Val: optimal at t = 20 (F1 = 1.0), zero at t = 40
    val_labels = [1, 1, 0, 0]
    val_scores = [20.0, 30.0, 5.0, 10.0]

    # Test: optimal at t = 40 (F1 = 1.0), suboptimal at t = 20 (F1 = 0.8)
    test_labels = [1, 1, 0, 0]
    test_scores = [45.0, 50.0, 15.0, 25.0]

    test_sweep, best_f1 = evaluate_thresholds(
        test_labels=test_labels,
        test_scores=test_scores,
        val_labels=val_labels,
        val_scores=val_scores,
        thresholds=[10, 20, 30, 40],
    )

    # Must pick t = 20 (from val), NOT t = 40 (which would be test tuning)
    assert best_f1["threshold"] == 20, f"Expected threshold 20 from val set, got {best_f1['threshold']}"
    assert best_f1["selected_on"] == "val"
    assert best_f1["val_f1"] == 1.0

    # Test metrics reported must be those at t = 20 on test set
    assert best_f1["f1"] == test_sweep[20]["f1"]
    assert best_f1["recall"] == test_sweep[20]["recall"]
    assert best_f1["fpr"] == test_sweep[20]["fpr"]
    assert best_f1["precision"] == test_sweep[20]["precision"]

