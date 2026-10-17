# SAFEGUARD AI — BENCHMARK RESULTS & ABLATION

| Cấu hình | Mô tả | Golden v1 Acc | Phish Identity Recall | Phish Aug Recall Avg | Benign Identity FPR | AUROC |
|---|---|---|---|---|---|---|
| **A-Baseline** | Code gốc ExplainableAgent (offline) | 65.0% (13/20 exact) | 22.1% | 26.9% | 7.4% | 0.5790 |

> [!NOTE]
> - **Cỡ mẫu phishing**: Đã lấy mẫu ngẫu nhiên 1000/5125 URL phishing (seed 42), toàn bộ 1968 URL benign từ tập test PhishVN (`url_test.csv`).
> - **Phish Aug Recall Avg**:
>   - Tính trên toàn bộ 11 biến thể augmentation ban đầu: **26.9%**.
>   - Tính khi loại trừ 2 biến thể artifact (`userinfo_decoy` và `base64_param`): **10.7%**.
>   - *Lý do*: Hai transform `userinfo_decoy` (chèn `vietcombank.com.vn@...`) và `base64_param` (chèn domain chứa dấu gạch ngang `track.mail-vn.com`) luôn đạt recall 100.0% là artifact của augmentation (chuỗi mồi tự động kích hoạt luật so khớp BLOCK D của ExplainableAgent).
> - **Quy tắc chấm Golden v1**: Luật chấm đổi từ lenient (14/20) sang exact (13/20).

<!-- ABLATION:START -->

## Bảng so sánh Ablation Module URL

| Cấu hình | Mô tả / Nguồn | Macro-F1 (v2) | Golden v1 Exact | Golden v2 Exact | Recall HIGH+ (v2) | FPR>=MED (v2) | Recall CRIT chặt (v2) | p95 (ms) | URL Identity Recall | URL recall@bestF1 | URL FPR@bestF1 | URL Aug Recall (Avg / No-art) | URL Benign FPR | AUROC |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **A (Phase 0)** | Đo ở Phase 0 (commit 250d938), không chạy lại | — | 65.0% (13/20) | 40.3% | 31.7% | 18.2% | 40.0% | — | 22.1% | — | — | 26.9% / 10.7% | 7.4% | 0.5790 |

> [!NOTE]
> - **Cấu hình A (Phase 0)**: Đo ở Phase 0 (commit 250d938), giữ nguyên làm đối chứng, không chạy lại.
> - **Cấu hình B (URL Off)**: Tắt module URL (`SAFEGUARD_URL_MODULE=off`), giữ nguyên logic ExplainableAgent cũ và cải tiến Phase 1.
> - **Cấu hình C (URL On)**: Bật module URL Deobfuscation & Analysis đầy đủ (WhatWG URL parsing, multi-layer decoding, IDN homoglyph, Brand catalog, PhishBlacklist train+val).
> - **Ngưỡng tối ưu**: Cột `URL recall@bestF1` và `URL FPR@bestF1` đo hiệu năng tại ngưỡng tối ưu F1 chọn trên tập validation (url_val.csv), tránh chọn ngưỡng trên test.

<!-- ABLATION:END -->
