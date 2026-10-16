# SAFEGUARD AI — BENCHMARK RESULTS & ABLATION

| Cấu hình | Mô tả | Golden v1 Acc | Phish Identity Recall | Phish Aug Recall Avg | Benign Identity FPR | AUROC |
|---|---|---|---|---|---|---|
| **A-Baseline** | Code gốc ExplainableAgent (offline) | 65.0% (13/20 exact) | 22.1% | 26.9% | 7.4% | 0.5790 |

> [!NOTE]
> - **Cỡ mẫu phishing**: Đã lấy mẫu ngẫu nhiên 1000/5125 URL phishing (seed 42), toàn bộ 1968 URL benign từ tập test PhishVN (`url_test.csv`).
> - **Phish Aug Recall Avg**:
>   - Tính trên toàn bộ 11 biến thể augmentation: **26.9%**.
>   - Tính khi loại trừ 2 biến thể artifact (`userinfo_decoy` và `base64_param`): **10.7%**.
>   - *Lý do*: Hai transform `userinfo_decoy` (chèn `vietcombank.com.vn@...`) và `base64_param` (chèn domain chứa dấu gạch ngang `track.mail-vn.com`) luôn đạt recall 100.0% là artifact của augmentation (chuỗi mồi tự động kích hoạt luật so khớp BLOCK D của ExplainableAgent).
> - **Quy tắc chấm Golden v1**: Luật chấm đổi từ lenient (14/20) sang exact (13/20).
