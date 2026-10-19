# NEXT_STEPS — việc còn lại của SafeGuardAI (Đồ án 3)

Cập nhật: 2026-10-19. Nhánh: `feature/upgrade-phase0-1a`. Kế hoạch gốc: `docs/UPGRADE_PLAN.md`
(§3 thiết kế URL; Phase 5 ở dòng ~554; đánh giá §5 ở dòng ~583).

## 1. Trạng thái hiện tại

Đã xong: Phase 0–4 và 4E (MySQL → SQLite). `pytest` 1319 test pass (~7 phút).

| Phase | Nội dung |
|---|---|
| 0–1 | Hạ tầng đo, golden v2, sửa logic tiếng Việt, ExplainableAgent, memory theo phiên |
| 2 | Module URL (`codebase/url_analysis/`): giải mã link che giấu, homoglyph, userinfo, open redirect, blacklist |
| 3 | Resolver chống SSRF, anti-bot, thông tin thụ động, threat intel, QR/ảnh. Mạng chỉ chạy khi request có `online_check=true` |
| 4 | Server đa luồng, rate limit, CORS/CSP, cô lập `client_id`, pipeline 2 tầng (LLM không hạ điểm), an toàn đầu vào/ra của LLM |
| 4E | Lịch sử chat lưu bằng SQLite (`data/safeguard.db`, bị gitignore). Đã bỏ MySQL |

## 2. Cách chạy / kiểm tra

```bash
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt -r requirements-dev.txt
set SAFEGUARD_OFFLINE=1            # mọi script đo phải đặt, nếu không có thể gọi Gemini thật
.venv/Scripts/python -m pytest -q -p no:cacheprovider
.venv/Scripts/python eval/run_eval.py          # golden v1/v2, xem README
.venv/Scripts/python codebase/server.py        # chạy server
```

Dữ liệu `data/data-phising-VN-ver1|ver2` (CSV PhishVN) không nằm trong git, cần có sẵn trong `data/`.
Cần thêm khóa API trong `.env` (file này bị gitignore, không có trong repo) nếu muốn bật LLM.

Số liệu offline tại HEAD (golden v2, 72 case): exact 73,6%, macro-F1 0,72, recall HIGH+ 73,2%,
FPR ≥MEDIUM 9,1%, recall CRITICAL 100%, p95 ~20 ms.

## 3. Việc CHƯA làm

### 3.1 Phase 5A — UI (`public/`)
- Thẻ "Phân tích đường link" cho từng finding: **Bạn thấy / Thực tế mở**, các bước che giấu,
  chuỗi redirect, lý do, gợi ý domain chính thức. URL hiển thị dạng defang, không bấm được,
  chỉ render bằng `textContent`.
- Hiển thị `pipeline_trace` thay cho animation giả; bộ chọn model nối với `llm_mode` hoặc bỏ đi.
- Hiển thị `network_actions` ("đã truy vấn ...").
- Ô/checkbox **"Kiểm tra trực tuyến"** (gửi `online_check`), kèm giải thích riêng tư.
- Hướng dẫn chụp màn hình trang khi link `unverified` (anti-bot/cloaking) để OCR.
- Ghi rõ: văn bản/ảnh vẫn được gửi cho Gemini khi LLM bật (nằm ngoài phạm vi `online_check`).
- Escape/cắt/bỏ ký tự điều khiển + bidi cho mọi chuỗi từ server (cert subject/SAN/issuer,
  tên/memo VietQR, `qr_urls`).

### 3.2 Phase 5B — dữ liệu và đánh giá
- Golden v2 lên ≥120 case (≥40 lành tính, ≥30 URL che giấu, ≥15 không dấu, ≥5 nhiều lượt,
  ≥5 injection, ≥5 ảnh/QR có fixture). Mọi domain trong golden phải là domain bịa.
- `eval/LABELING_GUIDE.md`; gán nhãn lại 30 case bởi người thứ hai, tính Cohen's kappa.
- Tạo bộ **held-out mới (heldout_v3)** chưa ai dùng để báo số cuối.
  Các bộ held-out cũ (v1, v2, urls_v1, qr_v1) nằm ngoài repo trên máy tác giả
  (`~/.safeguard_heldout/`), không có trong git, và đã dùng để chỉnh luật nên không còn độc lập.
- Chạy eval cuối + ablation (`eval/ablation.py --write-results`), phân tích ≥10 lỗi FN/FP,
  cập nhật `eval/RESULTS.md`.

### 3.3 Phase 5C — tài liệu
- README: bảng biến `SAFEGUARD_*`, các gói tùy chọn (`requirements-optional.txt`).
- Cập nhật `spec.md` §4 và §7 bằng số liệu thật (lệnh tái lập kèm `eval/results/*.json`).
- Viết `docs/ARCHITECTURE.md`, `docs/SECURITY.md` (threat model, SSRF, riêng tư), khung `docs/BAO_CAO_DO_AN_3.md`.
- Gỡ khẳng định "vector database" nếu không cài BM25/embedding.

### 3.4 Chất lượng phát hiện — chưa đạt mục tiêu
Mục tiêu đồ án: macro-F1 ≥0,80, recall HIGH+ ≥0,90, FPR ≥MEDIUM ≤10%, p95 <300 ms, URL-aug recall ≥0,90.
Hiện tại: macro-F1 0,72, recall HIGH+ 73% (golden). Trên held-out cũ còn yếu hơn:
tin nhắn HIGH+ 45% / FPR 13%; URL HIGH+ 51%; QR HIGH+ 6/15. Golden do tác giả tinh chỉnh nên lạc quan.

Lỗi đã biết, chưa sửa:
- URL combosquat/typosquat/TLD-swap đứng một mình chỉ ra 45 (MEDIUM) dù nhiều case kỳ vọng HIGH
  (cân nhắc nâng sàn lên 75 nếu FPR cho phép; đo bằng golden + held-out mới).
- Link rút gọn / hosting miễn phí offline chỉ ra điểm thấp (cần resolver, tức `online_check`).
- EmergencyAgent báo nhầm một số tin lành tính (ví dụ "Em da chuyen khoan roi anh nhe...").
- Tin không dấu, ngắn, kiểu Zalo có recall thấp; bill giả (CASE_03) chỉ MEDIUM.
- Hồi quy so với trước module URL: `faceb00k-login.com` 45→0, `haiquan-vn.top` 45→15,
  `vietqr-thanhtoan.xyz` 45→15 (brand lookalike nằm ngoài danh mục → xem lại hiệu chỉnh COMBOSQUAT).
- False positive còn lại: VNeID/công an cảnh báo/báo chí tường thuật/cọc tiệc-tour.
- URL AUROC 0,961 trên PhishVN có thể lạc quan do thiên lệch dữ liệu (benign là site phổ biến);
  khi viết báo cáo phải nêu hạn chế này.

### 3.5 Việc kỹ thuật tồn
- `pytest` chạy >7 phút (một số test timeout/ReDoS/dataset chủ đích; `test_orchestrator_network` ~50 s) — nên tối ưu.
- Chưa đối chiếu lại danh sách lỗi gốc (UPGRADE_PLAN §2: C1–C6, H1–H9) với code hiện tại.
- Chưa review độc lập: bản sửa 4D-3, toàn bộ 4E, và vòng 3 của lớp mạng/ảnh sau 3E-3.
- Chưa kiểm với MySQL thật (đã bỏ MySQL ở 4E nên không còn liên quan).
- Python 3.14 hoãn annotation: `tests/test_type_hints.py` bắt lỗi thiếu import; README ghi Python 3.10+.

## 4. Việc cần CHỦ DỰ ÁN quyết định/xác minh
1. Xác minh tay `codebase/knowledge_base/vn_brands.json` (mọi mục `verified=false`; nghi ngờ:
   tpb.vn, sacombank.com, techcombank.com, vinaphone.com.vn, mobifone.com.vn, vietteltelecom.vn) và bảng BIN VietQR.
2. Merge nhánh này vào `main` hay không.
3. Hiện quyết định KHÔNG dùng trình duyệt headless sandbox cho link chống bot (không né/giải captcha,
   không giả UA); mọi link bị chặn bot được coi là `unverified`, không bao giờ coi là an toàn.

## 5. Nguyên tắc cần giữ khi sửa tiếp
- Mặc định riêng tư: mạng chỉ chạy khi cài đặt cho phép **và** request có `online_check=true`.
- LLM không được hạ điểm do bằng chứng tất định; văn bản người dùng bọc thẻ không tin cậy.
- `client_id` ẩn danh không lưu lịch sử; GET `/api/history|sessions` từ chối tiền tố `anonymous-`.
- Không đưa nguyên văn case held-out vào prompt/luật; sửa luật dựa trên split dev.
- Mọi script đo đặt `SAFEGUARD_OFFLINE=1`.
- File `data/safeguard.db` chứa lịch sử chat riêng tư: không commit.
