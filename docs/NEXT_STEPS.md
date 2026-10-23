# NEXT_STEPS — SafeGuardAI (Đồ án 3): đã làm gì, đang đi hướng nào, việc tiếp theo

Cập nhật: 2026-10-24. Nhánh làm việc mới nhất: `wip/home-handoff` (có đủ code + ghi chú). Nhánh `feature/upgrade-phase0-1a`
dừng ở commit ổn định cũ (Phase 5A). Nhật ký chi tiết từng bước nằm ở `.claude/handoffs/HANDOFF.md` (dài, tiếng Việt).
Kế hoạch gốc: `docs/UPGRADE_PLAN.md`.

## 1. Hướng đi (đã chốt với chủ dự án)

**Kiến trúc Hybrid hai tầng.**
- **Tầng A** (tất định, ~15 ms, chạy offline): luật + module URL (`codebase/url_analysis/`) + blacklist PhishVN trong RAM.
  Giỏi phần kỹ thuật: link che giấu, homoglyph, redirect, APK, QR/VietQR.
- **Tầng B** (LLM, tùy chọn): phân tích ngữ nghĩa kịch bản (việc nhẹ lương cao, tình cảm, mượn tiền, giả danh).
- Quy tắc cứng: LLM **không được hạ điểm** khi Tầng A có bằng chứng kỹ thuật cứng; mạng chỉ chạy khi người dùng đồng ý
  (`online_check` mặc định TẮT; UI có nút "Kiểm tra sâu link này" bấm một lần); ưu tiên riêng tư mặc định.
- Mục tiêu đồ án: báo cáo thực nghiệm **ablation Tầng A vs Tầng A+B** + giao diện demo cho người phổ thông/người lớn tuổi.

**Luận điểm thực nghiệm:** trên bộ held-out độc lập (`heldout_v3`), luật offline chỉ bắt ~25% tin scam ở mức HIGH+; LLM nâng
recall rất mạnh (93% trên 54 ca đã đo) nhưng cũng báo nhầm nhiều hơn ở tin cảnh báo/tường thuật/nạn nhân hỏi lời khuyên →
cần cổng ngữ cảnh phát ngôn (Speech-Act Gate) ở cả hai tầng.

## 2. Đã làm (tất cả có trong nhánh `wip/home-handoff`)

| Mảng | Nội dung | Ghi chú kiểm chứng |
|---|---|---|
| Phase 0–4 | hạ tầng đo, sửa logic tiếng Việt, module URL, resolver chống SSRF, anti-bot, QR/ảnh, server đa luồng + rate limit + CSP, cô lập `client_id`, pipeline 2 tầng | đã qua review Opus nhiều vòng |
| 4E | MySQL → SQLite (`data/safeguard.db`, gitignore), di trú 126 dòng | |
| 5A | UI: thẻ phân tích link, pipeline_trace, network_actions, escape/defang | review Opus + sửa |
| Speech-Act Gate | `codebase/agents/speech_act.py` (phân loại: solicitation/news_report/public_warning/victim_advice/everyday); giảm điểm văn bản ở Tầng A (`explainable_agent.py`); **cap phần điểm LLM** ở chỗ merge trong `orchestrator.py` (`cap_llm_risk`, mặc định 35) khi không có bằng chứng cứng; cờ `SAFEGUARD_SPEECH_ACT=off` để làm ablation | 52 test riêng pass |
| Prompt LLM | khối "phân biệt 3 vai" (kẻ lừa đảo / bản tin cảnh báo / nạn nhân hỏi cách xử lý) trong `multi_llm_client.py` và `gemini_agent_runner.py` | |
| Sửa lỗi quan trọng | `_wrap_report_dict` đệ quy vô hạn (làm tràn RAM); cổng từng làm TĂNG điểm (do factor weight-0 kích hoạt sàn ≥2 factor); bỏ model Gemini cũ + bỏ trần cứng 8s | có test hồi quy |
| Dữ liệu nội địa | `vn_brands.json`: 40/52 thương hiệu `verified=true` bằng bằng chứng TLS/tổ chức/tiêu đề; 16/16 BIN VietQR khớp `api.vietqr.io/v2/banks` + 4 BIN mới | 12 thương hiệu còn chờ duyệt (mục 4) |
| UI cho người lớn tuổi | khối "KẾT LUẬN HÀNH ĐỘNG" chữ lớn đầu kết quả, chế độ đơn giản + `<details>` kỹ thuật, việt hóa 51 mã tín hiệu, `aria-*`, chữ ≥15px, nút ≥44px, tương phản ≥4,5:1, nút "Kiểm tra sâu" | 26 test UI chạy `app.js` thật trong node + 61 mutation thật |

**Số liệu hiện tại** (offline trừ khi ghi khác):
- Test: **1399 pass + 1 bỏ qua** (bỏ qua = test mutation ghi đè `public/*`, chỉ chạy khi `SAFEGUARD_RUN_MUTATIONS=1`).
- Golden: v1 85%, v2 75,0% (FPR v2 4,5%, recall CRITICAL 100%). *Golden do tác giả chỉnh luật nên lạc quan.*
- `heldout_v3` (120 scam + 120 lành tính, viết độc lập): scam HIGH+ 30/120 (25%); lành tính báo ≥MEDIUM 14/120 (11,7%),
  ≥HIGH 5/120 (4,2%).
- LLM (mới đo 85/240 ca vì quota): scam HIGH+ 50/54 (93%); lành tính ≥MEDIUM giảm 9 → 6 nhờ cap (chạy lại bằng
  `.claude/tools/heldout_rescore.py`, không gọi LLM). Các nhóm khó (báo chí, công an/ngân hàng cảnh báo, nạn nhân hỏi) vẫn bị báo nhầm.

## 3. Việc cần làm tiếp (đề xuất chia cho nhiều người)

### A. Chất lượng phát hiện (ưu tiên cao nhất)
1. **Đo LLM đầy đủ trên 240 ca** để có bảng Tầng A vs A+B theo nhóm kịch bản. Quota Gemini miễn phí chỉ 20 lượt/ngày/model;
   cần khóa có billing hoặc chia nhiều ngày. Lệnh: `.venv\Scripts\python.exe .claude\tools\heldout_run.py --set v3 --mode llm --stratified`
   (checkpoint từng ca, tự đổi model, chỉ gửi tin cho Gemini) rồi `heldout_compare.py`. Lưu ý: 85 ca cũ đo với prompt cũ.
2. **Hybrid đúng nghĩa:** hiện luôn gọi LLM khi bật. Cần chỉ gọi khi Tầng A không có URL độc hại rõ ràng/văn bản mơ hồ
   (sửa `orchestrator.py`, rồi chạy ablation).
3. **Nâng bộ phân loại ngữ cảnh** (`speech_act.py`): hiện chưa nhận ra phần lớn tin cảnh báo/tường thuật/nạn nhân hỏi của bộ
   độc lập, và có xếp nhầm một tin scam là "đời thường". Lưu ý: đã thử 3 lượt mở rộng luật bằng từ khóa và hồi quy; đừng
   nhồi từ khóa theo câu mẫu — cân nhắc bộ phân loại nhỏ (TF-IDF/embedding + hồi quy logistic) hoặc phân loại bằng LLM nhẹ.
   Mọi chỉnh sửa phải đo trên bộ held-out **mới** (xem mục 5), không tinh chỉnh theo `heldout_v3`.
4. Họ scam còn rất yếu offline: việc nhẹ lương cao, tình cảm + chuyển tiền, deepfake video call, đầu tư nhóm kín,
   mượn tiền/nick bạn bị hack, giả shipper/hải quan.

### B. Riêng tư & dữ liệu
5. **SQLite: TTL tự xóa + che thông tin nhạy cảm** (`codebase/knowledge_base/db_connect.py`) — chủ dự án yêu cầu, **chưa làm**.
6. Tra cứu STK/SĐT lừa đảo (hiện chỉ nhận dạng bằng regex, không có blacklist); cập nhật blacklist định kỳ thay cho CSV tĩnh.

### C. Giao diện
7. **Mở UI bằng trình duyệt thật** (mobile + desktop, người lớn tuổi thử) — hiện chỉ kiểm bằng DOM giả.
8. Tuỳ chọn: "luôn kiểm tra sâu" lưu `localStorage` (chỉ khi người dùng tick rõ); tin nạp lại từ lịch sử chưa có nút kiểm tra sâu.

### D. Báo cáo/tài liệu
9. Golden ≥120 ca + `eval/LABELING_GUIDE.md` + Cohen's kappa (cần người gán nhãn thứ hai); ablation cuối; phân tích ≥10 lỗi FN/FP.
10. README (bảng biến `SAFEGUARD_*`), cập nhật `spec.md` bằng số liệu thật, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`,
    `docs/BAO_CAO_DO_AN_3.md`. Khi viết số liệu: ghi **cả** FP ≥HIGH (4,2%) lẫn ≥MEDIUM (11,7%); nêu rõ golden là dev,
    `heldout_v3` mới là số trung thực.

### E. Kỹ thuật tồn đọng
11. Cấu hình `.env` mẫu: `GEMINI_MODEL` chậm (vd `gemini-3.5-flash-lite` ~18–20 s) luôn timeout → LLM âm thầm quay về offline;
    `gemini-2.5-flash` ~4,5 s chạy tốt. Groq `llama-3.3-70b-versatile` không còn; Mistral chưa cài `mistralai`.
12. pytest toàn bộ mất ~5 phút; file lớn (`orchestrator.py`, `explainable_agent.py`, `resolver.py`, `analyzer.py`) nên tách dần.

## 4. Quyết định còn chờ chủ dự án
- Duyệt 12 thương hiệu `vn_brands.json` (4 xác minh một phần: TPBank, Bộ Công an, EVN, MobiFone; 8 chưa: Cổng Dịch vụ công,
  Shopee, Viettel Post, Ninja Van, VinaPhone, VNPT, SeABank, Nam A). Lý do cụ thể ghi trong `source_url` / `unverified_domains`
  của từng mục. `verified` không ảnh hưởng hành vi phát hiện.
- Có bật `online_check` mặc định không (hiện TẮT vì gửi tên miền ra dịch vụ ngoài).
- Mức FP chấp nhận được cho bản demo (hiện ≥MEDIUM 11,7% trên bộ độc lập, chưa đạt mục tiêu ≤10%).

## 5. Cách chạy / kiểm tra, và các lưu ý quan trọng

```bash
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt -r requirements-dev.txt
set SAFEGUARD_OFFLINE=1                      # mọi script đo phải đặt, nếu không có thể gọi LLM thật
.venv/Scripts/python -m pytest -q -p no:cacheprovider        # ~5 phút
.venv/Scripts/python .claude/tools/verify.py --no-pytest     # golden v1/v2 + so với baseline (không được có [WORSE])
.venv/Scripts/python codebase/server.py                      # chạy server (cổng 8000)
```

**Không có trong git (cần lấy riêng từ chủ dự án):**
- `.env` (khóa API; **không bao giờ commit**), `data/data-phising-VN-ver1|ver2` (CSV PhishVN, ~283 MB), `data/safeguard.db`.
- Các bộ held-out riêng tư `~/.safeguard_heldout/` (`heldout_v3.json`...). Chúng cố ý nằm ngoài repo; **không đưa nội dung vào prompt/luật**.
  Nếu không có, hãy tự viết một bộ held-out mới độc lập để đo (người viết không được đọc mã phát hiện).

**Lưu ý an toàn khi làm việc:**
- **RAM:** một test từng làm tràn RAM/SSD (đệ quy vô hạn khi dùng `MagicMock` làm `url_report`). Đã sửa nhưng hãy chạy test từng file
  và **không dùng `MagicMock` cho báo cáo URL**. Hãy dùng bộ canh RAM (kill khi >3 GB hoặc quá giờ), ví dụ viết một script nhỏ
  bằng `psutil` bọc lệnh pytest.
- Test mutation `tests/test_ui_render.py::test_mutation_real_source_mutants_zero_survivors` **ghi đè file thật trong `public/`**;
  mặc định bị bỏ qua, chỉ bật bằng `SAFEGUARD_RUN_MUTATIONS=1` và không chạy song song với tiến trình khác đọc `public/`.
- Không tự chạy LLM/mạng khi chưa hỏi chủ dự án; luôn đặt `SAFEGUARD_OFFLINE=1` cho script đo.
- `.claude/` chứa công cụ và prompt giao việc cho `agy` (CLI Antigravity); không bắt buộc dùng. Quota Claude trên `agy` đã cạn
  (reset ~1 tuần); Gemini trên `agy` hay treo với việc sửa luật nhiều file — nên tự làm hoặc dùng tác tử mạnh hơn, và luôn tự chạy lại test.
- Quy tắc nền: LLM không hạ điểm khi có bằng chứng kỹ thuật cứng; `client_id` ẩn danh không lưu lịch sử; `data/safeguard.db`
  chứa lịch sử chat riêng tư, không commit.
