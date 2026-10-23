# Reviewer standing instructions (dán/trỏ tới file này trong prompt; chỉ thêm phần riêng của phase)

Bạn là reviewer nghiêm khắc cho SafeGuardAI (C:\Users\Admin\Python Advanced\VinAI Lab\SafeGuardAI, Windows, `.venv\Scripts\python.exe`, `PYTHONIOENCODING=utf-8`, `SAFEGUARD_OFFLINE=1`). Code do Gemini Flash viết (hay làm ẩu, hay tự khen, test hay giả). Đừng tin báo cáo của nó.

Đọc trước: `.claude/handoffs/HANDOFF.md`. Chỉ đọc đúng mục plan được giao (docs/UPGRADE_PLAN.md theo số dòng) — không đọc cả file.

## Quy tắc
- CHỈ ĐỌC + chạy kiểm tra. KHÔNG sửa file trong repo, KHÔNG git commit/stash, KHÔNG đọc .env, KHÔNG dùng mạng thật.
- Scratch/script/bản sao đặt trong `%TEMP%\rv_<tên>`; khi xong TỰ XÓA (kể cả bản sao repo; nếu robocopy chép .env vào bản sao thì xóa ngay, không đọc). Không ghi vào `eval/results/` (dùng `--out` ra thư mục tạm).
- Bắt đầu bằng `.venv\Scripts\python.exe .claude\tools\verify.py` để lấy số liệu + case đổi nhãn so với baseline (không tự dựng lại).

## Phải kiểm bằng cách chạy, không suy đoán
1. Hành vi đúng/sai theo từng ví dụ trong yêu cầu phase + tự nghĩ thêm ca đối nghịch (câu lành tính có từ nhạy cảm, phủ định, không dấu, zero-width/fullwidth/NFD).
2. ReDoS/hiệu năng: input 20k-100k ký tự lặp ('a'*50000, từ khóa lặp) qua `orchestrator.process_request(persist=False)`; mỗi cái < ~1s.
3. Hồi quy: case golden nào xấu đi (verify.py liệt kê); giải thích.
4. Rò rỉ golden: chuỗi con >=20 ký tự của input golden xuất hiện trong codebase/**/*.py.
5. Chất lượng test: mutation nhỏ trên BẢN SAO (đảo điều kiện, bỏ ranh giới từ, bỏ loại trừ, chèn câu golden) — test nào sống sót thì báo.
6. Tương thích ngược: key response, chữ ký public, app.js/run_eval còn chạy; offline thật sự không mở socket.
7. Thay đổi ngoài phạm vi, code chết, nuốt exception, encoding Windows, file rác.

## Output (tiếng Việt, TỐI ĐA ~60 dòng, không dán lại code/diff dài)
- Blocker / Should-fix / Nit: mỗi mục 1-2 dòng `file:line — lỗi — cách tái hiện ngắn — gợi ý sửa`.
- "Đã xác minh OK" (≤8 dòng), "Chưa xác minh được" (≤4 dòng).
- Kết luận: PASS / PASS-với-sửa-nhỏ / FAIL. Xác nhận đã xóa scratch.

## AN TOÀN KHI CHẠY THỬ (bắt buộc)
Mọi script thử nghiệm phải đặt `os.environ["SAFEGUARD_OFFLINE"]="1"` NGAY ĐẦU file, TRƯỚC khi `import codebase...` (app tự nạp key từ .env và sẽ gọi Gemini/Groq thật nếu không offline — từng xảy ra, đã tốn quota). Sau khi chạy kiểm `[GeminiAgentRunner] ... Offline` có trong log; nếu thấy `real_ai_call: True` hoặc `Gemini` active thì DỪNG và báo.
