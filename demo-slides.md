# SafeGuard AI - Demo Slides Script (5 phut)

> Kich ban thuyet trinh va demo live. De tai: Scam/Phishing Message Copilot.

## Slide 1 - Pain & Job (0:00-0:45)
- **Mo dau**: Moi ngay sinh vien va nguoi dung tre nhan link Shopee, email reset password, QR chuyen khoan, SMS ngan hang, tin shipper COD. Van de khong phai la "co scam hay khong", ma la "luc do minh co biet phai lam gi khong".
- **JTBD**: Khi nhan noi dung dang nghi, toi muon biet muc rui ro va cach kiem chung an toan de khong mat tien, lo thong tin hoac bo lo thong bao that.
- **Evidence**: 22/25 nguoi duoc hoi tung gap noi dung dang nghi; 18/25 khong tu tin tu kiem tra link/STK/QR; prototype doi soat PhishVN 51.362 ban ghi.
- **Quote**: "Em nhan link Shopee nhan qua, nhin qua rat giong that nhung ten mien la."

## Slide 2 - Vi sao chon bai toan nay (0:45-1:20)
- Da so sanh 3 ung vien: AI note summarizer, AI IT helpdesk, Scam/Phishing Copilot.
- Scam/phishing duoc chon vi tan suat gap cao, hau qua sai lam lon va co the can thiep dung thoi diem truoc khi nguoi dung bam link/chuyen tien.
- Automation duoc thiet ke la **AI-assisted decision support**: AI khong tu dong quyet dinh thay nguoi dung, nhung giai thich bang chung va goi y hanh dong.

## Slide 3 - Demo live: flow chinh (1:20-3:20)
### Case 1: Phishing link / fake Shopee
1. Dan link dang nghi vao prototype: `https://www.shopeee-vn.com/nhan-qua-thang-7`.
2. AI goi PromptGuard -> RAG/ThreatIntel -> ExplainableAgent -> ConfidenceAgent.
3. Ket qua mong doi: HIGH RISK, chi ra typo-squatting, khuyen khong dang nhap, tu go ten mien chinh thuc.

### Case 2: Vision OCR / fake bill
1. Upload anh bill VietQR hoac screenshot chuyen khoan dang nghi.
2. OCRAgent trich xuat chu, RAGAgent doi soat tactic fake bill, ExplainableAgent neu ly do.
3. Ket qua mong doi: canh bao chi giao hang khi tien da vao app ngan hang chinh thuc.

## Slide 4 - Emergency user flow 1'-3'-5'-10'-30' (3:20-4:05)
Demo cau: "Em vua chuyen 5 trieu vao tai khoan la va lo OTP."

| Moc | Viec can lam |
|---|---|
| 1' | Dung moi trao doi/chuyen tien, chup lai bang chung, khong xoa chat. |
| 3' | Goi tong dai ngan hang, yeu cau khoa giao dich/tai khoan lien quan. |
| 5' | Doi mat khau, dang xuat thiet bi la, khoa the/vi dien tu neu can. |
| 10' | Bao nguoi than/nhom lop de chan lua dao lan tiep. |
| 30' | Lap don trinh bao va gui bang chung qua kenh chinh thuc. |

Thong diep demo: AI khong lay lai tien thay nguoi dung, nhung giup ho lam dung viec trong thoi diem hoang mang nhat.

## Slide 5 - Kien truc RAG/Vision OCR & ket qua do (4:05-4:40)
- **RAG**: PhishVN 51.362 ban ghi + `vn_scam_tactics.json` + global phishing signals.
- **Vision OCR**: doc text tu screenshot/bill, ket hop red flags nhu QR, STK, APK, domain la, yeu cau OTP.
- **Explainability**: Risk Breakdown thay vi chi noi "nguy hiem".
- **Quality bar**: Risk Accuracy >=85%, Critical Pass =100%.
- **Ket qua luot 1**: 20 case, Risk Accuracy 90.0%, Critical Pass 100%.

## Slide 6 - Validation & bai hoc (4:40-5:00)
- 5 nguoi ngoai nhom dung thu prototype; feedback noi ket qua de hieu nhat khi co ly do va hanh dong tiep theo.
- Thay doi sau feedback: lam ro disclaimer Human-in-the-Loop va them Emergency Protocol theo moc thoi gian.
- **Bai hoc**: AI san pham tot khong phai AI noi thay con nguoi, ma la AI giup con nguoi ra quyet dinh an toan hon bang bang chung ro rang.

## Q&A du phong
- Neu hoi "AI sai thi sao?": He thong tach Risk Score va Confidence Score, voi case thieu bang chung se yeu cau xac minh them.
- Neu hoi "khac blacklist o dau?": Blacklist chi tra cuu tinh; SafeGuard AI phan tich ngu canh text/image va dua hanh dong.
- Neu hoi "co dung du lieu that khong?": Du lieu feedback/vi du da an danh; khong commit OTP, CCCD, mat khau hay du lieu nhay cam.
