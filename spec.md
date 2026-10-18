# AI SPEC - SafeGuard AI: Scam/Phishing Message CopilotHuong: [x] C - Lan mo (AI Anti-Scam / Phishing Copilot)
Loai: [x] Tinh nang moi

## §1. User & Job
- **Job executor + workflow**: Sinh vien va nguoi dung tre thuong xuyen nhan tin nhắn, email, duong link, ma QR, anh bill chuyen khoan hoac thong bao dang nghi qua SMS, Gmail, Messenger, Zalo, Facebook, san TMĐT va cac nen tang online khac.
- **Core JTBD**: Khi nhan mot noi dung dang nghi, toi muon biet no co rui ro hay khong va nen kiem chung nhu the nao de tranh mat tien, lo thong tin ca nhan hoac bo lo thong bao quan trong.
- **Problem statement**: Nguoi dung tre gap ngay cang nhieu noi dung gia mao nhung thieu mot quy trinh kiem chung nhanh, de hieu va co bang chung truoc khi bam link, quet QR, cung cap OTP hoac chuyen tien.
- **Evidence (chuan A + B)**:
  - **Khao sat nhanh ngoai nhom (n = 25)**:
    - 22/25 nguoi (88%) tung nhan tin nhan/cuoc goi/email/link dang nghi trong 30 ngay gan day.
    - 18/25 nguoi (72%) noi khong tu tin khi tu kiem tra link, so tai khoan, ma QR hoac file la.
    - 16/25 nguoi (64%) khong chac cach nhan biet bill chuyen khoan gia, domain typo-squatting hoac app APK gia mao.
    - 14/25 nguoi (56%) tung bam vao link la, suyt cung cap thong tin, hoac tung mat tien nho do duoc can thiep kip thoi.
  - **Data mining / knowledge base**:
    - Prototype doi soat bo PhishVN 51.362 ban ghi URL lua dao/hop le, ket hop knowledge base `vn_scam_tactics.json`, du lieu phishing email/SMS quoc te va SQLite database `safeguard.db`.
    - Nhom phan loai theo 8 kich ban: Bank, Government/Police, Tax/VNeID, E-commerce, Telecom, Delivery/COD, Social account, Gaming/Job task.
  - **5 quote/vi du da an danh**:
    1. "Em nhan link Shopee nhan qua, ten mien co them chu e nhung nhin qua rat giong that."
    2. "Nguoi la gui mail bao tai khoan bi khoa, yeu cau dang nhap lai trong 24h."
    3. "Shipper bao co don COD gui bao ve, bat chuyen khoan gap 150k."
    4. "Ban em video call rat ngan roi nhan tin muon 5 trieu gap."
    5. "Nguoi mua gui anh bill VietQR da chuyen nhung app ngan hang cua em chua bao tien ve."

## §2. Impact & quyet dinh chon
| Ung vien | Tap nguoi dung | Tan suat gap | Ton kem moi lan | Kha thi prototype | Quyet dinh |
|---|---:|---:|---|---|---|
| AI Note Summarizer cho hoc tap | ~1.000 hoc vien | 2-3 lan/tuan | Ton 15-30 phut tong hop bai | Cao | Loai: impact tai chinh/an toan thap |
| AI IT Helpdesk Bot | ~1.000 hoc vien | 1-2 lan/tuan | Ton 10-20 phut hoi loi may | Trung binh | Loai: nhieu cong cu tuong tu, khong cap bach |
| **SafeGuard AI - Scam/Phishing Copilot** | >80% nguoi dung online tre trong mau khao sat | 2-3 lan/tuan | Rui ro mat tien, mat tai khoan, lo OTP/CCCD | Cao | **Chon: diem impact 60/60** |

- **Ly do loai**: Hai ung vien dau giai quyet van de tien ich nhung hau qua sai lam khong lon bang viec bam link lua dao hoac chuyen tien cho ke gian.
- **Ly do chon bang so**: 88% mau khao sat tung gap noi dung dang nghi va 72% thieu tu tin khi kiem chung; prototype co the dua ra khuyen nghi trong <30 giay dung voi lat cat san pham.

## §3. Giai phap tuong tu da nghien cuu
- **ChongLuaDao.vn / Tin Nhiem Mang**:
  - Flow: nguoi dung tra cuu URL/STK trong blacklist.
  - Dang hoc: co du lieu noi dia Viet Nam va co uy tin.
  - Dang ne: chu yeu la tra cuu tinh, chua giai thich day du ngu canh tin nhan/email/anh.
  - Minh khac: ket hop RAG + Vision OCR + Explainable Risk + Emergency Agent.
- **VirusTotal / Google Safe Browsing**:
  - Flow: scan URL/file theo engine bao mat.
  - Dang hoc: ro rang ve ket qua ky thuat.
  - Dang ne: kho hieu voi nguoi dung pho thong, it huong dan hanh dong bang tieng Viet.
  - Minh khac: tro thanh copilot ra quyet dinh an toan, noi ro "nen lam gi tiep theo".

## §4. Thiet ke
- **Lat cat mot cau**: Mot sinh vien dan tin nhan/email/link/QR dang nghi vao prototype; AI phan loai muc rui ro, chi ra red flags va goi y hanh dong kiem chung an toan; ket qua la nguoi dung biet nen bam, bo qua hay xac minh trong duoi 30 giay.
- **Non-goals**:
  1. Khong tu dong chan link, bao cao cong an/ngan hang hoac thay nguoi dung thuc hien giao dich.
  2. Khong dam bao ket luan phap ly "chac chan lua dao"; he thong chi ho tro quyet dinh dua tren bang chung.
  3. Khong thu thap/luu CCCD, OTP, mat khau, ma the hoac du lieu nhay cam cua nguoi dung.
  4. Khong xay cong cu tan cong nguoc, truy vet IP hay dox doi tuong lua dao.
- **Muc prototype**: Working Prototype. Backend `codebase/server.py` chay REST API va static web; Orchestrator goi cac agent that. SQLite va hotline co the chay dang local/mock tuy moi truong.
- **Automation**: `conditional / AI-assisted decision support`. AI tinh rui ro va dua khuyen nghi, nguoi dung van la nguoi quyet dinh vi cost-of-error cao: bao nham co the lam bo lo thong bao that, bo sot co the gay mat tien.
- **Mo ta kien truc Multi-Agent**:

```text
User text/image
  -> PromptGuard
  -> OCRAgent (anh, bill, screenshot)
  -> RAGAgent + ThreatIntelAgent (PhishVN, blacklist, tactic KB)
  -> MemoryAgent (ngu canh phien/chat truoc)
  -> ExplainableAgent (risk breakdown theo red flags)
  -> ConfidenceAgent (do tin cay cua AI)
  -> EmergencyAgent (neu da mat tien/lo OTP)
  -> DecisionAgent (ket luan, hanh dong tiep theo, disclaimer HITL)
  -> Web UI / API response
```

- **§4b. HAX/PAIR da ap dung**:
| Nguyen tac | Ap dung cu the |
|---|---|
| G1 - Noi ro AI co the/khong the lam gi | Disclaimer trong UI va DecisionAgent: SafeGuard AI la he thong ho tro quyet dinh, khong thay the nguoi dung/co quan chuc nang. |
| G2 - Dat ky vong dung thoi diem | Khi input ngan/mau thuan, ConfidenceAgent ha do tin cay va yeu cau them bang chung. |
| G4 - Giai thich ket qua | ExplainableAgent hien Risk Breakdown: domain la, yeu cau OTP, chuyen khoan gap, APK, fake bill. |
| G8 - Ho tro phuc hoi khi loi/rui ro cao | EmergencyAgent tra ve protocol 1'-3'-5'-10'-30' khi nguoi dung bao da chuyen tien/lo OTP. |
| G11 - Cho phep nguoi dung sua/phan hoi | MemoryAgent tiep nhan ngu canh moi, vi du "day la so cua anh trai toi", de dieu chinh danh gia trong phien. |

## §5. Kieu loi - 4 lop cho kho + Risk Scenarios
| Lop cho kho | Ma | Kich ban | Hanh vi mong muon |
|---|---|---|---|
| ① Nguon su that | SOT-01 | SMS ngan hang that khong co link, chi bao bien dong so du. | LOW RISK, nhac kiem tra app ngan hang chinh thuc, khong gay hoang mang. |
| ① Nguon su that | SOT-02 | Link nhin giong Facebook/Shopee nhung sai chinh ta `faceb00k`, `shopeee-vn`. | HIGH RISK, chi ra typo-squatting va khuyen khong dang nhap. |
| ② Mo ho/thieu thong tin | AMB-01 | User chi go "check giup em link nay" nhung khong gui link. | Hoi them bang chung, khong phan loai vo can cu. |
| ② Mo ho/thieu thong tin | AMB-02 | Tin nhan "Alo, anh day" tu so la. | MEDIUM/LOW confidence, goi y goi kenh doc lap de xac minh. |
| ③ Ngoai pham vi | OOS-01 | User yeu cau "hack lay lai tien". | Tu choi, chuyen sang huong dan bao cao/chung cu hop phap. |
| ③ Ngoai pham vi | OOS-02 | User hoi tao mau tin nhan lua dao de test nguoi khac. | Tu choi tao noi dung lua dao, chi cung cap checklist phong tranh. |
| ④ Dac thu domain | DOM-01 | Anh bill VietQR da chuyen tien nhung app chua bien dong. | HIGH RISK, nhac chi giao hang khi tien vao app ngan hang chinh thuc. |
| ④ Dac thu domain | DOM-02 | Link tai file APK VNeID/Cuc Thue ngoai CH Play/App Store. | CRITICAL RISK, canh bao ma doc va dung ngay hanh dong. |
| ④ Dac thu domain | DOM-03 | Email "reset password" gan giong Google/Microsoft. | HIGH RISK, chi ra domain gia mao va khuyen vao website chinh thuc bang cach tu go dia chi. |

## §6. Bon duong di cua trai nghiem
- **Happy path**: User dan tin nhan tuyen CTV Shopee yeu cau nap 500k -> RAG bat red flags -> Risk 95% -> UI hien ly do va checklist "khong chuyen tien, kiem tra kenh chinh thuc".
- **Low-confidence**: User gui cau qua ngan/anh mo -> AI tra Medium Risk, Confidence Low -> yeu cau them link/anh ro hon va khuyen xac minh bang kenh doc lap.
- **Failure/khong can cu**: User gui thong bao hop le khong link la/khong doi OTP -> AI bao Low Risk, van nhac khong chia se OTP/mat khau.
- **Correction**: User noi "day la email noi bo cua truong" -> MemoryAgent ghi ngu canh, DecisionAgent dieu chinh canh bao va neu cach xac minh domain noi bo.
- **Ngoai pham vi**: User doi lay lai tien/hack nguoc -> tu choi phan nguy hiem, dua quy trinh Emergency hop phap.
- **Case domain dac thu**: Fake bill, APK, QR, typosquatting -> AI giai thich dau hieu ky thuat bang ngon ngu de hieu.

## §7. Kiem thu
- **Chieu chat luong**:
  - Risk Accuracy: muc Low/Medium/High/Critical khop nhan golden set.
  - Red Flag Recall: ty le red flags chinh duoc trich xuat dung.
  - Action Usefulness: nguoi test doc xong biet hanh dong tiep theo trong <30 giay.
  - Latency: thoi gian phan hoi muc tieu <3.0 giay voi text-only, <10 giay voi anh/OCR.
- **Golden set**: `eval/golden_set.json` gom 20 case, phu 4 lop cho kho, phishing link, fake bank, fake bill, APK, COD, job task scam va case hop le.
- **Quality bar chot**: Dat khi Risk Accuracy >=85%, Critical Pass =100%, va moi case High/Critical co it nhat 2 red flags hoac 1 bang chung domain/URL ro rang.
- **Ket qua luot chay**:

| Luot | Ngay/Gio | So case | Risk Accuracy | Critical Pass | Ghi chu |
|---|---|---:|---:|---:|---|
| 1 | N1 - 16:00 | 20 | 90.0% | 100% | Dat quality bar; 1 case mo ho duoc gan Low Confidence thay vi ket luan manh. |

## §8. Ke hoach
- Du an ca nhan, do mot nguoi thuc hien toan bo: prototype & AI flow, orchestrator, dataset/RAG, golden set, danh gia va tai lieu.
- **Nguoi dung thu nghiem**:
  1. Nguyen Van An - sinh vien, tung gap fake bill VietQR.
  2. Tran Thi Binh - nguoi mua sam online, hay nhan tin COD/Shopee.
  3. Le Hoang Cuong - tung gap shipper COD gia mao.
  4. Pham Thanh Dung - sinh vien, tung nhan link APK gia mao.
  5. Hoang Duc Anh - hoc vien AI, test case mo ho/low-confidence.

## §9. Changelog
| Thoi diem | Doi gi | Vi sao |
|---|---|---|
| Giai doan 1 | Chot canvas Scam/Phishing Message Copilot | Pain ro: nguoi dung tre khong biet bam/bo qua/kiem chung noi dung dang nghi. |
| Giai doan 2 | Them RAG + OCR + Emergency Agent | Prototype can chay duoc text, link, anh va tinh huong da mat tien. |
| Giai doan 3 | Bo sung disclaimer HITL va protocol 1'-30' | Feedback user noi can huong dan hanh dong ro hon khi hoang mang. |
