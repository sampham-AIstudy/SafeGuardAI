# SafeGuard AI - Scam/Phishing Message Copilot

> Do an ca nhan - He thong phat hien tin nhan lua dao/phishing dua tren LLM

SafeGuard AI la tro ly ho tro nguoi dung tre kiem tra tin nhan, email, duong link, ma QR va anh bill chuyen khoan dang nghi. San pham khong quyet dinh thay nguoi dung; AI phan tich rui ro, chi ra red flags, uoc luong confidence va goi y hanh dong kiem chung an toan trong duoi 30 giay.

## Lat cat san pham
Mot sinh vien dan tin nhan/email/link/QR dang nghi vao prototype; AI phan loai muc rui ro, chi ra red flags va goi y hanh dong kiem chung an toan; ket qua la nguoi dung biet nen bam, bo qua hay xac minh trong duoi 30 giay.

## Kien truc Multi-Agent
```text
Browser UI / Streamlit UI
  -> REST API / Orchestrator
  -> PromptGuard
  -> OCRAgent
  -> RAGAgent + ThreatIntelAgent
  -> MemoryAgent
  -> ExplainableAgent
  -> ConfidenceAgent
  -> EmergencyAgent
  -> DecisionAgent
  -> Risk score + reasons + next actions
```

### Agent chinh
- **PromptGuard**: chan prompt injection va yeu cau nguy hiem.
- **OCRAgent**: trich xuat chu tu screenshot, bill, QR/image input.
- **RAGAgent**: doi soat PhishVN 51.362 ban ghi, knowledge base scam tactics va blacklist noi dia.
- **ThreatIntelAgent**: bo sung tin hieu domain/URL va dau hieu phishing.
- **MemoryAgent**: luu ngu canh phien de nhan ra chuoi lua dao leo thang.
- **ExplainableAgent**: tinh Risk Breakdown theo red flags.
- **ConfidenceAgent**: tach biet muc rui ro va do tin cay cua AI.
- **EmergencyAgent**: kich hoat quy trinh 1'-3'-5'-10'-30' khi nguoi dung da chuyen tien/lo OTP.
- **DecisionAgent**: tong hop ket qua, dua khuyen nghi va disclaimer Human-in-the-Loop.

## Cau truc repo
| File / thu muc | Noi dung |
|---|---|
| `spec.md` | AI Product Specification |
| `demo-slides.md` | Kich ban slide va demo live 5 phut |
| `validation/user_feedback.md` | Log validation voi nguoi dung ben ngoai |
| `codebase/` | Prototype backend, agent va web server |
| `eval/` | Golden set va script danh gia |
| `tham-khao/` | Tai lieu tham khao JTBD (Strategyn playbook) |

## Cai dat
Yeu cau: Python 3.10+ va pip.

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

He thong su dung SQLite database (mac dinh tu dong tao tai data/safeguard.db). Khong can cai dat MySQL hay XAMPP. Neu khong co API key, prototype van co the chay hoan toan offline bang fallback tuy theo agent.

## Chay prototype hien tai
Ban web hien tai duoc phuc vu qua REST API server va static HTML:

```cmd
.\.venv\Scripts\activate
python codebase/server.py
```

Mo trinh duyet tai:

```text
http://localhost:8000
```



## Kiem thu
Chay golden set:

```cmd
.\.venv\Scripts\activate
python eval/run_eval.py
```

Quality bar trong `spec.md`: Risk Accuracy >=85%, Critical Pass =100%, va High/Critical case phai co bang chung/red flags ro rang.
