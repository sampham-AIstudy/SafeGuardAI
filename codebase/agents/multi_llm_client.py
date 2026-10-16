import os
import json
import time

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    from PIL import Image
except ImportError:
    Image = None

from codebase.config import get_settings, get_api_key


class MultiLLMClient:
    """
    Multi-LLM Smart Router for SafeGuard AI.

    Tries providers in order from fastest to most capable.
    Each provider has a timeout — failure automatically falls through to next.

    Routing chain:
      Groq (Llama 3.3 70B, ~300ms)
        → Gemini (2.5 Flash)
          → Mistral (Large)
            → Offline (rule-based fallback)

    All providers return the same structured JSON format for compatibility
    with the orchestrator and decision agent.
    """

    PROVIDER_TIMEOUT = 10  # seconds per provider

    def __init__(self):
        # API Keys
        self.groq_key = get_api_key("GROQ_API_KEY")
        self.gemini_key = get_api_key("GEMINI_API_KEY")
        self.mistral_key = get_api_key("MISTRAL_API_KEY")

        # Model configs
        self.groq_model = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
        self.gemini_model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        self.mistral_model = os.environ.get("MISTRAL_MODEL", "mistral-large-latest")

        # Track which model succeeded last time
        self.last_successful_provider = None
        self.last_successful_model = None

        # Lazy-initialized SDK clients
        self._groq_client = None
        self._gemini_genai = None
        self._mistral_client = None

        self._report_active_providers()

    def _report_active_providers(self):
        settings = get_settings()
        if settings.offline or settings.llm_mode == "off":
            print("[MultiLLMClient] [INFO] Offline/LLM disabled by settings.")
            return

        providers = []
        if self.groq_key:
            providers.append(f"Groq({self.groq_model})")
        if self.gemini_key:
            providers.append(f"Gemini({self.gemini_model})")
        if self.mistral_key:
            providers.append(f"Mistral({self.mistral_model})")

        if providers:
            print(f"[MultiLLMClient] ✅ Available providers: {' → '.join(providers)}")
        else:
            print("[MultiLLMClient] ⚠️  No LLM API keys configured — offline mode only.")

    # ─────────────────────────────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────────────────────────────
    def analyze_scam(self, user_text: str, matched_flags: list,
                     ocr_anomalies: list, pil_image=None) -> dict | None:
        """
        Analyze scam content using the best available LLM provider.
        Falls through the routing chain automatically on failure.
        """
        if not self.is_active:
            return None

        prompt = self._build_prompt(user_text, matched_flags, ocr_anomalies)

        # Routing order: Groq → Gemini → Mistral
        providers = [
            ("groq", self._call_groq),
            ("gemini", self._call_gemini),
            ("mistral", self._call_mistral),
        ]

        for provider_name, provider_fn in providers:
            try:
                result = provider_fn(prompt, pil_image)
                if result:
                    self.last_successful_provider = provider_name
                    self.last_successful_model = self._get_model_name(provider_name)
                    print(f"[MultiLLMClient] ✅ Used: {provider_name} ({self.last_successful_model})")
                    return result
            except Exception as e:
                print(f"[MultiLLMClient] ⚠️  {provider_name} failed: {type(e).__name__}: {e}")
                continue

        print("[MultiLLMClient] ❌ All providers failed — returning None (will use ExplainableAgent score)")
        return None

    @property
    def is_active(self) -> bool:
        settings = get_settings()
        if settings.offline or settings.llm_mode == "off":
            return False
        return bool(self.groq_key or self.gemini_key or self.mistral_key)

    @property
    def model_name(self) -> str:
        return self.last_successful_model or "offline"

    # ─────────────────────────────────────────────────────────────────────────
    # PROVIDER: GROQ (Llama 3.3 70B — fastest)
    # ─────────────────────────────────────────────────────────────────────────
    def _call_groq(self, prompt: str, pil_image=None) -> dict | None:
        if not self.groq_key:
            return None
        try:
            if not self._groq_client:
                from groq import Groq
                self._groq_client = Groq(api_key=self.groq_key)

            response = self._groq_client.chat.completions.create(
                model=self.groq_model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=1500,
                timeout=self.PROVIDER_TIMEOUT
            )
            text = response.choices[0].message.content
            return self._parse_json(text)
        except ImportError:
            print("[MultiLLMClient] groq package not installed. Run: pip install groq")
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # PROVIDER: GEMINI
    # ─────────────────────────────────────────────────────────────────────────
    def _call_gemini(self, prompt: str, pil_image=None) -> dict | None:
        if not self.gemini_key or self.gemini_key in ("YOUR_GEMINI_API_KEY_HERE", ""):
            return None
        try:
            if not self._gemini_genai:
                import warnings
                warnings.filterwarnings("ignore", category=FutureWarning)
                import google.generativeai as genai
                genai.configure(api_key=self.gemini_key)
                self._gemini_genai = genai

            models_to_try = [self.gemini_model, "gemini-2.5-flash", "gemini-1.5-flash", "gemini-2.0-flash"]
            content_inputs = [prompt]
            if pil_image and Image and isinstance(pil_image, Image.Image):
                content_inputs.append(pil_image)

            for m in models_to_try:
                try:
                    model = self._gemini_genai.GenerativeModel(m)
                    res = model.generate_content(content_inputs)
                    if res.text:
                        return self._parse_json(res.text)
                except Exception:
                    continue
            return None
        except ImportError:
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # PROVIDER: MISTRAL
    # ─────────────────────────────────────────────────────────────────────────
    def _call_mistral(self, prompt: str, pil_image=None) -> dict | None:
        if not self.mistral_key:
            return None
        try:
            if not self._mistral_client:
                from mistralai import Mistral
                self._mistral_client = Mistral(api_key=self.mistral_key)

            response = self._mistral_client.chat.complete(
                model=self.mistral_model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=1500,
            )
            text = response.choices[0].message.content
            return self._parse_json(text)
        except ImportError:
            print("[MultiLLMClient] mistralai package not installed. Run: pip install mistralai")
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # SHARED PROMPT BUILDER
    # ─────────────────────────────────────────────────────────────────────────
    def _build_prompt(self, user_text: str, matched_flags: list, ocr_anomalies: list) -> str:
        flags_str = "\n".join([f"  • {f}" for f in matched_flags]) if matched_flags else "  (Không có)"
        anomalies_str = "\n".join([f"  • {a}" for a in ocr_anomalies]) if ocr_anomalies else "  (Không có)"

        return f"""Bạn là SafeGuard AI — Chuyên gia phân tích an ninh mạng và phòng chống lừa đảo tại Việt Nam.

════════════════════════════════════════
NỘI DUNG NGƯỜI DÙNG GỬI:
"{user_text}"
════════════════════════════════════════

BẰNG CHỨNG TỪ HỆ THỐNG RAG & OCR:
Dấu hiệu đỏ:
{flags_str}

Anomaly từ OCR:
{anomalies_str}
════════════════════════════════════════

KỊCH BẢN LỪA ĐẢO PHỔ BIẾN TẠI VIỆT NAM:
1. CTV/Việc làm giả: TikTok, Shopee, yêu cầu nạp quỹ đảm bảo 500k-5tr
2. Banking Phishing: SMS giả ngân hàng, link cập nhật/xác minh tài khoản
3. Mạo danh cơ quan: Cục Thuế, Công An, VNEID, link APK giả
4. Đầu tư Ponzi/Forex: Lãi 1-5%/ngày, hoàn tiền đa cấp
5. VietQR giả: Bill chuyển khoản giả, QR code lừa đảo

QUY TẮC PHÂN LOẠI & TÍNH ĐIỂM RỦI RO:
1. Nếu chỉ là chào hỏi xã giao ("chào", "hello", "hi", "bạn là ai") → intent_type = "general_chat", risk_score = 0.
2. Nếu là thông báo chính thức từ đơn vị uy tín (Vcb tin nhắn thông báo số dư, Shopee thông báo mã giảm giá trên app, công an gửi giấy mời tới cơ quan, thông báo học phí...) → intent_type = "scam_analysis", risk_score = 0 đến 25 (LOW).
3. Nếu là tin nhắn mượn tiền từ nick quen, tin nhắn shipper báo COD giao bảo vệ, người chuyển nhầm tiền nhờ chuyển lại (chưa có link lạ/chưa có file .apk) → risk_score = 40 đến 60 (MEDIUM).
4. Nếu là kịch bản tuyển dụng CTV nạp tiền/quỹ, giả mạo website ngân hàng/cơ quan nhà nước → risk_score = 75 đến 89 (HIGH).
5. Nếu yêu cầu cài file .apk ngoài CH Play hoặc nạn nhân vừa bị lừa mất tiền → risk_score = 90 đến 99 (CRITICAL).

THANG ĐIỂM RỦI RO CHUẨN:
- 0 - 39: LOW (Rủi ro thấp)
- 40 - 74: MEDIUM (Rủi ro trung bình, cần xác minh thủ công)
- 75 - 89: HIGH (Rủi ro cao)
- 90 - 99: CRITICAL (Rủi ro khẩn cấp)

Trả về JSON hợp lệ (không có markdown):
{{
    "intent_type": "scam_analysis",
    "conversational_reply": "Phân tích cụ thể, tự nhiên về nội dung người dùng gửi",
    "risk_score": <0-99>,
    "explanation_breakdown": ["lý do 1", "lý do 2"],
    "recommendations": ["hành động 1", "hành động 2"]
}}"""

    # ─────────────────────────────────────────────────────────────────────────
    # UTILS
    # ─────────────────────────────────────────────────────────────────────────
    def _parse_json(self, text: str) -> dict | None:
        try:
            clean = text.replace("```json", "").replace("```", "").strip()
            return json.loads(clean)
        except Exception:
            return None

    def _get_model_name(self, provider: str) -> str:
        return {
            "groq": self.groq_model,
            "gemini": self.gemini_model,
            "mistral": self.mistral_model,
        }.get(provider, "unknown")


if __name__ == "__main__":
    client = MultiLLMClient()
    print(f"\n[MultiLLMClient] is_active: {client.is_active}")

    result = client.analyze_scam(
        user_text="Thông báo trúng thưởng xe máy SH, yêu cầu nạp tiền để làm thủ tục nhận giải",
        matched_flags=["trúng thưởng", "nạp tiền", "gấp"],
        ocr_anomalies=[]
    )
    if result:
        print(f"Provider: {client.last_successful_provider} | Risk: {result.get('risk_score')}%")
        print(f"Reply: {result.get('conversational_reply', '')[:200]}")
