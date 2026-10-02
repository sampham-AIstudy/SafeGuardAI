import sys
import os
import time

try:
    from PIL import Image
except ImportError:
    Image = None

# Add root project dir to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from codebase.agents.ocr_agent import OCRAgent
from codebase.agents.rag_agent import RAGAgent
from codebase.agents.memory_agent import MemoryAgent
from codebase.agents.explainable_agent import ExplainableAgent
from codebase.agents.confidence_agent import ConfidenceAgent
from codebase.agents.emergency_agent import EmergencyAgent
from codebase.agents.decision_agent import DecisionAgent
from codebase.agents.multi_llm_client import MultiLLMClient      # NEW: multi-platform router
from codebase.agents.gemini_agent_runner import GeminiAgentRunner
from codebase.agents.threat_intel_agent import ThreatIntelAgent  # NEW: threat intelligence
from codebase.agents.prompt_guard import PromptGuard
from codebase.knowledge_base.db_connect import MySQLManager


class SafeGuardOrchestrator:
    """
    Main Multi-Agent Orchestrator for SafeGuard AI.
    """

    def __init__(self):
        # Instantiate all sub-agents
        self.prompt_guard = PromptGuard()
        self.ocr_agent = OCRAgent()
        self.rag_agent = RAGAgent()
        self.memory_agent = MemoryAgent()
        self.explainable_agent = ExplainableAgent()
        self.confidence_agent = ConfidenceAgent()
        self.emergency_agent = EmergencyAgent()
        self.decision_agent = DecisionAgent()
        self.threat_intel_agent = ThreatIntelAgent()
        self.multi_llm_client = MultiLLMClient()
        self.llm_client = self.multi_llm_client
        self.db_manager = MySQLManager()

        # Gemini Agentic Runner — primary execution path
        self.agent_runner = GeminiAgentRunner(agents={
            "emergency": self.emergency_agent,
            "rag": self.rag_agent,
            "ocr": self.ocr_agent,
            "explainable": self.explainable_agent,
            "memory": self.memory_agent,
            "confidence": self.confidence_agent,
            "threat_intel": self.threat_intel_agent,
        })

    # ─────────────────────────────────────────────────────────────────────────
    # PUBLIC ENTRY POINT
    # ─────────────────────────────────────────────────────────────────────────
    def process_request(self, user_text: str = "", image_input=None, session_id: str = "session_default", image_base64: str = None) -> dict:
        start_time = time.time()

        # ── Step 0: Prompt Injection & Safety Guardrail Check ──────────────
        guard_eval = self.prompt_guard.evaluate_input(user_text)
        if not guard_eval["is_safe"]:
            print(f"[Orchestrator] Blocked unsafe prompt injection: {guard_eval['reason']}")
            return {
                "session_id": session_id,
                "user_input": user_text,
                "execution_path": "prompt_guard_blocked",
                "tool_calls_made": [{"tool": "prompt_guard", "desc": "Bao ve an toan & Phong chong Prompt Injection"}],
                "model_used": "security_guardrail",
                "decision": {
                    "intent_type": "general_chat",
                    "risk_level": "LOW",
                    "headline": guard_eval["refusal_message"],
                    "hitl_disclaimer": "SafeGuard AI Security & Ethics Policy Enforced."
                },
                "risk_score": 0,
                "latency_ms": round((time.time() - start_time) * 1000, 2)
            }

        # ── Step 1: Prepare PIL image ──────────────────────────────────────
        pil_image = None
        if image_input and Image:
            try:
                if isinstance(image_input, Image.Image):
                    pil_image = image_input
                else:
                    pil_image = Image.open(image_input)
            except Exception as e:
                print(f"[Orchestrator] PIL Image open notice: {e}")

        # ── Step 1: Hydrate Memory Agent from MySQL ────────────────────────
        if self.db_manager.is_connected:
            self.memory_agent.load_history_from_db(self.db_manager, session_id)

        # ══════════════════════════════════════════════════════════════════
        # PRIMARY PATH: Gemini Agentic Tool-Calling
        # ══════════════════════════════════════════════════════════════════
        effective_user_text = user_text
        if pil_image:
            effective_user_text = f"{user_text}\n[Người dùng đính kèm ảnh bằng chứng màn hình nghi vấn - BẮT BUỘC gọi ocr_extract() và scan_url_threat_intel() để kiểm tra link/chữ trên ảnh]".strip()

        agent_result = self.agent_runner.run(
            user_text=effective_user_text,
            pil_image=pil_image,
            session_id=session_id
        )

        if agent_result is not None:
            return self._finalize_agentic_result(
                agent_result=agent_result,
                user_text=user_text,
                session_id=session_id,
                start_time=start_time,
                image_base64=image_base64
            )

        # ══════════════════════════════════════════════════════════════════
        # FALLBACK PATH: Sequential Pipeline (no Gemini API)
        # ══════════════════════════════════════════════════════════════════
        print("[Orchestrator] ↩️  Gemini Agent unavailable — using sequential fallback.")
        return self._run_sequential_fallback(
            user_text=user_text,
            pil_image=pil_image,
            image_input=image_input,
            session_id=session_id,
            start_time=start_time,
            image_base64=image_base64
        )

    # ─────────────────────────────────────────────────────────────────────────
    # PATH A: Finalize result from Gemini Agentic Runner
    # ─────────────────────────────────────────────────────────────────────────
    def _finalize_agentic_result(self, agent_result: dict, user_text: str, session_id: str, start_time: float, image_base64: str = None) -> dict:
        """
        Post-process the Gemini agentic result:
        - Pull cached tool outputs for structured response
        - Apply evidence-based risk floor (same safety net as before)
        - Run DecisionAgent for risk_level labeling
        - Log to MySQL
        """
        tool_cache = agent_result.get("_tool_cache", {})

        # ── Extract outputs from tool cache ───────────────────────────────
        rag_result = tool_cache.get("rag", {
            "matched_flags": [], "matched_tactics": [],
            "total_patterns_matched": 0, "matched_phish_domains": [],
            "mysql_active": self.db_manager.is_connected,
            "phish_vn_stats": {}, "global_stats": {}
        })
        ocr_result = tool_cache.get("ocr", {
            "extracted_text": user_text, "anomalies": [], "has_image": False
        })
        explain_info = tool_cache.get("explainable", {
            "risk_score": 0, "risk_breakdown": [], "reasons": []
        })
        memory_result = tool_cache.get("memory", {
            "history_count": 0, "escalation_detected": False,
            "escalation_reason": "", "accumulated_flags": []
        })
        confidence_info = tool_cache.get("confidence", {
            "confidence_score": 50, "confidence_level": "MEDIUM",
            "reason": "", "recommend_human_verification": False
        })
        emergency_info = tool_cache.get("emergency", {"is_emergency": False})

        # ── Determine final risk_score ─────────────────────────────────────
        llm_risk = int(agent_result.get("risk_score", 0))
        explainable_risk = int(explain_info.get("risk_score", 0))

        # Use MAX of Gemini score and ExplainableAgent score
        risk_score = max(llm_risk, explainable_risk)

        # Evidence-based floor: prevents underreporting when pattern evidence is strong
        breakdown_count = len(explain_info.get("risk_breakdown", []))
        if breakdown_count >= 2:
            risk_score = max(risk_score, 50)
        if breakdown_count >= 3:
            risk_score = max(risk_score, 70)

        # Recalculate confidence with final score
        matched_flags = rag_result.get("matched_flags", [])
        if not confidence_info.get("confidence_score"):
            confidence_info = self.confidence_agent.evaluate(
                matched_flags_count=len(matched_flags),
                total_patterns_matched=rag_result.get("total_patterns_matched", 0),
                risk_score=risk_score
            )

        # ── DecisionAgent: map risk_score → risk_level ───────────────────
        decision_info = self.decision_agent.evaluate_decision(
            risk_score=risk_score,
            confidence_info=confidence_info,
            explainable_info=explain_info,
            emergency_info=emergency_info,
            user_text=user_text,
            real_llm_result=agent_result
        )

        # Merge LLM recommendations into decision
        llm_recs = agent_result.get("recommendations", [])
        if llm_recs:
            existing = set(decision_info.get("recommendations", []))
            for rec in llm_recs:
                if rec not in existing:
                    decision_info["recommendations"].append(rec)

        # ── Memory: record interaction ────────────────────────────────────
        self.memory_agent.add_interaction(
            user_text, decision_info["risk_level"], matched_flags
        )

        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        # ── MySQL log ─────────────────────────────────────────────────────
        if self.db_manager.is_connected:
            self.db_manager.log_user_analysis(
                user_text=user_text,
                risk_score=risk_score,
                risk_level=decision_info["risk_level"],
                confidence_score=confidence_info["confidence_score"],
                matched_flags=matched_flags,
                latency_ms=elapsed_ms,
                session_id=session_id,
                bot_response=decision_info["headline"],
                image_base64=image_base64
            )

        return {
            "session_id": session_id,
            "user_input": user_text,
            "execution_path": "gemini_agentic",
            "tool_calls_made": agent_result.get("tool_calls_made", []),
            "model_used": agent_result.get("model_used", self.agent_runner.model_name),
            "ocr": ocr_result,
            "rag": rag_result,
            "memory": memory_result,
            "explainable": explain_info,
            "confidence": confidence_info,
            "emergency": emergency_info,
            "decision": decision_info,
            "risk_score": risk_score,
            "real_ai_call": True,
            "latency_ms": elapsed_ms
        }

    # ─────────────────────────────────────────────────────────────────────────
    # PATH B: Sequential Fallback Pipeline (original logic, preserved fully)
    # ─────────────────────────────────────────────────────────────────────────
    def _run_sequential_fallback(self, user_text: str, pil_image, image_input,
                                  session_id: str, start_time: float, image_base64: str = None) -> dict:
        """
        Original 8-step sequential pipeline. Runs when Gemini API is unavailable.
        Preserves all previous behavior exactly.
        """
        # Step 1: Emergency Check
        emergency_info = self.emergency_agent.check_trigger(user_text)

        # Step 2: Vision / OCR Agent
        ocr_result = self.ocr_agent.process(image_input=pil_image or image_input, raw_text=user_text)
        full_text = ocr_result["extracted_text"] or user_text

        # Step 3: RAG Agent Knowledge Match
        rag_result = self.rag_agent.search(full_text)

        # Step 4: Memory Agent Escalation Check
        escalation_info = self.memory_agent.analyze_escalation(full_text)

        # Step 5: LLM Fallback (GeminiLLMClient text-only, no tool calling)
        real_llm_result = self.llm_client.analyze_scam(
            user_text=full_text,
            matched_flags=rag_result["matched_flags"],
            ocr_anomalies=ocr_result["anomalies"],
            pil_image=pil_image
        )

        # Step 6: Explainable Agent Risk Score
        explain_info = self.explainable_agent.explain(
            text=full_text,
            matched_flags=rag_result["matched_flags"],
            ocr_anomalies=ocr_result["anomalies"],
            escalation_info=escalation_info
        )

        # Risk score aggregation: MAX of LLM and ExplainableAgent
        explainable_score = explain_info["risk_score"]
        if real_llm_result and "risk_score" in real_llm_result:
            llm_score = int(real_llm_result["risk_score"])
            risk_score = max(llm_score, explainable_score)
        else:
            risk_score = emergency_info.get("risk_score", explainable_score)

        # Evidence-based floor
        breakdown_count = len(explain_info.get("risk_breakdown", []))
        if breakdown_count >= 2:
            risk_score = max(risk_score, 50)
        if breakdown_count >= 3:
            risk_score = max(risk_score, 70)

        # Step 7: Confidence Agent
        confidence_info = self.confidence_agent.evaluate(
            matched_flags_count=len(rag_result["matched_flags"]),
            total_patterns_matched=rag_result["total_patterns_matched"],
            risk_score=risk_score
        )

        # Step 8: Decision Agent
        decision_info = self.decision_agent.evaluate_decision(
            risk_score=risk_score,
            confidence_info=confidence_info,
            explainable_info=explain_info,
            emergency_info=emergency_info,
            user_text=user_text,
            real_llm_result=real_llm_result
        )

        if real_llm_result and real_llm_result.get("recommendations"):
            decision_info["recommendations"].extend(real_llm_result["recommendations"])

        self.memory_agent.add_interaction(full_text, decision_info["risk_level"], rag_result["matched_flags"])
        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        if self.db_manager.is_connected:
            self.db_manager.log_user_analysis(
                user_text=full_text,
                risk_score=risk_score,
                risk_level=decision_info["risk_level"],
                confidence_score=confidence_info["confidence_score"],
                matched_flags=rag_result["matched_flags"],
                latency_ms=elapsed_ms,
                session_id=session_id,
                bot_response=decision_info["headline"],
                image_base64=image_base64
            )

        tool_calls_log = [
            {"tool": "emergency_check", "desc": "Kiểm tra tình huống khẩn cấp (Emergency Check)"},
            {"tool": "ocr_extract", "desc": "Trích xuất chữ & dấu hiệu bất thường trên ảnh (Vision OCR)"},
            {"tool": "rag_search", "desc": "Đối soát CSDL vector PhishVN & dữ liệu lừa đảo quốc tế"},
            {"tool": "memory_escalation", "desc": "Đánh giá mức độ leo thang rủi ro qua lịch sử"},
            {"tool": "explainable_score", "desc": "Tính ma trận trọng số rủi ro (Explainable AI Score)"},
            {"tool": "confidence_eval", "desc": "Đánh giá mức độ tin cậy AI & đưa ra quyết định (Confidence Agent)"}
        ]

        return {
            "session_id": session_id,
            "user_input": user_text,
            "execution_path": "sequential_fallback",
            "tool_calls_made": tool_calls_log,
            "model_used": self.llm_client.model_name if self.llm_client.is_active else "offline",
            "ocr": ocr_result,
            "rag": rag_result,
            "memory": escalation_info,
            "explainable": explain_info,
            "confidence": confidence_info,
            "emergency": emergency_info,
            "decision": decision_info,
            "risk_score": risk_score,
            "real_ai_call": self.llm_client.is_active,
            "latency_ms": elapsed_ms
        }


if __name__ == "__main__":
    orchestrator = SafeGuardOrchestrator()
    result = orchestrator.process_request(
        "Tuyển dụng xem TikTok nạp 500k quỹ chuyển khoản gấp",
        session_id="test_session"
    )
    path = result.get("execution_path", "unknown")
    tools = [t["tool"] for t in result.get("tool_calls_made", [])]
    print(f"[Orchestrator] Path: {path} | Tools: {tools}")
    print(f"[Orchestrator] Risk: {result['risk_score']}% ({result['decision']['risk_level']}) | Model: {result['model_used']}")
