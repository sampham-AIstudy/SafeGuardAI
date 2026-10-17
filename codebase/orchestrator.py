import sys
import os
import time
import re
import urllib.parse
import concurrent.futures

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
from typing import Any
from codebase.agents.multi_llm_client import MultiLLMClient      # NEW: multi-platform router
from codebase.agents.gemini_agent_runner import GeminiAgentRunner
from codebase.agents.threat_intel_agent import ThreatIntelAgent  # NEW: threat intelligence
from codebase.agents.prompt_guard import PromptGuard
from codebase.agents.url_analysis_agent import URLAnalysisAgent
from codebase.url_analysis.analyzer import UrlAnalyzer
from codebase.url_analysis.blacklist import PhishBlacklist
from codebase.knowledge_base.db_connect import MySQLManager
from codebase.config import get_settings


class AnalysisDict(dict):
    """
    A dict subclass supporting attribute access (e.g. report.findings, finding.effective_host)
    and transparent JSON serialization with standard json.dumps.
    """
    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value

    def to_dict(self) -> dict[str, Any]:
        return dict(self)


def _wrap_report_dict(val: Any) -> Any:
    """Recursively wrap dictionaries/lists into AnalysisDict for attribute access."""
    if val is None:
        return None
    if hasattr(val, "to_dict") and not isinstance(val, dict):
        val = val.to_dict()
    if isinstance(val, dict):
        return AnalysisDict({k: _wrap_report_dict(v) for k, v in val.items()})
    if isinstance(val, list):
        return [_wrap_report_dict(item) for item in val]
    return val


def _clean_text_for_url_analysis(text: str) -> str:
    """
    Sanitize text before URL analysis to remove standalone clock times (e.g. '14:30', '08:00').
    Prevents WHATWG single-integer IPv4 parser from misinterpreting '14:30' as host '0.0.0.14' port 30.
    """
    if not text:
        return text
    return re.sub(r'(?<![0-9a-zA-Z/])(?:[01]?[0-9]|2[0-3]):[0-5][0-9](?![0-9a-zA-Z/]|(?:\.[a-zA-Z]))', ' ', text)


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

        # URL Analysis Agent — single instantiation in __init__
        try:
            phish_data = getattr(self.rag_agent, "phish_data", None)
            blacklist = PhishBlacklist.from_dataset(phish_data)
        except Exception:
            blacklist = PhishBlacklist()

        self.url_analyzer = UrlAnalyzer(blacklist=blacklist)
        self.url_agent = URLAnalysisAgent(analyzer=self.url_analyzer)

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
    def process_request(self, user_text: str = "", image_input=None, session_id: str = "session_default", image_base64: str = None, persist: bool = True, pil_image=None) -> dict:
        start_time = time.time()
        max_chars = get_settings().max_text_chars
        input_truncated = False
        if user_text and len(user_text) > max_chars:
            user_text = user_text[:max_chars]
            input_truncated = True

        # ── Step 0: Prompt Injection & Safety Guardrail Check ──────────────
        guard_eval = self.prompt_guard.evaluate_input(user_text)
        if not guard_eval.get("is_safe", True):
            print(f"[Orchestrator] Refused malicious request: {guard_eval.get('reason')}")
            url_report = None
            if get_settings().url_module_enabled:
                allow_net = bool(get_settings().network_enabled and not get_settings().offline)
                raw_rep = self.url_agent.analyze(_clean_text_for_url_analysis(user_text), allow_network=allow_net)
                url_report = _wrap_report_dict(raw_rep)
            return {
                "session_id": session_id,
                "user_input": user_text,
                "input_truncated": input_truncated,
                "execution_path": "prompt_guard_refusal",
                "tool_calls_made": [{"tool": "prompt_guard", "desc": "Bảo vệ an toàn & Từ chối yêu cầu độc hại"}],
                "model_used": "security_guardrail",
                "decision": {
                    "intent_type": "refusal",
                    "risk_level": "LOW",
                    "headline": guard_eval.get("refusal_message", ""),
                    "hitl_disclaimer": "SafeGuard AI Security & Ethics Policy Enforced."
                },
                "risk_score": 0,
                "latency_ms": round((time.time() - start_time) * 1000, 2),
                "url_analysis": url_report,
                "network_actions": []
            }

        injection_detected = bool(guard_eval.get("injection_detected", False))

        # ── Step 1: Prepare PIL image ──────────────────────────────────────
        image_input = image_input or pil_image
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
        if persist and self.db_manager.is_connected:
            self.memory_agent.load_history_from_db(self.db_manager, session_id)

        # ══════════════════════════════════════════════════════════════════
        # PRIMARY PATH: Gemini Agentic Tool-Calling
        # ══════════════════════════════════════════════════════════════════
        agent_result = None
        if not injection_detected:
            effective_user_text = user_text
            if pil_image:
                effective_user_text = f"{user_text}\n[Người dùng đính kèm ảnh bằng chứng màn hình nghi vấn - BẮT BUỘC gọi ocr_extract() và scan_url_threat_intel() để kiểm tra link/chữ trên ảnh]".strip()

            agent_result = self.agent_runner.run(
                user_text=effective_user_text,
                pil_image=pil_image,
                session_id=session_id
            )
        else:
            print("[Orchestrator] ⚠️ Prompt injection detected — bypassing LLM agent runner.")

        if agent_result is not None:
            return self._finalize_agentic_result(
                agent_result=agent_result,
                user_text=user_text,
                session_id=session_id,
                start_time=start_time,
                image_base64=image_base64,
                persist=persist,
                injection_detected=injection_detected,
                input_truncated=input_truncated,
                pil_image=pil_image
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
            image_base64=image_base64,
            persist=persist,
            injection_detected=injection_detected,
            input_truncated=input_truncated
        )

    # ─────────────────────────────────────────────────────────────────────────
    # URL EVIDENCE FLOORS
    # ─────────────────────────────────────────────────────────────────────────
    def _apply_evidence_floors(
        self,
        risk_score: int,
        url_report: Any = None,
        explain_info: dict | None = None,
        extra_critical_codes: set[str] | list[str] | None = None,
    ) -> tuple[int, bool]:
        """
        Apply evidence-based floors according to Phase 2D & Phase 3C:
        - When module is disabled or url_report is None: checks extra_critical_codes
        - Critical codes (USERINFO_BRAND_DECOY, HOMOGLYPH_BRAND, BLACKLIST_HIT,
          APK_DOWNLOAD, DATA_OR_JS_URI, BACKSLASH_CONFUSION, THREAT_INTEL_MALICIOUS...) => risk >= 85
          (APK/DATA => >= 90)
        - max_url_risk >= 70 => risk >= 75
        - max_url_risk 40-69 => risk >= 45
        - critical_evidence = True if any critical code is present
        """
        crit_codes = set()
        if extra_critical_codes:
            crit_codes.update(extra_critical_codes)

        if not get_settings().url_module_enabled and not crit_codes:
            return risk_score, False

        raw_crit = getattr(url_report, "critical_codes", None) if url_report else None
        if raw_crit is None and isinstance(url_report, dict):
            raw_crit = url_report.get("critical_codes", [])
        if raw_crit:
            crit_codes.update(raw_crit)

        findings = getattr(url_report, "findings", None) if url_report else None
        if findings is None and isinstance(url_report, dict):
            findings = url_report.get("findings", [])

        has_apk_or_data = False
        all_signal_codes = set()

        def _scan_finding(f_item):
            nonlocal has_apk_or_data
            sigs = getattr(f_item, "signals", None)
            if sigs is None and isinstance(f_item, dict):
                sigs = f_item.get("signals", [])
            for s in sigs or []:
                code = getattr(s, "code", None) if not isinstance(s, dict) else s.get("code")
                sev = getattr(s, "severity", None) if not isinstance(s, dict) else s.get("severity")
                if code:
                    all_signal_codes.add(code)
                if sev == "critical":
                    crit_codes.add(code)
                if code in ("APK_DOWNLOAD", "DATA_OR_JS_URI") or (code and ("APK" in code or "DATA_OR_JS" in code)):
                    has_apk_or_data = True

            children = getattr(f_item, "children", None)
            if children is None and isinstance(f_item, dict):
                children = f_item.get("children", [])
            for ch in children or []:
                _scan_finding(ch)

        for f in findings or []:
            _scan_finding(f)

        critical_url_codes = {
            "USERINFO_BRAND_DECOY", "HOMOGLYPH_BRAND", "BLACKLIST_HIT",
            "APK_DOWNLOAD", "DATA_OR_JS_URI", "BACKSLASH_CONFUSION",
            "THREAT_INTEL_MALICIOUS"
        }
        has_critical = bool(crit_codes) or bool(all_signal_codes & critical_url_codes)
        critical_evidence = has_critical

        max_url_risk = getattr(url_report, "max_url_risk", None) if url_report else None
        if max_url_risk is None and isinstance(url_report, dict):
            max_url_risk = url_report.get("max_url_risk", 0)
        max_url_risk = max_url_risk or 0

        res_risk = risk_score
        if has_critical:
            res_risk = max(res_risk, 85)
        if has_apk_or_data:
            res_risk = max(res_risk, 90)
        if max_url_risk >= 70:
            res_risk = max(res_risk, 75)
        elif max_url_risk >= 40:
            res_risk = max(res_risk, 45)

        return min(99, res_risk), critical_evidence

    def _run_threat_intel_for_report(
        self,
        url_report: Any,
        tool_cache_ti: Any = None,
        budget_s: float = 6.0
    ) -> dict | None:
        """
        Run ThreatIntel for up to 3 non-official findings that have:
        - verdict >= suspicious (suspicious or dangerous)
        - or are shorteners / antibot / unverified.
        Runs concurrently within budget_s (default 6.0s).
        Returns aggregated ThreatIntel dict or None.
        """
        settings = get_settings()
        if settings.offline or not settings.network_enabled:
            return None

        # If LLM already ran ThreatIntel via tool_calling in agentic branch, reuse cached result
        if tool_cache_ti:
            if isinstance(tool_cache_ti, list) and tool_cache_ti:
                if len(tool_cache_ti) == 1:
                    return tool_cache_ti[0]
                return self._aggregate_ti_results(tool_cache_ti)
            elif isinstance(tool_cache_ti, dict) and tool_cache_ti:
                return tool_cache_ti

        if not url_report:
            return None

        findings = getattr(url_report, "findings", None)
        if findings is None and isinstance(url_report, dict):
            findings = url_report.get("findings", [])
        if not findings:
            return None

        eligible_urls: list[str] = []
        for f in findings:
            is_off = getattr(f, "is_official", False) if not isinstance(f, dict) else f.get("is_official", False)
            if is_off:
                continue

            verdict = str(getattr(f, "verdict", "") if not isinstance(f, dict) else f.get("verdict", "")).lower()
            sigs = getattr(f, "signals", []) if not isinstance(f, dict) else f.get("signals", [])
            sig_codes = {getattr(s, "code", "") if not isinstance(s, dict) else s.get("code", "") for s in sigs or []}

            has_suspicious_verdict = verdict in ("suspicious", "dangerous")
            eff_host = getattr(f, "effective_host", "") if not isinstance(f, dict) else f.get("effective_host", "")
            has_shortener = (
                bool(getattr(f, "redirect_chain", None) if not isinstance(f, dict) else f.get("redirect_chain", None))
                or "SHORTENER" in sig_codes
                or "SHORTENER_RESOLVED" in sig_codes
                or self.url_analyzer._is_shortener(eff_host)
            )
            has_antibot = "ANTIBOT_CHALLENGE" in sig_codes or "CLOAKING_SUSPECTED" in sig_codes
            is_unverified = verdict == "unverified"

            if has_suspicious_verdict or has_shortener or has_antibot or is_unverified:
                target = (
                    getattr(f, "final_url", None)
                    or getattr(f, "normalized", None)
                    or getattr(f, "raw", None)
                    if not isinstance(f, dict)
                    else (f.get("final_url") or f.get("normalized") or f.get("raw"))
                )
                if target and target not in eligible_urls:
                    eligible_urls.append(target)
                    if len(eligible_urls) >= 3:
                        break

        if not eligible_urls:
            return None

        ti_results: list[dict] = []
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=min(3, len(eligible_urls)))
        try:
            futures = {executor.submit(self.threat_intel_agent.scan_url, u): u for u in eligible_urls}
            done, not_done = concurrent.futures.wait(futures.keys(), timeout=budget_s)
            for future in done:
                try:
                    res = future.result()
                    if res:
                        ti_results.append(res)
                except Exception as ex:
                    u = futures[future]
                    ti_results.append({"url": u, "is_malicious": False, "error": str(ex)})
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        if not ti_results:
            return None

        if len(ti_results) == 1:
            return ti_results[0]
        return self._aggregate_ti_results(ti_results)

    def _aggregate_ti_results(self, ti_results: list[dict]) -> dict:
        is_malicious = any(r.get("is_malicious", False) for r in ti_results)
        malicious_count = sum(r.get("malicious_sources", 0) for r in ti_results)
        sources_checked = sorted(list(set(s for r in ti_results for s in r.get("sources_checked", []))))
        summaries = [
            r.get("verdict_summary", "") for r in ti_results
            if r.get("verdict_summary") and r.get("verdict_summary") != "Không phát hiện mối đe dọa"
        ]
        verdict_summary = " | ".join(summaries) if summaries else "Không phát hiện mối đe dọa"
        details = {r.get("url", f"url_{i}"): r.get("details", {}) for i, r in enumerate(ti_results)}
        network_actions = [act for r in ti_results for act in r.get("network_actions", [])]
        return {
            "url": ti_results[0].get("url", ""),
            "domain": ti_results[0].get("domain", ""),
            "is_malicious": is_malicious,
            "malicious_sources": malicious_count,
            "sources_checked": sources_checked,
            "verdict_summary": verdict_summary,
            "details": details,
            "network_actions": network_actions,
            "scans": ti_results
        }

    def _collect_network_actions(self, url_report: Any, ti_result: dict | None) -> list[dict[str, str]]:
        settings = get_settings()
        if settings.offline or not settings.network_enabled:
            return []

        actions: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()

        def _add_action(atype: str, target: str):
            if not target or not isinstance(target, str):
                return
            t = target.strip()
            if "://" in t:
                try:
                    t = urllib.parse.urlsplit(t).netloc or t
                except Exception:
                    pass
            if "@" in t:
                t = t.split("@")[-1]
            if ":" in t and not t.startswith("["):
                t = t.split(":")[0]
            if "/" in t:
                t = t.split("/")[0]
            if "?" in t:
                t = t.split("?")[0]
            t = t.strip().lower()
            if not t:
                return
            key = (atype, t)
            if key not in seen:
                seen.add(key)
                actions.append({"type": atype, "target": t})

        # 1. From url_report findings
        if url_report:
            findings = getattr(url_report, "findings", None)
            if findings is None and isinstance(url_report, dict):
                findings = url_report.get("findings", [])

            def _scan_f(f_item):
                r_chain = getattr(f_item, "redirect_chain", None)
                if r_chain is None and isinstance(f_item, dict):
                    r_chain = f_item.get("redirect_chain", [])
                for hop in r_chain or []:
                    hop_url = hop.get("url", "") if isinstance(hop, dict) else getattr(hop, "url", "")
                    if hop_url:
                        _add_action("resolver_lookup", hop_url)

                p_intel = getattr(f_item, "passive_intel", None)
                if p_intel is None and isinstance(f_item, dict):
                    p_intel = f_item.get("passive_intel", None)
                if p_intel and isinstance(p_intel, dict):
                    reg = getattr(f_item, "registrable_domain", "") if not isinstance(f_item, dict) else f_item.get("registrable_domain", "")
                    host = getattr(f_item, "effective_host", "") if not isinstance(f_item, dict) else f_item.get("effective_host", "")
                    if p_intel.get("domain_age") is not None and reg:
                        _add_action("rdap_lookup", reg)
                    if p_intel.get("ct") is not None and reg:
                        _add_action("crtsh_lookup", reg)
                    if p_intel.get("tls") is not None and (host or reg):
                        _add_action("tls_probe", host or reg)
                    if p_intel.get("dns_status") not in (None, "unknown") and (host or reg):
                        _add_action("dns_lookup", host or reg)

                children = getattr(f_item, "children", None)
                if children is None and isinstance(f_item, dict):
                    children = f_item.get("children", [])
                for ch in children or []:
                    _scan_f(ch)

            for f in findings or []:
                _scan_f(f)

        # 2. From ti_result
        if ti_result and isinstance(ti_result, dict):
            for act in ti_result.get("network_actions", []):
                if isinstance(act, dict):
                    atype = act.get("type", "threat_intel")
                    atarget = act.get("target", "")
                    _add_action(atype, atarget)

        return actions

    # ─────────────────────────────────────────────────────────────────────────
    # PATH A: Finalize result from Gemini Agentic Runner
    # ─────────────────────────────────────────────────────────────────────────
    def _finalize_agentic_result(self, agent_result: dict, user_text: str, session_id: str, start_time: float, image_base64: str = None, persist: bool = True, injection_detected: bool = False, input_truncated: bool = False, pil_image=None) -> dict:
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
        ocr_extracted = (ocr_result.get("extracted_text") or "").strip()
        has_image = bool(
            ocr_result.get("has_image", False)
            or pil_image
            or image_base64
            or (ocr_extracted and ocr_extracted != (user_text or "").strip())
        )
        if ocr_extracted and ocr_extracted != (user_text or "").strip():
            full_text = f"{user_text}\n{ocr_extracted}".strip() if user_text else ocr_extracted
        else:
            full_text = user_text

        url_report = None
        if get_settings().url_module_enabled:
            allow_net = bool(get_settings().network_enabled and not get_settings().offline)
            raw_rep = self.url_agent.analyze(_clean_text_for_url_analysis(full_text), allow_network=allow_net)
            url_report = _wrap_report_dict(raw_rep)

        # ThreatIntel in agentic branch
        ti_from_cache = tool_cache.get("threat_intel")
        ti_result = None
        try:
            ti_result = self._run_threat_intel_for_report(
                url_report=url_report,
                tool_cache_ti=ti_from_cache,
                budget_s=6.0
            )
        except Exception as ex:
            print(f"[Orchestrator] ThreatIntel error in agentic: {ex}")

        if ti_result and ti_result.get("is_malicious"):
            if "risk_breakdown" not in explain_info:
                explain_info["risk_breakdown"] = []
            explain_info["risk_breakdown"].append({
                "factor": "Cảnh báo cơ sở dữ liệu đe dọa toàn cầu (Threat Intelligence): Độc hại",
                "score": 60
            })
            if "reasons" not in explain_info:
                explain_info["reasons"] = []
            explain_info["reasons"].append(
                f"Cơ sở dữ liệu an ninh mạng cảnh báo URL độc hại: {ti_result.get('verdict_summary', '')}"
            )

        critical_evidence = False
        extra_crit = {"THREAT_INTEL_MALICIOUS"} if (ti_result and ti_result.get("is_malicious")) else None
        if get_settings().url_module_enabled or extra_crit:
            risk_score, critical_evidence = self._apply_evidence_floors(
                risk_score=risk_score,
                url_report=url_report,
                explain_info=explain_info,
                extra_critical_codes=extra_crit
            )

        decision_info = self.decision_agent.evaluate_decision(
            risk_score=risk_score,
            confidence_info=confidence_info,
            explainable_info=explain_info,
            emergency_info=emergency_info,
            user_text=user_text,
            real_llm_result=agent_result,
            critical_evidence=critical_evidence,
            url_report=url_report,
            has_image=has_image,
            full_text=full_text
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
            user_text, decision_info["risk_level"], matched_flags, session_id=session_id
        )

        if input_truncated:
            decision_info.setdefault("recommendations", []).append(
                "Nội dung đầu vào vượt quá giới hạn độ dài cho phép (20.000 ký tự) và đã được cắt bớt để xử lý an toàn."
            )

        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        # ── MySQL log ─────────────────────────────────────────────────────
        if persist and self.db_manager.is_connected:
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

        network_actions = self._collect_network_actions(url_report, ti_result)

        resp = {
            "session_id": session_id,
            "user_input": user_text,
            "input_truncated": input_truncated,
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
            "latency_ms": elapsed_ms,
            "url_analysis": url_report,
            "network_actions": network_actions,
        }
        if ti_result is not None:
            resp["threat_intel"] = ti_result
        return resp

    # ─────────────────────────────────────────────────────────────────────────
    # PATH B: Sequential Fallback Pipeline (original logic, preserved fully)
    # ─────────────────────────────────────────────────────────────────────────
    def _run_sequential_fallback(self, user_text: str, pil_image, image_input,
                                  session_id: str, start_time: float, image_base64: str = None, persist: bool = True,
                                  injection_detected: bool = False, input_truncated: bool = False) -> dict:
        """
        Original 8-step sequential pipeline. Runs when Gemini API is unavailable.
        Preserves all previous behavior exactly.
        """
        # Step 1: Emergency Check
        emergency_info = self.emergency_agent.check_trigger(user_text)

        # Step 2: Vision / OCR Agent
        ocr_result = self.ocr_agent.process(image_input=pil_image or image_input, raw_text=user_text)
        ocr_extracted = (ocr_result.get("extracted_text") or "").strip()
        has_image = bool(
            ocr_result.get("has_image", False)
            or pil_image
            or image_input
            or image_base64
            or (ocr_extracted and ocr_extracted != (user_text or "").strip())
        )
        if ocr_extracted and ocr_extracted != (user_text or "").strip():
            full_text = f"{user_text}\n{ocr_extracted}".strip() if user_text else ocr_extracted
        else:
            full_text = user_text

        # URL Analysis (if module enabled)
        url_report = None
        if get_settings().url_module_enabled:
            allow_net = bool(get_settings().network_enabled and not get_settings().offline)
            raw_rep = self.url_agent.analyze(_clean_text_for_url_analysis(full_text), allow_network=allow_net)
            url_report = _wrap_report_dict(raw_rep)

        # ThreatIntel in sequential fallback branch
        ti_result = None
        try:
            ti_result = self._run_threat_intel_for_report(
                url_report=url_report,
                budget_s=6.0
            )
        except Exception as ex:
            print(f"[Orchestrator] ThreatIntel error in fallback: {ex}")

        # Step 3: RAG Agent Knowledge Match
        # Protect against single-token DoS repetitive strings (e.g. 'a'*50000 without spaces/dots)
        rag_text = full_text
        if len(full_text) > 1000 and " " not in full_text and "." not in full_text:
            rag_text = full_text[:1000]
        rag_result = self.rag_agent.search(rag_text, url_report=url_report)

        # Step 4: Memory Agent Escalation Check
        escalation_info = self.memory_agent.analyze_escalation(full_text, session_id=session_id)

        # Step 5: LLM Fallback (GeminiLLMClient text-only, no tool calling)
        real_llm_result = None
        if not injection_detected:
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
            escalation_info=escalation_info,
            url_report=url_report
        )

        if injection_detected:
            if "risk_breakdown" not in explain_info:
                explain_info["risk_breakdown"] = []
            explain_info["risk_breakdown"].append({
                "factor": "Tin chứa câu lệnh thao túng AI (Prompt Injection)",
                "score": 20
            })
            if "reasons" not in explain_info:
                explain_info["reasons"] = []
            explain_info["reasons"].append(
                "Phát hiện dấu hiệu chèn câu lệnh thao túng AI nhằm né tránh kiểm duyệt an toàn."
            )
            explain_info["risk_score"] = min(99, explain_info.get("risk_score", 0) + 20)

        if ti_result and ti_result.get("is_malicious"):
            if "risk_breakdown" not in explain_info:
                explain_info["risk_breakdown"] = []
            explain_info["risk_breakdown"].append({
                "factor": "Cảnh báo cơ sở dữ liệu đe dọa toàn cầu (Threat Intelligence): Độc hại",
                "score": 60
            })
            if "reasons" not in explain_info:
                explain_info["reasons"] = []
            explain_info["reasons"].append(
                f"Cơ sở dữ liệu an ninh mạng cảnh báo URL độc hại: {ti_result.get('verdict_summary', '')}"
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

        critical_evidence = False
        extra_crit = {"THREAT_INTEL_MALICIOUS"} if (ti_result and ti_result.get("is_malicious")) else None
        if get_settings().url_module_enabled or extra_crit:
            risk_score, critical_evidence = self._apply_evidence_floors(
                risk_score=risk_score,
                url_report=url_report,
                explain_info=explain_info,
                extra_critical_codes=extra_crit
            )

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
            real_llm_result=real_llm_result,
            critical_evidence=critical_evidence,
            url_report=url_report,
            has_image=has_image,
            full_text=full_text
        )


        if real_llm_result and real_llm_result.get("recommendations"):
            decision_info["recommendations"].extend(real_llm_result["recommendations"])

        self.memory_agent.add_interaction(full_text, decision_info["risk_level"], rag_result["matched_flags"], session_id=session_id)
        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        if persist and self.db_manager.is_connected:
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

        if input_truncated:
            decision_info.setdefault("recommendations", []).append(
                "Nội dung đầu vào vượt quá giới hạn độ dài cho phép (20.000 ký tự) và đã được cắt bớt để xử lý an toàn."
            )

        tool_calls_log = [
            {"tool": "emergency_check", "desc": "Kiểm tra tình huống khẩn cấp (Emergency Check)"},
            {"tool": "ocr_extract", "desc": "Trích xuất chữ & dấu hiệu bất thường trên ảnh (Vision OCR)"},
            {"tool": "rag_search", "desc": "Đối soát CSDL vector PhishVN & dữ liệu lừa đảo quốc tế"},
            {"tool": "memory_escalation", "desc": "Đánh giá mức độ leo thang rủi ro qua lịch sử"},
            {"tool": "explainable_score", "desc": "Tính ma trận trọng số rủi ro (Explainable AI Score)"},
            {"tool": "confidence_eval", "desc": "Đánh giá mức độ tin cậy AI & đưa ra quyết định (Confidence Agent)"}
        ]
        if ti_result is not None:
            tool_calls_log.append(
                {"tool": "threat_intel_scan", "desc": "Đối soát cơ sở dữ liệu đe dọa toàn cầu (Threat Intelligence)"}
            )

        network_actions = self._collect_network_actions(url_report, ti_result)

        resp = {
            "session_id": session_id,
            "user_input": user_text,
            "input_truncated": input_truncated,
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
            "latency_ms": elapsed_ms,
            "url_analysis": url_report,
            "network_actions": network_actions,
        }
        if ti_result is not None:
            resp["threat_intel"] = ti_result
        return resp


if __name__ == "__main__":
    orchestrator = SafeGuardOrchestrator()
    result = orchestrator.process_request(
        "Thông báo trúng thưởng xe máy SH, yêu cầu nạp phí hồ sơ gấp",
        session_id="test_session"
    )
    path = result.get("execution_path", "unknown")
    tools = [t["tool"] for t in result.get("tool_calls_made", [])]
    print(f"[Orchestrator] Path: {path} | Tools: {tools}")
    print(f"[Orchestrator] Risk: {result['risk_score']}% ({result['decision']['risk_level']}) | Model: {result['model_used']}")
