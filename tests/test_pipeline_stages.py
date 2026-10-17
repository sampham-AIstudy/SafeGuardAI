import time
import concurrent.futures
from unittest.mock import patch, MagicMock

import pytest

from codebase.orchestrator import SafeGuardOrchestrator
from codebase.agents.gemini_agent_runner import GeminiAgentRunner, RunContext
from codebase.config import Settings


@pytest.fixture
def orchestrator():
    return SafeGuardOrchestrator()


def test_pipeline_trace_schema_offline(orchestrator):
    with patch("codebase.orchestrator.get_settings") as mock_settings:
        mock_settings.return_value = Settings(offline=True, llm_mode="off", network_enabled=False)

        res = orchestrator.process_request("Chào bạn", persist=False)
        assert res["execution_path"] == "deterministic_only"

        trace = res.get("pipeline_trace")
        assert trace is not None
        assert len(trace) == 4

        stages = [s["stage"] for s in trace]
        assert stages == ["A_deterministic", "B_network", "B_llm", "merge"]

        for entry in trace:
            assert "stage" in entry
            assert "ms" in entry
            assert "status" in entry
            assert entry["status"] in ("ok", "skipped", "timeout", "error", "disabled")
            assert isinstance(entry["ms"], (int, float))

        # In offline mode, network and llm should be disabled
        assert trace[1]["status"] == "disabled"
        assert trace[2]["status"] == "disabled"


def test_execution_path_variations(orchestrator):
    # 1. Mode off -> deterministic_only
    with patch("codebase.orchestrator.get_settings") as mock_settings:
        mock_settings.return_value = Settings(offline=False, llm_mode="off", network_enabled=False)
        res = orchestrator.process_request("Tin nhắn test", persist=False)
        assert res["execution_path"] == "deterministic_only"

    # 2. Mode single -> single_llm
    with patch("codebase.orchestrator.get_settings") as mock_settings, \
         patch.object(orchestrator.multi_llm_client, "is_active", True), \
         patch.object(orchestrator.multi_llm_client, "analyze_scam", return_value={"risk_score": 10}):
        mock_settings.return_value = Settings(offline=False, llm_mode="single", network_enabled=False)
        res = orchestrator.process_request("Tin nhắn test", llm_mode="single", persist=False)
        assert res["execution_path"] == "single_llm"

    # 3. Mode agentic with success -> gemini_agentic
    mock_agent_result = {
        "risk_score": 50,
        "recommendations": [],
        "explanation_breakdown": [],
        "tool_calls_made": [],
        "model_used": "gemini-test",
        "_tool_cache": {},
    }
    with patch("codebase.orchestrator.get_settings") as mock_settings, \
         patch.object(orchestrator.agent_runner, "is_active", True), \
         patch.object(orchestrator.agent_runner, "run", return_value=mock_agent_result):
        mock_settings.return_value = Settings(offline=False, llm_mode="agentic", network_enabled=False)
        res = orchestrator.process_request("Tin nhắn test", llm_mode="agentic", persist=False)
        assert res["execution_path"] == "gemini_agentic"

    # 4. Mode agentic with failure -> sequential_fallback
    with patch("codebase.orchestrator.get_settings") as mock_settings, \
         patch.object(orchestrator.agent_runner, "is_active", True), \
         patch.object(orchestrator.agent_runner, "run", side_effect=RuntimeError("API error")):
        mock_settings.return_value = Settings(offline=False, llm_mode="agentic", network_enabled=False)
        res = orchestrator.process_request("Tin nhắn test", llm_mode="agentic", persist=False)
        assert res["execution_path"] == "sequential_fallback"


def test_hanging_llm_respects_timeout(orchestrator):
    def slow_llm(*args, **kwargs):
        time.sleep(5.0)
        return {"risk_score": 90}

    with patch("codebase.orchestrator.get_settings") as mock_settings, \
         patch.object(orchestrator.multi_llm_client, "is_active", True), \
         patch.object(orchestrator.multi_llm_client, "analyze_scam", side_effect=slow_llm):
        # 1.0 second timeout
        mock_settings.return_value = Settings(
            offline=False,
            llm_mode="single",
            network_enabled=False,
            llm_timeout_s=1.0,
            request_budget_s=2.0,
        )

        t0 = time.time()
        res = orchestrator.process_request("Tin nhắn kiểm tra timeout", llm_mode="single", persist=False)
        duration = time.time() - t0

        # Should finish well under 3 seconds despite 5s sleep in LLM
        assert duration <= 2.5
        b_llm_stage = next(s for s in res["pipeline_trace"] if s["stage"] == "B_llm")
        assert b_llm_stage["status"] in ("timeout", "error")


def test_8_concurrent_requests_session_isolation(orchestrator):
    def _worker(i):
        session_id = f"session_concurrent_{i}"
        user_text = f"Nội dung kiểm tra số {i} nạp tiền nhận hoa hồng"
        return orchestrator.process_request(user_text, session_id=session_id, persist=False)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_worker, i) for i in range(8)]
        results = [f.result(timeout=10) for f in futures]

    assert len(results) == 8
    for i, res in enumerate(results):
        assert res["session_id"] == f"session_concurrent_{i}"
        assert isinstance(res["risk_score"], int)
        assert "pipeline_trace" in res


def test_explainable_score_uses_original_text_not_llm_text(orchestrator):
    runner = orchestrator.agent_runner
    ctx = RunContext(
        tool_cache={},
        allow_net=False,
        recorder=None,
        deadline=time.monotonic() + 10,
        session_id="test_sess",
        client_id="test_client",
        original_text="ORIGINAL_TRUSTED_TEXT",
    )

    with patch.object(runner.agents["explainable"], "explain") as mock_explain:
        mock_explain.return_value = {"risk_score": 10, "reasons": []}

        # Simulate LLM trying to inject a different text argument into the tool
        runner._execute_tool(
            "explainable_score",
            {"text": "INJECTED_UNTRUSTED_TEXT_FROM_LLM"},
            ctx=ctx,
        )

        mock_explain.assert_called_once()
        called_args, called_kwargs = mock_explain.call_args
        # The text passed to explain must be ctx.original_text
        assert called_kwargs.get("text") == "ORIGINAL_TRUSTED_TEXT"


def test_runner_no_instance_state_alternating_calls(orchestrator):
    runner = orchestrator.agent_runner
    # Confirm runner does NOT have _tool_results_cache attribute
    assert not hasattr(runner, "_tool_results_cache")

    ctx1 = RunContext(tool_cache={}, allow_net=False, recorder=None, deadline=time.monotonic()+10, session_id="s1", client_id="c1", original_text="msg1")
    ctx2 = RunContext(tool_cache={}, allow_net=False, recorder=None, deadline=time.monotonic()+10, session_id="s2", client_id="c2", original_text="msg2")

    runner._execute_tool("emergency_check", {"text": "msg1"}, ctx=ctx1)
    runner._execute_tool("rag_search", {"text": "msg2"}, ctx=ctx2)

    assert "emergency" in ctx1.tool_cache
    assert "rag" not in ctx1.tool_cache

    assert "rag" in ctx2.tool_cache
    assert "emergency" not in ctx2.tool_cache


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4B Regression Tests: Stage A Deterministic Floors & Snapshot Match
# ─────────────────────────────────────────────────────────────────────────────
OBFUSCATED_TEN_SAMPLES = [
    ("userinfo", "Tài khoản bị khóa, đăng nhập ngay tại https://vietcombank.com.vn:443@vcb-secure.xyz/login", True),
    ("homoglyph_a", "Quý khách bấm vào https://vietcomb\u0430nk.com/login để xác thực", True),
    ("homoglyph_e", "Quý khách bấm vào https://vi\u0435tcombank.com/login để xác thực", True),
    ("homoglyph_greek", "Quý khách bấm vào https://vi\u03b5tcombank.com/login để xác thực", True),
    ("apk_subdomain", "Quý khách bấm vào https://vneid.dichvucong.gov.vn.capnhat-hethong.xyz/vneid-update.apk để xác thực", True),
    ("apk_direct", "Cơ quan Thuế thông báo: Vui lòng truy cập http://vneid-capnhat.apk để tải file APK cài đặt", True),
    ("defang_hxxps", "Quý khách bấm vào hxxps://vietcombank-xacthuc[.]xyz:8080/dang-nhap để xác thực", False),
    ("ip_decimal", "Quý khách bấm vào http://3565158400:8080/vietcombank/login để xác thực", False),
    ("nested_redirect", "Quý khách bấm vào https://vcb-portal.xyz/redirect?url=aHR0cHM6Ly92Y2IteGFjdGh1Yy54eXovbG9naW4= để xác thực", False),
    ("percent_encoded", "Quý khách bấm vào https://v%69etcombank-xacminh.com/login để xác thực", False),
]


@pytest.mark.parametrize("name,text,expect_crit", OBFUSCATED_TEN_SAMPLES, ids=[s[0] for s in OBFUSCATED_TEN_SAMPLES])
def test_stage_a_floors_preserved_with_llm_off(orchestrator, name, text, expect_crit):
    """With LLM off, 10 obfuscated URLs must yield risk >= 75 and critical_codes when applicable."""
    res = orchestrator.process_request(text, persist=False)
    assert res["risk_score"] >= 75, f"[{name}] risk_score {res['risk_score']} < 75"
    assert res["decision"]["risk_level"] in ("HIGH", "CRITICAL")
    assert res["url_analysis"] is not None
    assert len(res["url_analysis"]["findings"]) > 0
    if expect_crit:
        assert len(res["url_analysis"]["critical_codes"]) > 0, f"[{name}] expected critical_codes"


@pytest.mark.parametrize("name,text,expect_crit", OBFUSCATED_TEN_SAMPLES, ids=[s[0] for s in OBFUSCATED_TEN_SAMPLES])
def test_stage_a_floors_preserved_when_fake_llm_returns_low(orchestrator, name, text, expect_crit):
    """When a fake LLM returns low score (e.g. 10), it CANNOT pull score below deterministic floor >= 75."""
    with patch("codebase.orchestrator.get_settings") as mock_settings, \
         patch.object(orchestrator.multi_llm_client, "is_active", True), \
         patch.object(orchestrator.multi_llm_client, "analyze_scam", return_value={"risk_score": 10, "recommendations": []}):
        mock_settings.return_value = Settings(offline=False, llm_mode="single", network_enabled=False)
        res = orchestrator.process_request(text, llm_mode="single", persist=False)
        assert res["risk_score"] >= 75, f"[{name}] fake LLM lowered score to {res['risk_score']} < 75"
        assert res["decision"]["risk_level"] in ("HIGH", "CRITICAL")
        assert res["url_analysis"] is not None
        if expect_crit:
            assert len(res["url_analysis"]["critical_codes"]) > 0, f"[{name}] expected critical_codes"


def test_stage_a_matches_phase1_predictions_when_url_module_off(orchestrator, monkeypatch):
    """When SAFEGUARD_URL_MODULE=off, Stage A deterministic output matches phase1_predictions.json for 20 v1 cases."""
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    v1_file = root / "eval" / "golden_set.json"
    pred_file = root / "tests" / "data" / "phase1_predictions.json"

    with open(v1_file, "r", encoding="utf-8") as f:
        v1_data = json.load(f)["golden_set"]
    with open(pred_file, "r", encoding="utf-8") as f:
        p1_preds = json.load(f)["v1"]

    monkeypatch.setenv("SAFEGUARD_URL_MODULE", "off")
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "1")
    from codebase.config import get_settings
    get_settings(refresh=True)

    try:
        for item in v1_data:
            cid = item["id"]
            exp_lvl, exp_score = p1_preds[cid]
            sid = f"eval_stage_a_{cid}"
            if hasattr(orchestrator.memory_agent, "reset"):
                orchestrator.memory_agent.reset(sid)
            res = orchestrator.process_request(item["input_text"], session_id=sid, persist=False)
            actual_lvl = res["decision"]["risk_level"]
            actual_score = res["risk_score"]
            assert (actual_lvl, actual_score) == (exp_lvl, exp_score), (
                f"[{cid}] Expected ({exp_lvl}, {exp_score}), got ({actual_lvl}, {actual_score})"
            )
    finally:
        monkeypatch.delenv("SAFEGUARD_URL_MODULE", raising=False)
        get_settings(refresh=True)
