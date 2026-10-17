"""
tests/test_gemini_runner_network.py
Unit tests for GeminiAgentRunner network privacy & security (Phase 3E-3 B1).
Verifies:
- allow_net=False: 0 network requests, status="network_checks_disabled", empty network_actions
- allow_net=True: calls ThreatIntel with deadline and recorder, records network_actions
- Tool declarations omit network tools when allow_net=False
- System prompt omits forced network tool calls when allow_net=False
- Exception handling masks error message and prevents leaking URLs or secret keys
- Thread-safety across 8 concurrent threads with mixed allow_net values
"""

import threading
import time
from unittest.mock import MagicMock
import pytest

from codebase.agents.gemini_agent_runner import GeminiAgentRunner, NETWORK_TOOL_NAMES
from codebase.url_analysis.resolver import NetworkRecorder


def test_gemini_runner_allow_net_false_blocks_network_tools():
    threat_spy = MagicMock()
    runner = GeminiAgentRunner(agents={"threat_intel": threat_spy})

    recorder = NetworkRecorder()
    runner.set_request_context(allow_net=False, recorder=recorder, deadline=time.time() + 5.0)

    for tool_name in ("scan_url_threat_intel", "lookup_domain_info", "check_phishing_db"):
        res = runner._execute_tool(tool_name, {"url": "https://malicious.example.com", "domain": "malicious.example.com"})
        assert res.get("status") == "network_checks_disabled"
        assert "Người dùng chưa bật Kiểm tra trực tuyến" in res.get("note", "")

    # ThreatIntelAgent spy must NEVER be called
    assert threat_spy.scan_url.call_count == 0
    assert threat_spy.lookup_domain.call_count == 0
    assert threat_spy.check_phishing_db.call_count == 0
    assert len(recorder.actions) == 0


def test_gemini_runner_allow_net_true_passes_recorder_and_deadline():
    threat_spy = MagicMock()
    threat_spy.scan_url.return_value = {"is_malicious": False, "score": 0}
    threat_spy.lookup_domain.return_value = {"status": "ok"}
    threat_spy.check_phishing_db.return_value = {"in_database": False}

    runner = GeminiAgentRunner(agents={"threat_intel": threat_spy})
    recorder = NetworkRecorder()
    deadline = time.time() + 4.0

    runner.set_request_context(allow_net=True, recorder=recorder, deadline=deadline)

    res1 = runner._execute_tool("scan_url_threat_intel", {"url": "https://example.com"})
    assert res1.get("is_malicious") is False
    assert threat_spy.scan_url.call_count == 1
    _, kwargs1 = threat_spy.scan_url.call_args
    assert kwargs1.get("recorder") is recorder
    assert kwargs1.get("deadline_s") is not None
    assert kwargs1.get("deadline_s") > 0

    res2 = runner._execute_tool("lookup_domain_info", {"domain": "example.com"})
    assert res2.get("status") == "ok"
    assert threat_spy.lookup_domain.call_count == 1
    _, kwargs2 = threat_spy.lookup_domain.call_args
    assert kwargs2.get("recorder") is recorder
    assert kwargs2.get("deadline_s") is not None


def test_gemini_runner_tool_declarations_omit_network_tools_when_disabled():
    runner = GeminiAgentRunner(agents={})

    # When allow_net=False
    tools_disabled = runner._build_gemini_tools(allow_net=False)
    # Check that none of NETWORK_TOOL_NAMES are present
    declared_names_disabled = set()
    for decl in tools_disabled:
        if isinstance(decl, dict) and "function_declarations" in decl:
            for f in decl["function_declarations"]:
                declared_names_disabled.add(f.get("name") if isinstance(f, dict) else getattr(f, "name", ""))
        elif isinstance(decl, dict) and "name" in decl:
            declared_names_disabled.add(decl["name"])

    assert not (declared_names_disabled & NETWORK_TOOL_NAMES)

    # When allow_net=True
    tools_enabled = runner._build_gemini_tools(allow_net=True)
    declared_names_enabled = set()
    for decl in tools_enabled:
        if isinstance(decl, dict) and "function_declarations" in decl:
            for f in decl["function_declarations"]:
                declared_names_enabled.add(f.get("name") if isinstance(f, dict) else getattr(f, "name", ""))
        elif isinstance(decl, dict) and "name" in decl:
            declared_names_enabled.add(decl["name"])

    assert NETWORK_TOOL_NAMES.issubset(declared_names_enabled)


def test_gemini_runner_system_prompt_omits_network_mandate_when_disabled():
    runner = GeminiAgentRunner(agents={})

    prompt_disabled = runner._build_system_prompt(allow_net=False)
    assert "scan_url_threat_intel" not in prompt_disabled
    assert "lookup_domain_info" not in prompt_disabled

    prompt_enabled = runner._build_system_prompt(allow_net=True)
    assert "scan_url_threat_intel" in prompt_enabled


def test_gemini_runner_exception_handling_masks_secret_and_url():
    threat_spy = MagicMock()
    # Simulate an exception containing an internal URL and API secret key
    threat_spy.scan_url.side_effect = RuntimeError("Failed connecting to https://internal.secret.com with GSBKEYSECRET-12345")

    runner = GeminiAgentRunner(agents={"threat_intel": threat_spy})
    runner.set_request_context(allow_net=True, recorder=NetworkRecorder(), deadline=time.time() + 5.0)

    res = runner._execute_tool("scan_url_threat_intel", {"url": "https://target.com"})
    assert res.get("status") == "error"
    # Error field must only contain the exception type name, not the secret or url
    assert res.get("error") == "RuntimeError"
    assert "GSBKEYSECRET" not in str(res)
    assert "https://internal.secret.com" not in str(res)


def test_gemini_runner_thread_safety_8_threads():
    runner = GeminiAgentRunner(agents={})
    results = [None] * 8
    errors = []

    def worker(idx: int, allow_net: bool):
        try:
            rec = NetworkRecorder()
            runner.set_request_context(allow_net=allow_net, recorder=rec, deadline=time.time() + 5.0)
            # Sleep slightly to provoke potential race conditions across threads
            time.sleep(0.01 * (idx % 3))
            ctx = runner.get_request_context()
            results[idx] = (ctx["allow_net"], ctx["recorder"])
        except Exception as e:
            errors.append(e)

    threads = []
    for i in range(8):
        # Alternate allow_net True and False
        t = threading.Thread(target=worker, args=(i, i % 2 == 0))
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=5.0)

    assert not errors
    for i in range(8):
        expected_allow = (i % 2 == 0)
        actual_allow, actual_rec = results[i]
        assert actual_allow == expected_allow
        assert isinstance(actual_rec, NetworkRecorder)
