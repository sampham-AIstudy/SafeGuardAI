import json
import os
from pathlib import Path
import pytest
from codebase.agents.rag_agent import RAGAgent
from codebase.knowledge_base.dataset_loader import DatasetLoader


def test_rag_load_from_different_cwd(tmp_path, monkeypatch):
    """RAGAgent and DatasetLoader must load tactics even when cwd is changed to a temp dir."""
    orig_cwd = os.getcwd()
    monkeypatch.chdir(tmp_path)
    try:
        agent = RAGAgent()
        assert len(agent.tactics) > 0, "RAGAgent must load tactics from arbitrary working directory"

        loader = DatasetLoader()
        kb = loader.load_knowledge_base()
        assert len(kb) > 0, "DatasetLoader must load knowledge base from arbitrary working directory"
    finally:
        os.chdir(orig_cwd)


def test_missing_data_dir_warning(tmp_path, capsys):
    """DatasetLoader warns when data directory is missing and does not crash."""
    non_existent = tmp_path / "no_data_here"
    loader = DatasetLoader(data_dir=str(non_existent))
    captured = capsys.readouterr()
    assert "[WARNING]" in captured.out
    # Loading datasets on missing dir returns empty results gracefully
    phish = loader.load_phish_vn_datasets()
    assert phish["total_phishing_records"] == 0
    glob = loader.load_global_phishing_datasets()
    assert glob["total_global_files"] == 0


def test_trigger_phrases_match_and_benign_no_match():
    """Matching text triggers matched_flags; benign text matches zero flags."""
    agent = RAGAgent()

    # Query with trigger phrase (accented)
    res1 = agent.search("Công ty đang tuyển cộng tác viên chốt đơn Shopee lương cao")
    assert len(res1["matched_flags"]) > 0
    assert any("cộng tác viên" in f.lower() or "shopee" in f.lower() for f in res1["matched_flags"])

    # Query with unaccented trigger phrase
    res2 = agent.search("huong dan cai vneid qua link va cap nhat")
    assert len(res2["matched_flags"]) > 0

    # Benign text must not match
    benign_text = "Hôm nay trời đẹp, chiều đi học nhóm"
    res_benign = agent.search(benign_text)
    assert len(res_benign["matched_flags"]) == 0
    assert len(res_benign["matched_tactics"]) == 0
    assert res_benign["total_patterns_matched"] == 0


def test_blacklist_query_requires_dot():
    """PhishVN blacklist substring matching must only run when query contains '.'"""
    agent = RAGAgent()
    # Mock phish_data with a domain
    test_domain = "fake-bank-test12345.com"
    agent.phish_data = {"phishing_domains": {test_domain}, "total_phishing_records": 1}

    # Query without dot containing the domain string without dot: should not match
    res_no_dot = agent.search("tin nhan khong co dau cham nao ca")
    assert len(res_no_dot["matched_phish_domains"]) == 0

    # Query with dot containing domain: should match
    res_with_dot = agent.search(f"vui long truy cap {test_domain} de cap nhat")
    assert test_domain in res_with_dot["matched_phish_domains"]


def test_custom_phish_data_platform_and_official_not_matched():
    """B2: Platform and official domains inside custom phish_data must NEVER match."""
    agent = RAGAgent()
    fake_domain = "fake-bank-test12345.com"
    platform_domain = "facebook.com"
    official_domain = "vietcombank.com.vn"

    agent.phish_data = {
        "phishing_domains": {fake_domain, platform_domain, official_domain},
        "total_phishing_records": 3,
    }

    res = agent.search(f"Truy cap {fake_domain} hoac {platform_domain} hoac {official_domain}")
    assert fake_domain in res["matched_phish_domains"]
    assert platform_domain not in res["matched_phish_domains"]
    assert official_domain not in res["matched_phish_domains"]


def test_two_rag_agents_with_different_phish_data_isolated():
    """B2: Two RAGAgents with different custom phish_data must not use each other's blacklist."""
    agent1 = RAGAgent()
    dom1 = "custom-scam-agent1.com"
    agent1.phish_data = {"phishing_domains": {dom1}, "total_phishing_records": 1}

    agent2 = RAGAgent()
    dom2 = "custom-scam-agent2.com"
    agent2.phish_data = {"phishing_domains": {dom2}, "total_phishing_records": 1}

    res1 = agent1.search(f"kiem tra {dom1}")
    assert dom1 in res1["matched_phish_domains"]
    assert dom2 not in res1["matched_phish_domains"]

    res2_check_dom1 = agent2.search(f"kiem tra {dom1}")
    assert dom1 not in res2_check_dom1["matched_phish_domains"]

    res2 = agent2.search(f"kiem tra {dom2}")
    assert dom2 in res2["matched_phish_domains"]
    assert dom1 not in res2["matched_phish_domains"]


def test_trigger_phrases_count_and_no_golden_leak():
    """Total trigger phrases must be > 0 and no phrase >= 40 chars."""
    kb_path = Path(__file__).resolve().parent.parent / "codebase" / "knowledge_base" / "vn_scam_tactics.json"
    data = json.loads(kb_path.read_text(encoding="utf-8"))
    tactics = data.get("scam_tactics", [])
    assert len(tactics) >= 5

    total_triggers = 0
    for t in tactics:
        triggers = t.get("trigger_phrases", [])
        assert len(triggers) >= 3, f"Tactic {t['id']} should have >= 3 trigger phrases"
        total_triggers += len(triggers)
        for phrase in triggers:
            assert len(phrase) < 40, f"Trigger phrase '{phrase}' is too long (>= 40 chars)"

    assert total_triggers > 0


def test_rag_result_json_serializable_no_object_leak():
    """RAG result must be purely JSON serializable and must not leak PhraseMatcher objects (Task E3)."""
    agent = RAGAgent()
    res = agent.search("Tuyển cộng tác viên chốt đơn nạp quỹ đảm bảo")
    assert len(res["matched_tactics"]) > 0
    # Standard json.dumps must succeed without custom default serializer
    serialized = json.dumps(res, ensure_ascii=False)
    assert "PhraseMatcher" not in serialized
    assert "object at 0x" not in serialized
    parsed = json.loads(serialized)
    assert isinstance(parsed["matched_tactics"], list)
    for mt in parsed["matched_tactics"]:
        assert "_matcher" not in mt["tactic"]

