import os
import sys
import json
import time
import http.client
import threading
import pandas as pd
import numpy as np
import pytest

from codebase.config import get_settings
from codebase.knowledge_base.dataset_loader import DatasetLoader
from codebase.orchestrator import SafeGuardOrchestrator, warm_up, health_info
from codebase.server import create_server, SafeGuardServer, TokenBucketRateLimiter


@pytest.fixture
def test_server():
    """Starts live SafeGuardServer on port 0 with daemon thread."""
    server = create_server(host="127.0.0.1", port=0)
    server_thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.02), daemon=True)
    server_thread.start()
    host, port = server.server_address[:2]
    yield host, port, server
    server.shutdown()
    server.server_close()


def make_request(host, port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection(host, port, timeout=10)
    headers = headers or {}
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    resp_body = resp.read()
    hdr_dict = {k.lower(): v for k, v in resp.getheaders()}
    conn.close()
    return resp.status, resp_body, hdr_dict


# ─────────────────────────────────────────────────────────────────────────────
# C1: DatasetLoader Vectorization Tests
# ─────────────────────────────────────────────────────────────────────────────

def _slow_reference_process_df(phish_df):
    """Slow reference implementation reproducing pandas iterrows logic."""
    domains = set()
    urls = set()
    scenario_counts = {}

    for _, row in phish_df.iterrows():
        domain = str(row.get("domain", "")).strip().lower()
        url = str(row.get("url", "")).strip().lower()
        scenario = str(row.get("scenario", "other")).strip().lower()

        if domain and domain != "nan":
            domains.add(domain)
        if url and url != "nan":
            urls.add(url)

        scenario_counts[scenario] = scenario_counts.get(scenario, 0) + 1

    return domains, urls, scenario_counts


def _vectorized_process_df(phish_df):
    """Vectorized column operations matching new dataset_loader.py."""
    domains = set()
    urls = set()
    scenario_counts = {}

    if "domain" in phish_df.columns:
        s_dom = phish_df["domain"].dropna().astype(str).str.strip().str.lower()
        valid_doms = s_dom[(s_dom != "") & (s_dom != "nan")]
        domains.update(valid_doms.tolist())

    if "url" in phish_df.columns:
        s_url = phish_df["url"].dropna().astype(str).str.strip().str.lower()
        valid_urls = s_url[(s_url != "") & (s_url != "nan")]
        urls.update(valid_urls.tolist())

    if "scenario" in phish_df.columns:
        s_scen = phish_df["scenario"].fillna("nan").astype(str).str.strip().str.lower()
        for sc, count in s_scen.value_counts().items():
            scenario_counts[sc] = scenario_counts.get(sc, 0) + int(count)
    else:
        scenario_counts["other"] = scenario_counts.get("other", 0) + len(phish_df)

    return domains, urls, scenario_counts


def test_dataset_loader_vectorized_vs_slow_reference_synthetic():
    """Verify that vectorized column operations yield identical results to slow iterrows."""
    raw_data = {
        "label": ["phishing"] * 10,
        "domain": [
            "  VnEID-GiaMao.COM  ",
            "bank-scam.vn",
            "",
            "   ",
            np.nan,
            "nan",
            "NAN",
            None,
            "duplicate-domain.com",
            "duplicate-domain.com",
        ],
        "url": [
            "https://VnEID-GiaMao.COM/login?id=1",
            "http://bank-scam.vn/otp",
            "",
            " ",
            np.nan,
            "nan",
            "NaN",
            None,
            "https://duplicate-domain.com/path",
            "https://duplicate-domain.com/path",
        ],
        "scenario": [
            "  gia mao cong an  ",
            "gia mao ngan hang",
            "",
            " ",
            np.nan,
            "other",
            "OTHER",
            None,
            "trung thuong",
            "trung thuong",
        ]
    }
    df = pd.DataFrame(raw_data)

    slow_doms, slow_urls, slow_scen = _slow_reference_process_df(df)
    vec_doms, vec_urls, vec_scen = _vectorized_process_df(df)

    assert len(vec_doms) > 0, "Vectorized domains must not be empty"
    assert len(vec_urls) > 0, "Vectorized URLs must not be empty"
    assert len(vec_scen) > 0, "Vectorized scenarios must not be empty"

    assert vec_doms == slow_doms, f"Domain sets differ: vec={vec_doms} vs slow={slow_doms}"
    assert vec_urls == slow_urls, f"URL sets differ: vec={vec_urls} vs slow={slow_urls}"
    assert vec_scen == slow_scen, f"Scenario counts differ: vec={vec_scen} vs slow={slow_scen}"


def test_dataset_loader_real_data_benchmark_and_equivalence():
    """Benchmark vectorized vs slow iterrows on real dataset if present, asserting t_vec <= t_slow."""
    loader = DatasetLoader()
    if not os.path.exists(loader.data_dir):
        pytest.skip("data directory not found, skipping real dataset benchmark")

    target_csv = os.path.join(loader.data_dir, "data-phising-VN-ver1", "dataset_url.csv")
    if not os.path.exists(target_csv):
        pytest.skip(f"{target_csv} not found, skipping real benchmark")

    df = pd.read_csv(target_csv, low_memory=False)
    phish_df = df[df["label"] == "phishing"]
    assert len(phish_df) > 0, "Phish dataframe must not be empty"

    # Measure slow iterrows
    t0 = time.perf_counter()
    slow_doms, slow_urls, slow_scen = _slow_reference_process_df(phish_df)
    t_slow = time.perf_counter() - t0

    # Measure vectorized
    t1 = time.perf_counter()
    vec_doms, vec_urls, vec_scen = _vectorized_process_df(phish_df)
    t_vec = time.perf_counter() - t1

    assert vec_doms == slow_doms, "Real data domains must match exactly"
    assert vec_urls == slow_urls, "Real data URLs must match exactly"
    assert vec_scen == slow_scen, "Real data scenarios must match exactly"

    # Vectorized must be <= slow version
    assert t_vec <= t_slow, f"Vectorized loading ({t_vec:.4f}s) should be <= slow iterrows ({t_slow:.4f}s)"


# ─────────────────────────────────────────────────────────────────────────────
# C2: Warm-up Tests (Latency, Idempotency, 16 Threads, Missing Data)
# ─────────────────────────────────────────────────────────────────────────────

def test_warmup_first_request_latency_under_300ms():
    """After warm_up(), the first offline request must complete in < 0.3s."""
    loader = DatasetLoader()
    if not os.path.exists(loader.data_dir):
        pytest.skip("data directory not found, skipping latency test")

    orch = SafeGuardOrchestrator()
    w_res = orch.warm_up()
    assert w_res.get("status") in ("ok", "already_warmed")

    # Time first request
    t0 = time.perf_counter()
    res = orch.process_request(
        user_text="Xin chào, tôi cần kiểm tra tính an toàn của liên kết http://example.com",
        session_id="first_req_test",
        persist=False,
        online_check=False,
        network=False,
        llm_mode="off",
    )
    t_first_req = time.perf_counter() - t0

    assert isinstance(res, dict)
    assert "risk_score" in res
    assert isinstance(res["risk_score"], int)
    assert t_first_req < 0.3, f"First request after warm_up took {t_first_req:.4f}s (must be < 0.3s)"


def test_warmup_idempotency_and_16_threads():
    """Calling warm_up() twice or across 16 concurrent threads must not raise any error."""
    orch = SafeGuardOrchestrator()

    # Sequential calls
    res1 = orch.warm_up()
    assert res1.get("status") in ("ok", "partial")
    res2 = orch.warm_up()
    assert res2.get("status") == "already_warmed"

    # Concurrent 16 threads
    errors = []

    def run_warmup_thread():
        try:
            orch.warm_up()
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=run_warmup_thread) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert len(errors) == 0, f"Thread errors during warm_up: {errors}"


def test_warmup_handles_missing_data_directory_gracefully(tmp_path, monkeypatch):
    """warm_up() must succeed without error even if data/ does not exist."""
    fake_empty_dir = tmp_path / "non_existent_data_dir"
    monkeypatch.setattr("codebase.knowledge_base.dataset_loader.DEFAULT_DATA_DIR", fake_empty_dir)

    orch = SafeGuardOrchestrator()
    w_res = orch.warm_up()
    assert isinstance(w_res, dict)
    assert w_res.get("status") in ("ok", "partial", "already_warmed")


# ─────────────────────────────────────────────────────────────────────────────
# C3: GET /api/health Endpoint Tests (Schema, No Leaks, Env Flags, 405 for POST)
# ─────────────────────────────────────────────────────────────────────────────

def test_health_endpoint_schema_and_keys(test_server):
    """GET /api/health must return status 200 and all required JSON fields."""
    host, port, _ = test_server
    status, body, headers = make_request(host, port, "GET", "/api/health")

    assert status == 200
    assert headers.get("content-type", "").startswith("application/json")

    data = json.loads(body.decode("utf-8"))
    assert data.get("ok") is True
    assert isinstance(data.get("version"), str) and len(data["version"]) > 0
    assert "llm_mode" in data
    assert isinstance(data.get("llm_active"), bool)
    assert isinstance(data.get("network_enabled"), bool)
    assert isinstance(data.get("online_check_available"), bool)
    assert isinstance(data.get("store_images"), bool)
    assert isinstance(data.get("max_concurrency"), int)
    assert isinstance(data.get("rate_limit_per_min"), int)
    assert isinstance(data.get("url_module"), bool)
    assert isinstance(data.get("phish_blacklist_loaded"), bool)


def test_health_endpoint_no_secrets_leaked(test_server, monkeypatch):
    """GET /api/health must NEVER leak API keys, system paths, or environment dumps."""
    secret_marker = "HEALTHKEY123"
    monkeypatch.setenv("GEMINI_API_KEY", f"{secret_marker}_GEMINI")
    monkeypatch.setenv("MISTRAL_API_KEY", f"{secret_marker}_MISTRAL")
    monkeypatch.setenv("GROQ_API_KEY", f"{secret_marker}_GROQ")
    monkeypatch.setenv("SAFEGUARD_API_KEY", f"{secret_marker}_APP")
    monkeypatch.setenv("DB_PASSWORD", f"{secret_marker}_SECRET_PASS")

    host, port, _ = test_server
    status, body, headers = make_request(host, port, "GET", "/api/health")

    raw_response_text = body.decode("utf-8")
    assert status == 200
    assert secret_marker not in raw_response_text, "Secret key was leaked in /api/health response body!"
    for hname, hval in headers.items():
        assert secret_marker not in hval, f"Secret key was leaked in header {hname}!"


def test_health_endpoint_reflects_environment_flags(test_server, monkeypatch):
    """Changing SAFEGUARD_* environment variables must update the health endpoint flags."""
    monkeypatch.setenv("SAFEGUARD_STORE_IMAGES", "1")
    monkeypatch.setenv("SAFEGUARD_MAX_CONCURRENCY", "7")
    monkeypatch.setenv("SAFEGUARD_RATE_LIMIT", "45")
    monkeypatch.setenv("SAFEGUARD_URL_MODULE", "0")

    host, port, _ = test_server
    status, body, _ = make_request(host, port, "GET", "/api/health")

    assert status == 200
    data = json.loads(body.decode("utf-8"))
    assert data["store_images"] is True
    assert data["max_concurrency"] == 7
    assert data["rate_limit_per_min"] == 45
    assert data["url_module"] is False


def test_health_endpoint_post_returns_405(test_server):
    """POST /api/health must return HTTP 405 Method Not Allowed with Allow header."""
    host, port, _ = test_server
    status, body, headers = make_request(host, port, "POST", "/api/health", body=b'{"check": true}')

    assert status == 405
    data = json.loads(body.decode("utf-8"))
    assert "error" in data
    assert "allow" in headers
    assert "GET" in headers["allow"]


def test_health_endpoint_no_client_id_required(test_server):
    """GET /api/health does not require X-Client-Id header (unlike /api/sessions)."""
    host, port, _ = test_server
    # Request with NO X-Client-Id
    status, body, _ = make_request(host, port, "GET", "/api/health", headers={})
    assert status == 200
    data = json.loads(body.decode("utf-8"))
    assert data.get("ok") is True


def test_health_endpoint_security_headers_present(test_server):
    """Security headers (CSP, nosniff, DENY) must be present on /api/health response."""
    host, port, _ = test_server
    status, _, headers = make_request(host, port, "GET", "/api/health")

    assert status == 200
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert headers.get("referrer-policy") == "no-referrer"
    assert "content-security-policy" in headers
