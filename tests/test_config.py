import os
import pytest
from codebase.config import get_api_key, get_settings, Settings


def test_get_api_key(monkeypatch):
    # Empty string or missing
    monkeypatch.delenv("TEST_KEY", raising=False)
    assert get_api_key("TEST_KEY") == ""

    monkeypatch.setenv("TEST_KEY", "")
    assert get_api_key("TEST_KEY") == ""

    # Whitespace only
    monkeypatch.setenv("TEST_KEY", "    ")
    assert get_api_key("TEST_KEY") == ""

    # YOUR_* placeholders
    monkeypatch.setenv("TEST_KEY", "YOUR_GEMINI_KEY")
    assert get_api_key("TEST_KEY") == ""

    monkeypatch.setenv("TEST_KEY", "YOUR_API_KEY_123")
    assert get_api_key("TEST_KEY") == ""

    monkeypatch.setenv("TEST_KEY", "  YOUR_KEY  ")
    assert get_api_key("TEST_KEY") == ""

    # *_HERE placeholders
    monkeypatch.setenv("TEST_KEY", "API_KEY_HERE")
    assert get_api_key("TEST_KEY") == ""

    monkeypatch.setenv("TEST_KEY", "SECRET_TOKEN_HERE")
    assert get_api_key("TEST_KEY") == ""

    monkeypatch.setenv("TEST_KEY", "  TOKEN_HERE  ")
    assert get_api_key("TEST_KEY") == ""

    # Valid real key
    monkeypatch.setenv("TEST_KEY", "AIzaSyD-RealGeminiApiKey_98765")
    assert get_api_key("TEST_KEY") == "AIzaSyD-RealGeminiApiKey_98765"


def test_get_settings_defaults(monkeypatch):
    # Clear all SAFEGUARD_* env vars
    env_keys = [k for k in os.environ if k.startswith("SAFEGUARD_")]
    for k in env_keys:
        monkeypatch.delenv(k, raising=False)

    s = get_settings(refresh=True)
    assert s.offline is False
    assert s.llm_mode == "agentic"
    assert s.network_enabled is True
    assert s.db_enabled is True
    assert s.host == "127.0.0.1"
    assert s.port == 8000
    assert s.max_body_bytes == 8_000_000
    assert s.max_text_chars == 20000
    assert s.rate_limit_per_min == 20
    assert s.url_module_enabled is True


def test_get_settings_offline_enforcement(monkeypatch):
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "1")
    monkeypatch.setenv("SAFEGUARD_LLM_MODE", "agentic")
    monkeypatch.setenv("SAFEGUARD_NETWORK", "on")
    monkeypatch.setenv("SAFEGUARD_DB", "on")

    s = get_settings(refresh=True)
    assert s.offline is True
    assert s.llm_mode == "off"
    assert s.network_enabled is False
    assert s.db_enabled is False


def test_get_settings_invalid_fallbacks(monkeypatch):
    # Invalid port falls back to 8000
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "0")
    monkeypatch.setenv("SAFEGUARD_PORT", "invalid_port")
    s = get_settings(refresh=True)
    assert s.port == 8000

    # Invalid llm_mode falls back to "agentic"
    monkeypatch.setenv("SAFEGUARD_LLM_MODE", "unsupported_mode")
    s = get_settings(refresh=True)
    assert s.llm_mode == "agentic"

    # Invalid max_body_bytes falls back to default
    monkeypatch.setenv("SAFEGUARD_MAX_BODY_BYTES", "not_an_int")
    s = get_settings(refresh=True)
    assert s.max_body_bytes == 8_000_000

    # Invalid max_text_chars falls back to default
    monkeypatch.setenv("SAFEGUARD_MAX_TEXT_CHARS", "bad")
    s = get_settings(refresh=True)
    assert s.max_text_chars == 20000

    # Invalid rate_limit falls back to default
    monkeypatch.setenv("SAFEGUARD_RATE_LIMIT", "nan")
    s = get_settings(refresh=True)
    assert s.rate_limit_per_min == 20
