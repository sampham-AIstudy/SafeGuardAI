import os
from dataclasses import dataclass


@dataclass
class Settings:
    offline: bool = False
    llm_mode: str = "single"  # single | agentic | off
    network_enabled: bool = True
    db_enabled: bool = True
    redirect_mode: str = "shorteners"  # off | shorteners | all
    store_images: bool = False
    host: str = "127.0.0.1"
    port: int = 8000
    max_body_bytes: int = 8_000_000
    max_text_chars: int = 20000
    rate_limit_per_min: int = 20
    url_module_enabled: bool = True
    passive_tls: bool = False
    phishtank_enabled: bool = False
    request_budget_s: float = 6.0
    max_concurrency: int = 4
    cors_origins: tuple[str, ...] = ()
    trust_proxy: bool = False
    llm_timeout_s: float = 15.0
    runner_deadline_s: float = 20.0


_SETTINGS_INSTANCE: Settings | None = None


def _parse_bool(val: str | None, default: bool) -> bool:
    if val is None:
        return default
    v = str(val).strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return default


_API_KEY_PLACEHOLDERS = {
    "your_api_key_here",
    "<your-key>",
    "changeme",
    "xxx",
    "placeholder",
    "none",
    "null",
    "test",
}


def get_api_key(name: str) -> str:
    """
    Get API key from environment variables.
    Returns empty string if empty, matches known placeholders, contains 'YOUR_', or ends with '_HERE'.
    """
    val = os.environ.get(name, "").strip()
    if not val:
        return ""
    val_lower = val.lower()
    if val_lower in _API_KEY_PLACEHOLDERS:
        return ""
    if "your_" in val_lower or val_lower.endswith("_here"):
        return ""
    return val


def get_settings(refresh: bool = False) -> Settings:
    """
    Get application settings, reading SAFEGUARD_* environment variables on call.
    Caches settings until refresh=True.
    """
    global _SETTINGS_INSTANCE
    if _SETTINGS_INSTANCE is not None and not refresh:
        return _SETTINGS_INSTANCE

    offline = _parse_bool(os.environ.get("SAFEGUARD_OFFLINE"), False)

    if offline:
        llm_mode = "off"
        network_enabled = False
        db_enabled = False
    else:
        llm_mode = os.environ.get("SAFEGUARD_LLM_MODE", "single").strip().lower()
        if llm_mode not in ("agentic", "single", "off"):
            llm_mode = "single"
        network_enabled = _parse_bool(os.environ.get("SAFEGUARD_NETWORK"), True)
        db_enabled = _parse_bool(os.environ.get("SAFEGUARD_DB"), True)

    redirect_mode = os.environ.get("SAFEGUARD_REDIRECT_MODE", "shorteners").strip().lower()
    store_images = _parse_bool(os.environ.get("SAFEGUARD_STORE_IMAGES"), False)
    host = os.environ.get("SAFEGUARD_HOST", "127.0.0.1").strip()

    try:
        port = int(os.environ.get("SAFEGUARD_PORT", "8000").strip())
    except ValueError:
        port = 8000

    try:
        max_body_bytes = int(os.environ.get("SAFEGUARD_MAX_BODY_BYTES", "8000000").strip())
    except ValueError:
        max_body_bytes = 8_000_000

    try:
        max_text_chars = int(os.environ.get("SAFEGUARD_MAX_TEXT_CHARS", "20000").strip())
    except ValueError:
        max_text_chars = 20000

    try:
        rate_limit_per_min = int(os.environ.get("SAFEGUARD_RATE_LIMIT", "20").strip())
    except ValueError:
        rate_limit_per_min = 20

    url_module_enabled = _parse_bool(os.environ.get("SAFEGUARD_URL_MODULE"), True)
    passive_tls = _parse_bool(os.environ.get("SAFEGUARD_PASSIVE_TLS"), False)
    phishtank_enabled = _parse_bool(os.environ.get("SAFEGUARD_PHISHTANK"), False)

    try:
        request_budget_s = float(os.environ.get("SAFEGUARD_NET_BUDGET", "6.0").strip())
        request_budget_s = max(1.0, min(15.0, request_budget_s))
    except (ValueError, TypeError):
        request_budget_s = 6.0

    try:
        raw_mc = int(os.environ.get("SAFEGUARD_MAX_CONCURRENCY", "4").strip())
        max_concurrency = max(1, min(16, raw_mc))
    except (ValueError, TypeError):
        max_concurrency = 4

    raw_cors = os.environ.get("SAFEGUARD_CORS_ORIGINS", "").strip()
    if raw_cors:
        cors_origins = tuple(o.strip() for o in raw_cors.split(",") if o.strip())
    else:
        cors_origins = ()

    trust_proxy = _parse_bool(os.environ.get("SAFEGUARD_TRUST_PROXY"), False)

    try:
        raw_llm_timeout = float(os.environ.get("SAFEGUARD_LLM_TIMEOUT", "15.0").strip())
        llm_timeout_s = max(3.0, min(60.0, raw_llm_timeout))
    except (ValueError, TypeError):
        llm_timeout_s = 15.0

    try:
        raw_runner_deadline = float(os.environ.get("SAFEGUARD_RUNNER_DEADLINE", "20.0").strip())
        runner_deadline_s = max(5.0, min(60.0, raw_runner_deadline))
    except (ValueError, TypeError):
        runner_deadline_s = 20.0

    _SETTINGS_INSTANCE = Settings(
        offline=offline,
        llm_mode=llm_mode,
        network_enabled=network_enabled,
        db_enabled=db_enabled,
        redirect_mode=redirect_mode,
        store_images=store_images,
        host=host,
        port=port,
        max_body_bytes=max_body_bytes,
        max_text_chars=max_text_chars,
        rate_limit_per_min=rate_limit_per_min,
        url_module_enabled=url_module_enabled,
        passive_tls=passive_tls,
        phishtank_enabled=phishtank_enabled,
        request_budget_s=request_budget_s,
        max_concurrency=max_concurrency,
        cors_origins=cors_origins,
        trust_proxy=trust_proxy,
        llm_timeout_s=llm_timeout_s,
        runner_deadline_s=runner_deadline_s,
    )
    return _SETTINGS_INSTANCE
