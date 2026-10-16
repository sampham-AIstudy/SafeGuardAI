from __future__ import annotations

from dataclasses import dataclass, field, is_dataclass, asdict
from typing import Any


def _serialize_value(val: Any) -> Any:
    """Recursively serialize dataclasses, dicts, lists, and primitives into JSON-safe objects."""
    if hasattr(val, "to_dict") and callable(val.to_dict):
        return val.to_dict()
    elif is_dataclass(val) and not isinstance(val, type):
        return {k: _serialize_value(v) for k, v in asdict(val).items()}
    elif isinstance(val, dict):
        return {k: _serialize_value(v) for k, v in val.items()}
    elif isinstance(val, (list, tuple, set)):
        return [_serialize_value(item) for item in val]
    return val


@dataclass
class ObfuscationStep:
    technique: str      # zero_width | defanged | fullwidth | percent_host | double_encoding | base64_param |
                        # hex_param | html_entity | backslash | userinfo | ip_obfuscated | punycode |
                        # homoglyph | shortener | redirect_param | anchor_mismatch
    detail_vi: str
    before: str         # cắt <= 200 ký tự
    after: str

    def __post_init__(self):
        if len(self.before) > 200:
            self.before = self.before[:200]
        if len(self.after) > 200:
            self.after = self.after[:200]

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique": self.technique,
            "detail_vi": self.detail_vi,
            "before": self.before,
            "after": self.after,
        }


@dataclass
class UrlSignal:
    code: str
    severity: str       # info | low | medium | high | critical
    weight: int
    message_vi: str
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "weight": self.weight,
            "message_vi": self.message_vi,
            "evidence": self.evidence,
        }


@dataclass
class UrlFinding:
    raw: str
    normalized: str
    final_url: str
    display_host: str          # host người dùng "nhìn thấy"
    effective_host: str        # host trình duyệt thực sự kết nối (ASCII/punycode)
    effective_host_unicode: str
    registrable_domain: str
    is_official: bool
    brand_match: dict[str, Any] | None   # {brand_id, display_name, technique, distance, official_domain}
    source: str                          # text | anchor | markdown | qr | ocr | embedded | redirect
    obfuscation_chain: list[ObfuscationStep] = field(default_factory=list)
    redirect_chain: list[dict[str, Any]] = field(default_factory=list)   # [{url, status}]
    signals: list[UrlSignal] = field(default_factory=list)
    children: list[UrlFinding] = field(default_factory=list)
    url_risk_score: int = 0
    verdict: str = "unknown"             # official | benign | low | suspicious | dangerous | unknown
    network_used: bool = False
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "normalized": self.normalized,
            "final_url": self.final_url,
            "display_host": self.display_host,
            "effective_host": self.effective_host,
            "effective_host_unicode": self.effective_host_unicode,
            "registrable_domain": self.registrable_domain,
            "is_official": self.is_official,
            "brand_match": _serialize_value(self.brand_match),
            "source": self.source,
            "obfuscation_chain": [step.to_dict() for step in self.obfuscation_chain],
            "redirect_chain": _serialize_value(self.redirect_chain),
            "signals": [sig.to_dict() for sig in self.signals],
            "children": [child.to_dict() for child in self.children],
            "url_risk_score": self.url_risk_score,
            "verdict": self.verdict,
            "network_used": self.network_used,
            "errors": list(self.errors),
        }


@dataclass
class UrlAnalysisReport:
    findings: list[UrlFinding] = field(default_factory=list)
    max_url_risk: int = 0
    has_obfuscation: bool = False
    has_only_official_urls: bool = False   # tính trên effective_host SAU khi bóc lớp
    critical_codes: list[str] = field(default_factory=list)
    summary_vi: list[str] = field(default_factory=list)
    truncated: bool = False
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "max_url_risk": self.max_url_risk,
            "has_obfuscation": self.has_obfuscation,
            "has_only_official_urls": self.has_only_official_urls,
            "critical_codes": list(self.critical_codes),
            "summary_vi": list(self.summary_vi),
            "truncated": self.truncated,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass
class Candidate:
    raw: str
    start: int
    end: int
    source: str = "text"                 # text | anchor | markdown | qr | ocr | embedded | redirect
    display_text: str | None = None
    is_long: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "start": self.start,
            "end": self.end,
            "source": self.source,
            "display_text": self.display_text,
            "is_long": self.is_long,
        }
