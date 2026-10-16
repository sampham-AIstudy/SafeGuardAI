from __future__ import annotations

from typing import Any

from codebase.config import get_settings
from codebase.url_analysis.analyzer import UrlAnalyzer


class URLAnalysisAgent:
    """
    Agent facade for URL Deobfuscation and Impersonation Analysis.
    Follows the standard agent pattern across SafeGuard AI.
    """

    def __init__(self, analyzer: UrlAnalyzer | None = None):
        self.analyzer = analyzer or UrlAnalyzer()

    def analyze(
        self,
        text: str,
        extra_urls: list[tuple[str, str]] | None = None,
        allow_network: bool | None = None,
    ) -> dict[str, Any]:
        """
        Analyze text containing potential URLs and return a serialized dictionary report.
        """
        settings = get_settings()
        if allow_network is None:
            allow_net = bool(settings.network_enabled and not settings.offline)
        else:
            allow_net = bool(allow_network)

        report = self.analyzer.analyze_text(
            text=text,
            extra_urls=extra_urls,
            allow_network=allow_net,
        )
        return report.to_dict()
