"""Regression: _wrap_report_dict must stay bounded for self-similar to_dict() objects
(a MagicMock url_report once made a test grow past 3 GB of RAM)."""
from codebase.url_analysis.analyzer import AnalysisDict, _wrap_report_dict


class _SelfSimilar:
    """to_dict() returns another object that also has to_dict() - used to recurse without end."""
    calls = 0

    def to_dict(self):
        _SelfSimilar.calls += 1
        return _SelfSimilar()


class _Report:
    def __init__(self, findings):
        self._f = findings

    def to_dict(self):
        return {"findings": self._f, "max_url_risk": 55}


def test_self_similar_to_dict_is_not_followed_forever():
    _SelfSimilar.calls = 0
    obj = _SelfSimilar()
    assert _wrap_report_dict(obj) is obj
    assert _SelfSimilar.calls == 1


def test_deeply_nested_dict_is_depth_limited():
    d = cur = {}
    for _ in range(500):
        cur["x"] = {}
        cur = cur["x"]
    out = _wrap_report_dict(d)  # must return, not raise RecursionError
    assert isinstance(out, AnalysisDict)


def test_normal_report_still_wrapped_with_attribute_access():
    rep = _wrap_report_dict(_Report([{"verdict": "dangerous", "children": []}]))
    assert rep.max_url_risk == 55
    assert rep.findings[0].verdict == "dangerous"
