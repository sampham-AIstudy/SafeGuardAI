"""
tests/test_decision.py
Unit tests for DecisionAgent regarding general_chat vs need_more_info,
action/money keywords, and image handling.
"""

import pytest
from codebase.agents.decision_agent import DecisionAgent


@pytest.fixture(scope="module")
def decision_agent():
    return DecisionAgent()


def test_decision_agent_scammed_greeting_need_more_info(decision_agent):
    """
    (E2-a) 'hi, tôi bị lừa' with risk 0 must NOT return general_chat.
    It must return need_more_info because it contains action/scam terms 'bị', 'lừa'.
    """
    res = decision_agent.evaluate_decision(
        risk_score=0,
        confidence_info={"confidence_score": 90, "confidence_level": "HIGH"},
        explainable_info={"risk_breakdown": []},
        emergency_info={"is_emergency": False},
        user_text="hi, tôi bị lừa",
    )
    assert res["intent_type"] != "general_chat", f"Should not be general_chat: {res}"
    assert res["intent_type"] == "need_more_info", f"Expected need_more_info, got: {res}"
    assert res["risk_level"] == "LOW"


@pytest.mark.parametrize("scam_phrase", [
    "tôi bị lừa",
    "em bị lừa đảo",
    "bị hack tài khoản",
    "tôi bị mất tiền",
    "bị lộ mật khẩu",
    "bị chiếm tài khoản",
    "alo, tôi bị lừa",
])
def test_decision_agent_action_keywords_prevent_general_chat(decision_agent, scam_phrase):
    res = decision_agent.evaluate_decision(
        risk_score=0,
        confidence_info={"confidence_score": 90, "confidence_level": "HIGH"},
        explainable_info={"risk_breakdown": []},
        emergency_info={"is_emergency": False},
        user_text=scam_phrase,
    )
    assert res["intent_type"] != "general_chat"
    assert res["intent_type"] == "need_more_info"


def test_decision_agent_empty_user_text_with_image(decision_agent):
    """
    (E2-b) Empty user_text with has_image=True must NOT return general_chat greeting.
    """
    res = decision_agent.evaluate_decision(
        risk_score=0,
        confidence_info={"confidence_score": 90, "confidence_level": "HIGH"},
        explainable_info={"risk_breakdown": []},
        emergency_info={"is_emergency": False},
        user_text="",
        has_image=True,
    )
    assert res["intent_type"] != "general_chat", f"Empty text with image should not be greeting: {res}"


def test_decision_agent_empty_user_text_without_image(decision_agent):
    """Empty user_text without image must not return general_chat greeting."""
    res = decision_agent.evaluate_decision(
        risk_score=0,
        confidence_info={"confidence_score": 90, "confidence_level": "HIGH"},
        explainable_info={"risk_breakdown": []},
        emergency_info={"is_emergency": False},
        user_text="",
        has_image=False,
    )
    assert res["intent_type"] == "need_more_info"
    assert res["intent_type"] != "general_chat"


@pytest.mark.parametrize("greeting", [
    "chào bạn",
    "xin chào",
    "hello",
    "hi",
    "chào",
    "chào bạn nhé",
    "alo bạn ơi",
])
def test_decision_agent_pure_greetings(decision_agent, greeting):
    """Pure greetings with risk 0 must return general_chat."""
    res = decision_agent.evaluate_decision(
        risk_score=0,
        confidence_info={"confidence_score": 90, "confidence_level": "HIGH"},
        explainable_info={"risk_breakdown": []},
        emergency_info={"is_emergency": False},
        user_text=greeting,
    )
    assert res["intent_type"] == "general_chat"
    assert res["risk_level"] == "LOW"


@pytest.mark.parametrize("distress_phrase", [
    "cứu tôi với",
    "cứu em",
    "giúp tôi với",
    "toang rồi",
    "em hoảng quá",
])
def test_decision_agent_distress_calls_not_general_chat(decision_agent, distress_phrase):
    """
    (C4) Distress calls ('cứu tôi với', 'cứu em', 'giúp tôi với', 'toang', 'hoảng')
    must NOT return general_chat. They must return need_more_info or scan.
    """
    res = decision_agent.evaluate_decision(
        risk_score=0,
        confidence_info={"confidence_score": 90, "confidence_level": "HIGH"},
        explainable_info={"risk_breakdown": []},
        emergency_info={"is_emergency": False},
        user_text=distress_phrase,
    )
    assert res["intent_type"] != "general_chat", f"Distress call '{distress_phrase}' should not be general_chat"
    assert res["intent_type"] in ("need_more_info", "scam_analysis")


def test_decision_agent_risk_score_prevents_general_chat(decision_agent):
    """
    (C6 Mutation Test) If the condition 'risk_score < 25' is removed from general_chat,
    a message with a greeting but high risk score (>= 25, e.g. 80) would wrongly return general_chat.
    """
    res = decision_agent.evaluate_decision(
        risk_score=80,
        confidence_info={"confidence_score": 85, "confidence_level": "HIGH"},
        explainable_info={"risk_breakdown": []},
        emergency_info={"is_emergency": False},
        user_text="chào bạn",
    )
    assert res["intent_type"] != "general_chat", "High risk greeting must not return general_chat"
    assert res["intent_type"] == "scam_analysis"
    assert res["risk_level"] == "HIGH"


def test_decision_agent_mutation_13_has_image_prevents_general_chat(decision_agent):
    """
    (Mutation 13 Test) Image presence check in DecisionAgent:
    When user input is a pure greeting ('chào') with low risk score (0),
    having an attached image (has_image=True) MUST prevent classification as general_chat.
    Dropping 'not has_image' condition causes this test to fail.
    """
    res = decision_agent.evaluate_decision(
        risk_score=0,
        confidence_info={"confidence_score": 90, "confidence_level": "HIGH"},
        explainable_info={"risk_breakdown": []},
        emergency_info={"is_emergency": False},
        user_text="chào",
        has_image=True,
    )
    assert res["intent_type"] != "general_chat", f"Mutation 13: has_image=True falsely returned general_chat: {res}"



