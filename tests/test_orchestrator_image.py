import pytest
from PIL import Image
from codebase.orchestrator import SafeGuardOrchestrator


def test_image_without_text_not_general_chat(orchestrator):
    """
    M5: When an image is provided without text (or with empty text),
    has_image=True must be passed to DecisionAgent, preventing intent_type='general_chat'.
    """
    img = Image.new("RGB", (100, 100), color="white")
    res = orchestrator.process_request(
        user_text="",
        pil_image=img,
        session_id="session_test_img_no_text",
        persist=False
    )
    assert res is not None
    assert "decision" in res
    assert res["decision"]["intent_type"] != "general_chat"
    assert res["decision"]["intent_type"] == "scam_analysis"


def test_greeting_with_image_not_general_chat(orchestrator):
    """
    Even if user_text is a greeting like 'chào bạn' (which normally triggers general_chat),
    having an attached image indicates an analysis request, so it must not be general_chat.
    """
    # Baseline without image -> general_chat
    res_no_img = orchestrator.process_request(
        user_text="chào bạn",
        session_id="session_test_greeting_no_img",
        persist=False
    )
    assert res_no_img["decision"]["intent_type"] == "general_chat"

    # With image -> not general_chat
    img = Image.new("RGB", (100, 100), color="blue")
    res_with_img = orchestrator.process_request(
        user_text="chào bạn",
        pil_image=img,
        session_id="session_test_greeting_with_img",
        persist=False
    )
    assert res_with_img["decision"]["intent_type"] != "general_chat"


def test_image_base64_not_general_chat(orchestrator):
    """
    Image passed via image_base64 should also trigger has_image=True.
    """
    # 1x1 white PNG base64
    b64_png = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
    res = orchestrator.process_request(
        user_text="",
        image_base64=b64_png,
        session_id="session_test_b64_img",
        persist=False
    )
    assert res["decision"]["intent_type"] != "general_chat"
