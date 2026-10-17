import json
import socket
import sys
import time
import pytest
from PIL import Image

from codebase.url_analysis.image_sources import (
    crc16_ccitt_false,
    _parse_tlv,
    open_image_safely,
    extract_qr_payloads,
    parse_vietqr,
    classify_qr_payload,
)


def _build_test_vietqr(
    bin_code: str = "970436",
    account: str = "0123456789",
    amount: str = "50000",
    name: str = "NGUYEN VAN A",
    memo: str = "TIEN HANG",
) -> str:
    """Construct a valid EMVCo VietQR string with correct TLV structure and CCITT-FALSE CRC."""
    def tlv(tag: str, val: str) -> str:
        return f"{tag}{len(val):02d}{val}"

    sub00 = tlv("00", bin_code)
    sub01 = tlv("01", account)
    ben = sub00 + sub01

    tag38 = tlv("00", "A000000727") + tlv("01", ben) + tlv("02", "QRIBFTTA")

    body = (
        tlv("00", "01")
        + tlv("01", "12")
        + tlv("38", tag38)
        + tlv("53", "704")
        + (tlv("54", amount) if amount else "")
        + tlv("58", "VN")
        + (tlv("59", name) if name else "")
        + tlv("60", "HANOI")
        + (tlv("62", tlv("08", memo)) if memo else "")
        + "6304"
    )

    crc_val = crc16_ccitt_false(body.encode("utf-8"))
    return body + f"{crc_val:04X}"


def _make_qr_image(payload: str) -> Image.Image:
    qrcode = pytest.importorskip("qrcode")
    qr = qrcode.QRCode(box_size=8, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white").convert("RGB")


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator End-to-End Image QR Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_orchestrator_qr_phishing_url(orchestrator):
    """
    QR code containing a phishing URL (https://vcb-xacminh.top/login) without text
    must yield risk >= 75, risk_level HIGH or CRITICAL, and url_analysis.findings with source 'qr'.
    """
    pytest.importorskip("cv2")
    qr_img = _make_qr_image("https://vcb-xacminh.top/login")

    res = orchestrator.process_request(user_text="", image_input=qr_img, persist=False)
    assert res is not None
    assert res["risk_score"] >= 75
    assert res["decision"]["risk_level"] in ("HIGH", "CRITICAL")

    # url_analysis findings must have source 'qr'
    url_report = res.get("url_analysis")
    assert url_report is not None
    findings = url_report.get("findings", [])
    assert len(findings) >= 1
    qr_findings = [f for f in findings if f.get("source") == "qr"]
    assert len(qr_findings) >= 1

    # image_analysis must be populated
    img_an = res.get("image_analysis")
    assert img_an is not None
    assert img_an["qr_count"] >= 1
    assert any("vcb-xacminh" in u for u in img_an["qr_urls"])
    assert img_an["risky_payloads"] == 0


def test_orchestrator_qr_official_url(orchestrator):
    """
    QR code pointing to an official domain (https://vietcombank.com.vn/vi-VN/Ca-nhan)
    must yield risk < 40 and risk_level LOW.
    """
    pytest.importorskip("cv2")
    qr_img = _make_qr_image("https://vietcombank.com.vn/vi-VN/Ca-nhan")

    res = orchestrator.process_request(user_text="", image_input=qr_img, persist=False)
    assert res is not None
    assert res["risk_score"] < 40
    assert res["decision"]["risk_level"] == "LOW"


def test_orchestrator_qr_javascript(orchestrator):
    """
    QR code containing a dangerous URI (javascript:alert(1))
    must trigger DATA_OR_JS_URI floor, yielding CRITICAL risk.
    """
    pytest.importorskip("cv2")
    qr_img = _make_qr_image("javascript:alert(1)")

    res = orchestrator.process_request(user_text="", image_input=qr_img, persist=False)
    assert res is not None
    assert res["risk_score"] >= 90
    assert res["decision"]["risk_level"] == "CRITICAL"
    assert res["image_analysis"]["risky_payloads"] >= 1


def test_orchestrator_benign_text_with_benign_qr(orchestrator):
    """
    Benign conversational text with benign official QR image must stay LOW.
    """
    pytest.importorskip("cv2")
    qr_img = _make_qr_image("https://vietcombank.com.vn")

    res = orchestrator.process_request(
        user_text="Chào bạn, em gửi chị thông tin kiểm tra",
        image_input=qr_img,
        persist=False
    )
    assert res is not None
    assert res["risk_score"] < 40
    assert res["decision"]["risk_level"] == "LOW"


def test_orchestrator_vietqr_parsed_and_json_serializable(orchestrator):
    """
    VietQR image is parsed accurately into image_analysis.vietqr without leaking full account number,
    and the complete response dict is standard JSON serializable.
    """
    pytest.importorskip("cv2")
    qr_payload = _build_test_vietqr(
        bin_code="970436",
        account="0123456789",
        amount="50000",
        name="NGUYEN VAN A",
        memo="TIEN HANG",
    )
    qr_img = _make_qr_image(qr_payload)

    res = orchestrator.process_request(user_text="", image_input=qr_img, persist=False)
    assert res is not None
    img_an = res.get("image_analysis")
    assert img_an is not None
    assert img_an["qr_count"] >= 1
    assert len(img_an["vietqr"]) >= 1

    v = img_an["vietqr"][0]
    assert v["bank_name"] == "Vietcombank"
    assert v["bin"] == "970436"
    assert v["masked_account"] == "01****89"
    # Full account must NOT be present in response
    assert "account" not in v
    assert "0123456789" not in v["masked_account"]
    assert v["amount"] == "50000"
    assert v["name"] == "NGUYEN VAN A"
    assert v["memo"] == "TIEN HANG"
    assert v["crc_ok"] is True

    # Entire response must be valid JSON serializable
    dumped = json.dumps(res, ensure_ascii=False)
    assert "0123456789" not in dumped
    assert "01****89" in dumped


def test_orchestrator_vietqr_corrupt_crc_adds_reason(orchestrator):
    """
    VietQR with corrupted CRC must flag crc_ok=False and append Vietnamese warning reason.
    """
    pytest.importorskip("cv2")
    qr_payload = _build_test_vietqr()
    # Corrupt the CRC value at the end without breaking the TLV tag structure
    corrupted_payload = qr_payload[:-4] + ("0000" if qr_payload[-4:] != "0000" else "FFFF")
    qr_img = _make_qr_image(corrupted_payload)

    res = orchestrator.process_request(user_text="", image_input=qr_img, persist=False)
    assert res is not None
    v = res["image_analysis"]["vietqr"][0]
    assert v["crc_ok"] is False

    reasons = res.get("explainable", {}).get("reasons", [])
    assert any("Mã VietQR bị chỉnh sửa/không hợp lệ (sai CRC)" in r for r in reasons)


def test_orchestrator_offline_zero_network_calls(orchestrator, monkeypatch):
    """
    During offline processing of image and QR analysis, exactly 0 network calls are made.
    """
    pytest.importorskip("cv2")
    network_call_count = 0

    def spy_connect(*args, **kwargs):
        nonlocal network_call_count
        network_call_count += 1
        raise RuntimeError("Network attempted in offline test!")

    monkeypatch.setattr(socket.socket, "connect", spy_connect)

    qr_img = _make_qr_image("https://vcb-xacminh.top/login")
    res = orchestrator.process_request(user_text="", image_input=qr_img, persist=False)
    assert res is not None
    assert network_call_count == 0


def test_orchestrator_no_image_image_analysis_is_none(orchestrator):
    """
    When no image is provided, image_analysis key must be None.
    """
    res = orchestrator.process_request(user_text="Xin chào", persist=False)
    assert res["image_analysis"] is None


def test_orchestrator_corrupt_image_quiet_fallback(orchestrator):
    """
    When corrupt image data is supplied, orchestrator handles it quietly without raising,
    image_analysis has qr_count=0, and response remains valid.
    """
    corrupt_bytes = b"NotValidImageDataAtAll"
    res = orchestrator.process_request(user_text="", image_input=corrupt_bytes, persist=False)
    assert res is not None
    assert res["image_analysis"] is not None
    assert res["image_analysis"]["qr_count"] == 0
    assert res["image_analysis"]["qr_urls"] == []
    assert res["image_analysis"]["vietqr"] == []


# ─────────────────────────────────────────────────────────────────────────────
# 6 Mutation Verification Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_mutation_1_pixel_limit_enforced():
    """Mutation: Removing pixel limit would allow decompression bomb to be loaded."""
    import struct, zlib
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 30000, 30000, 8, 0, 0, 0, 0)
    ihdr_crc = struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data))
    ihdr = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + ihdr_crc
    raw = zlib.compress(b"\x00" * 100)
    idat = struct.pack(">I", len(raw)) + b"IDAT" + raw + struct.pack(">I", zlib.crc32(b"IDAT" + raw))
    iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND"))
    bomb = signature + ihdr + idat + iend

    assert open_image_safely(bomb) is None


def test_mutation_2_time_budget_enforced():
    """Mutation: Removing time budget would let image variants run indefinitely."""
    pytest.importorskip("cv2")
    large_blank = Image.new("RGB", (3500, 2500), color="white")
    t0 = time.perf_counter()
    res = extract_qr_payloads(large_blank, time_budget_s=0.2)
    elapsed = time.perf_counter() - t0
    assert res == []
    assert elapsed < 1.0


def test_mutation_3_crc_check_enforced():
    """Mutation: Skipping CRC check would allow tampered VietQR to pass as valid."""
    qr = _build_test_vietqr()
    corrupted = qr[:12] + ("X" if qr[12] != "X" else "Y") + qr[13:]
    parsed = parse_vietqr(corrupted)
    assert parsed is not None
    assert parsed["crc_ok"] is False


def test_mutation_4_qr_urls_in_extra_urls(orchestrator):
    """Mutation: Not adding QR URL to extra_urls would result in 0 findings and missing 'qr' source."""
    pytest.importorskip("cv2")
    qr_img = _make_qr_image("https://vcb-xacminh.top/login")
    res = orchestrator.process_request(user_text="", image_input=qr_img, persist=False)
    findings = res.get("url_analysis", {}).get("findings", [])
    assert len(findings) > 0
    assert any(f.get("source") == "qr" for f in findings)


def test_mutation_5_no_full_account_in_response(orchestrator):
    """Mutation: Exposing full account in response would leak raw number in JSON serialization."""
    pytest.importorskip("cv2")
    secret_acc = "112233445566"
    qr_str = _build_test_vietqr(account=secret_acc)
    qr_img = _make_qr_image(qr_str)
    res = orchestrator.process_request(user_text="", image_input=qr_img, persist=False)
    v = res["image_analysis"]["vietqr"][0]
    assert "account" not in v
    assert secret_acc not in json.dumps(res)


def test_mutation_6_missing_cv2_does_not_raise(monkeypatch):
    """Mutation: Missing cv2 raising an uncaught exception instead of returning []."""
    monkeypatch.setitem(sys.modules, "cv2", None)
    img = Image.new("RGB", (100, 100), color="white")
    assert extract_qr_payloads(img) == []


def test_mutation_vietqr_crc_failure_floors_risk_score_45(orchestrator):
    """B7 mutation: Tampered VietQR (CRC failed) must add >= 30 points and floor risk at >= 45."""
    pytest.importorskip("cv2")
    qr = _build_test_vietqr()
    corrupted_qr = qr[:-4] + "FFFF"
    qr_img = _make_qr_image(corrupted_qr)
    res = orchestrator.process_request(user_text="Thanh toán đơn hàng", image_input=qr_img, persist=False)
    risk = res.get("risk_score", 0)
    assert risk >= 45, f"Expected risk >= 45 for tampered VietQR CRC, got {risk}"
    reasons = res.get("explainable", {}).get("reasons", [])
    assert any("CRC" in r for r in reasons)
