import io
import struct
import sys
import time
import zlib
import pytest
from PIL import Image

from codebase.url_analysis.image_sources import (
    open_image_safely,
    extract_qr_payloads,
    classify_qr_payload,
    parse_vietqr,
    defang_url,
    crc16_ccitt_false,
    mask_account,
    VIETQR_BANKS,
    MAX_IMAGE_BYTES,
    MAX_IMAGE_PIXELS,
)


def _make_pixel_bomb_bytes() -> bytes:
    """Generate a valid PNG header declaring 30000x30000 dimensions with minimal compressed bytes."""
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 30000, 30000, 8, 0, 0, 0, 0)
    ihdr_crc = struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data))
    ihdr = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + ihdr_crc
    raw = zlib.compress(b"\x00" * 100)
    idat = struct.pack(">I", len(raw)) + b"IDAT" + raw + struct.pack(">I", zlib.crc32(b"IDAT" + raw))
    iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND"))
    return signature + ihdr + idat + iend


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


# ─────────────────────────────────────────────────────────────────────────────
# Unit Tests: open_image_safely
# ─────────────────────────────────────────────────────────────────────────────

def test_open_image_safely_valid_and_resize():
    # Large image (11.9MP, under the 12MP cap): 4400x2700 -> scaled so the long edge is 2000 px
    img = Image.new("RGBA", (4400, 2700), color=(100, 150, 200, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    raw = buf.getvalue()

    opened = open_image_safely(raw)
    assert opened is not None
    assert opened.mode == "RGB"
    assert max(opened.width, opened.height) <= 2000
    assert opened.width == 2000
    assert opened.height in (1227, 1228)  # 2700 * 2000 / 4400


def test_open_image_safely_max_bytes():
    # Exceed max_bytes
    fake_huge_data = b"GIF89a" + b"\x00" * 1000
    res = open_image_safely(fake_huge_data, max_bytes=500)
    assert res is None


def test_open_image_safely_pixel_bomb():
    bomb = _make_pixel_bomb_bytes()
    t0 = time.perf_counter()
    res = open_image_safely(bomb)
    elapsed = time.perf_counter() - t0
    assert res is None
    assert elapsed < 2.0


def test_open_image_safely_corrupt_data():
    garbage = b"PK\x03\x04ThisIsNotAnImageFileAtAll"
    assert open_image_safely(garbage) is None
    assert open_image_safely(b"") is None
    assert open_image_safely(None) is None


# ─────────────────────────────────────────────────────────────────────────────
# Unit Tests: classify_qr_payload (12 types)
# ─────────────────────────────────────────────────────────────────────────────

def test_classify_qr_payload_12_types():
    # 1. Naked url
    c1 = classify_qr_payload("example.com/pay")
    assert c1["kind"] == "url"
    assert c1["url"] == "example.com/pay"
    assert not c1.get("risky")

    # 2. https URL
    c2 = classify_qr_payload("https://vcb-xacminh.top/login")
    assert c2["kind"] == "url"
    assert c2["url"] == "https://vcb-xacminh.top/login"

    # 3. javascript:
    c3 = classify_qr_payload("javascript:alert(document.cookie)")
    assert c3["kind"] == "other"
    assert c3.get("risky") is True

    # 4. data:
    c4 = classify_qr_payload("data:text/html,<script>alert(1)</script>")
    assert c4["kind"] == "other"
    assert c4.get("risky") is True

    # 5. WIFI
    c5 = classify_qr_payload("WIFI:T:WPA;S:OfficeNet;P:p@ssw0rd;;")
    assert c5["kind"] == "wifi"
    assert c5["url"] is None

    # 6. tel:
    c6 = classify_qr_payload("tel:+84912345678")
    assert c6["kind"] == "tel"
    assert c6["url"] is None

    # 7. sms:
    c7 = classify_qr_payload("sms:0912345678?body=MaOTP")
    assert c7["kind"] == "sms"

    # 8. mailto:
    c8 = classify_qr_payload("mailto:support@vietcombank.com.vn")
    assert c8["kind"] == "mailto"

    # 9. geo:
    c9 = classify_qr_payload("geo:21.0285,105.8542")
    assert c9["kind"] == "geo"

    # 10. vcard:
    c10 = classify_qr_payload("BEGIN:VCARD\nVERSION:3.0\nFN:Nguyen Van A\nEND:VCARD")
    assert c10["kind"] == "vcard"

    # 11. text:
    c11 = classify_qr_payload("Chuyen tien mua hang thang 10")
    assert c11["kind"] == "text"
    assert c11["url"] is None

    # 12. vietqr:
    qr_str = _build_test_vietqr()
    c12 = classify_qr_payload(qr_str)
    assert c12["kind"] == "vietqr"
    assert c12["url"] is None


# ─────────────────────────────────────────────────────────────────────────────
# Unit Tests: parse_vietqr
# ─────────────────────────────────────────────────────────────────────────────

def test_parse_vietqr_valid():
    qr = _build_test_vietqr(
        bin_code="970436",
        account="0123456789",
        amount="150000",
        name="TRAN VAN B",
        memo="DONG TIEN HOC",
    )
    parsed = parse_vietqr(qr)
    assert parsed is not None
    assert parsed["bin"] == "970436"
    assert parsed["bank_name"] == "Vietcombank"
    assert parsed["account"] == "0123456789"
    assert parsed["masked_account"] == "01****89"
    assert parsed["amount"] == "150000"
    assert parsed["name"] == "TRAN VAN B"
    assert parsed["memo"] == "DONG TIEN HOC"
    assert parsed["crc_ok"] is True


def test_parse_vietqr_corrupt_crc():
    qr = _build_test_vietqr()
    # Modify 1 character in the payload body (e.g. at index 10)
    corrupted = qr[:10] + ("0" if qr[10] != "0" else "1") + qr[11:]
    parsed = parse_vietqr(corrupted)
    assert parsed is not None
    assert parsed["crc_ok"] is False


def test_parse_vietqr_malformed_truncated_and_10k():
    # Truncated
    assert parse_vietqr("00020101") is None
    # Bad length tag
    assert parse_vietqr("000201389900") is None
    # 10k character payload -> None without raising
    huge_payload = "000201" + "A" * 10000
    assert parse_vietqr(huge_payload) is None


def test_parse_vietqr_masked_account_no_leak():
    qr = _build_test_vietqr(account="987654321012")
    parsed = parse_vietqr(qr)
    assert parsed is not None
    masked = parsed["masked_account"]
    assert masked == "98****12"
    assert "987654321012" not in masked


def test_defang_url():
    assert defang_url("https://vcb-xacminh.top/login") == "hxxps://vcb-xacminh[.]top/login"
    assert defang_url("http://example.com/test") == "hxxp://example[.]com/test"
    assert defang_url("vietcombank.com.vn") == "vietcombank[.]com[.]vn"


# ─────────────────────────────────────────────────────────────────────────────
# Tests requiring cv2 and qrcode
# ─────────────────────────────────────────────────────────────────────────────

def test_extract_qr_payloads_cv2_missing(monkeypatch):
    """When cv2 is missing or raises ImportError, extract_qr_payloads returns [] without raising."""
    monkeypatch.setitem(sys.modules, "cv2", None)
    img = Image.new("RGB", (100, 100), color="white")
    res = extract_qr_payloads(img)
    assert res == []


def test_extract_qr_payloads_no_qr():
    pytest.importorskip("cv2")
    img = Image.new("RGB", (200, 200), color="white")
    assert extract_qr_payloads(img) == []


def test_extract_qr_payloads_single_url():
    pytest.importorskip("cv2")
    qrcode = pytest.importorskip("qrcode")

    qr = qrcode.QRCode(box_size=10, border=4)
    target_url = "https://vcb-xacminh.top/login"
    qr.add_data(target_url)
    qr.make(fit=True)
    pil_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")

    payloads = extract_qr_payloads(pil_img)
    assert len(payloads) == 1
    assert payloads[0] == target_url


def test_extract_qr_payloads_multiple_qr():
    pytest.importorskip("cv2")
    qrcode = pytest.importorskip("qrcode")

    qr1 = qrcode.make("https://fake-link-one.top").convert("RGB")
    qr2 = qrcode.make("https://fake-link-two.top").convert("RGB")

    combo = Image.new("RGB", (qr1.width * 2 + 60, qr1.height + 40), color="white")
    combo.paste(qr1, (20, 20))
    combo.paste(qr2, (qr1.width + 40, 20))

    payloads = extract_qr_payloads(combo)
    assert len(payloads) >= 2
    assert "https://fake-link-one.top" in payloads
    assert "https://fake-link-two.top" in payloads


def test_extract_qr_payloads_rotated_90_180():
    pytest.importorskip("cv2")
    qrcode = pytest.importorskip("qrcode")

    qr = qrcode.QRCode(box_size=8, border=4)
    qr.add_data("https://rotated-qr.xyz")
    qr.make(fit=True)
    pil_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")

    rot90 = pil_img.rotate(90, expand=True)
    p90 = extract_qr_payloads(rot90)
    assert "https://rotated-qr.xyz" in p90

    rot180 = pil_img.rotate(180, expand=True)
    p180 = extract_qr_payloads(rot180)
    assert "https://rotated-qr.xyz" in p180


def test_extract_qr_payloads_inverted_and_low_contrast():
    pytest.importorskip("cv2")
    qrcode = pytest.importorskip("qrcode")

    # Inverted colors (white QR on black background)
    qr = qrcode.QRCode(box_size=8, border=4)
    qr.add_data("https://inverted-qr.xyz")
    qr.make(fit=True)
    inverted_img = qr.make_image(fill_color="white", back_color="black").convert("RGB")

    p_inv = extract_qr_payloads(inverted_img)
    assert "https://inverted-qr.xyz" in p_inv


def test_extract_qr_payloads_time_budget():
    pytest.importorskip("cv2")
    # Large blank image with tiny time budget
    large = Image.new("RGB", (3000, 2500), color="white")
    t0 = time.perf_counter()
    res = extract_qr_payloads(large, time_budget_s=0.3)
    elapsed = time.perf_counter() - t0
    assert res == []
    assert elapsed < 1.0


def test_extract_qr_payloads_160px_in_3000x2000_decoded():
    """B5: 160px QR code in 3000x2000 image is successfully decoded via tiled crops."""
    pytest.importorskip("cv2")
    qrcode = pytest.importorskip("qrcode")

    qr = qrcode.QRCode(box_size=4, border=2)
    qr.add_data("https://safeguard-tiled-test.vn")
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    # Resize QR to exactly 160x160
    qr_160 = qr_img.resize((160, 160))

    canvas = Image.new("RGB", (3000, 2000), color="white")
    # Paste QR in top-left tile quadrant
    canvas.paste(qr_160, (200, 200))

    payloads = extract_qr_payloads(canvas, time_budget_s=2.0)
    assert len(payloads) > 0
    assert "https://safeguard-tiled-test.vn" in payloads


def test_classify_qr_payload_risky_schemes():
    """B5: Test risky schemes including itms-services, smb, jar, and USSD forwarding tel:."""
    # 1. itms-services:
    c1 = classify_qr_payload("itms-services://?action=download-manifest&url=https://evil.top")
    assert c1.get("risky") is True

    # 2. smb:
    c2 = classify_qr_payload("smb://evil.top/malware.exe")
    assert c2.get("risky") is True

    # 3. jar:
    c3 = classify_qr_payload("jar:https://evil.top/app.jar!/exploit.class")
    assert c3.get("risky") is True

    # 4. tel: USSD forwarding *21*...#
    c4 = classify_qr_payload("tel:*21*0912345678#")
    assert c4.get("kind") == "tel"
    assert c4.get("risky") is True

    # 5. tel: USSD forwarding with percent encoded #
    c5 = classify_qr_payload("tel:*21*0912345678%23")
    assert c5.get("kind") == "tel"
    assert c5.get("risky") is True

    # 6. tel: USSD hash command #...#
    c6 = classify_qr_payload("tel:#21#")
    assert c6.get("kind") == "tel"
    assert c6.get("risky") is True

    # 7. Normal phone number -> not risky
    c7 = classify_qr_payload("tel:0912345678")
    assert c7.get("kind") == "tel"
    assert c7.get("risky") is False


def test_mutation_pixel_limit_5000x5000_rejected():
    """B7 mutation: 5000x5000 PNG (25MP) exceeds 12MP cap and must be rejected."""
    huge_img = Image.new("RGB", (5000, 5000), color="white")
    assert open_image_safely(huge_img) is None
    assert extract_qr_payloads(huge_img) == []


def test_mutation_qr_time_budget_early_stop_on_noise():
    """B7 mutation: 4000x3000 noise image with small budget stops early."""
    pytest.importorskip("cv2")
    # Generate image
    img = Image.new("RGB", (4000, 3000), color=(128, 128, 128))
    t0 = time.perf_counter()
    res = extract_qr_payloads(img, time_budget_s=0.25)
    elapsed = time.perf_counter() - t0
    assert elapsed < 0.8
    assert res == []


def test_mutation_max_codes_limit_exact_8():
    """B7 mutation: image with 12 QR codes respects max_codes=8."""
    pytest.importorskip("cv2")
    qrcode = pytest.importorskip("qrcode")

    # Generate 12 distinct QRs
    qr_list = []
    for i in range(12):
        q = qrcode.QRCode(box_size=3, border=1)
        q.add_data(f"https://safeguard-qr-{i}.vn")
        q.make(fit=True)
        qr_list.append(q.make_image().convert("RGB"))

    canvas = Image.new("RGB", (1200, 900), color="white")
    idx = 0
    for r in range(3):
        for c in range(4):
            canvas.paste(qr_list[idx], (c * 280 + 20, r * 280 + 20))
            idx += 1

    payloads = extract_qr_payloads(canvas, max_codes=8, time_budget_s=3.0)
    assert len(payloads) == 8, f"Expected exactly 8 payloads, got {len(payloads)}"

