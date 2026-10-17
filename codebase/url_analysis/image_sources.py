from __future__ import annotations

import io
import os
import re
import time
from typing import Any

try:
    from PIL import Image
    try:
        from PIL.Image import DecompressionBombError
    except ImportError:
        DecompressionBombError = Exception
except ImportError:
    Image = None
    DecompressionBombError = Exception

from codebase.url_analysis.normalize import load_url_lists

# Bảng BIN các ngân hàng Việt Nam phổ biến
# Ghi chú: Bảng BIN các ngân hàng Việt Nam cần xác minh định kỳ theo NAPAS.
VIETQR_BANKS: dict[str, str] = {
    "970436": "Vietcombank",
    "970418": "BIDV",
    "970415": "VietinBank",
    "970405": "Agribank",
    "970407": "Techcombank",
    "970422": "MB",
    "970416": "ACB",
    "970432": "VPBank",
    "970423": "TPBank",
    "970403": "Sacombank",
    "970441": "VIB",
    "970443": "SHB",
    "970437": "HDBank",
    "970426": "MSB",
    "970448": "OCB",
    "970429": "SCB",
}

MAX_IMAGE_BYTES = 8_000_000
MAX_IMAGE_PIXELS = 25_000_000
MAX_QR_CODES = 8
MAX_PAYLOAD_LEN = 4096

RE_SCHEME = re.compile(r"^(?:https?|ftp)://", re.IGNORECASE)
RE_GENERIC_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]{1,31}:")
RE_IPV4 = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")


def defang_url(url: str) -> str:
    """Defang URL for safe UI display (hxxps://, [.])."""
    if not url or not isinstance(url, str):
        return ""
    res = re.sub(r"^https://", "hxxps://", url, flags=re.IGNORECASE)
    res = re.sub(r"^http://", "hxxp://", res, flags=re.IGNORECASE)
    return res.replace(".", "[.]")


def mask_account(account: str | None) -> str | None:
    """Mask bank account number for UI: 4 initial digits + **** + 3 trailing digits."""
    if not account:
        return None
    acc = str(account).strip()
    if len(acc) >= 8:
        return f"{acc[:4]}****{acc[-3:]}"
    elif len(acc) > 4:
        return f"{acc[:2]}****{acc[-2:]}"
    return "****"


def crc16_ccitt_false(data: bytes) -> int:
    """Calculate CRC16-CCITT-FALSE (poly 0x1021, init 0xFFFF, refIn=False, refOut=False, xorOut=0x0000)."""
    crc = 0xFFFF
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def open_image_safely(
    data: bytes | Any | str,
    *,
    max_bytes: int = MAX_IMAGE_BYTES,
    max_pixels: int = MAX_IMAGE_PIXELS,
) -> Any | None:
    """
    Safely open and validate an image against decompression bombs and corrupt files.
    - Checks file/byte size (max_bytes)
    - Sets Image.MAX_IMAGE_PIXELS
    - Calls img.verify() on a probe copy before reloading
    - Catches DecompressionBombError, OSError, ValueError -> returns None
    - Converts to RGB
    - Scales down proportionally if long edge > 4000 px
    """
    if data is None or Image is None:
        return None

    Image.MAX_IMAGE_PIXELS = max_pixels

    raw_bytes: bytes | None = None
    if isinstance(data, (bytes, bytearray)):
        if len(data) > max_bytes:
            return None
        raw_bytes = bytes(data)
    elif isinstance(data, str):
        try:
            if not os.path.isfile(data):
                return None
            if os.path.getsize(data) > max_bytes:
                return None
            with open(data, "rb") as f:
                raw_bytes = f.read()
        except Exception:
            return None
    elif hasattr(data, "read"):
        try:
            if hasattr(data, "getvalue"):
                raw_bytes = data.getvalue()
            else:
                raw_bytes = data.read()
            if len(raw_bytes) > max_bytes:
                return None
        except Exception:
            return None
    elif isinstance(data, Image.Image):
        # Image is already a PIL Image object
        try:
            if (data.width * data.height) > max_pixels:
                return None
            img = data.copy()
            if img.mode != "RGB":
                img = img.convert("RGB")
            max_edge = max(img.width, img.height)
            if max_edge > 4000:
                scale = 4000.0 / max_edge
                new_w = max(1, int(img.width * scale))
                new_h = max(1, int(img.height * scale))
                resample_filter = getattr(getattr(Image, "Resampling", Image), "LANCZOS", Image.LANCZOS)
                img = img.resize((new_w, new_h), resample=resample_filter)
            return img
        except Exception:
            return None
    else:
        return None

    if raw_bytes is None:
        return None

    try:
        # Step 1: Probe and verify without full decode
        probe = Image.open(io.BytesIO(raw_bytes))
        if hasattr(probe, "size"):
            w, h = probe.size
            if (w * h) > max_pixels:
                return None
        probe.verify()

        # Step 2: Reopen for actual processing (verify closes/invalidates the stream)
        img = Image.open(io.BytesIO(raw_bytes))
        if (img.width * img.height) > max_pixels:
            return None

        img.load()

        # Step 3: Convert to RGB
        if img.mode != "RGB":
            img = img.convert("RGB")

        # Step 4: Scale down if long edge > 4000 px (preserving aspect ratio)
        max_edge = max(img.width, img.height)
        if max_edge > 4000:
            scale = 4000.0 / max_edge
            new_w = max(1, int(img.width * scale))
            new_h = max(1, int(img.height * scale))
            resample_filter = getattr(getattr(Image, "Resampling", Image), "LANCZOS", Image.LANCZOS)
            img = img.resize((new_w, new_h), resample=resample_filter)

        return img
    except (DecompressionBombError, OSError, ValueError, SyntaxError, Exception):
        return None


def extract_qr_payloads(
    pil_img: Any,
    *,
    max_codes: int = MAX_QR_CODES,
    time_budget_s: float = 1.5,
) -> list[str]:
    """
    Extract QR payloads from a PIL image using cv2.QRCodeDetector across multiple variants.
    - Variants: original, grayscale, 2x scale, Otsu threshold, inverted
    - Stops when time_budget_s expires or max_codes reached
    - Deduplicates payloads, truncated to max 4096 chars
    - Never raises exceptions; returns [] if cv2 is missing or image is invalid
    """
    if pil_img is None:
        return []

    # Optional cv2 import at runtime
    try:
        import cv2
        import numpy as np
    except (ImportError, Exception):
        return []

    if cv2 is None or np is None:
        return []

    start_time = time.perf_counter()
    payloads: list[str] = []

    try:
        arr = np.array(pil_img)
        if arr.size == 0:
            return []

        if len(arr.shape) == 2:
            gray = arr
            bgr = cv2.cvtColor(gray, cv2.COLOR_GRAY2BGR)
        elif arr.shape[2] == 3:
            bgr = cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)
            gray = cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY)
        elif arr.shape[2] == 4:
            bgr = cv2.cvtColor(arr, cv2.COLOR_RGBA2BGR)
            gray = cv2.cvtColor(arr, cv2.COLOR_RGBA2GRAY)
        else:
            return []

        detector = cv2.QRCodeDetector()
        has_multi = hasattr(detector, "detectAndDecodeMulti")

        def _scan(variant: Any) -> None:
            nonlocal payloads
            if variant is None or len(payloads) >= max_codes:
                return
            try:
                if has_multi:
                    retval, decoded_info, points, _ = detector.detectAndDecodeMulti(variant)
                    if retval and decoded_info is not None:
                        for item in decoded_info:
                            if item and isinstance(item, str):
                                clean_item = item.strip()[:MAX_PAYLOAD_LEN]
                                if clean_item and clean_item not in payloads:
                                    payloads.append(clean_item)
                                    if len(payloads) >= max_codes:
                                        return
                else:
                    retval, points, _ = detector.detectAndDecode(variant)
                    if retval and isinstance(retval, str):
                        clean_item = retval.strip()[:MAX_PAYLOAD_LEN]
                        if clean_item and clean_item not in payloads:
                            payloads.append(clean_item)
            except Exception:
                pass

        # Variant 1: Original BGR
        _scan(bgr)
        if len(payloads) >= max_codes or (time.perf_counter() - start_time) >= time_budget_s:
            return payloads

        # Variant 2: Grayscale
        _scan(gray)
        if len(payloads) >= max_codes or (time.perf_counter() - start_time) >= time_budget_s:
            return payloads

        # Variant 3: Scaled 2x (only if not already huge to preserve time budget)
        max_dim = max(gray.shape[:2])
        if max_dim <= 1500 and (time.perf_counter() - start_time) < (time_budget_s * 0.7):
            try:
                scaled_2x = cv2.resize(gray, (0, 0), fx=2.0, fy=2.0, interpolation=cv2.INTER_LINEAR)
                _scan(scaled_2x)
            except Exception:
                pass
        if len(payloads) >= max_codes or (time.perf_counter() - start_time) >= time_budget_s:
            return payloads

        # Variant 4: Otsu threshold
        try:
            _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            _scan(otsu)
        except Exception:
            pass
        if len(payloads) >= max_codes or (time.perf_counter() - start_time) >= time_budget_s:
            return payloads

        # Variant 5: Inverted
        try:
            inverted = cv2.bitwise_not(gray)
            _scan(inverted)
        except Exception:
            pass

    except Exception:
        pass

    return payloads


def classify_qr_payload(payload: str) -> dict[str, Any]:
    """
    Classify a decoded QR payload into one of 12 types:
    - 'vietqr': EMVCo starting with '000201'
    - 'wifi': starting with 'WIFI:'
    - 'tel': starting with 'tel:'
    - 'sms': starting with 'sms:' or 'smsto:'
    - 'mailto': starting with 'mailto:'
    - 'geo': starting with 'geo:'
    - 'vcard': starting with 'BEGIN:VCARD'
    - 'other' with risky=True: 'javascript:' or 'data:'
    - 'url': 'http(s)://', 'www.', or naked domain with valid TLD / IPv4
    - 'other': unclassified URI scheme
    - 'text': plain text / notes / unclassified
    """
    if not isinstance(payload, str):
        return {"kind": "text", "url": None, "risky": False}

    raw = payload.strip()
    if not raw:
        return {"kind": "text", "url": None, "risky": False}

    low = raw.lower()

    # 1. EMVCo VietQR
    if raw.startswith("000201"):
        return {"kind": "vietqr", "url": None, "risky": False}

    # 2. WIFI
    if raw.upper().startswith("WIFI:"):
        return {"kind": "wifi", "url": None, "risky": False}

    # 3. Risky URI schemes: javascript: or data:
    if low.startswith(("javascript:", "data:")):
        return {"kind": "other", "url": None, "risky": True}

    # 4. tel:
    if low.startswith("tel:"):
        return {"kind": "tel", "url": None, "risky": False}

    # 5. sms: / smsto:
    if low.startswith(("sms:", "smsto:")):
        return {"kind": "sms", "url": None, "risky": False}

    # 6. mailto:
    if low.startswith("mailto:"):
        return {"kind": "mailto", "url": None, "risky": False}

    # 7. geo:
    if low.startswith("geo:"):
        return {"kind": "geo", "url": None, "risky": False}

    # 8. vcard:
    if raw.upper().startswith("BEGIN:VCARD"):
        return {"kind": "vcard", "url": None, "risky": False}

    # 9. Standard URL schemes (http://, https://, ftp://)
    if RE_SCHEME.match(raw):
        return {"kind": "url", "url": raw, "risky": False}

    # 10. www. prefix
    if low.startswith("www."):
        return {"kind": "url", "url": raw, "risky": False}

    # 11. Naked domain or IP check
    # Extract host before delimiter /, ?, #, :
    first_token = re.split(r"[/\\?#:]", raw)[0]
    if "." in first_token and " " not in first_token:
        # Check if IPv4
        if RE_IPV4.match(first_token):
            parts = [int(p) for p in first_token.split(".")]
            if all(0 <= p <= 255 for p in parts):
                return {"kind": "url", "url": raw, "risky": False}

        # Check if valid TLD
        labels = [lbl for lbl in first_token.split(".") if lbl]
        if len(labels) >= 2:
            tld = labels[-1].lower()
            try:
                valid_tlds = set(load_url_lists().get("valid_tlds", []))
            except Exception:
                valid_tlds = {"vn", "com", "net", "org", "top", "xyz", "vip", "online", "edu", "gov"}
            if tld in valid_tlds:
                return {"kind": "url", "url": raw, "risky": False}

    # 12. Generic unknown URI scheme
    if RE_GENERIC_SCHEME.match(raw) and " " not in raw.split(":", 1)[0]:
        return {"kind": "other", "url": None, "risky": False}

    # 13. Plain text
    return {"kind": "text", "url": None, "risky": False}


def _parse_tlv(raw: str, max_depth: int = 4) -> dict[str, str] | None:
    """Safely parse EMVCo TLV string with depth protection."""
    if max_depth <= 0 or not raw or not isinstance(raw, str):
        return None
    res: dict[str, str] = {}
    idx = 0
    length_raw = len(raw)
    while idx < length_raw:
        if idx + 4 > length_raw:
            return None
        tag = raw[idx:idx + 2]
        len_s = raw[idx + 2:idx + 4]
        if not len_s.isdigit():
            return None
        val_len = int(len_s)
        if idx + 4 + val_len > length_raw:
            return None
        val = raw[idx + 4:idx + 4 + val_len]
        res[tag] = val
        idx += 4 + val_len
    return res


def parse_vietqr(payload: str) -> dict[str, Any] | None:
    """
    Parse an EMVCo VietQR payload according to NAPAS/VietQR specification.
    Tags:
      00: version (01)
      01: point of initiation (11 static / 12 dynamic)
      38: NAPAS Merchant info (sub 00 GUID 'A000000727', sub 01 -> sub 00 BIN + sub 01 account, sub 02 service)
      53: currency (704 for VND)
      54: amount
      58: country (VN)
      59: beneficiary name
      60: city
      62: additional data (sub 08 memo)
      63: CRC16-CCITT-FALSE
    Returns:
      {
        bin: str | None,
        bank_name: str | None,
        account: str | None,
        masked_account: str | None,
        amount: str | None,
        name: str | None,
        memo: str | None,
        crc_ok: bool
      }
    Returns None if payload is corrupted/truncated/exceeds 4096 chars.
    Never raises exceptions.
    """
    if not isinstance(payload, str) or len(payload) > MAX_PAYLOAD_LEN or len(payload) < 8:
        return None

    raw = payload.strip()
    if not raw.startswith("000201"):
        return None

    # Verify CRC16-CCITT-FALSE
    crc_ok = False
    if len(raw) >= 8 and raw[-8:-4] == "6304":
        expected_crc = f"{crc16_ccitt_false(raw[:-4].encode('utf-8')):04X}"
        actual_crc = raw[-4:].upper()
        crc_ok = (actual_crc == expected_crc)
    else:
        # Malformed or missing CRC tag
        crc_ok = False

    try:
        top_tlv = _parse_tlv(raw)
        if top_tlv is None:
            return None

        bin_code: str | None = None
        account: str | None = None
        service: str | None = None

        tag_38 = top_tlv.get("38")
        if tag_38:
            sub38 = _parse_tlv(tag_38, max_depth=3)
            if sub38:
                ben_data = sub38.get("01")
                if ben_data:
                    sub_ben = _parse_tlv(ben_data, max_depth=2)
                    if sub_ben:
                        bin_code = sub_ben.get("00")
                        account = sub_ben.get("01")
                service = sub38.get("02")

        amount = top_tlv.get("54")
        name = top_tlv.get("59")
        memo: str | None = None

        tag_62 = top_tlv.get("62")
        if tag_62:
            sub62 = _parse_tlv(tag_62, max_depth=3)
            if sub62:
                memo = sub62.get("08")

        bank_name = VIETQR_BANKS.get(bin_code) if bin_code else None
        masked_acc = mask_account(account) if account else None

        return {
            "bin": bin_code,
            "bank_name": bank_name,
            "account": account,
            "masked_account": masked_acc,
            "amount": amount,
            "name": name,
            "memo": memo,
            "crc_ok": crc_ok,
        }
    except Exception:
        return None
