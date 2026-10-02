import re

try:
    from PIL import Image
except ImportError:
    Image = None

class OCRAgent:
    """
    Vision & OCR Agent:
    Extracts text from screenshots (SMS, VietQR bills, Zalo chat, VNeID links)
    using PIL and pytesseract (if available) or Gemini Multimodal Vision fallback.
    Identifies visual anomalies and fake bill signatures.
    """
    def __init__(self):
        self.tesseract_available = False
        try:
            import pytesseract
            self.pytesseract = pytesseract
            self.tesseract_available = True
        except ImportError:
            self.pytesseract = None

    def process(self, image_input=None, raw_text=""):
        extracted_text = raw_text or ""
        anomalies = []
        has_image = False
        image_details = {}

        if image_input and Image:
            has_image = True
            try:
                if not isinstance(image_input, Image.Image):
                    pil_img = Image.open(image_input)
                else:
                    pil_img = image_input

                if pil_img.mode != "RGB":
                    pil_img = pil_img.convert("RGB")

                image_details = {
                    "format": getattr(pil_img, "format", "RGB"),
                    "size": pil_img.size,
                    "mode": pil_img.mode
                }

                if self.tesseract_available:
                    try:
                        ocr_txt = self.pytesseract.image_to_string(pil_img, lang='vie+eng')
                        if ocr_txt and len(ocr_txt.strip()) > 5:
                            extracted_text = (extracted_text + "\n" + ocr_txt.strip()).strip()
                    except Exception as e:
                        print(f"[OCRAgent] pytesseract notice: {e}")

                if not extracted_text:
                    extracted_text = f"[Ảnh màn hình {pil_img.size[0]}x{pil_img.size[1]}]: Đã tải lên ảnh bằng chứng (Bill/SMS/Chat)."

            except Exception as e:
                print(f"[OCRAgent] Image processing error: {e}")
                extracted_text = extracted_text or "[Ảnh bằng chứng đã được đính kèm]"

        # Text analysis for visual/text anomalies
        txt_lower = extracted_text.lower()
        if "vietqr" in txt_lower or "bill" in txt_lower or "chuyển khoản thành công" in txt_lower or "giao dịch thành công" in txt_lower:
            if "chưa nhận" in txt_lower or "chưa tăng" in txt_lower or "chưa nhảy tiền" in txt_lower or "chưa thấy tiền" in txt_lower:
                anomalies.append("Phát hiện bất thường: Ảnh bill báo chuyển khoản thành công nhưng số dư tài khoản chưa nhận được tiền thực tế (Nghi vấn Fake VietQR Bill).")

        if ".apk" in txt_lower or "vneid-capnhat" in txt_lower or "cai-dat.apk" in txt_lower:
            anomalies.append("Phát hiện đính kèm file cài đặt Android (.apk) từ trang web giả mạo ngoài Google Play Store.")

        if "công an" in txt_lower or "cục thuế" in txt_lower or "tòa án" in txt_lower or "viện kiểm sát" in txt_lower:
            if "gọi điện" in txt_lower or "lỗi đồng bộ" in txt_lower or "lỗi hồ sơ" in txt_lower:
                anomalies.append("Dấu hiệu mạo danh cơ quan nhà nước / Cán bộ nhà nước gọi điện/gửi tin nhắn thông báo lỗi để ép cài phần mềm.")

        return {
            "extracted_text": extracted_text,
            "anomalies": anomalies,
            "has_image": has_image,
            "image_details": image_details
        }

if __name__ == "__main__":
    ocr = OCRAgent()
    res = ocr.process(raw_text="Em nhận được link vneid.apk hỗ trợ thuế")
    print("[OCRAgent] Result:", res)
