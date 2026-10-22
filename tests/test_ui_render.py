import json
import os
import re
import shutil
import subprocess
import sys
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
UI_RENDER_JS = os.path.join(ROOT_DIR, "public", "ui_render.js")
APP_JS = os.path.join(ROOT_DIR, "public", "app.js")
INDEX_HTML = os.path.join(ROOT_DIR, "public", "index.html")
STYLES_CSS = os.path.join(ROOT_DIR, "public", "styles.css")


def check_node_available():
    return shutil.which("node") is not None


pytestmark = pytest.mark.skipif(
    not check_node_available(), reason="Node.js is required for UI render tests"
)


def run_node_eval(script: str, timeout_s: float = 15.0) -> dict:
    """Execute a Node.js snippet and return parsed JSON output."""
    node_exe = shutil.which("node") or "node"
    ui_render_path_js = UI_RENDER_JS.replace("\\", "/")

    preamble = f"""
    const UIRender = require('{ui_render_path_js}');
    """
    full_script = preamble + "\n" + script

    proc = subprocess.run(
        [node_exe, "-e", full_script],
        capture_output=True,
        text=True,
        timeout=timeout_s,
        encoding="utf-8",
        cwd=ROOT_DIR,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Node execution failed (code {proc.returncode}):\nSTDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
        )
    try:
        return json.loads(proc.stdout.strip())
    except json.JSONDecodeError:
        return {"raw_stdout": proc.stdout.strip()}


# ─────────────────────────────────────────────────────────────────────────────
# 1. Defang Tests (B2 & Idempotency)
# ─────────────────────────────────────────────────────────────────────────────

def test_defang_url_vectors():
    script = """
    const cases = [
        UIRender.defangUrl("http://evil.com/path"),
        UIRender.defangUrl("https://vietcombank.com.vn:443@evil.com/login"),
        UIRender.defangUrl("https://tеchcombank.com/transfer"),
        UIRender.defangUrl("http://1.2.3.4:8080/download"),
        UIRender.defangUrl("evil.com"),
        UIRender.defangUrl("already[.]defanged[.]com"),
        // B2: Embedded URLs in query / path
        UIRender.defangUrl("hxxps://www[.]google[.]com/url?q=https://evil-bank.xyz/login"),
        UIRender.defangUrl("https://www.google.com/url?url=//evil-bank.xyz/login&dest=ftp://upload.evil.com"),
        // B2: Unicode dots U+3002, U+FF0E, U+FF61
        UIRender.defangUrl("http://evil\\u3002com/path"),
        UIRender.defangUrl("https://evil\\uFF0Ecom\\uFF61vn")
    ];
    console.log(JSON.stringify(cases));
    """
    res = run_node_eval(script)
    assert isinstance(res, list)
    assert len(res) == 10

    # 1. http -> hxxp, dot -> [.]
    assert res[0] == "hxxp://evil[.]com/path"
    # 2. userinfo defanged
    assert res[1] == "hxxps://vietcombank[.]com[.]vn:443@evil[.]com/login"
    # 3. homoglyph defanged
    assert "hxxps://tеchcombank[.]com/transfer" == res[2]
    # 4. IP defanged
    assert res[3] == "hxxp://1[.]2[.]3[.]4:8080/download"
    # 5. Domain without scheme
    assert res[4] == "evil[.]com"
    # 6. Idempotent: no double [[.]]
    assert res[5] == "already[.]defanged[.]com"
    assert "[[.]]" not in res[5]

    # B2: embedded URLs in query
    assert "hxxps://evil-bank[.]xyz/login" in res[6]
    assert "hxxps://www[.]google[.]com" in res[6]
    assert "[[.]]" not in res[6]

    # B2: embedded //host and ftp scheme
    assert "//evil-bank[.]xyz/login" in res[7]
    assert "fxp://upload[.]evil[.]com" in res[7]

    # B2: Unicode dots converted to [.]
    assert res[8] == "hxxp://evil[.]com/path"
    assert res[9] == "hxxps://evil[.]com[.]vn"

    # Idempotent verification: calling defangUrl twice produces identical output
    idempotent_script = f"""
    const s = "{res[6]}";
    const twice = UIRender.defangUrl(s);
    console.log(JSON.stringify({{ match: s === twice, twice }}));
    """
    idemp_res = run_node_eval(idempotent_script)
    assert idemp_res["match"] is True
    assert "[[.]]" not in idemp_res["twice"]


def test_defang_text_vietnamese_and_domains():
    """S2: defangText defangs domain/URL in free text without corrupting numbers or sentences."""
    script = """
    const cases = {
        c1: UIRender.defangText("trình duyệt thực sự mở evil-login.xyz"),
        c2: UIRender.defangText("host=vietcombank-xacminh.top"),
        c3: UIRender.defangText("Truy cập http://phishing.site/login để nhận quà"),
        vietnameseSentence: UIRender.defangText("Tôi đã chuyển 500.000 VNĐ cho anh Nam. Ngày mai nhận hàng."),
        ipAddress: UIRender.defangText("kết nối máy chủ 192.168.1.1:8080")
    };
    console.log(JSON.stringify(cases));
    """
    res = run_node_eval(script)
    assert res["c1"] == "trình duyệt thực sự mở evil-login[.]xyz"
    assert res["c2"] == "host=vietcombank-xacminh[.]top"
    assert "hxxp://phishing[.]site/login" in res["c3"]
    assert "500.000" in res["vietnameseSentence"]
    assert "Nam. Ngày" in res["vietnameseSentence"]
    assert "192[.]168[.]1[.]1:8080" in res["ipAddress"]


# ─────────────────────────────────────────────────────────────────────────────
# 2. SanitizeText Tests: <script>, Bidi, NUL, Invisible Chars, 1MB truncation
# ─────────────────────────────────────────────────────────────────────────────

def test_sanitize_text_vectors():
    script = """
    // U+202E (RLO), U+2066 (LRI), U+061C (ALM), U+2028 (LS), U+2029 (PS), U+2060 (WJ), U+180E (MVS), U+034F (CGJ)
    const bidiStr = "evil" + String.fromCharCode(0x202E) + "txt.exe" + String.fromCharCode(0x2066) + String.fromCharCode(0x061C);
    const invisStr = "clean" + String.fromCharCode(0x2028) + String.fromCharCode(0x2029) + String.fromCharCode(0x2060) + String.fromCharCode(0x180E) + String.fromCharCode(0x034F) + "text";
    const nulStr = "hello\\x00world\\x01\\x02\\x1Ftest";
    const oneMbStr = "A".repeat(1000000);
    const scriptStr = "<script>alert(1)</script>";

    const results = {
        bidi: UIRender.sanitizeText(bidiStr, 100),
        invis: UIRender.sanitizeText(invisStr, 100),
        nul: UIRender.sanitizeText(nulStr, 100),
        truncatedLength: UIRender.sanitizeText(oneMbStr, 300).length,
        scriptClean: UIRender.sanitizeText(scriptStr, 300)
    };
    console.log(JSON.stringify(results));
    """
    res = run_node_eval(script)

    # Bidi characters stripped
    assert "\u202E" not in res["bidi"]
    assert "\u2066" not in res["bidi"]
    assert "\u061C" not in res["bidi"]
    assert res["bidi"] == "eviltxt.exe"

    # Invisible formatting characters stripped (U+2028, U+2029, U+2060, U+180E, U+034F)
    assert res["invis"] == "cleantext"

    # NUL and control characters stripped
    assert "\x00" not in res["nul"]
    assert "\x01" not in res["nul"]
    assert "\x1F" not in res["nul"]
    assert res["nul"] == "helloworldtest"

    # 1MB string truncated to max limit (300)
    assert res["truncatedLength"] == 300

    # Script tag retained as sanitized plain text (not executed)
    assert res["scriptClean"] == "<script>alert(1)</script>"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Source code audit: Grep app.js & ui_render.js for innerHTML, etc.
# ─────────────────────────────────────────────────────────────────────────────

def test_source_code_innerhtml_audit():
    """Verify that no innerHTML/insertAdjacentHTML/outerHTML/document.write ever passes server data."""
    with open(UI_RENDER_JS, "r", encoding="utf-8") as f:
        ui_code = f.read()

    with open(APP_JS, "r", encoding="utf-8") as f:
        app_code = f.read()

    # In ui_render.js:
    for idx, line in enumerate(ui_code.splitlines(), start=1):
        clean = line.strip()
        if "innerHTML" in clean and not clean.startswith("//") and not clean.startswith("*"):
            assert (
                "this._innerHTML" in clean
                or "_innerHTMLAccessed" in clean
                or "_innerHTMLAssigned" in clean
                or "innerHTML:" in clean
                or "innerHTML()" in clean
                or "get innerHTML" in clean
                or "set innerHTML" in clean
            ), f"Unexpected innerHTML in ui_render.js line {idx}: {clean}"
        assert "insertAdjacentHTML" not in clean, f"insertAdjacentHTML in ui_render.js line {idx}"
        assert "outerHTML" not in clean, f"outerHTML in ui_render.js line {idx}"
        assert "document.write" not in clean, f"document.write in ui_render.js line {idx}"

    # In app.js:
    for idx, line in enumerate(app_code.splitlines(), start=1):
        clean = line.strip()
        if "innerHTML" in clean and not clean.startswith("//"):
            assert re.search(r'\.innerHTML\s*=\s*["\']["\']\s*;', clean), (
                f"app.js line {idx} has non-empty innerHTML assignment: {clean}"
            )
        assert "insertAdjacentHTML" not in clean, f"insertAdjacentHTML in app.js line {idx}"
        assert "outerHTML" not in clean, f"outerHTML in app.js line {idx}"
        assert "document.write" not in clean, f"document.write in app.js line {idx}"


# ─────────────────────────────────────────────────────────────────────────────
# 4. S1: Mảng chứa phần tử null / không phải object không ném lỗi
# ─────────────────────────────────────────────────────────────────────────────

def test_array_null_and_invalid_elements_resilience():
    script = """
    const mockDoc = UIRender.createMockDocument();
    const malformedFinding = {
        raw: "http://test.com",
        url_risk_score: 50,
        verdict: "suspicious",
        // Malformed arrays with null, numbers, strings, arrays, objects without expected keys
        obfuscation_chain: [null, 123, "invalid", {}, { technique: "test", detail_vi: "chi tiết" }],
        redirect_chain: [null, "not-an-object", { status: 301, url: "http://hop1.com" }, undefined],
        signals: [null, 456, { severity: "high", message_vi: "tín hiệu", evidence: "evil.com" }],
        children: [null, 789, { verdict: "dangerous", raw: "http://child.com", url_risk_score: 80 }],
        passive_intel: {
            cert: { subject: "bad\\x00cert.com", issuer: "Acme", san: [null, "san.com"] }
        }
    };

    let caughtError = null;
    let card = null;
    try {
        card = UIRender.buildLinkCard(malformedFinding, mockDoc);
    } catch (e) {
        caughtError = e.message;
    }

    // Also test malformed url_analysis container
    const container = mockDoc.createElement("div");
    let urlAnalysisError = null;
    try {
        UIRender.renderUrlAnalysis({
            findings: [null, malformedFinding, 999],
            summary_vi: [null, "Tóm tắt 1", 123]
        }, container, mockDoc);
    } catch (e) {
        urlAnalysisError = e.message;
    }

    // Also test malformed network actions
    let netError = null;
    try {
        UIRender.renderNetworkActions([null, 123, { status: "skipped", target: "skip.com" }], container, mockDoc);
    } catch (e) {
        netError = e.message;
    }

    // Also test malformed image analysis
    let imgError = null;
    try {
        UIRender.renderImageAnalysis({
            qr_urls: [null, 123, "http://qr.com"],
            vietqr: [null, { bank_name: "VCB", memo: "chuyen tien" }]
        }, container, mockDoc);
    } catch (e) {
        imgError = e.message;
    }

    console.log(JSON.stringify({
        caughtError,
        urlAnalysisError,
        netError,
        imgError,
        cardBuilt: Boolean(card),
        hasHops: Boolean(card && card.querySelector(".redirect-hop-item")),
        hasSignals: Boolean(card && card.querySelector(".signal-item"))
    }));
    """
    res = run_node_eval(script)
    assert res["caughtError"] is None
    assert res["urlAnalysisError"] is None
    assert res["netError"] is None
    assert res["imgError"] is None
    assert res["cardBuilt"] is True
    assert res["hasHops"] is True
    assert res["hasSignals"] is True


# ─────────────────────────────────────────────────────────────────────────────
# 5. S3: CSS Rule Test — Mọi class JS tạo đều có selector trong styles.css
# ─────────────────────────────────────────────────────────────────────────────

def test_css_classes_match_styles():
    with open(APP_JS, "r", encoding="utf-8") as f:
        app_js = f.read()
    with open(UI_RENDER_JS, "r", encoding="utf-8") as f:
        ui_js = f.read()
    with open(STYLES_CSS, "r", encoding="utf-8") as f:
        css = f.read()

    classes = set()
    for code in (app_js, ui_js):
        for m in re.finditer(r'className\s*=\s*["`\']([^"`\']+)["`\']', code):
            for c in m.group(1).split():
                if c and not any(ch in c for ch in ["$", "{", "}", "+", "=", "?"]):
                    classes.add(c)
        for m in re.finditer(r'classList\.add\(\s*["`\']([^"`\']+)["`\']', code):
            classes.add(m.group(1))

    # Whitelist prefixes / suffixes intentionally dynamic
    ignored_patterns = {"activeSessionId", "severity-", "status-", "status-flag-", "risk-level-"}

    # The 18 classes required by S3 must all be present
    required_s3_classes = [
        "hitl-footer", "metric-sub", "metric-accent", "recs-box", "recs-title", "rec-item",
        "chat-headline-text", "chat-recommendations-list", "breakdown-title", "breakdown-pct",
        "user-msg-text", "empty-history-notice", "image-not-stored-notice", "emergency-title",
        "emergency-step-row", "qr-link-item", "status-item", "step-detail"
    ]
    for s3_cls in required_s3_classes:
        pat = r"\." + re.escape(s3_cls) + r"(?=[^-_a-zA-Z0-9]|$)"
        assert re.search(pat, css), f"Missing required S3 class in styles.css: {s3_cls}"

    missing = []
    for c in sorted(classes):
        if c in ignored_patterns or any(c.startswith(p) for p in ignored_patterns):
            continue
        pat = r"\." + re.escape(c) + r"(?=[^-_a-zA-Z0-9]|$)"
        if not re.search(pat, css):
            missing.append(c)

    assert len(missing) == 0, f"Classes generated in JS missing from styles.css: {missing}"


# ─────────────────────────────────────────────────────────────────────────────
# 6. S4 & d: index.html checks
# ─────────────────────────────────────────────────────────────────────────────

def test_index_html_security_and_structure():
    with open(INDEX_HTML, "r", encoding="utf-8") as f:
        html = f.read()

    # Strip HTML comments to avoid false matches on commented out scripts
    active_html = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)

    # ui_render.js must appear before app.js
    pos_ui = active_html.find('src="ui_render.js"')
    pos_app = active_html.find('src="app.js"')
    assert pos_ui != -1, "ui_render.js script missing or commented out in index.html"
    assert pos_app != -1, "app.js script missing in index.html"
    assert pos_ui < pos_app, "ui_render.js must appear before app.js in index.html"

    # No inline script (other than src="...")
    script_tags = re.findall(r"<script\b([^>]*)>(.*?)</script>", active_html, re.DOTALL | re.IGNORECASE)
    for attrs, body in script_tags:
        assert 'src="' in attrs, f"Inline script tag detected in index.html: {body[:100]}"
        assert body.strip() == "", f"Inline script body detected in index.html: {body[:100]}"

    # No inline style
    assert "<style" not in active_html.lower(), "Inline <style> tag detected in index.html"
    assert 'style="' not in active_html.lower(), "Inline style attribute detected in index.html"

    # No inline event handlers (onclick, onload, etc.)
    inline_handlers = re.findall(r'\bon[a-z]+\s*=\s*["\']', active_html, re.IGNORECASE)
    assert len(inline_handlers) == 0, f"Inline event handlers detected in index.html: {inline_handlers}"

    # Checkbox onlineCheckCheckbox must have autocomplete="off" and not be checked
    cb_match = re.search(r'<input\b[^>]*id=["\']onlineCheckCheckbox["\'][^>]*>', active_html, re.IGNORECASE)
    assert cb_match is not None, "onlineCheckCheckbox not found in index.html"
    cb_tag = cb_match.group(0)
    assert 'autocomplete="off"' in cb_tag, "onlineCheckCheckbox must have autocomplete='off'"
    assert "checked" not in cb_tag.lower(), "onlineCheckCheckbox must NOT be checked by default"


# ─────────────────────────────────────────────────────────────────────────────
# 7. S5: Pipeline Trace, Network Actions, LLM Status History Rules
# ─────────────────────────────────────────────────────────────────────────────

def test_pipeline_trace_separate_stages_and_llm_status():
    script = """
    const mockDoc = UIRender.createMockDocument();

    // 1. Pipeline Trace displays Stage A ms and Stage B ms separately
    const traceContainer = mockDoc.createElement("div");
    const trace = [
        { stage: "A_deterministic", ms: 12.5, status: "ok" },
        { stage: "B_network", ms: 45.2, status: "ok" },
        { stage: "B_llm", ms: 120.0, status: "ok" },
        { stage: "merge", ms: 1.2, status: "ok" }
    ];
    UIRender.renderPipelineTrace(trace, traceContainer, mockDoc);
    const traceTitle = traceContainer.querySelector(".pipeline-trace-header").textContent;

    // 2. Network actions with status 'skipped' renders 'bỏ qua'
    const netContainer = mockDoc.createElement("div");
    const netActions = [
        { type: "tls_probe", status: "skipped", target: "evil.com" }
    ];
    UIRender.renderNetworkActions(netActions, netContainer, mockDoc);
    const netTitle = netContainer.querySelector(".network-actions-title").textContent;
    const netStatusText = netContainer.querySelector(".act-status").textContent;

    // 3. LLM Status when model is offline
    const llmContainer = mockDoc.createElement("div");
    UIRender.renderLLMStatus({ model_used: "offline", llm_status: "ok" }, llmContainer, mockDoc);
    const llmText = llmContainer.textContent;

    // 4. LLM Status when keys are undefined (e.g. loaded from history)
    const historyContainer = mockDoc.createElement("div");
    UIRender.renderLLMStatus({ risk_score: 50 }, historyContainer, mockDoc);
    const historyChildrenCount = historyContainer.children.length;

    console.log(JSON.stringify({
        traceTitle,
        netTitle,
        netStatusText,
        llmText,
        historyChildrenCount
    }));
    """
    res = run_node_eval(script)

    # Stage A and Stage B displayed separately; Stage B is not added to Stage A
    assert "A: 12.5ms" in res["traceTitle"]
    assert "B: 120.0ms" in res["traceTitle"]
    assert "178.9" not in res["traceTitle"]

    # Network actions title has "Đã truy vấn / bỏ qua" and status renders "bỏ qua"
    assert "Đã truy vấn / bỏ qua" in res["netTitle"]
    assert res["netStatusText"] == "bỏ qua"

    # Offline model does not claim LLM ok
    assert "Chế độ: offline, không gọi LLM" in res["llmText"]
    assert "Trạng thái LLM: ok" not in res["llmText"]

    # History without keys does not render LLM status bar
    assert res["historyChildrenCount"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# 8. B1 Real Code Execution: app.js + ui_render.js in Node with VM
# ─────────────────────────────────────────────────────────────────────────────

def test_real_app_and_ui_render_in_node():
    """Execute real app.js and ui_render.js code in Node.js VM."""
    script = f"""
    const fs = require("fs");
    const vm = require("vm");

    const uiRenderCode = fs.readFileSync("{UI_RENDER_JS.replace('\\', '/')}", "utf8");
    const appCode = fs.readFileSync("{APP_JS.replace('\\', '/')}", "utf8");

    class MockElement {{
        constructor(tagName, id) {{
            this.tagName = String(tagName).toUpperCase();
            this.id = id || "";
            this.children = [];
            this.attributes = {{}};
            this.style = {{}};
            this.dataset = {{}};
            this._listeners = {{}};
            this._textContent = "";
            this.value = "";
            this.checked = false;
            this.parentNode = null;
            this.classList = {{
                _classes: new Set(),
                add: (...args) => args.forEach(c => c && this.classList._classes.add(String(c))),
                remove: (...args) => args.forEach(c => this.classList._classes.delete(String(c))),
                contains: (c) => this.classList._classes.has(String(c)),
                toggle: (c) => {{
                    if (this.classList.contains(c)) {{ this.classList.remove(c); return false; }}
                    this.classList.add(c); return true;
                }}
            }};
        }}
        remove() {{
            if (this.parentNode) {{
                this.parentNode.children = this.parentNode.children.filter(c => c !== this);
            }}
        }}
        get textContent() {{
            if (this.children && this.children.length > 0) {{
                return this.children.map(c => c.textContent || "").join("");
            }}
            return this._textContent;
        }}
        set textContent(val) {{ this._textContent = String(val); this.children = []; }}
        get innerHTML() {{ return this.textContent; }}
        set innerHTML(val) {{ this._textContent = String(val); }}
        get className() {{
            return Array.from(this.classList._classes).join(" ");
        }}
        set className(val) {{
            this.classList._classes = new Set(String(val || "").split(/\\s+/).filter(Boolean));
        }}
        appendChild(child) {{ if (child) {{ this.children.push(child); child.parentNode = this; }} return child; }}
        addEventListener(evt, fn) {{ this._listeners[evt] = this._listeners[evt] || []; this._listeners[evt].push(fn); }}
        dispatchEvent(evt) {{ (this._listeners[evt] || []).forEach(fn => fn({{ preventDefault: () => {{}} }})); }}
        click() {{ this.dispatchEvent("click"); }}
        _matches(sel) {{
            if (!sel) return false;
            if (sel.startsWith(".")) return this.classList.contains(sel.slice(1));
            if (sel.startsWith("#")) return this.id === sel.slice(1);
            return this.tagName.toLowerCase() === sel.toLowerCase();
        }}
        querySelector(sel) {{
            for (const c of this.children) {{
                if (c._matches(sel)) return c;
                const sub = c.querySelector(sel); if (sub) return sub;
            }}
            return null;
        }}
        querySelectorAll(sel) {{
            const res = [];
            for (const c of this.children) {{
                if (c._matches(sel)) res.push(c);
                res.push(...c.querySelectorAll(sel));
            }}
            return res;
        }}
    }}

    const elementsById = {{}};
    const getElem = (id, tag = "div") => {{
        if (!elementsById[id]) elementsById[id] = new MockElement(tag, id);
        return elementsById[id];
    }};

    [
        "btnNewChat", "sessionList", "landingView", "messagesContainer", "chatViewport",
        "chatInput", "btnSend", "fileInput", "filePreview", "fileNameText", "btnRemoveFile",
        "inputContainer", "onlineCheckCheckbox", "imageLightboxModal", "lightboxImage",
        "lightboxBackdrop", "lightboxCloseBtn", "lightboxCaption"
    ].forEach(id => getElem(id));

    const allFetchCalls = [];
    let nextResponse = {{
        ok: true,
        status: 200,
        headers: {{ get: () => null }},
        json: async () => ({{
            decision: {{
                intent_type: "scam_analysis",
                risk_level: "DANGEROUS_ATTEMPT",
                headline: "Phát hiện link độc hại"
            }},
            risk_score: 90,
            url_analysis: {{
                findings: [{{
                    raw: "https://evil.com/" + "A".repeat(1000),
                    verdict: "unverified",
                    url_risk_score: 85,
                    brand_match: {{ official_domain: "vietcombank\\x00.com.vn\\u202E" }},
                    redirect_chain: [{{ url: "https://evil\\x00.com/hop1\\u202E", status: 302 }}],
                    signals: [{{ severity: "CRITICAL_ATTACK", message_vi: "Lừa đảo evil-login.xyz", evidence: "host=vietcombank-xacminh.top\\u202E" }}],
                    obfuscation_chain: [{{ technique: "userinfo", detail_vi: "Mở evil-login.xyz\\u202E" }}],
                    passive_intel: {{
                        cert: {{
                            subject: "evil\\x00.com\\u202E",
                            issuer: "Let's Encrypt\\u202E",
                            san: ["san1\\x00.com\\u202E"]
                        }}
                    }}
                }}]
            }},
            network_actions: [{{ type: "resolve", status: "sent", target: "evil\\x00.com\\u202E" }}],
            image_analysis: {{
                qr_urls: ["https://qr\\x00.com\\u202E"],
                vietqr: [{{ bank_name: "VCB", name: "NGUYEN VAN A\\u202E", memo: "chuyen tien\\u202E" }}]
            }}
        }})
    }};

    const mockFetch = async (url, options) => {{
        const call = {{ url, options, body: options && options.body ? JSON.parse(options.body) : null }};
        allFetchCalls.push(call);
        if (url.includes("/api/sessions")) {{
            return {{ ok: true, status: 200, json: async () => [] }};
        }}
        return nextResponse;
    }};

    let domContentLoadedHandler = null;
    const sandbox = {{
        console,
        crypto: {{ randomUUID: () => "00000000-0000-4000-8000-000000000000" }},
        localStorage: {{ getItem: () => null, setItem: () => {{}} }},
        fetch: mockFetch,
        document: {{
            getElementById: (id) => getElem(id),
            createElement: (tag) => new MockElement(tag),
            createTextNode: (txt) => ({{ textContent: String(txt || "") }}),
            addEventListener: (evt, fn) => {{ if (evt === "DOMContentLoaded") domContentLoadedHandler = fn; }}
        }},
        setTimeout: (fn) => fn(),
        clearTimeout: () => {{}}
    }};
    sandbox.window = sandbox;
    sandbox.globalThis = sandbox;

    vm.createContext(sandbox);
    vm.runInContext(uiRenderCode, sandbox);
    vm.runInContext(appCode, sandbox);

    if (domContentLoadedHandler) domContentLoadedHandler();

    (async () => {{
        // 1. Test Send with Default Checkbox (false)
        getElem("chatInput").value = "Kiểm tra mặc định";
        getElem("btnSend").click();
        await new Promise(r => setImmediate(r));

        const call1 = allFetchCalls.find(c => c.url === "/api/analyze");
        const onlineCheckDefault = call1 ? call1.body.online_check : null;
        const onlineCheckTypeDefault = typeof onlineCheckDefault;
        const checkboxResetAfterSend = getElem("onlineCheckCheckbox").checked;

        // 2. Test Send with Checked Checkbox (true)
        getElem("onlineCheckCheckbox").checked = true;
        getElem("chatInput").value = "Kiểm tra bật mạng";
        getElem("btnSend").click();
        await new Promise(r => setImmediate(r));

        const call2 = allFetchCalls.filter(c => c.url === "/api/analyze")[1];
        const onlineCheckActive = call2 ? call2.body.online_check : null;
        const onlineCheckTypeActive = typeof onlineCheckActive;
        const checkboxResetAfterSend2 = getElem("onlineCheckCheckbox").checked;

        // 3. Test Reset on New Chat and Switch Session
        getElem("onlineCheckCheckbox").checked = true;
        getElem("btnNewChat").click();
        const checkboxResetAfterNewChat = getElem("onlineCheckCheckbox").checked;

        // 4. Assert individual fields rendered inside messagesContainer
        const msgContainer = getElem("messagesContainer");
        const rawValEl = msgContainer.querySelector(".link-display-value");
        const displayRawText = rawValEl ? rawValEl.textContent : "";

        const hopEl = msgContainer.querySelector(".hop-url");
        const hopText = hopEl ? hopEl.textContent : "";

        const netTargetEl = msgContainer.querySelector(".act-target");
        const netTargetText = netTargetEl ? netTargetEl.textContent : "";

        const qrEl = msgContainer.querySelector(".qr-link-item");
        const qrText = qrEl ? qrEl.textContent : "";

        const brandEl = msgContainer.querySelector(".brand-domain-text");
        const brandText = brandEl ? brandEl.textContent : "";

        const vietqrValues = msgContainer.querySelectorAll(".vietqr-value");
        const vietqrTexts = vietqrValues.map(v => v.textContent);

        const certSubjEl = msgContainer.querySelector(".cert-subject");
        const certSubjText = certSubjEl ? certSubjEl.textContent : "";

        const certIssEl = msgContainer.querySelector(".cert-issuer");
        const certIssText = certIssEl ? certIssEl.textContent : "";

        const certSanEl = msgContainer.querySelector(".cert-san");
        const certSanText = certSanEl ? certSanEl.textContent : "";

        const sigEvEl = msgContainer.querySelector(".signal-evidence");
        const sigEvText = sigEvEl ? sigEvEl.textContent : "";

        const sigMsgEl = msgContainer.querySelector(".signal-message");
        const sigMsgText = sigMsgEl ? sigMsgEl.textContent : "";

        const stepDetailEl = msgContainer.querySelector(".step-detail");
        const stepDetailText = stepDetailEl ? stepDetailEl.textContent : "";

        const u4Box = msgContainer.querySelector(".unverified-guide-box");
        const hasU4 = Boolean(u4Box);

        const riskHeaderEl = msgContainer.querySelector(".risk-header");
        const riskHeaderClass = riskHeaderEl ? riskHeaderEl.className : "";

        console.log(JSON.stringify({{
            onlineCheckDefault,
            onlineCheckTypeDefault,
            checkboxResetAfterSend,
            onlineCheckActive,
            onlineCheckTypeActive,
            checkboxResetAfterSend2,
            checkboxResetAfterNewChat,
            displayRawTextLength: displayRawText.length,
            displayRawText,
            hopText,
            netTargetText,
            qrText,
            brandText,
            vietqrTexts,
            certSubjText,
            certIssText,
            certSanText,
            sigEvText,
            sigMsgText,
            stepDetailText,
            hasU4,
            riskHeaderClass
        }}));
    }})();
    """
    node_exe = shutil.which("node") or "node"
    proc = subprocess.run([node_exe, "-e", script], capture_output=True, text=True, cwd=ROOT_DIR, timeout=20, encoding="utf-8")
    assert proc.returncode == 0, f"Node script failed: {proc.stderr}\n{proc.stdout}"
    res = json.loads(proc.stdout.strip())

    # (a) online_check is boolean, default false, reset after send and new chat
    assert res["onlineCheckDefault"] is False
    assert res["onlineCheckTypeDefault"] == "boolean"
    assert res["checkboxResetAfterSend"] is False
    assert res["onlineCheckActive"] is True
    assert res["onlineCheckTypeActive"] == "boolean"
    assert res["checkboxResetAfterSend2"] is False
    assert res["checkboxResetAfterNewChat"] is False

    # (f) 'Bạn thấy' length truncated (max 300 before defanging bracket expansion, so <= 320 instead of 1000)
    assert res["displayRawTextLength"] <= 320
    assert res["displayRawTextLength"] < 500

    # (b) Every server field has its own assertion proving sanitize/defang:
    # 1. redirect_chain hop: defanged (hxxps, [.]), no \x00, no \u202E
    assert "\x00" not in res["hopText"]
    assert "\u202E" not in res["hopText"]
    assert "hxxps://evil[.]com" in res["hopText"]

    # 2. network_actions target: defanged, no \x00, no \u202E
    assert "\x00" not in res["netTargetText"]
    assert "\u202E" not in res["netTargetText"]
    assert "evil[.]com" in res["netTargetText"]

    # 3. qr_urls: defanged, no \x00, no \u202E
    assert "\x00" not in res["qrText"]
    assert "\u202E" not in res["qrText"]
    assert "hxxps://qr[.]com" in res["qrText"]

    # 4. brand_match.official_domain: defanged, no \x00, no \u202E
    assert "\x00" not in res["brandText"]
    assert "\u202E" not in res["brandText"]
    assert "vietcombank[.]com[.]vn" in res["brandText"]

    # 5. VietQR name / memo: no \u202E
    assert len(res["vietqrTexts"]) > 0
    for v_text in res["vietqrTexts"]:
        assert "\u202E" not in v_text

    # 6. cert subject/SAN/issuer: defanged, no \x00, no \u202E
    assert "\x00" not in res["certSubjText"]
    assert "\u202E" not in res["certSubjText"]
    assert "evil[.]com" in res["certSubjText"]
    assert "\u202E" not in res["certIssText"]
    assert "\x00" not in res["certSanText"]
    assert "\u202E" not in res["certSanText"]
    assert "san1[.]com" in res["certSanText"]

    # 7. signals.evidence: defanged, no \u202E
    assert "\u202E" not in res["sigEvText"]
    assert "vietcombank-xacminh[.]top" in res["sigEvText"]
    assert "evil-login[.]xyz" in res["sigMsgText"]

    # 8. obfuscation_chain detail_vi: defanged, no \u202E
    assert "\u202E" not in res["stepDetailText"]
    assert "evil-login[.]xyz" in res["stepDetailText"]

    # (e) U4 box appears for unverified
    assert res["hasU4"] is True

    # N Nit: Whitelist className (DANGEROUS_ATTEMPT is invalid risk level -> mapped to unknown)
    assert "risk-level-unknown" in res["riskHeaderClass"]


# ─────────────────────────────────────────────────────────────────────────────
# 9. S6: HTTP Error Status Handling in app.js
# ─────────────────────────────────────────────────────────────────────────────

def test_http_error_reporting_in_app():
    """Verify app.js handles 429 (with Retry-After), 413, 400, 503, 5xx, and network error."""
    script = f"""
    const fs = require("fs");
    const vm = require("vm");
    const uiRenderCode = fs.readFileSync("{UI_RENDER_JS.replace('\\', '/')}", "utf8");
    const appCode = fs.readFileSync("{APP_JS.replace('\\', '/')}", "utf8");

    class MockElement {{
        constructor(tagName, id) {{
            this.tagName = String(tagName).toUpperCase();
            this.id = id || "";
            this.children = [];
            this.attributes = {{}};
            this.style = {{}};
            this.classList = {{
                _classes: new Set(),
                add: (...args) => args.forEach(c => c && this.classList._classes.add(String(c))),
                remove: (...args) => args.forEach(c => this.classList._classes.delete(String(c))),
                contains: (c) => this.classList._classes.has(String(c))
            }};
            this._listeners = {{}};
            this._textContent = "";
            this.value = "";
            this.checked = false;
        }}
        remove() {{}}
        get textContent() {{
            if (this.children && this.children.length > 0) {{
                return this.children.map(c => c.textContent || "").join("");
            }}
            return this._textContent;
        }}
        set textContent(val) {{ this._textContent = String(val); this.children = []; }}
        get innerHTML() {{ return this.textContent; }}
        set innerHTML(val) {{ this._textContent = String(val); }}
        get className() {{
            return Array.from(this.classList._classes).join(" ");
        }}
        set className(val) {{
            this.classList._classes = new Set(String(val || "").split(/\\s+/).filter(Boolean));
        }}
        appendChild(child) {{ this.children.push(child); return child; }}
        addEventListener(evt, fn) {{ this._listeners[evt] = this._listeners[evt] || []; this._listeners[evt].push(fn); }}
        dispatchEvent(evt) {{ (this._listeners[evt] || []).forEach(fn => fn({{ preventDefault: () => {{}} }})); }}
        click() {{ this.dispatchEvent("click"); }}
        _matches(sel) {{
            if (!sel) return false;
            if (sel.startsWith(".")) return this.classList.contains(sel.slice(1));
            if (sel.startsWith("#")) return this.id === sel.slice(1);
            return this.tagName.toLowerCase() === sel.toLowerCase();
        }}
        querySelector(sel) {{
            for (const c of this.children) {{
                if (c._matches(sel)) return c;
                const sub = c.querySelector(sel);
                if (sub) return sub;
            }}
            return null;
        }}
    }}

    async function testStatus(status, retryAfterVal, networkError = false) {{
        const localElems = {{
            chatInput: new MockElement("input", "chatInput"),
            messagesContainer: new MockElement("div", "messagesContainer"),
            chatViewport: new MockElement("div", "chatViewport"),
            btnSend: new MockElement("button", "btnSend")
        }};
        let fetchFn;
        if (networkError) {{
            fetchFn = async () => {{ throw new Error("Failed to fetch"); }};
        }} else {{
            fetchFn = async (url) => {{
                if (url.includes("/api/sessions")) return {{ ok: true, status: 200, json: async () => [] }};
                return {{
                    ok: false,
                    status: status,
                    headers: {{ get: (k) => k.toLowerCase() === "retry-after" ? retryAfterVal : null }}
                }};
            }};
        }}

        let domHandler = null;
        const sandbox = {{
            console,
            crypto: {{ randomUUID: () => "00000000-0000-4000-8000-000000000000" }},
            localStorage: {{ getItem: () => null, setItem: () => {{}} }},
            fetch: fetchFn,
            document: {{
                getElementById: (id) => localElems[id] || new MockElement("div", id),
                createElement: (t) => new MockElement(t),
                createTextNode: (t) => ({{ textContent: t }}),
                addEventListener: (evt, fn) => {{ if (evt === "DOMContentLoaded") domHandler = fn; }}
            }},
            setTimeout: (fn) => setTimeout(fn, 0),
            clearTimeout: () => {{}}
        }};
        sandbox.window = sandbox;
        sandbox.globalThis = sandbox;

        vm.createContext(sandbox);
        vm.runInContext(uiRenderCode, sandbox);
        vm.runInContext(appCode, sandbox);
        if (domHandler) domHandler();

        localElems.chatInput.value = "test message";
        const btnSend = sandbox.document.getElementById("btnSend");
        btnSend.click();

        await new Promise(r => setTimeout(r, 20));

        const headlineEl = localElems.messagesContainer.querySelector(".chat-headline-text");
        return headlineEl ? headlineEl.textContent : "";
    }}

    (async () => {{
        const r429_retry = await testStatus(429, "15");
        const r429_no_retry = await testStatus(429, null);
        const r413 = await testStatus(413, null);
        const r400 = await testStatus(400, null);
        const r503 = await testStatus(503, null);
        const r500 = await testStatus(500, null);
        const netErr = await testStatus(0, null, true);

        console.log(JSON.stringify({{
            r429_retry,
            r429_no_retry,
            r413,
            r400,
            r503,
            r500,
            netErr
        }}));
    }})();
    """
    node_exe = shutil.which("node") or "node"
    proc = subprocess.run([node_exe, "-e", script], capture_output=True, text=True, cwd=ROOT_DIR, timeout=15, encoding="utf-8")
    assert proc.returncode == 0, f"Error test failed: {proc.stderr}\n{proc.stdout}"
    res = json.loads(proc.stdout.strip())

    assert "Gửi quá nhanh, thử lại sau 15 giây" in res["r429_retry"]
    assert "Gửi quá nhanh, thử lại sau" in res["r429_no_retry"]
    assert "Ảnh/nội dung quá lớn" in res["r413"]
    assert "Dữ liệu không hợp lệ" in res["r400"]
    assert "Server đang bận" in res["r503"]
    assert "Lỗi hệ thống máy chủ (500)" in res["r500"]
    assert "Không kết nối được" in res["netErr"]


# ─────────────────────────────────────────────────────────────────────────────
# 10. B1: 21 Real Code Mutations — 0 Survivors
# ─────────────────────────────────────────────────────────────────────────────

def test_mutation_testing_fifteen_real_mutants_zero_survivors():
    """
    Applies >= 15 REAL mutations directly to public/ source files.
    Every single mutation MUST be caught and killed by the test suite.
    Each mutation is restored immediately in a finally block.
    Total survivors MUST be 0.
    """
    mutations = [
        # 1. Bỏ sanitize ở redirect_chain hop
        (
            UI_RENDER_JS,
            'defangUrl(sanitizeText(hop.url || "", 300))',
            'defangUrl(hop.url || "")',
            'test_real_app_and_ui_render_in_node',
        ),
        # 2. Bỏ sanitize ở network_actions target
        (
            UI_RENDER_JS,
            'defangHost(sanitizeText(act.target || "none", 100))',
            'defangHost(act.target || "none")',
            'test_real_app_and_ui_render_in_node',
        ),
        # 3. Bỏ sanitize ở qr_urls
        (
            UI_RENDER_JS,
            'defangUrl(sanitizeText(u, 300))',
            'defangUrl(u)',
            'test_real_app_and_ui_render_in_node',
        ),
        # 4. Bỏ sanitize ở brand_match.official_domain
        (
            UI_RENDER_JS,
            'defangHost(sanitizeText(finding.brand_match.official_domain, 100))',
            'defangHost(finding.brand_match.official_domain)',
            'test_real_app_and_ui_render_in_node',
        ),
        # 5. Bỏ sanitize ở VietQR tên/memo
        (
            UI_RENDER_JS,
            'vl.textContent = sanitizeText(val, 150);',
            'vl.textContent = String(val);',
            'test_real_app_and_ui_render_in_node',
        ),
        # 6. Bỏ sanitize ở cert subject
        (
            UI_RENDER_JS,
            'defangHost(sanitizeText(subjectVal, 150))',
            'defangHost(subjectVal)',
            'test_real_app_and_ui_render_in_node',
        ),
        # 7. Bỏ sanitize ở signals.evidence
        (
            UI_RENDER_JS,
            'defangText(sanitizeText(sig.evidence, 200))',
            'defangText(sig.evidence)',
            'test_real_app_and_ui_render_in_node',
        ),
        # 8. Bỏ sanitize ở detail_vi
        (
            UI_RENDER_JS,
            'defangText(sanitizeText(step.detail_vi || "", 300))',
            'defangText(step.detail_vi || "")',
            'test_real_app_and_ui_render_in_node',
        ),
        # 9. Giữ RLO U+202E (bỏ strip RLO trong sanitizeText)
        (
            UI_RENDER_JS,
            'str = str.replace(/[\\u202A-\\u202E\\u2066-\\u2069\\u200E\\u200F\\u061C]/g, "");',
            'str = str.replace(/[\\u202A-\\u202D\\u2066-\\u2069\\u200E\\u200F\\u061C]/g, "");',
            'test_sanitize_text_vectors',
        ),
        # 10. Bỏ lọc zero-width (bỏ strip ZWSP trong sanitizeText)
        (
            UI_RENDER_JS,
            'str = str.replace(/[\\u200B-\\u200D\\uFEFF\\u00AD\\u2028\\u2029\\u2060\\u180E\\u034F]/g, "");',
            '/* no zwsp removal */',
            'test_sanitize_text_vectors',
        ),
        # 11. Bỏ defang redirect hop
        (
            UI_RENDER_JS,
            'hopUrl.textContent = defangUrl(sanitizeText(hop.url || "", 300));',
            'hopUrl.textContent = sanitizeText(hop.url || "", 300);',
            'test_real_app_and_ui_render_in_node',
        ),
        # 12. Bỏ defang qr_urls
        (
            UI_RENDER_JS,
            'item.textContent = "• " + defangUrl(sanitizeText(u, 300));',
            'item.textContent = "• " + sanitizeText(u, 300);',
            'test_real_app_and_ui_render_in_node',
        ),
        # 13. Bỏ defang official_domain
        (
            UI_RENDER_JS,
            'domainVal.textContent = defangHost(sanitizeText(finding.brand_match.official_domain, 100));',
            'domainVal.textContent = sanitizeText(finding.brand_match.official_domain, 100);',
            'test_real_app_and_ui_render_in_node',
        ),
        # 14. Bỏ cắt độ dài trong sanitizeText
        (
            UI_RENDER_JS,
            'if (str.length > max) {\n            str = str.slice(0, max);\n        }',
            '/* no length slice */',
            'test_sanitize_text_vectors',
        ),
        # 15. Bỏ giới hạn 10 thẻ (render tất cả findings)
        (
            UI_RENDER_JS,
            'const renderedFindings = findings.slice(0, maxCards);',
            'const renderedFindings = findings;',
            'test_build_link_card_no_anchor_and_no_innerhtml',
        ),
        # 16. app.js gửi "true" thay vì boolean
        (
            APP_JS,
            'const isOnlineCheck = Boolean(onlineCheckCheckbox && onlineCheckCheckbox.checked);',
            'const isOnlineCheck = onlineCheckCheckbox && onlineCheckCheckbox.checked ? "true" : "false";',
            'test_real_app_and_ui_render_in_node',
        ),
        # 17. Dùng insertAdjacentHTML cho headline
        (
            APP_JS,
            'headlineEl.textContent = headline;',
            'headlineEl.insertAdjacentHTML("beforeend", headline);',
            'test_source_code_innerhtml_audit',
        ),
        # 18. Bỏ render thẻ link (comment out renderUrlAnalysis)
        (
            APP_JS,
            'UIRender.renderUrlAnalysis(res.url_analysis, content);',
            '/* UIRender.renderUrlAnalysis(res.url_analysis, content); */',
            'test_real_app_and_ui_render_in_node',
        ),
        # 19. Bỏ script ui_render.js khỏi index.html
        (
            INDEX_HTML,
            '<script src="ui_render.js"></script>',
            '<!-- removed ui_render.js -->',
            'test_index_html_security_and_structure',
        ),
        # 20. Checkbox mặc định checked
        (
            INDEX_HTML,
            '<input type="checkbox" id="onlineCheckCheckbox" autocomplete="off">',
            '<input type="checkbox" id="onlineCheckCheckbox" checked autocomplete="off">',
            'test_index_html_security_and_structure',
        ),
        # 21. Bỏ hộp U4
        (
            UI_RENDER_JS,
            'if (isUnverified || hasBotError) {',
            'if (false) {',
            'test_real_app_and_ui_render_in_node',
        ),
    ]

    assert len(mutations) >= 15, f"Expected >= 15 mutations, got {len(mutations)}"

    killed = 0
    survivors = []

    # Map target test name to callable
    test_dispatch = {
        'test_real_app_and_ui_render_in_node': test_real_app_and_ui_render_in_node,
        'test_sanitize_text_vectors': test_sanitize_text_vectors,
        'test_source_code_innerhtml_audit': test_source_code_innerhtml_audit,
        'test_index_html_security_and_structure': test_index_html_security_and_structure,
        'test_build_link_card_no_anchor_and_no_innerhtml': None,
    }

    for idx, (filepath, target_str, mutated_str, test_name) in enumerate(mutations, start=1):
        with open(filepath, "r", encoding="utf-8") as f:
            original_code = f.read()

        assert target_str in original_code, (
            f"Mutant {idx} target string not found in {os.path.basename(filepath)}:\n{target_str[:80]}"
        )

        try:
            mutated_code = original_code.replace(target_str, mutated_str, 1)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(mutated_code)

            # Run the test that is supposed to catch this mutant
            caught = False
            try:
                if test_name == 'test_build_link_card_no_anchor_and_no_innerhtml':
                    script = """
                    const mockDoc = UIRender.createMockDocument();
                    const container = mockDoc.createElement("div");
                    const fifteen = [];
                    for (let i = 0; i < 15; i++) {
                        fifteen.push({ raw: "http://evil" + i + ".com", url_risk_score: 50, verdict: "suspicious" });
                    }
                    UIRender.renderUrlAnalysis({ findings: fifteen }, container, mockDoc);
                    const cards = container.querySelectorAll(".link-analysis-card");
                    console.log(JSON.stringify({ cardCount: cards.length }));
                    """
                    r = run_node_eval(script)
                    assert r["cardCount"] == 10, f"Card count was {r['cardCount']}, expected 10"
                else:
                    fn = test_dispatch.get(test_name)
                    assert fn is not None, f"Unknown test dispatch: {test_name}"
                    fn()
            except (AssertionError, RuntimeError, Exception):
                caught = True

            if caught:
                killed += 1
            else:
                survivors.append(f"Mutant #{idx}: {target_str[:40]} -> {mutated_str[:40]}")

        finally:
            # Restore original code immediately
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(original_code)

    assert len(survivors) == 0, f"Mutants survived ({len(survivors)}): {survivors}"
    assert killed == len(mutations)
