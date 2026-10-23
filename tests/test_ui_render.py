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
        setAttribute(n, v) {{ this.attributes[String(n)] = String(v); }}
        getAttribute(n) {{ return this.attributes[String(n)] === undefined ? null : this.attributes[String(n)]; }}
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
        setAttribute(n, v) {{ this.attributes[String(n)] = String(v); }}
        getAttribute(n) {{ return this.attributes[String(n)] === undefined ? null : this.attributes[String(n)]; }}
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
# 10. Shared harness: REAL app.js + ui_render.js in node vm with fake DOM + fetch mock
# ─────────────────────────────────────────────────────────────────────────────

HARNESS_JS = r"""
const fs = require("fs");
const vm = require("vm");
const PATHS = __PATHS__;
const uiRenderCode = fs.readFileSync(PATHS.ui, "utf8");
const appCode = fs.readFileSync(PATHS.app, "utf8");
const innerHTMLWrites = [];
const consoleErrors = [];
const registry = {};

class MockElement {
    constructor(tagName, id) {
        this.tagName = String(tagName).toUpperCase();
        this.children = [];
        this.attributes = {};
        this.style = {};
        this.dataset = {};
        this._listeners = {};
        this._textContent = "";
        this.value = "";
        this.checked = false;
        this.disabled = false;
        this.open = false;
        this.parentNode = null;
        this.id = id || "";
        this.classList = {
            _classes: new Set(),
            add: (...a) => a.forEach(c => c && this.classList._classes.add(String(c))),
            remove: (...a) => a.forEach(c => this.classList._classes.delete(String(c))),
            contains: (c) => this.classList._classes.has(String(c)),
            toggle: (c) => { if (this.classList.contains(c)) { this.classList.remove(c); return false; } this.classList.add(c); return true; }
        };
    }
    remove() {
        if (this.parentNode) this.parentNode.children = this.parentNode.children.filter(c => c !== this);
        if (this.id && registry[this.id] === this) delete registry[this.id];
    }
    get textContent() {
        if (this.children.length > 0) return this.children.map(c => c.textContent || "").join("");
        return this._textContent;
    }
    set textContent(v) { this._textContent = String(v); this.children = []; }
    get innerHTML() { return this.textContent; }
    set innerHTML(v) { innerHTMLWrites.push(String(v)); this._textContent = String(v); this.children = []; }
    get className() { return Array.from(this.classList._classes).join(" "); }
    set className(v) { this.classList._classes = new Set(String(v || "").split(/\s+/).filter(Boolean)); }
    setAttribute(n, v) { this.attributes[String(n)] = String(v); if (String(n) === "open") this.open = true; }
    getAttribute(n) { return this.attributes[String(n)] === undefined ? null : this.attributes[String(n)]; }
    removeAttribute(n) { delete this.attributes[String(n)]; if (String(n) === "open") this.open = false; }
    appendChild(child) {
        if (!child) return child;
        this.children.push(child);
        child.parentNode = this;
        if (child.id) registry[child.id] = child;
        return child;
    }
    addEventListener(evt, fn) { (this._listeners[evt] = this._listeners[evt] || []).push(fn); }
    dispatchEvent(evt, extra) {
        (this._listeners[evt] || []).forEach(fn => fn(Object.assign({ preventDefault() {}, stopPropagation() {}, currentTarget: this, target: this }, extra || {})));
    }
    click() { this.dispatchEvent("click"); }
    _matches(sel) {
        if (!sel) return false;
        if (sel.startsWith(".")) return this.classList.contains(sel.slice(1));
        if (sel.startsWith("#")) return this.id === sel.slice(1);
        return this.tagName.toLowerCase() === sel.toLowerCase();
    }
    querySelector(sel) {
        for (const c of this.children) {
            if (c._matches(sel)) return c;
            const sub = c.querySelector(sel);
            if (sub) return sub;
        }
        return null;
    }
    querySelectorAll(sel) {
        const out = [];
        for (const c of this.children) {
            if (c._matches(sel)) out.push(c);
            out.push(...c.querySelectorAll(sel));
        }
        return out;
    }
}

// Text a user can see WITHOUT opening <details> (details subtree is skipped entirely)
function visibleText(el) {
    if (el.tagName === "DETAILS") return "";
    if (el.children.length === 0) return el._textContent || "";
    return el.children.map(visibleText).join(" | ");
}
function allText(el) {
    if (el.children.length === 0) return el._textContent || "";
    return el.children.map(allText).join(" | ");
}
function walkAll(el, fn) { fn(el); el.children.forEach(c => walkAll(c, fn)); }
// nodes with class `cls` that are NOT inside any <details>
function outsideDetails(el, cls) {
    const out = [];
    (function rec(n) {
        if (n.tagName === "DETAILS") return;
        if (n.classList.contains(cls)) out.push(n);
        n.children.forEach(rec);
    })(el);
    return out;
}

async function flush() { for (let i = 0; i < 6; i++) await new Promise(r => setImmediate(r)); }

function makeApp(handler) {
    const ids = ["btnNewChat", "sessionList", "landingView", "messagesContainer", "chatViewport",
        "chatInput", "btnSend", "fileInput", "filePreview", "fileNameText", "btnRemoveFile",
        "inputContainer", "onlineCheckCheckbox", "imageLightboxModal", "lightboxImage",
        "lightboxBackdrop", "lightboxCloseBtn", "lightboxCaption"];
    ids.forEach(id => { registry[id] = new MockElement("div", id); });
    const getElem = (id) => registry[id];
    const calls = [];
    const docListeners = {};
    const sandbox = {
        console: { log() {}, warn() {}, info() {}, error: (...a) => consoleErrors.push(a.map(String).join(" ")) },
        crypto: { randomUUID: () => "00000000-0000-4000-8000-000000000000" },
        localStorage: { getItem: () => null, setItem: () => {} },
        fetch: async (url, opts) => {
            if (String(url).includes("/api/sessions")) return { ok: true, status: 200, json: async () => [] };
            if (url === "/api/analyze") {
                const body = JSON.parse(opts.body);
                calls.push({ url, body });
                const payload = await handler(body, calls.length);
                return { ok: true, status: 200, headers: { get: () => null }, json: async () => payload };
            }
            return { ok: false, status: 404, headers: { get: () => null } };
        },
        document: {
            getElementById: (id) => registry[id] || null,
            createElement: (t) => new MockElement(t),
            createTextNode: (t) => ({ textContent: String(t) }),
            addEventListener: (evt, fn) => { (docListeners[evt] = docListeners[evt] || []).push(fn); },
            querySelector: () => null
        },
        setTimeout: (fn) => fn(),
        clearTimeout: () => {}
    };
    sandbox.window = sandbox;
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(uiRenderCode, sandbox);
    vm.runInContext(appCode, sandbox);
    (docListeners["DOMContentLoaded"] || []).forEach(fn => fn());
    const app = {
        getElem, calls, docListeners, sandbox,
        async send(text, opts) {
            getElem("chatInput").value = text;
            if (opts && opts.online) getElem("onlineCheckCheckbox").checked = true;
            getElem("btnSend").click();
            await flush();
        },
        lastContent() {
            const rows = getElem("messagesContainer").children.filter(r => r.classList.contains("assistant") && !r.classList.contains("thinking-row"));
            const row = rows[rows.length - 1];
            return row ? row.children[1] : null;
        }
    };
    return app;
}

function mkRes(over) {
    return Object.assign({
        decision: { intent_type: "scam_analysis", risk_level: "LOW", headline: "Tiêu đề kiểm tra", recommendations: [] },
        risk_score: 10,
        confidence: { confidence_score: 80, confidence_level: "HIGH" },
        latency_ms: 12,
        model_used: "offline",
        llm_status: "ok",
        pipeline_trace: [{ stage: "A_deterministic", ms: 3.2, status: "ok" }, { stage: "merge", ms: 0.4, status: "ok" }],
        network_actions: [{ type: "resolve", status: "skipped", target: "evil-login.xyz" }]
    }, over || {});
}
const out = (o) => process.stdout.write(JSON.stringify(o) + "\n");
"""


def run_app_node(body_js: str, timeout_s: float = 40.0) -> dict:
    """Run a JS scenario against the REAL public/app.js + public/ui_render.js inside node vm."""
    node_exe = shutil.which("node") or "node"
    paths = json.dumps({"ui": UI_RENDER_JS, "app": APP_JS})
    script = (
        HARNESS_JS.replace("__PATHS__", paths)
        + "\n(async () => {\ntry {\n"
        + body_js
        + "\n} catch (e) { process.stderr.write(String(e && e.stack || e)); process.exit(2); }\n})();\n"
    )
    proc = subprocess.run(
        [node_exe, "-"],
        input=script,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout_s,
        cwd=ROOT_DIR,
    )
    assert proc.returncode == 0, f"node scenario failed: {proc.stderr}\n{proc.stdout}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


CONCLUSION_TEXT = {
    "CRITICAL": "DỪNG LẠI NGAY — Đừng chuyển thêm tiền. Gọi ngay ngân hàng của bạn hoặc 113.",
    "HIGH": "DỪNG LẠI — KHÔNG chuyển tiền, KHÔNG bấm link, KHÔNG đưa mã OTP.",
    "MEDIUM": "CẨN THẬN — Chưa nên làm theo tin này. Hãy gọi số điện thoại chính thức của nơi gửi để hỏi lại.",
    "LOW": "CHƯA THẤY DẤU HIỆU LỪA ĐẢO — Nhưng vẫn không chia sẻ mã OTP, mật khẩu cho bất kỳ ai.",
    "UNVERIFIED": "CHƯA KIỂM TRA ĐƯỢC LINK — Đừng coi là an toàn. Đừng bấm vào.",
}
FORBIDDEN_WORDS = ["defang", "combosquat", "homoglyph", "redirect", "typosquat", "obfuscation"]


# ─────────────────────────────────────────────────────────────────────────────
# C1. app.js calls renderActionConclusion; the conclusion is the FIRST element
# ─────────────────────────────────────────────────────────────────────────────

def test_c1_action_conclusion_is_first_with_exact_strings_and_aria():
    res = run_app_node(r"""
    const mk = (risk, extra) => mkRes(Object.assign({
        decision: { intent_type: "scam_analysis", risk_level: risk, headline: "H", recommendations: ["Làm theo hướng dẫn chính thức"] }
    }, extra || {}));
    const unverifiedLink = { url_analysis: { summary_vi: [], findings: [{ raw: "http://x.example/a", verdict: "unverified", url_risk_score: 0, network_used: false, signals: [] }] } };
    const scenarios = {
        LOW: mk("LOW"),
        MEDIUM: mk("MEDIUM"),
        HIGH: mk("HIGH"),
        CRITICAL: mk("CRITICAL"),
        EMERGENCY: mk("LOW", { emergency: { is_emergency: true, protocol_steps: [{ time_window: "0-5 phút", action: "Gọi ngân hàng" }] } }),
        UNVERIFIED: mk("LOW", unverifiedLink),
        MEDIUM_UNVERIFIED: mk("MEDIUM", unverifiedLink)
    };
    const app = makeApp(async (body) => scenarios[body.user_text]);
    const result = {};
    for (const k of Object.keys(scenarios)) {
        await app.send(k);
        const c = app.lastContent();
        const first = c.children[0];
        const textEl = first.querySelector(".action-conclusion-text");
        const iconEl = first.querySelector(".action-conclusion-icon");
        result[k] = {
            firstClass: first.className,
            text: textEl ? textEl.textContent : null,
            textTag: textEl ? textEl.tagName : null,
            icon: iconEl ? iconEl.textContent : null,
            role: first.getAttribute("role"),
            ariaLive: first.getAttribute("aria-live"),
            nConclusionBlocks: c.querySelectorAll(".action-conclusion").length,
            childClasses: c.children.map(x => x.className)
        };
    }
    out({ result, consoleErrors });
    """)
    assert res["consoleErrors"] == []
    expected = {
        "LOW": "LOW", "MEDIUM": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL",
        "EMERGENCY": "CRITICAL", "UNVERIFIED": "UNVERIFIED", "MEDIUM_UNVERIFIED": "UNVERIFIED",
    }
    for key, level in expected.items():
        r = res["result"][key]
        assert "action-conclusion" in r["firstClass"].split(), f"{key}: first child is {r['childClasses'][:3]}"
        assert r["text"] == CONCLUSION_TEXT[level], f"{key}: {r['text']!r}"
        assert r["icon"], f"{key}: conclusion needs an icon (not colour alone)"
        assert r["nConclusionBlocks"] == 1
        if level in ("HIGH", "CRITICAL"):
            assert r["role"] == "alert", key
            assert r["ariaLive"] == "assertive", key
        else:
            assert r["role"] != "alert", key
            assert r["ariaLive"] == "polite", key
    # emergency (risk LOW but is_emergency) must also be assertive alert
    assert res["result"]["EMERGENCY"]["role"] == "alert"
    assert res["result"]["EMERGENCY"]["ariaLive"] == "assertive"
    # LOW must never claim absolute safety
    low = CONCLUSION_TEXT["LOW"].lower()
    assert "an toàn tuyệt đối" not in low and "chắc chắn an toàn" not in low
    for k, r in res["result"].items():
        assert "an toàn tuyệt đối" not in r["text"].lower()
        assert "chắc chắn an toàn" not in r["text"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# C2. Simple mode: only Vì sao + Bạn nên làm under the conclusion; rest in ONE closed <details>
# ─────────────────────────────────────────────────────────────────────────────

RICH_RESPONSE_JS = r"""
const richResponse = mkRes({
    decision: {
        intent_type: "scam_analysis", risk_level: "HIGH", headline: "Phát hiện link giả mạo ngân hàng",
        recommendations: ["Không bấm link", "Không đưa OTP", "Gọi ngân hàng", "Chặn người gửi", "Báo công an"],
        hitl_disclaimer: "Chỉ hỗ trợ ra quyết định"
    },
    risk_score: 92,
    explainable: { reasons: ["Link giả ngân hàng: +40", "Yêu cầu OTP: +30", "Tạo áp lực thời gian: +20", "Người gửi lạ: +10"] },
    url_analysis: {
        summary_vi: ["Link giả mạo ngân hàng", "Tên miền mới tạo", "Có yêu cầu đăng nhập", "Địa chỉ che giấu"],
        findings: [{
            raw: "http://vietcombank-xacminh.top/login", display_host: "vietcombank-xacminh.top", effective_host: "vietcombank-xacminh.top",
            verdict: "dangerous", url_risk_score: 90, network_used: false,
            signals: [
                { code: "COMBOSQUAT_BRAND", severity: "high", message_vi: "Tên miền ghép", evidence: "vietcombank-xacminh.top" },
                { code: "SUSPICIOUS_TLD", severity: "medium", message_vi: "Đuôi lạ", evidence: ".top" },
                { code: "HTTP_PLAIN", severity: "info", message_vi: "Không mã hóa", evidence: "http" },
                { code: "LONG_URL", severity: "low", message_vi: "Dài", evidence: "x" }
            ],
            obfuscation_chain: [{ technique: "combosquat", detail_vi: "ghép chữ" }]
        }]
    },
    image_analysis: { qr_urls: ["http://scan-me.top/pay"], vietqr: [{ bank_name: "VCB", masked_account: "***1234", crc_ok: true }] }
});
"""


def test_c2_simple_mode_details_closed_and_only_why_and_actions_outside():
    res = run_app_node(RICH_RESPONSE_JS + r"""
    const app = makeApp(async () => richResponse);
    await app.send("kiểm tra giúp tôi");
    const c = app.lastContent();
    const details = c.querySelectorAll("details");
    const d = details[0];
    const summary = d ? d.querySelector("summary") : null;
    const techClasses = ["link-analysis-card", "pipeline-trace-box", "network-actions-box", "llm-status-bar",
        "metrics-grid", "risk-header", "url-analysis-container", "image-analysis-box", "breakdown-section", "hitl-footer", "emergency-box", "recs-box"];
    const outsideCounts = {};
    techClasses.forEach(k => { outsideCounts[k] = outsideDetails(c, k).length; });
    const insideCounts = {};
    techClasses.forEach(k => { insideCounts[k] = d ? d.querySelectorAll("." + k).length : 0; });
    const why = c.querySelector(".simple-why-list");
    const act = c.querySelector(".simple-actions-list");
    const condensed = outsideDetails(c, "condensed-link-card")[0];
    out({
        childClasses: c.children.map(x => x.className),
        childTags: c.children.map(x => x.tagName),
        nDetails: details.length,
        detailsOpenProp: d ? d.open : null,
        detailsOpenAttr: d ? d.getAttribute("open") : null,
        summaryText: summary ? summary.textContent : null,
        summaryAria: summary ? summary.getAttribute("aria-label") : null,
        outsideCounts, insideCounts,
        whyCount: why ? why.children.length : -1,
        actTag: act ? act.tagName : null,
        actCount: act ? act.children.length : -1,
        actItems: act ? act.children.map(x => x.textContent) : [],
        condensedText: condensed ? allText(condensed) : "",
        innerHTMLWrites, consoleErrors
    });
    """)
    assert res["consoleErrors"] == []
    allowed = {"simple-why-box", "simple-actions-box", "condensed-link-card", "deep-check-box", "technical-details"}
    first, rest = res["childClasses"][0], res["childClasses"][1:]
    assert "action-conclusion" in first.split()
    assert len(rest) >= 3
    for cls in rest:
        assert set(cls.split()) & allowed, f"unexpected element directly under conclusion: {cls}"
    assert rest[0] == "simple-why-box" and rest[1] == "simple-actions-box"
    # exactly one <details>, closed by default, summary labelled
    assert res["nDetails"] == 1
    assert res["childTags"][-1] == "DETAILS"
    assert res["detailsOpenProp"] is False
    assert res["detailsOpenAttr"] is None
    assert res["summaryText"] and "Xem chi tiết kỹ thuật" in res["summaryText"]
    assert res["summaryAria"] and "chi tiết kỹ thuật" in res["summaryAria"]
    # technical content ONLY inside details, and actually present inside it
    for cls, n in res["outsideCounts"].items():
        assert n == 0, f"{cls} leaked outside <details>"
    for cls in ("link-analysis-card", "pipeline-trace-box", "network-actions-box", "llm-status-bar",
                "metrics-grid", "risk-header", "image-analysis-box"):
        assert res["insideCounts"][cls] >= 1, f"{cls} missing inside <details>"
    # why <= 3 bullets, actions <= 3 as numbered list
    assert 1 <= res["whyCount"] <= 3
    assert res["actTag"] == "OL"
    assert 1 <= res["actCount"] <= 3
    # condensed card still visible with defanged lines
    assert "Bạn thấy:" in res["condensedText"] and "Thực tế mở:" in res["condensedText"]
    assert "hxxp://vietcombank-xacminh[.]top/login" in res["condensedText"]
    # server data never goes through innerHTML (only empty-string clears)
    assert all(w == "" for w in res["innerHTMLWrites"])


def test_c2_source_has_no_innerhtml_for_server_data_in_new_code():
    with open(APP_JS, "r", encoding="utf-8") as f:
        app_code = f.read()
    with open(UI_RENDER_JS, "r", encoding="utf-8") as f:
        ui_code = f.read()
    assert "createTechnicalDetails" in app_code and "renderActionConclusion" in app_code
    assert "renderSimpleMode" in app_code
    assert 'createElement("details")' in ui_code and 'createElement("summary")' in ui_code
    assert re.search(r"details\.(setAttribute\(\s*[\"']open|open\s*=\s*true)", ui_code) is None


# ─────────────────────────────────────────────────────────────────────────────
# C3. Vietnamese wording: >= 20 REAL codes (regex-extracted from codebase/url_analysis), no jargon shown
# ─────────────────────────────────────────────────────────────────────────────

URL_ANALYSIS_DIR = os.path.join(ROOT_DIR, "codebase", "url_analysis")


def _real_signal_codes_and_techniques():
    codes, techs = set(), set()
    for fn in sorted(os.listdir(URL_ANALYSIS_DIR)):
        if not fn.endswith(".py"):
            continue
        with open(os.path.join(URL_ANALYSIS_DIR, fn), "r", encoding="utf-8") as f:
            src = f.read()
        codes |= set(re.findall(r'add_sig\(\s*"([A-Z][A-Z0-9_]+)"', src))
        codes |= set(re.findall(r'\bcode="([A-Z][A-Z0-9_]+)"', src))
        codes |= set(re.findall(r'_sig\(\s*"([A-Z][A-Z0-9_]+)"', src))
        techs |= set(re.findall(r'technique="([a-z_]+)"', src))
        techs |= set(re.findall(r'"technique":\s*"([a-z_]+)"', src))
    return sorted(codes), sorted(techs)


def test_c3_mapping_covers_real_codes_and_has_no_jargon():
    codes, techs = _real_signal_codes_and_techniques()
    assert len(codes) >= 20, f"regex found too few real codes: {codes}"
    assert len(techs) >= 8, f"regex found too few techniques: {techs}"
    res = run_node_eval("""
    const fallbackSignal = UIRender.getFriendlySignal("NOPE_NOT_A_CODE", "");
    const fallbackTech = UIRender.getFriendlyTechnique("nope_not_a_technique");
    console.log(JSON.stringify({
        signalKeys: Object.keys(UIRender.SIGNAL_MAP),
        techKeys: Object.keys(UIRender.TECHNIQUE_MAP),
        signalMap: UIRender.SIGNAL_MAP,
        techMap: UIRender.TECHNIQUE_MAP,
        fallbackSignal, fallbackTech
    }));
    """)
    missing_codes = [c for c in codes if c not in res["signalKeys"]]
    assert missing_codes == [], f"real signal codes without Vietnamese mapping: {missing_codes}"
    missing_techs = [t for t in techs if t not in res["techKeys"] and t.upper() not in res["signalKeys"]]
    assert missing_techs == [], f"real techniques without Vietnamese mapping: {missing_techs}"
    assert len(set(codes) & set(res["signalKeys"])) >= 20
    # the mapped sentences themselves must be jargon free and never echo a raw code
    for table in (res["signalMap"], res["techMap"]):
        for key, sentence in table.items():
            low = sentence.lower()
            for word in FORBIDDEN_WORDS:
                assert word not in low, f"{key} -> {sentence!r} contains {word}"
            assert not re.search(r"\b[A-Z]{3,}(?:_[A-Z0-9]+)+\b", sentence), f"{key} leaks a raw code"
    # codes never become visible via the friendly helpers
    friendly = run_node_eval("""
    const codes = %s;
    console.log(JSON.stringify(codes.map(c => UIRender.getFriendlySignal(c, ""))));
    """ % json.dumps(codes))
    for code, text in zip(codes, friendly):
        assert code not in text
        assert text != res["fallbackSignal"], f"{code} falls back to the generic sentence"


def test_c3_visible_text_outside_details_is_jargon_free_for_six_samples():
    res = run_app_node(r"""
    const base = (risk, headline, recs, extra) => mkRes(Object.assign({
        decision: { intent_type: "scam_analysis", risk_level: risk, headline, recommendations: recs }
    }, extra || {}));
    const samples = {
        userinfo: base("HIGH", "Link giả ngân hàng dùng defang và redirect", ["Không bấm link — đây là kỹ thuật obfuscation", "Gọi ngân hàng"], {
            url_analysis: { summary_vi: ["Link dùng userinfo để giấu địa chỉ thật (homoglyph, combosquat)"], findings: [{
                raw: "http://vietcombank.com.vn@evil-login.xyz/login", display_host: "vietcombank.com.vn", effective_host: "evil-login.xyz",
                verdict: "dangerous", url_risk_score: 90, network_used: false,
                signals: [
                    { code: "USERINFO_BRAND_DECOY", severity: "high", message_vi: "Userinfo giả brand (typosquat)", evidence: "x" },
                    { code: "COMBOSQUAT_BRAND", severity: "high", message_vi: "combosquat brand", evidence: "evil-login.xyz" }],
                obfuscation_chain: [{ technique: "userinfo", detail_vi: "dùng @" }]
            }] }
        }),
        homoglyph: base("HIGH", "Tên miền giả mạo", ["Không đăng nhập"], {
            url_analysis: { summary_vi: [], findings: [{
                raw: "https://vietcоmbank.com/login", verdict: "dangerous", url_risk_score: 88, network_used: false,
                signals: [
                    { code: "HOMOGLYPH_BRAND", severity: "high", message_vi: "homoglyph", evidence: "o" },
                    { code: "ZZZ_UNKNOWN_CODE", severity: "high", message_vi: "Phát hiện homoglyph, redirect, obfuscation lạ", evidence: "x" },
                    { code: "MIXED_SCRIPT", severity: "medium", message_vi: "trộn chữ", evidence: "x" }]
            }] }
        }),
        shortener_redirect: base("MEDIUM", "Link rút gọn", ["Đừng bấm vào link rút gọn (open redirect)"], {
            url_analysis: { summary_vi: ["Link rút gọn dẫn qua nhiều trang (redirect chain)"], findings: [{
                raw: "https://bit.ly/3abcXYZ", final_url: "https://evil-pay.top/x", verdict: "suspicious", url_risk_score: 55, network_used: true,
                redirect_chain: [{ url: "https://bit.ly/3abcXYZ", status: 301 }, { url: "https://evil-pay.top/x", status: 200 }],
                signals: [
                    { code: "SHORTENER", severity: "medium", message_vi: "shortener", evidence: "bit.ly" },
                    { code: "REDIRECT_CHAIN", severity: "high", message_vi: "Chuỗi redirect qua 3 trang", evidence: "3" }]
            }] }
        }),
        qr: base("HIGH", "Mã QR dẫn tới link độc hại", ["Đừng quét mã QR lạ", "Link bị defanged để an toàn"], {
            image_analysis: { qr_urls: ["http://scan-me.top/pay"], vietqr: [] }
        }),
        otp_real: base("HIGH", "Yêu cầu cung cấp mã OTP", ["Không đưa mã OTP cho bất kỳ ai", "Gọi tổng đài 1900 chính thức"], {
            explainable: { reasons: ["Yêu cầu OTP: +40", "Giả danh ngân hàng (homoglyph): +20"] }
        }),
        unverified: base("MEDIUM", "Không kiểm tra được", ["Chụp màn hình gửi lại"], {
            url_analysis: { summary_vi: [], findings: [{
                raw: "http://khong-ro.example/a", verdict: "unverified", url_risk_score: 20, network_used: true,
                signals: [{ code: "ANTIBOT_CHALLENGE", severity: "medium", message_vi: "Trang chặn bot (cloaking)", evidence: "x" }]
            }] }
        })
    };
    const app = makeApp(async (body) => samples[body.user_text]);
    const result = {};
    for (const k of Object.keys(samples)) {
        await app.send(k);
        const c = app.lastContent();
        const codeCaptions = [];
        walkAll(c, n => { if (n.classList.contains("signal-code")) codeCaptions.push(n.textContent); });
        result[k] = {
            visible: visibleText(c),
            codeCaptions,
            captionsAllInsideDetails: outsideDetails(c, "signal-code").length === 0
        };
    }
    out({ result, consoleErrors });
    """)
    assert res["consoleErrors"] == []
    raw_code_re = re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b")
    assert set(res["result"]) == {"userinfo", "homoglyph", "shortener_redirect", "qr", "otp_real", "unverified"}
    for name, r in res["result"].items():
        text = r["visible"]
        assert len(text) > 50, f"{name}: nothing rendered"
        low = text.lower()
        for word in FORBIDDEN_WORDS:
            assert word not in low, f"{name}: forbidden word {word!r} visible: {text}"
        assert not raw_code_re.search(text), f"{name}: raw code visible: {raw_code_re.search(text).group(0)}"
        assert r["captionsAllInsideDetails"] is True
    u = res["result"]["userinfo"]["visible"]
    assert "Dùng tên ngân hàng trước ký tự @ để lừa bạn vào trang giả" in u
    assert "Tên miền ghép thêm chữ cho giống tên ngân hàng" in u
    assert any("COMBOSQUAT_BRAND" in cap for cap in res["result"]["userinfo"]["codeCaptions"]), \
        "raw code must still be available as a small caption inside the technical details"
    h = res["result"]["homoglyph"]["visible"]
    assert "Dùng chữ cái giống hệt (như chữ Nga) để giả tên ngân hàng" in h
    assert "chuyển hướng" in h and "che giấu" in h  # unknown code -> server message_vi, humanized
    s = res["result"]["shortener_redirect"]["visible"]
    assert "Link tự chuyển bạn qua nhiều trang liên tiếp" in s
    assert "hxxps://evil-pay[.]top/x" in s
    assert "http" not in res["result"]["qr"]["visible"].lower().replace("hxxp", "")  # QR link only defanged / in details
    o = res["result"]["otp_real"]["visible"]
    assert "OTP" in o
    assert "Chưa" in res["result"]["unverified"]["visible"] or "CHƯA" in res["result"]["unverified"]["visible"]


# ─────────────────────────────────────────────────────────────────────────────
# C4. index.html accessibility structure
# ─────────────────────────────────────────────────────────────────────────────

from html.parser import HTMLParser


class _HtmlCollector(HTMLParser):
    VOID = {"img", "input", "meta", "link", "br", "hr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.elements = []
        self.stack = []

    def handle_starttag(self, tag, attrs):
        el = {"tag": tag, "attrs": dict((k, v if v is not None else "") for k, v in attrs), "text": [], "ancestors": [e["tag"] for e in self.stack], "anc_els": list(self.stack)}
        self.elements.append(el)
        if tag not in self.VOID:
            self.stack.append(el)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i]["tag"] == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        for el in self.stack:
            el["text"].append(data)


def _parse_html():
    with open(INDEX_HTML, "r", encoding="utf-8") as f:
        html = f.read()
    active = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)
    p = _HtmlCollector()
    p.feed(active)
    return active, p.elements


def test_c4_index_html_accessibility():
    active, els = _parse_html()
    by_id = {e["attrs"].get("id"): e for e in els if e["attrs"].get("id")}
    tags = [e["tag"] for e in els]

    assert re.search(r'<html[^>]*\blang="vi"', active)
    assert len(re.findall(r"\baria-[a-z]+\s*=", active)) >= 8
    assert tags.count("header") >= 1
    assert tags.count("main") >= 1
    assert not [e for e in els if e["tag"] == "script" and e["attrs"].get("src") is None]
    assert "<style" not in active.lower() and 'style="' not in active.lower()
    assert not re.findall(r'\bon[a-z]+\s*=\s*["\']', active, re.IGNORECASE)

    # results region: aria-live polite + label
    region = by_id["messagesContainer"]
    assert region["attrs"].get("aria-live") == "polite"
    assert region["attrs"].get("aria-label", "").strip()
    assert by_id["mainContent"]["tag"] == "main" and by_id["mainContent"]["attrs"].get("aria-label")

    label_for = {e["attrs"].get("for") for e in els if e["tag"] == "label" and e["attrs"].get("for")}
    name_re = re.compile(r"[A-Za-zÀ-ỹ]{2,}")

    def accessible(e):
        a = e["attrs"]
        if a.get("aria-label", "").strip() or a.get("aria-labelledby"):
            return True
        if a.get("id") in label_for:
            return True
        text = "".join(e["text"])
        if e["tag"] in ("button", "label") and name_re.search(text):
            return True
        for anc in e["anc_els"]:
            if anc["tag"] == "label" and (anc["attrs"].get("aria-label", "").strip() or name_re.search("".join(anc["text"]))):
                return True
        return False

    for e in els:
        if e["tag"] in ("button", "textarea", "select"):
            assert accessible(e), f"control without accessible name: {e['tag']} {e['attrs']}"
        if e["tag"] == "input" and e["attrs"].get("type", "text") != "hidden":
            assert accessible(e), f"input without accessible name: {e['attrs']}"
        if e["tag"] == "label" and "btn-attach" in e["attrs"].get("class", ""):
            assert e["attrs"].get("aria-label", "").strip(), "image upload label needs aria-label"
        if e["tag"] == "img":
            assert e["attrs"].get("alt", "").strip(), f"image without alt: {e['attrs']}"
        assert not (e["attrs"].get("tabindex", "0").lstrip("-").isdigit() and int(e["attrs"].get("tabindex", "0")) > 0), "positive tabindex breaks natural Tab order"
    for e in els:
        if "suggestion-card" in e["attrs"].get("class", "").split():
            assert e["attrs"].get("role") == "button" and e["attrs"].get("tabindex") == "0"
    # specific controls named in the checklist
    for cid in ("btnNewChat", "btnSend", "btnRemoveFile", "lightboxCloseBtn", "chatInput", "fileInput"):
        assert by_id[cid]["attrs"].get("aria-label", "").strip(), f"{cid} needs aria-label"
    cb = by_id["onlineCheckCheckbox"]
    assert cb["attrs"].get("autocomplete") == "off" and "checked" not in cb["attrs"]


def test_c4_keyboard_activation_of_cards_and_history_items():
    res = run_app_node(r"""
    const app = makeApp(async () => mkRes());
    const card = new MockElement("div");
    card.classList.add("suggestion-card");
    let clicks = 0;
    card.addEventListener("click", () => { clicks++; });
    const plain = new MockElement("div");
    let plainClicks = 0;
    plain.addEventListener("click", () => { plainClicks++; });
    const fire = (key, target) => (app.docListeners["keydown"] || []).forEach(fn => fn({ key, target, preventDefault() {} }));
    fire("Enter", card);
    fire(" ", card);
    fire("a", card);
    fire("Enter", plain);
    out({ clicks, plainClicks, registered: (app.docListeners["keydown"] || []).length });
    """)
    assert res["registered"] >= 1
    assert res["clicks"] == 2, "Enter and Space must activate a suggestion card"
    assert res["plainClicks"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# C5. styles.css — parse the REAL rules
# ─────────────────────────────────────────────────────────────────────────────

def parse_css(css: str):
    """Tiny CSS parser: returns [{'sels': [...], 'decls': {...}, 'media': str|None, 'comment': str}]"""
    rules = []
    i, n = 0, len(css)
    start = 0
    media_stack = []  # media prelude per open @media block

    def strip_comments(chunk):
        comments = re.findall(r"/\*(.*?)\*/", chunk, flags=re.DOTALL)
        return re.sub(r"/\*.*?\*/", "", chunk, flags=re.DOTALL).strip(), (comments[-1] if comments else "")

    def skip_block(pos):
        depth = 0
        while pos < n:
            if css[pos] == "{":
                depth += 1
            elif css[pos] == "}":
                depth -= 1
                if depth == 0:
                    return pos + 1
            pos += 1
        return n

    while i < n:
        ch = css[i]
        if ch == "{":
            prelude, comment = strip_comments(css[start:i])
            if prelude.startswith("@media"):
                media_stack.append(prelude)
                i += 1
                start = i
                continue
            if prelude.startswith("@"):
                i = skip_block(i)
                start = i
                continue
            j = css.index("}", i)
            body = css[i + 1:j]
            decls = {}
            for part in re.sub(r"/\*.*?\*/", "", body, flags=re.DOTALL).split(";"):
                if ":" in part:
                    k, v = part.split(":", 1)
                    decls[k.strip().lower()] = re.sub(r"\s*!important\s*$", "", v.strip(), flags=re.IGNORECASE)
            rules.append({
                "sels": [s.strip() for s in prelude.split(",") if s.strip()],
                "decls": decls,
                "media": media_stack[-1] if media_stack else None,
                "comment": comment,
            })
            i = j + 1
            start = i
            continue
        if ch == "}":
            if media_stack:
                media_stack.pop()
            i += 1
            start = i
            continue
        i += 1
    return rules


def _css_rules():
    with open(STYLES_CSS, "r", encoding="utf-8") as f:
        return parse_css(f.read())


def _px(value):
    m = re.fullmatch(r"([\d.]+)px", value.strip())
    return float(m.group(1)) if m else None


def _rules_for(rules, selector):
    return [r for r in rules if selector in r["sels"]]


def _css_vars(rules):
    root = {}
    for r in rules:
        if ":root" in r["sels"]:
            for k, v in r["decls"].items():
                if k.startswith("--"):
                    root[k] = v
    return root


def _parse_color(value, css_vars, backdrop=None):
    value = value.strip()
    m = re.fullmatch(r"var\((--[\w-]+)\)", value)
    if m:
        return _parse_color(css_vars[m.group(1)], css_vars, backdrop)
    m = re.fullmatch(r"#([0-9a-fA-F]{6})", value)
    if m:
        h = m.group(1)
        return tuple(int(h[k:k + 2], 16) for k in (0, 2, 4))
    m = re.fullmatch(r"#([0-9a-fA-F]{3})", value)
    if m:
        return tuple(int(c * 2, 16) for c in m.group(1))
    m = re.fullmatch(r"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*([\d.]+)\s*)?\)", value)
    if m:
        r, g, b = int(m.group(1)), int(m.group(2)), int(m.group(3))
        a = float(m.group(4)) if m.group(4) is not None else 1.0
        if a < 1.0:
            assert backdrop is not None, f"translucent colour {value} needs a backdrop"
            return tuple(round(a * c + (1 - a) * bc) for c, bc in zip((r, g, b), backdrop))
        return (r, g, b)
    raise AssertionError(f"cannot parse colour {value!r}")


def _luminance(rgb):
    def f(c):
        c = c / 255.0
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (f(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(a, b):
    la, lb = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def test_c5_css_font_sizes_body_and_small_caption_rule():
    rules = _css_rules()
    assert len(rules) > 200
    problems = []
    for r in rules:
        fs = r["decls"].get("font-size")
        if fs is None:
            continue
        px = _px(fs)
        assert px is not None, f"non-px font-size {fs} in {r['sels']}"
        if px >= 15:
            continue
        # only exception: small caption >= 13px that carries a /* small-caption */ comment directly above
        if px >= 13 and "small-caption" in r["comment"]:
            continue
        problems.append((r["sels"], fs))
    assert problems == [], f"content text below 15px: {problems}"
    body = [r for r in rules if r["sels"] == ["body"]]
    assert body and _px(body[0]["decls"]["font-size"]) >= 17
    # U1: conclusion text is very large everywhere (incl. media queries)
    concl = _rules_for(rules, ".action-conclusion-text")
    assert concl
    for r in concl:
        if "font-size" in r["decls"]:
            assert _px(r["decls"]["font-size"]) >= 28
    assert any(int(_px(r["decls"]["font-size"])) >= 28 and r["decls"].get("font-weight") in ("700", "800", "bold") for r in concl if "font-size" in r["decls"])


def test_c5_css_touch_targets_focus_and_reduced_motion():
    rules = _css_rules()
    # global rule for every button / textarea / select / text input
    global_rules = [r for r in rules if "button" in r["sels"] and "textarea" in r["sels"] and r["media"] is None]
    assert global_rules, "missing global min-height rule for button/textarea/select/input"
    assert _px(global_rules[0]["decls"]["min-height"]) >= 44
    assert any(s.startswith("input:not") for s in global_rules[0]["sels"])
    assert "select" in global_rules[0]["sels"]
    # every specific control selector: no rule may declare a height / min-height below 44px
    controls = [".btn-new-chat", ".btn-send", ".btn-attach", ".btn-remove-file", ".lightbox-close-btn",
                ".btn-deep-check", ".btn-upload-screenshot", ".input-container textarea", ".session-item",
                ".online-check-label", ".btn-quick-action", ".technical-details-summary"]
    for sel in controls:
        rs = _rules_for(rules, sel)
        assert rs, f"no CSS rule for {sel}"
        heights = []
        for r in rs:
            for prop in ("height", "min-height"):
                if prop in r["decls"] and _px(r["decls"][prop]) is not None:
                    heights.append(_px(r["decls"][prop]))
        assert heights, f"{sel} declares no explicit height/min-height"
        assert min(heights) >= 44, f"{sel} has a control height below 44px: {heights}"
    for sel in (".btn-send", ".lightbox-close-btn"):  # icon buttons: width too
        widths = [_px(r["decls"]["width"]) for r in _rules_for(rules, sel) if "width" in r["decls"]]
        assert widths and min(widths) >= 44
    # keyboard focus: every :focus-visible rule has an outline >= 3px
    fv = [r for r in rules if any(":focus-visible" in s for s in r["sels"])]
    assert fv and any(":focus-visible" in r["sels"] for r in fv)
    for r in fv:
        m = re.match(r"(\d+(?:\.\d+)?)px", r["decls"].get("outline", ""))
        assert m and float(m.group(1)) >= 3, f"weak focus outline in {r['sels']}"
    # prefers-reduced-motion turns animation + transition off
    rm = [r for r in rules if r["media"] and "prefers-reduced-motion" in r["media"] and "reduce" in r["media"]]
    assert rm, "missing @media (prefers-reduced-motion: reduce)"
    assert any(r["decls"].get("animation") == "none" and r["decls"].get("transition") == "none" for r in rm)
    # narrow layout (<= 480px): conclusion + link cards wrap instead of overflowing
    narrow = [r for r in rules if r["media"] and re.search(r"max-width:\s*480px", r["media"])]
    assert narrow, "missing @media (max-width: 480px)"
    sels = {s for r in narrow for s in r["sels"]}
    assert ".action-conclusion" in sels and ".action-conclusion-text" in sels
    assert ".condensed-link-card" in sels and ".link-analysis-card" in sels
    wraps = [r for r in narrow if r["decls"].get("overflow-wrap") == "anywhere" or r["decls"].get("word-break") in ("break-word", "break-all")]
    assert any(".condensed-link-card" in r["sels"] for r in wraps)
    assert any(".action-conclusion-text" in r["sels"] for r in wraps)


def test_c5_css_contrast_wcag_aa_on_main_pairs():
    rules = _css_rules()
    v = _css_vars(rules)
    bg_primary = _parse_color(v["--bg-primary"], v)
    bg_card = _parse_color(v["--bg-card"], v)

    def decl(selector, prop):
        found = [r["decls"][prop] for r in _rules_for(rules, selector) if prop in r["decls"] and r["media"] is None]
        assert found, f"{selector} has no {prop}"
        return found[-1]

    pairs = [
        ("body text on page", _parse_color(decl("body", "color"), v), bg_primary),
        ("secondary text on card", _parse_color(v["--text-secondary"], v), bg_card),
        ("muted text on card", _parse_color(v["--text-muted"], v), bg_card),
        ("muted text on page", _parse_color(v["--text-muted"], v), bg_primary),
        ("primary text on card (why/actions)", _parse_color(decl(".simple-action-item", "color"), v), bg_card),
        ("deep-check button", _parse_color(decl(".btn-deep-check", "color"), v), _parse_color(decl(".btn-deep-check", "background"), v)),
        ("deep-check button hover", _parse_color(decl(".btn-deep-check", "color"), v), _parse_color(decl(".btn-deep-check:hover", "background"), v)),
        ("privacy notice", _parse_color(decl(".privacy-notice", "color"), v), bg_primary),
    ]
    for level in ("critical", "high", "medium", "low", "unverified"):
        sel = f".action-conclusion-{level}"
        bg = _parse_color(decl(sel, "background"), v, backdrop=bg_primary)
        pairs.append((f"conclusion {level}", _parse_color(decl(sel, "color"), v), bg))
    assert len(pairs) >= 5
    failures = [(name, round(contrast_ratio(fg, bg), 2)) for name, fg, bg in pairs if contrast_ratio(fg, bg) < 4.5]
    assert failures == [], f"WCAG AA (4.5:1) violated: {failures}"


# ─────────────────────────────────────────────────────────────────────────────
# C6. Smart deep-check button
# ─────────────────────────────────────────────────────────────────────────────

def test_c6_deep_check_button_cases_and_online_check_boolean_then_reset():
    res = run_app_node(r"""
    const finding = (over) => Object.assign({ raw: "http://khong-ro.example/a", verdict: "unverified", url_risk_score: 10, network_used: false, signals: [] }, over || {});
    const withFinding = (f, risk) => mkRes({
        decision: { intent_type: "scam_analysis", risk_level: risk || "MEDIUM", headline: "H", recommendations: ["Cẩn thận"] },
        url_analysis: { summary_vi: [], findings: [f] }
    });
    const cases = {
        unverified: withFinding(finding()),
        shortener_unexpanded: withFinding(finding({ verdict: "suspicious", signals: [{ code: "SHORTENER", severity: "medium", message_vi: "x" }] })),
        offline_suspicious: withFinding(finding({ verdict: "suspicious" })),
        // NOT shown
        dangerous_known: withFinding(finding({ verdict: "dangerous", url_risk_score: 90 }), "HIGH"),
        official: withFinding(finding({ verdict: "official" }), "LOW"),
        suspicious_online_done: withFinding(finding({ verdict: "suspicious", network_used: true })),
        shortener_resolved: withFinding(finding({ verdict: "suspicious", network_used: true, signals: [{ code: "SHORTENER", severity: "medium", message_vi: "x" }, { code: "SHORTENER_RESOLVED", severity: "medium", message_vi: "y" }] })),
        no_links: mkRes({ decision: { intent_type: "scam_analysis", risk_level: "HIGH", headline: "H", recommendations: [] } })
    };
    const shown = {};
    let app = makeApp(async (body) => cases[body.user_text]);
    for (const k of Object.keys(cases)) {
        await app.send(k);
        const c = app.lastContent();
        const btns = outsideDetails(c, "btn-deep-check");
        shown[k] = btns.length;
    }
    const extra = {};
    {
        // full flow on the unverified case
        let n = 0;
        app = makeApp(async (body, callNo) => {
            if (callNo === 1) return cases.unverified;
            // online answer: still cannot verify, but the check WAS done -> button must not come back
            return withFinding(finding({ network_used: true }));
        });
        await app.send("Xem link http://khong-ro.example/a giúp tôi");
        const c1 = app.lastContent();
        const btn = outsideDetails(c1, "btn-deep-check")[0];
        extra.btnText = btn.textContent;
        extra.btnAria = btn.getAttribute("aria-label");
        extra.btnType = btn.type;
        extra.desc = outsideDetails(c1, "deep-check-desc")[0].textContent;
        extra.checkboxBefore = app.getElem("onlineCheckCheckbox").checked;
        extra.firstBodyOnline = app.calls[0].body.online_check;
        btn.click();
        await flush();
        extra.callCount = app.calls.length;
        extra.secondText = app.calls[1] ? app.calls[1].body.user_text : null;
        extra.secondOnline = app.calls[1] ? app.calls[1].body.online_check : null;
        extra.secondOnlineType = app.calls[1] ? typeof app.calls[1].body.online_check : null;
        extra.secondSession = app.calls[1] ? app.calls[1].body.session_id === app.calls[0].body.session_id : null;
        extra.checkboxAfter = app.getElem("onlineCheckCheckbox").checked;
        extra.buttonAfterOnlineAnswer = outsideDetails(app.lastContent(), "btn-deep-check").length;
        await app.send("tin tiếp theo");
        extra.thirdOnline = app.calls[2] ? app.calls[2].body.online_check : null;
        extra.thirdOnlineType = app.calls[2] ? typeof app.calls[2].body.online_check : null;
    }
    out({ shown, extra, consoleErrors });
    """)
    assert res["consoleErrors"] == []
    for k in ("unverified", "shortener_unexpanded", "offline_suspicious"):
        assert res["shown"][k] == 1, f"deep-check button must show for {k}"
    for k in ("dangerous_known", "official", "suspicious_online_done", "shortener_resolved", "no_links"):
        assert res["shown"][k] == 0, f"deep-check button must NOT show for {k}"
    e = res["extra"]
    assert "Kiểm tra sâu link này" in e["btnText"]
    assert e["btnAria"] == "Kiểm tra sâu link này"
    assert e["btnType"] == "button"
    assert "chỉ gửi tên miền, không gửi nội dung tin" in e["desc"]
    # default: OFF and boolean false
    assert e["checkboxBefore"] is False
    assert e["firstBodyOnline"] is False
    # click: SAME message resent with online_check === true (real boolean) in the same session
    assert e["callCount"] == 2
    assert e["secondText"] == "Xem link http://khong-ro.example/a giúp tôi"
    assert e["secondOnline"] is True and e["secondOnlineType"] == "boolean"
    assert e["secondSession"] is True
    # box auto-reset to false, button gone once the online check was done, next send is private again
    assert e["checkboxAfter"] is False
    assert e["buttonAfterOnlineAnswer"] == 0
    assert e["thirdOnline"] is False and e["thirdOnlineType"] == "boolean"


def test_c6_button_css_and_default_off_in_html():
    rules = _css_rules()
    deep = _rules_for(rules, ".btn-deep-check")
    assert deep and _px(deep[0]["decls"]["min-height"]) >= 44
    with open(INDEX_HTML, "r", encoding="utf-8") as f:
        html = f.read()
    cb = re.search(r'<input\b[^>]*id="onlineCheckCheckbox"[^>]*>', html)
    assert cb and "checked" not in cb.group(0)
    with open(APP_JS, "r", encoding="utf-8") as f:
        app_code = f.read()
    assert "localStorage.setItem(\"safeguard_online" not in app_code  # no silent persistence of online_check


# ─────────────────────────────────────────────────────────────────────────────
# C7. Phase 5A safety regression on the NEW render path (runtime, hostile data)
# ─────────────────────────────────────────────────────────────────────────────

def test_c7_phase5a_safety_regression_on_new_layout():
    res = run_app_node(r"""
    const RLO = String.fromCharCode(0x202E);
    const hostile = mkRes({
        decision: { intent_type: "scam_analysis", risk_level: "HIGH", headline: "<img src=x onerror=alert(1)> evil-login.xyz" + RLO,
            recommendations: ["Vào http://evil-login.xyz/a" + RLO + " ngay", "<script>alert(1)</script>"] },
        explainable: { reasons: ["Lừa đảo evil-login.xyz" + RLO + ": +40"] },
        url_analysis: { summary_vi: ["Truy cập http://evil-login.xyz/a\u0000 để nhận quà" + RLO], findings: [{
            raw: "http://evil-login.xyz/" + "A".repeat(900) + RLO, final_url: "https://evil\u0000-pay.top/x" + RLO, verdict: "dangerous", url_risk_score: 95, network_used: false,
            signals: [{ code: "COMBOSQUAT_BRAND", severity: "high", message_vi: "x" + RLO, evidence: "host=evil-login.xyz" + RLO }],
            brand_match: { display_name: "VCB" + RLO, official_domain: "vietcombank.com.vn\u0000" + RLO },
            redirect_chain: [{ url: "http://hop.evil-login.xyz/" + RLO, status: 302 }]
        }] },
        image_analysis: { qr_urls: ["http://qr.evil-login.xyz/" + RLO], vietqr: [] },
        network_actions: [{ type: "resolve", status: "sent", target: "evil-login.xyz" + RLO }]
    });
    const app = makeApp(async () => hostile);
    await app.send("hostile");
    const c = app.lastContent();
    const tags = [];
    walkAll(c, n => tags.push(n.tagName));
    const everything = allText(c);
    out({
        hasAnchor: tags.includes("A"),
        hasScriptOrImgFromServer: tags.includes("SCRIPT") || (tags.filter(t => t === "IMG").length > 0),
        hasRLO: everything.includes(RLO),
        hasNul: everything.includes("\u0000"),
        liveUrl: /https?:\/\//i.test(everything),
        bareDomains: (everything.match(/[a-z0-9-]+\.(?:xyz|top)\b/gi) || []),
        longestLine: Math.max(...everything.split(" | ").map(s => s.length)),
        innerHTMLWrites, consoleErrors
    });
    """)
    assert res["consoleErrors"] == []
    assert res["hasAnchor"] is False, "link analysis must never create <a>"
    assert res["hasScriptOrImgFromServer"] is False
    assert res["hasRLO"] is False and res["hasNul"] is False
    assert res["liveUrl"] is False, "every URL must be defanged (hxxp / [.])"
    assert res["bareDomains"] == [], f"un-defanged domains: {res['bareDomains']}"
    assert res["longestLine"] < 700
    assert all(w == "" for w in res["innerHTMLWrites"]), "innerHTML only allowed for clearing containers"


def test_c7_no_anchor_creation_and_csp_friendly_sources():
    with open(UI_RENDER_JS, "r", encoding="utf-8") as f:
        ui_code = f.read()
    with open(APP_JS, "r", encoding="utf-8") as f:
        app_code = f.read()
    for code in (ui_code, app_code):
        assert not re.search(r"createElement\(\s*[\"']a[\"']\s*\)", code), "<a> must never be created"
        assert "setAttribute(\"href\"" not in code and ".href =" not in code
        assert not re.search(r"\.setAttribute\(\s*[\"']on[a-z]+", code)
        assert "eval(" not in code and "new Function" not in code
        assert "style.cssText" not in code


def test_url_cards_capped_at_ten():
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


# ─────────────────────────────────────────────────────────────────────────────
# C8. REAL source mutations (edit file on disk -> run tests -> restore bytes). Survivors must be 0.
# ─────────────────────────────────────────────────────────────────────────────

C1 = ["test_c1_action_conclusion_is_first_with_exact_strings_and_aria"]
C2 = ["test_c2_simple_mode_details_closed_and_only_why_and_actions_outside"]
C3S = ["test_c3_visible_text_outside_details_is_jargon_free_for_six_samples"]
C3M = ["test_c3_mapping_covers_real_codes_and_has_no_jargon"]
C4 = ["test_c4_index_html_accessibility"]
C5F = ["test_c5_css_font_sizes_body_and_small_caption_rule"]
C5T = ["test_c5_css_touch_targets_focus_and_reduced_motion"]
C5C = ["test_c5_css_contrast_wcag_aa_on_main_pairs"]
C6 = ["test_c6_deep_check_button_cases_and_online_check_boolean_then_reset"]
C7 = ["test_c7_phase5a_safety_regression_on_new_layout", "test_c7_no_anchor_creation_and_csp_friendly_sources",
      "test_source_code_innerhtml_audit"]

REAL_APP = ["test_real_app_and_ui_render_in_node"]
SANITIZE = ["test_sanitize_text_vectors"]
AUDIT = ["test_source_code_innerhtml_audit"]
INDEX = ["test_index_html_security_and_structure"]

MUTATIONS = [
    # ── pre-existing Phase 5A mutants (kept) ──
    (UI_RENDER_JS, 'defangUrl(sanitizeText(hop.url || "", 300))', 'defangUrl(hop.url || "")', REAL_APP),
    (UI_RENDER_JS, 'defangHost(sanitizeText(act.target || "none", 100))', 'defangHost(act.target || "none")', REAL_APP),
    (UI_RENDER_JS, 'defangUrl(sanitizeText(u, 300))', 'defangUrl(u)', REAL_APP),
    (UI_RENDER_JS, 'defangHost(sanitizeText(finding.brand_match.official_domain, 100))', 'defangHost(finding.brand_match.official_domain)', REAL_APP),
    (UI_RENDER_JS, 'vl.textContent = sanitizeText(val, 150);', 'vl.textContent = String(val);', REAL_APP),
    (UI_RENDER_JS, 'defangHost(sanitizeText(subjectVal, 150))', 'defangHost(subjectVal)', REAL_APP),
    (UI_RENDER_JS, 'defangText(sanitizeText(sig.evidence, 200))', 'defangText(sig.evidence)', REAL_APP),
    (UI_RENDER_JS, 'defangText(sanitizeText(step.detail_vi || "", 300))', 'defangText(step.detail_vi || "")', REAL_APP),
    (UI_RENDER_JS, 'str = str.replace(/[\\u202A-\\u202E\\u2066-\\u2069\\u200E\\u200F\\u061C]/g, "");',
     'str = str.replace(/[\\u202A-\\u202D\\u2066-\\u2069\\u200E\\u200F\\u061C]/g, "");', SANITIZE),
    (UI_RENDER_JS, 'str = str.replace(/[\\u200B-\\u200D\\uFEFF\\u00AD\\u2028\\u2029\\u2060\\u180E\\u034F]/g, "");', '/* no zwsp removal */', SANITIZE),
    (UI_RENDER_JS, 'hopUrl.textContent = defangUrl(sanitizeText(hop.url || "", 300));', 'hopUrl.textContent = sanitizeText(hop.url || "", 300);', REAL_APP),
    (UI_RENDER_JS, 'item.textContent = "• " + defangUrl(sanitizeText(u, 300));', 'item.textContent = "• " + sanitizeText(u, 300);', REAL_APP),
    (UI_RENDER_JS, 'domainVal.textContent = defangHost(sanitizeText(finding.brand_match.official_domain, 100));',
     'domainVal.textContent = sanitizeText(finding.brand_match.official_domain, 100);', REAL_APP),
    (UI_RENDER_JS, 'if (str.length > max) {\n            str = str.slice(0, max);\n        }', '/* no length slice */', SANITIZE),
    (UI_RENDER_JS, 'const renderedFindings = findings.slice(0, maxCards);', 'const renderedFindings = findings;', ["test_url_cards_capped_at_ten"]),
    (APP_JS, 'const isOnlineCheck = Boolean(onlineCheckCheckbox && onlineCheckCheckbox.checked);',
     'const isOnlineCheck = onlineCheckCheckbox && onlineCheckCheckbox.checked ? "true" : "false";', REAL_APP),
    (APP_JS, 'headlineEl.textContent = headline;', 'headlineEl.insertAdjacentHTML("beforeend", headline);', AUDIT),
    (APP_JS, 'safeRender("url_analysis", () => UIRender.renderUrlAnalysis(res.url_analysis, body));',
     '/* url_analysis not rendered */', REAL_APP),
    (INDEX_HTML, '<script src="ui_render.js"></script>', '<!-- removed ui_render.js -->', INDEX),
    (INDEX_HTML, '<input type="checkbox" id="onlineCheckCheckbox" autocomplete="off" aria-describedby="onlineCheckHelp">',
     '<input type="checkbox" id="onlineCheckCheckbox" checked autocomplete="off" aria-describedby="onlineCheckHelp">', INDEX),
    (UI_RENDER_JS, 'if (isUnverified || hasBotError) {', 'if (false) {', REAL_APP),

    # ── C1: action conclusion ──
    (UI_RENDER_JS, 'text: "DỪNG LẠI — KHÔNG chuyển tiền, KHÔNG bấm link, KHÔNG đưa mã OTP.",', 'text: "DỪNG LẠI — hãy cân nhắc.",', C1),
    (UI_RENDER_JS, 'box.setAttribute("role", "alert");', 'box.setAttribute("role", "status");', C1),
    (UI_RENDER_JS, 'ariaLive: "assertive",', 'ariaLive: "polite",', C1),
    (UI_RENDER_JS, 'text: "CHƯA THẤY DẤU HIỆU LỪA ĐẢO — Nhưng vẫn không chia sẻ mã OTP, mật khẩu cho bất kỳ ai.",',
     'text: "AN TOÀN TUYỆT ĐỐI — Bạn cứ yên tâm.",', C1),
    (APP_JS, 'safeRender("action conclusion", () => UIRender.renderActionConclusion(res, content, document));',
     '/* conclusion call removed */', C1),
    # ── C2: simple mode / details ──
    (UI_RENDER_JS, 'details.className = "technical-details";', 'details.className = "technical-details"; details.setAttribute("open", "");', C2),
    (APP_JS, 'if (tech && tech.body) techBody = tech.body;', '/* technical content stays in the open */', C2),
    (UI_RENDER_JS, 'whyItems.slice(0, 3).forEach(', 'whyItems.slice(0, 9).forEach(', C2),
    (UI_RENDER_JS, 'summary.setAttribute("aria-label", "Xem chi tiết kỹ thuật: điểm số, phân tích đường link, nhật ký hệ thống");', '/* no aria-label */', C2),
    (UI_RENDER_JS, 'rawVal.textContent = defangUrl(sanitizeText(displayRaw, 300));', 'rawVal.textContent = sanitizeText(displayRaw, 300);', C2),
    # ── C3: Vietnamese wording ──
    (UI_RENDER_JS, '"COMBOSQUAT_BRAND": "Tên miền ghép thêm chữ cho giống tên ngân hàng",', '', C3M),
    (UI_RENDER_JS, 'return SIGNAL_MAP[cleanCode];', 'return cleanCode;', C3S),
    (UI_RENDER_JS, 's = s.replace(wordRe("redirect"), "chuyển hướng");', '', C3S),
    # ── C4: HTML accessibility ──
    (INDEX_HTML, 'role="region" aria-live="polite" aria-label="Kết quả phân tích"', 'role="region" aria-label="Kết quả phân tích"', C4),
    (INDEX_HTML, ' alt="SafeGuard AI Logo"', '', C4),
    (INDEX_HTML, '<main class="main-content" id="mainContent"', '<section class="main-content" id="mainContent"', C4),
    (INDEX_HTML, ' aria-label="Gửi để kiểm tra"', '', C4),
    (INDEX_HTML, '<header class="sidebar-header">', '<div class="sidebar-header">', C4),
    (APP_JS, '(e.target.classList.contains("suggestion-card") || e.target.classList.contains("session-item"))) {', '(e.target.classList.contains("never-matches") || e.target.classList.contains("session-item"))) {', ["test_c4_keyboard_activation_of_cards_and_history_items"]),
    # ── C5: CSS ──
    (STYLES_CSS, '.simple-why-item {\n    font-size: 16px;', '.simple-why-item {\n    font-size: 12px;', C5F),
    (STYLES_CSS, 'overflow: hidden;\n    font-size: 17px;', 'overflow: hidden;\n    font-size: 14px;', C5F),
    (STYLES_CSS, '.action-conclusion-text {\n    font-size: 28px;', '.action-conclusion-text {\n    font-size: 20px;', C5F),
    (STYLES_CSS, '@media (prefers-reduced-motion: reduce) {', '@media (prefers-contrast: more) {', C5T),
    (STYLES_CSS, 'input:not([type="checkbox"]):not([type="radio"]):not([type="file"]) {\n    min-height: 44px;',
     'input:not([type="checkbox"]):not([type="radio"]):not([type="file"]) {\n    min-height: 38px;', C5T),
    (STYLES_CSS, ':focus-visible {\n    outline: 3px solid #fde047;', ':focus-visible {\n    outline: 1px solid #fde047;', C5T),
    (STYLES_CSS, '@media (max-width: 480px) {', '@media (max-width: 481px) {', C5T),
    (STYLES_CSS, '.btn-deep-check {\n    min-height: 44px;', '.btn-deep-check {\n    min-height: 30px;', C5T),
    (STYLES_CSS, '--text-muted: #8fa0b8;', '--text-muted: #64748b;', C5C),
    (STYLES_CSS, '    border-color: #ef4444;\n    color: #fca5a5;', '    border-color: #ef4444;\n    color: #7f1d1d;', C5C),
    (STYLES_CSS, '    border-color: #10b981;\n    color: #6ee7b7;', '    border-color: #10b981;\n    color: #0b3d2e;', C5C),
    (STYLES_CSS, '    color: #04281d;\n    background: var(--accent);', '    color: #ffffff;\n    background: var(--accent);', C5C),
    # ── C6: deep check ──
    (UI_RENDER_JS, 'if (typeof onDeepCheckClick === "function" && shouldShowDeepCheck(res)) {', 'if (false) {', C6),
    (APP_JS, 'const isOnlineCheck = Boolean(onlineCheckCheckbox && onlineCheckCheckbox.checked);',
     'const isOnlineCheck = onlineCheckCheckbox && onlineCheckCheckbox.checked ? "true" : false;', C6),
    (APP_JS, '        if (onlineCheckCheckbox) {\n            onlineCheckCheckbox.checked = false;\n        }\n', '', C6),
    (APP_JS, '        if (onlineCheckCheckbox) onlineCheckCheckbox.checked = true;', '        /* flag not set */', C6),
    (APP_JS, 'res._checked_online = Boolean(ctx && ctx.onlineCheck === true);', 'res._checked_online = false;', C6),
    # ── C7: 5A safety on the new layout ──
    (APP_JS, 'riskHeadlineEl.textContent = headline;', 'riskHeadlineEl.innerHTML = headline;', C7),
    (UI_RENDER_JS, 'const cleanRec = defangText(humanizeText(sanitizeText(rec, 250)));', 'const cleanRec = defangText(humanizeText(String(rec)));', C7),
    (UI_RENDER_JS, 'const deepBtn = documentRef.createElement("button");', 'const deepBtn = documentRef.createElement("a");', C7),
    (APP_JS, 'const headline = safeText(decision.headline || "Rủi ro không xác định", 500);',
     'const headline = sanitize(decision.headline || "Rủi ro không xác định", 500);', C7),
]


def _run_mutation_tests(names):
    """Return True if at least one of the named tests FAILS on the mutated tree (mutant killed)."""
    for name in names:
        try:
            globals()[name]()
        except BaseException:  # noqa: BLE001 - any failure/exception kills the mutant
            return True
    return False


@pytest.mark.skipif(
    os.environ.get("SAFEGUARD_RUN_MUTATIONS") != "1",
    reason="Rewrites public/* on disk while running; if the process is killed mid-run the sources stay mutated. "
           "Opt in with SAFEGUARD_RUN_MUTATIONS=1 (never run it in parallel with anything that reads public/).",
)
def test_mutation_real_source_mutants_zero_survivors():
    """
    >= 12 REAL on-disk mutations (strings changed in public/*.js|html|css), tests re-run, bytes restored.
    Every mutant must be killed by at least one named test. Survivors MUST be 0.
    """
    assert len(MUTATIONS) >= 12
    originals = {}
    for path in {m[0] for m in MUTATIONS}:
        with open(path, "rb") as f:
            originals[path] = f.read()

    survivors, killed = [], 0
    try:
        for idx, (path, target, mutated, names) in enumerate(MUTATIONS, start=1):
            raw = originals[path]
            text = raw.decode("utf-8")
            crlf = "\r\n" in text
            norm = text.replace("\r\n", "\n")
            assert target in norm, f"Mutant {idx}: target not found in {os.path.basename(path)}: {target[:70]!r}"
            new = norm.replace(target, mutated, 1)
            assert new != norm, f"Mutant {idx} does not change the file"
            if crlf:
                new = new.replace("\n", "\r\n")
            try:
                with open(path, "wb") as f:
                    f.write(new.encode("utf-8"))
                if _run_mutation_tests(names):
                    killed += 1
                else:
                    survivors.append(f"#{idx} {os.path.basename(path)}: {target[:50]!r} -> {mutated[:40]!r}")
            finally:
                with open(path, "wb") as f:
                    f.write(raw)
    finally:
        for path, raw in originals.items():
            with open(path, "wb") as f:
                f.write(raw)

    for path, raw in originals.items():
        with open(path, "rb") as f:
            assert f.read() == raw, f"{path} was not restored byte-for-byte"
    assert survivors == [], f"Mutants survived ({len(survivors)}): {survivors}"
    assert killed == len(MUTATIONS)
