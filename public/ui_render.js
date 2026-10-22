/**
 * SafeGuard AI — UI Render Module
 * Pure rendering functions for URL analysis, Pipeline Trace, Network Actions, and Sanitization.
 * Compatible with modern browsers and Node.js test environment (CommonJS guard).
 */

(function (root, factory) {
    if (typeof module !== "undefined" && module.exports) {
        module.exports = factory();
    } else {
        root.UIRender = factory();
    }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
    "use strict";

    /**
     * Minimal DOM mock implementation for Node.js test runners without external dependencies.
     */
    function createMockDocument() {
        function createMockElement(tagName) {
            return {
                tagName: String(tagName).toUpperCase(),
                children: [],
                childNodes: [],
                attributes: {},
                _innerHTMLAccessed: false,
                _innerHTMLAssigned: false,
                classList: {
                    _classes: new Set(),
                    add: function () {
                        for (let i = 0; i < arguments.length; i++) {
                            if (arguments[i]) this._classes.add(String(arguments[i]));
                        }
                    },
                    remove: function () {
                        for (let i = 0; i < arguments.length; i++) {
                            this._classes.delete(String(arguments[i]));
                        }
                    },
                    contains: function (cls) {
                        return this._classes.has(String(cls));
                    },
                    toggle: function (cls) {
                        const s = String(cls);
                        if (this._classes.has(s)) {
                            this._classes.delete(s);
                            return false;
                        } else {
                            this._classes.add(s);
                            return true;
                        }
                    }
                },
                style: {},
                dataset: {},
                _textContent: "",
                get textContent() {
                    if (this.children && this.children.length > 0) {
                        return this.children.map(function (c) {
                            return c.textContent || "";
                        }).join("");
                    }
                    return this._textContent;
                },
                set textContent(val) {
                    this._textContent = String(val);
                    this.children = [];
                    this.childNodes = [];
                },
                get innerHTML() {
                    this._innerHTMLAccessed = true;
                    return this._textContent;
                },
                set innerHTML(val) {
                    this._innerHTMLAssigned = true;
                    this._textContent = String(val);
                },
                get className() {
                    return Array.from(this.classList._classes).join(" ");
                },
                set className(val) {
                    this.classList._classes = new Set(String(val || "").split(/\s+/).filter(Boolean));
                },
                appendChild: function (child) {
                    if (!child) return null;
                    this.children.push(child);
                    this.childNodes.push(child);
                    child.parentNode = this;
                    return child;
                },
                setAttribute: function (name, val) {
                    this.attributes[String(name)] = String(val);
                },
                getAttribute: function (name) {
                    return this.attributes[String(name)] || null;
                },
                addEventListener: function (evt, fn) {
                    this._listeners = this._listeners || {};
                    this._listeners[evt] = this._listeners[evt] || [];
                    this._listeners[evt].push(fn);
                },
                querySelector: function (sel) {
                    for (let i = 0; i < this.children.length; i++) {
                        const child = this.children[i];
                        if (child._matchesSelector(sel)) return child;
                        const sub = child.querySelector(sel);
                        if (sub) return sub;
                    }
                    return null;
                },
                querySelectorAll: function (sel) {
                    const results = [];
                    for (let i = 0; i < this.children.length; i++) {
                        const child = this.children[i];
                        if (child._matchesSelector(sel)) results.push(child);
                        const subList = child.querySelectorAll(sel);
                        for (let j = 0; j < subList.length; j++) {
                            results.push(subList[j]);
                        }
                    }
                    return results;
                },
                _matchesSelector: function (sel) {
                    if (!sel) return false;
                    if (sel.startsWith(".")) {
                        return this.classList.contains(sel.slice(1));
                    }
                    return this.tagName.toLowerCase() === sel.toLowerCase();
                }
            };
        }

        return {
            createElement: createMockElement,
            createTextNode: function (text) {
                return {
                    nodeType: 3,
                    textContent: String(text || "")
                };
            }
        };
    }

    /**
     * Sanitize server text before rendering.
     * Strips control characters, NUL, Bidi overrides (U+202A-202E, U+2066-2069, U+200E/F, U+061C),
     * zero-width spaces, invisible formatting (U+2028, U+2029, U+2060, U+180E, U+034F),
     * and truncates length to maxLength.
     */
    function sanitizeText(s, maxLength) {
        if (s === null || s === undefined) return "";
        let str = String(s);

        // 1. Remove NUL and C0/C1 control characters (keep standard \n and \t if present)
        str = str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, "");

        // 2. Remove Bidi override, isolate, and mark characters:
        // U+202A (LRE), U+202B (RLE), U+202C (PDF), U+202D (LRO), U+202E (RLO)
        // U+2066 (LRI), U+2067 (RLI), U+2068 (FSI), U+2069 (PDI)
        // U+200E (LRM), U+200F (RLM), U+061C (ALM)
        str = str.replace(/[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/g, "");

        // 3. Remove Zero-Width characters and invisible format characters:
        // U+200B (ZWSP), U+200C (ZWNJ), U+200D (ZWJ), U+FEFF (BOM), U+00AD (soft hyphen)
        // U+2028 (LS), U+2029 (PS), U+2060 (WJ), U+180E (MVS), U+034F (CGJ)
        str = str.replace(/[\u200B-\u200D\uFEFF\u00AD\u2028\u2029\u2060\u180E\u034F]/g, "");

        // 4. Bounded length slice
        const max = (typeof maxLength === "number" && maxLength > 0) ? maxLength : 300;
        if (str.length > max) {
            str = str.slice(0, max);
        }

        return str;
    }

    /**
     * Defang a host string by replacing dots with '[.]'.
     * Normalizes Unicode dots and avoids double brackets (idempotent).
     */
    function defangHost(host) {
        if (!host) return "";
        let h = String(host).trim();
        h = h.replace(/[\u3002\uFF0E\uFF61]/g, ".");
        // Collapse existing [.] back to . to prevent double-defang
        h = h.replace(/\[\.\]/g, ".");
        h = h.replace(/\./g, "[.]");
        return h;
    }

    /**
     * Defang a full URL or host string:
     * - Defangs schemes everywhere: http(s)/ftp -> hxxp(s)/fxp
     * - Defangs '.' to '[.]' in all authorities/hosts across the string (including userinfo/embedded queries)
     * - Normalizes Unicode dots (U+3002, U+FF0E, U+FF61) to '[.]'
     * - Fully idempotent (no double [[.]]).
     */
    function defangUrl(urlStr) {
        if (!urlStr) return "";
        let s = String(urlStr).trim();
        if (s.length > 2000) {
            s = s.slice(0, 2000);
        }

        // 1. Defang schemes across entire string
        s = s.replace(/\bhttps:\/\//gi, "hxxps://");
        s = s.replace(/\bhttp:\/\//gi, "hxxp://");
        s = s.replace(/\bftps:\/\//gi, "fxps://");
        s = s.replace(/\bftp:\/\//gi, "fxp://");
        s = s.replace(/\bhttps:/gi, "hxxps:");
        s = s.replace(/\bhttp:/gi, "hxxp:");
        s = s.replace(/\bftps:/gi, "fxps:");
        s = s.replace(/\bftp:/gi, "fxp:");

        // Non-boundary starts
        s = s.replace(/^https?:\/\//i, function (m) {
            return m.toLowerCase().startsWith("https") ? "hxxps://" : "hxxp://";
        });
        s = s.replace(/^ftps?:\/\//i, function (m) {
            return m.toLowerCase().startsWith("ftps") ? "fxps://" : "fxp://";
        });

        function safeDefangAuthority(auth) {
            if (!auth) return "";
            let a = String(auth);
            a = a.replace(/[\u3002\uFF0E\uFF61]/g, ".");
            a = a.replace(/\[\.\]/g, ".");
            a = a.replace(/\./g, "[.]");
            return a;
        }

        // 2. Defang authority after schemes: (hxxps?:\/\/|fxps?:\/\/) or (//)
        s = s.replace(/((?:hxxps?|fxps?):\/\/|\/\/)([^\/\?\#\s]{1,255})/gi, function (match, prefix, authority) {
            return prefix + safeDefangAuthority(authority);
        });

        // 3. Defang hosts embedded after query parameters: q=, url=, dest=, target=, redirect=, next=, link=, host=
        s = s.replace(/([?&;](?:q|url|dest|destination|target|redirect|link|next|goto|r|host)=)([^\s&#]{1,255})/gi, function (match, paramPrefix, val) {
            const slashIdx = val.search(/[\/\?\#]/);
            const hostPart = slashIdx !== -1 ? val.slice(0, slashIdx) : val;
            const restPart = slashIdx !== -1 ? val.slice(slashIdx) : "";
            if (/[\.\u3002\uFF0E\uFF61]|\[\.\]/.test(hostPart)) {
                return paramPrefix + safeDefangAuthority(hostPart) + restPart;
            }
            return match;
        });

        // 4. Stand-alone host without scheme at start
        if (!/^(?:hxxps?|fxps?):\/\/|^\/\//i.test(s)) {
            const firstDelim = s.search(/[\/\?\#]/);
            const topHost = firstDelim !== -1 ? s.slice(0, firstDelim) : s;
            const topRest = firstDelim !== -1 ? s.slice(firstDelim) : "";
            if (/[\.\u3002\uFF0E\uFF61]|\[\.\]/.test(topHost)) {
                s = safeDefangAuthority(topHost) + topRest;
            }
        }

        // 5. Replace any remaining Unicode dots
        s = s.replace(/[\u3002\uFF0E\uFF61]/g, "[.]");

        // Idempotency check: collapse any nested brackets
        while (s.includes("[[.]") || s.includes("[.]]")) {
            s = s.replace(/\[\[\.\]/g, "[.]").replace(/\[\.\]\]/g, "[.]");
        }

        return s;
    }

    /**
     * Defang hostnames and URLs in free text (summary_vi, message_vi, evidence, detail_vi).
     * Defangs domains and URLs without corrupting regular Vietnamese text, numbers, or sentence periods.
     */
    function defangText(text) {
        if (!text) return "";
        let s = String(text);
        if (s.length > 5000) {
            s = s.slice(0, 5000);
        }

        // 1. Defang any explicit URLs first
        s = s.replace(/\b(?:https?|ftp):\/\/[^\s<>"'`]+/gi, function (urlMatch) {
            return defangUrl(urlMatch);
        });

        // 2. Defang IPv4 addresses
        s = s.replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::(\d{1,5}))?\b/g, function (m, a, b, c, d, port) {
            const p = port ? ":" + port : "";
            return a + "[.]" + b + "[.]" + c + "[.]" + d + p;
        });

        // 3. Defang domain-like patterns: e.g. evil-login.xyz, host=vietcombank-xacminh.top
        // Linear regex with bounded labels, does not match number strings like 500.000 or sentence ends like "Nam. Ngày"
        const domainRegex = /\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)((?:[\.\u3002\uFF0E\uFF61]|\[\.\])[a-zA-Z0-9-]{1,63})*([\.\u3002\uFF0E\uFF61]|\[\.\])([a-zA-Z]{2,24})\b/g;

        s = s.replace(domainRegex, function (match) {
            if (match.includes("[.]") && !/[\.\u3002\uFF0E\uFF61]/.test(match.replace(/\[\.\]/g, ""))) {
                return match;
            }
            let defanged = match.replace(/[\u3002\uFF0E\uFF61]/g, ".");
            defanged = defanged.replace(/\[\.\]/g, ".");
            defanged = defanged.replace(/\./g, "[.]");
            return defanged;
        });

        return s;
    }

    /**
     * Severity weights for sorting signals.
     */
    const SEVERITY_ORDER = {
        critical: 5,
        high: 4,
        medium: 3,
        low: 2,
        info: 1
    };

    /**
     * Map verdict code to Vietnamese label and visual CSS class.
     */
    function getVerdictInfo(verdict) {
        const v = String(verdict || "").toLowerCase();
        switch (v) {
            case "dangerous":
                return { label: "🚨 Nguy hiểm (Dangerous)", cls: "verdict-dangerous" };
            case "suspicious":
                return { label: "⚠️ Nghi vấn (Suspicious)", cls: "verdict-suspicious" };
            case "unverified":
                return { label: "🟡 Chưa xác minh (Unverified)", cls: "verdict-unverified" };
            case "official":
                return { label: "🛡️ Chính thức (Official)", cls: "verdict-official" };
            case "benign":
                return { label: "✅ Lành tính (Benign)", cls: "verdict-benign" };
            case "low":
                return { label: "ℹ️ Rủi ro thấp (Low)", cls: "verdict-low" };
            default:
                return { label: "❓ Không xác định (Unknown)", cls: "verdict-unknown" };
        }
    }

    /**
     * Build a single URL analysis card for a UrlFinding.
     * Guaranteed: NEVER creates <a> elements, NEVER uses innerHTML with server data.
     */
    function buildLinkCard(finding, doc) {
        const documentRef = doc || (typeof document !== "undefined" ? document : createMockDocument());
        const card = documentRef.createElement("div");
        card.className = "link-analysis-card";

        if (!finding) return card;

        // 1. Header (Verdict badge, Risk Score, Source tag)
        const header = documentRef.createElement("div");
        header.className = "link-card-header";

        const verdictInfo = getVerdictInfo(finding.verdict);
        const verdictBadge = documentRef.createElement("span");
        verdictBadge.className = "verdict-badge " + verdictInfo.cls;
        verdictBadge.textContent = verdictInfo.label;
        header.appendChild(verdictBadge);

        const scoreBadge = documentRef.createElement("span");
        scoreBadge.className = "link-score-badge";
        const scoreVal = typeof finding.url_risk_score === "number" ? finding.url_risk_score : 0;
        scoreBadge.textContent = "Điểm rủi ro URL: " + scoreVal + "/99";
        header.appendChild(scoreBadge);

        if (finding.source) {
            const sourceTag = documentRef.createElement("span");
            sourceTag.className = "link-source-tag";
            sourceTag.textContent = "Nguồn: " + sanitizeText(finding.source, 50);
            header.appendChild(sourceTag);
        }

        card.appendChild(header);

        // 2. Hai dòng chính: "Bạn thấy:" và "Thực tế mở:"
        const urlRows = documentRef.createElement("div");
        urlRows.className = "link-card-urls";

        // Dòng 1: Bạn thấy
        const rawRow = documentRef.createElement("div");
        rawRow.className = "link-url-row";
        const rawLabel = documentRef.createElement("span");
        rawLabel.className = "link-row-label";
        rawLabel.textContent = "Bạn thấy:";
        const rawVal = documentRef.createElement("span");
        rawVal.className = "link-row-value link-display-value";
        const displayRaw = finding.raw || finding.display_host || "";
        rawVal.textContent = defangUrl(sanitizeText(displayRaw, 300));
        rawRow.appendChild(rawLabel);
        rawRow.appendChild(rawVal);
        urlRows.appendChild(rawRow);

        // Dòng 2: Thực tế mở
        const finalRow = documentRef.createElement("div");
        finalRow.className = "link-url-row";
        const finalLabel = documentRef.createElement("span");
        finalLabel.className = "link-row-label";
        finalLabel.textContent = "Thực tế mở:";
        const finalVal = documentRef.createElement("span");
        finalVal.className = "link-row-value link-actual-value";
        const actualUrl = finding.final_url || finding.effective_host_unicode || finding.effective_host || "";
        finalVal.textContent = defangUrl(sanitizeText(actualUrl, 300));
        finalRow.appendChild(finalLabel);
        finalRow.appendChild(finalVal);
        urlRows.appendChild(finalRow);

        // Hiển thị thêm Host Unicode nếu khác display_host
        if (finding.effective_host_unicode && finding.display_host && finding.effective_host_unicode !== finding.display_host) {
            const hostDiffRow = documentRef.createElement("div");
            hostDiffRow.className = "link-url-row link-host-diff";
            const hostDiffLabel = documentRef.createElement("span");
            hostDiffLabel.className = "link-row-label";
            hostDiffLabel.textContent = "Máy chủ đích:";
            const hostDiffVal = documentRef.createElement("span");
            hostDiffVal.className = "link-row-value";
            hostDiffVal.textContent = defangHost(sanitizeText(finding.effective_host_unicode, 100));
            hostDiffRow.appendChild(hostDiffLabel);
            hostDiffRow.appendChild(hostDiffVal);
            urlRows.appendChild(hostDiffRow);
        }

        card.appendChild(urlRows);

        // 3. Gợi ý domain chính thức khi có brand_match (KHÔNG làm thành link bấm được)
        try {
            if (finding.brand_match && typeof finding.brand_match === "object") {
                const brandBox = documentRef.createElement("div");
                brandBox.className = "brand-match-box";

                const brandTitle = documentRef.createElement("div");
                brandTitle.className = "brand-match-title";
                const brandName = sanitizeText(finding.brand_match.display_name || "Tổ chức", 100);
                brandTitle.textContent = "⚠️ Dấu hiệu mạo danh thương hiệu: " + brandName;
                brandBox.appendChild(brandTitle);

                if (finding.brand_match.official_domain) {
                    const officialDomainRow = documentRef.createElement("div");
                    officialDomainRow.className = "brand-official-domain";
                    const domainLabel = documentRef.createElement("span");
                    domainLabel.textContent = "Tên miền chính thức của đơn vị: ";
                    const domainVal = documentRef.createElement("span");
                    domainVal.className = "brand-domain-text";
                    // URL defanged and rendered strictly via textContent — NO <a> tag!
                    domainVal.textContent = defangHost(sanitizeText(finding.brand_match.official_domain, 100));
                    officialDomainRow.appendChild(domainLabel);
                    officialDomainRow.appendChild(domainVal);
                    brandBox.appendChild(officialDomainRow);
                }

                const brandWarn = documentRef.createElement("div");
                brandWarn.className = "brand-match-warning";
                brandWarn.textContent = "Khuyến nghị: Tuyệt đối không đăng nhập hay nhập mã OTP trên website này.";
                brandBox.appendChild(brandWarn);

                card.appendChild(brandBox);
            }
        } catch (err) {
            console.error("Error rendering brand_match:", err);
        }

        // 4. Danh sách các bước che giấu (Obfuscation chain)
        try {
            if (finding.obfuscation_chain && Array.isArray(finding.obfuscation_chain) && finding.obfuscation_chain.length > 0) {
                const obfBox = documentRef.createElement("div");
                obfBox.className = "obfuscation-section";

                const obfTitle = documentRef.createElement("div");
                obfTitle.className = "section-subtitle";
                obfTitle.textContent = "🛡️ Các kỹ thuật che giấu phát hiện được:";
                obfBox.appendChild(obfTitle);

                const obfList = documentRef.createElement("div");
                obfList.className = "obfuscation-list";

                finding.obfuscation_chain.forEach(function (step, idx) {
                    if (!step || typeof step !== "object") return;
                    const stepItem = documentRef.createElement("div");
                    stepItem.className = "obfuscation-step-item";

                    const stepNumber = documentRef.createElement("span");
                    stepNumber.className = "step-number";
                    stepNumber.textContent = "Bước " + (idx + 1) + ":";

                    const stepTech = documentRef.createElement("span");
                    stepTech.className = "step-tech";
                    stepTech.textContent = "[" + sanitizeText(step.technique, 80) + "]";

                    const stepDetail = documentRef.createElement("span");
                    stepDetail.className = "step-detail";
                    stepDetail.textContent = defangText(sanitizeText(step.detail_vi || "", 300));

                    stepItem.appendChild(stepNumber);
                    stepItem.appendChild(stepTech);
                    stepItem.appendChild(stepDetail);
                    obfList.appendChild(stepItem);
                });

                obfBox.appendChild(obfList);
                card.appendChild(obfBox);
            }
        } catch (err) {
            console.error("Error rendering obfuscation_chain:", err);
        }

        // 5. Chuỗi chuyển hướng (Redirect chain)
        try {
            if (finding.redirect_chain && Array.isArray(finding.redirect_chain) && finding.redirect_chain.length > 0) {
                const redBox = documentRef.createElement("div");
                redBox.className = "redirect-section";

                const redTitle = documentRef.createElement("div");
                redTitle.className = "section-subtitle";
                redTitle.textContent = "↪️ Chuỗi chuyển hướng (Redirect Chain):";
                redBox.appendChild(redTitle);

                const redList = documentRef.createElement("div");
                redList.className = "redirect-list";

                finding.redirect_chain.forEach(function (hop, idx) {
                    if (!hop || typeof hop !== "object") return;
                    const hopItem = documentRef.createElement("div");
                    hopItem.className = "redirect-hop-item";

                    const hopIndex = documentRef.createElement("span");
                    hopIndex.className = "hop-index";
                    hopIndex.textContent = "Chặng " + (idx + 1) + ":";

                    const hopStatus = documentRef.createElement("span");
                    hopStatus.className = "hop-status";
                    hopStatus.textContent = hop.status ? "(" + sanitizeText(String(hop.status), 30) + ")" : "(redirect)";

                    const hopUrl = documentRef.createElement("span");
                    hopUrl.className = "hop-url";
                    hopUrl.textContent = defangUrl(sanitizeText(hop.url || "", 300));

                    hopItem.appendChild(hopIndex);
                    hopItem.appendChild(hopStatus);
                    hopItem.appendChild(hopUrl);
                    redList.appendChild(hopItem);
                });

                redBox.appendChild(redList);
                card.appendChild(redBox);
            }
        } catch (err) {
            console.error("Error rendering redirect_chain:", err);
        }

        // 6. Signals an ninh (sắp xếp theo severity)
        try {
            if (finding.signals && Array.isArray(finding.signals) && finding.signals.length > 0) {
                const validSignals = finding.signals.filter(function (s) {
                    return s && typeof s === "object";
                });

                if (validSignals.length > 0) {
                    const sigBox = documentRef.createElement("div");
                    sigBox.className = "signals-section";

                    const sigTitle = documentRef.createElement("div");
                    sigTitle.className = "section-subtitle";
                    sigTitle.textContent = "🔍 Tín hiệu an ninh phát hiện:";
                    sigBox.appendChild(sigTitle);

                    const sortedSignals = validSignals.slice().sort(function (a, b) {
                        const wA = SEVERITY_ORDER[String(a.severity || "").toLowerCase()] || 0;
                        const wB = SEVERITY_ORDER[String(b.severity || "").toLowerCase()] || 0;
                        return wB - wA;
                    });

                    const sigList = documentRef.createElement("div");
                    sigList.className = "signals-list";

                    const SEV_WHITELIST = ["critical", "high", "medium", "low", "info"];

                    sortedSignals.forEach(function (sig) {
                        const cleanSev = String(sig.severity || "info").toLowerCase();
                        const sevCls = SEV_WHITELIST.includes(cleanSev) ? cleanSev : "unknown";

                        const sigItem = documentRef.createElement("div");
                        sigItem.className = "signal-item severity-" + sevCls;

                        const sigSev = documentRef.createElement("span");
                        sigSev.className = "signal-badge";
                        sigSev.textContent = String(sig.severity || "INFO").toUpperCase();

                        const sigMsg = documentRef.createElement("span");
                        sigMsg.className = "signal-message";
                        sigMsg.textContent = defangText(sanitizeText(sig.message_vi || sig.code || "", 300));

                        sigItem.appendChild(sigSev);
                        sigItem.appendChild(sigMsg);

                        if (sig.evidence) {
                            const sigEv = documentRef.createElement("span");
                            sigEv.className = "signal-evidence";
                            sigEv.textContent = " (Bằng chứng: " + defangText(sanitizeText(sig.evidence, 200)) + ")";
                            sigItem.appendChild(sigEv);
                        }

                        sigList.appendChild(sigItem);
                    });

                    sigBox.appendChild(sigList);
                    card.appendChild(sigBox);
                }
            }
        } catch (err) {
            console.error("Error rendering signals:", err);
        }

        // 7. Children của finding (finding con open-redirect rút gọn)
        try {
            if (Array.isArray(finding.children) && finding.children.length > 0) {
                const validChildren = finding.children.filter(function (c) {
                    return c && typeof c === "object";
                });
                if (validChildren.length > 0) {
                    const childBox = documentRef.createElement("div");
                    childBox.className = "finding-children-box";

                    const childTitle = documentRef.createElement("div");
                    childTitle.className = "section-subtitle";
                    childTitle.textContent = "🔗 Đường link chuyển tiếp phát hiện bên trong (Open-Redirect Target):";
                    childBox.appendChild(childTitle);

                    validChildren.forEach(function (child) {
                        const childItem = documentRef.createElement("div");
                        childItem.className = "finding-child-item";

                        const childVerdict = getVerdictInfo(child.verdict);
                        const badge = documentRef.createElement("span");
                        badge.className = "verdict-badge " + childVerdict.cls;
                        badge.textContent = childVerdict.label;
                        childItem.appendChild(badge);

                        const childUrlSpan = documentRef.createElement("span");
                        childUrlSpan.className = "child-url-text";
                        const childUrlRaw = child.final_url || child.raw || child.display_host || "";
                        childUrlSpan.textContent = defangUrl(sanitizeText(childUrlRaw, 300));
                        childItem.appendChild(childUrlSpan);

                        if (typeof child.url_risk_score === "number") {
                            const scoreSpan = documentRef.createElement("span");
                            scoreSpan.className = "link-score-badge";
                            scoreSpan.textContent = "Điểm: " + child.url_risk_score + "/99";
                            childItem.appendChild(scoreSpan);
                        }

                        childBox.appendChild(childItem);
                    });
                    card.appendChild(childBox);
                }
            }
        } catch (err) {
            console.error("Error rendering finding children:", err);
        }

        // 8. Thông tin tình báo thụ động (Passive Intel: cert subject/SAN/issuer, domain_age, dns_status)
        try {
            if (finding.passive_intel && typeof finding.passive_intel === "object") {
                const intel = finding.passive_intel;
                const intelBox = documentRef.createElement("div");
                intelBox.className = "passive-intel-box";

                const intelTitle = documentRef.createElement("div");
                intelTitle.className = "section-subtitle";
                intelTitle.textContent = "🌐 Thông tin tên miền & Chứng chỉ số (Passive Intel):";
                intelBox.appendChild(intelTitle);

                const intelList = documentRef.createElement("div");
                intelList.className = "passive-intel-list";

                // Domain age / WHOIS
                if (intel.domain_age && typeof intel.domain_age === "object") {
                    const da = intel.domain_age;
                    const daItem = documentRef.createElement("div");
                    daItem.className = "intel-item";
                    let daText = "Tuổi tên miền: ";
                    if (typeof da.age_days === "number") {
                        daText += da.age_days + " ngày";
                    }
                    if (da.registrar) {
                        daText += " (Nhà đăng ký: " + sanitizeText(da.registrar, 100) + ")";
                    }
                    daItem.textContent = daText;
                    intelList.appendChild(daItem);
                }

                // TLS Certificate (subject / SAN / issuer)
                const cert = intel.cert || intel.tls;
                if (cert && typeof cert === "object") {
                    const certItem = documentRef.createElement("div");
                    certItem.className = "intel-item cert-info-item";

                    const subjectVal = cert.subject_cn || cert.subject || "";
                    const issuerVal = cert.issuer_org || cert.issuer || "";
                    const sanList = Array.isArray(cert.san) ? cert.san : [];

                    if (subjectVal) {
                        const subjRow = documentRef.createElement("div");
                        subjRow.className = "cert-row cert-subject";
                        subjRow.textContent = "Chứng chỉ (Subject): " + defangHost(sanitizeText(subjectVal, 150));
                        certItem.appendChild(subjRow);
                    }

                    if (issuerVal) {
                        const issRow = documentRef.createElement("div");
                        issRow.className = "cert-row cert-issuer";
                        issRow.textContent = "Tổ chức phát hành (Issuer): " + sanitizeText(issuerVal, 150);
                        certItem.appendChild(issRow);
                    }

                    if (sanList.length > 0) {
                        const sanRow = documentRef.createElement("div");
                        sanRow.className = "cert-row cert-san";
                        const defangedSan = sanList.slice(0, 5).map(function (s) {
                            return defangHost(sanitizeText(s, 100));
                        }).join(", ");
                        sanRow.textContent = "Tên thay thế (SAN): " + defangedSan + (sanList.length > 5 ? " (+" + (sanList.length - 5) + " khác)" : "");
                        certItem.appendChild(sanRow);
                    }

                    intelList.appendChild(certItem);
                }

                // DNS Status
                if (intel.dns_status) {
                    const dnsItem = documentRef.createElement("div");
                    dnsItem.className = "intel-item";
                    dnsItem.textContent = "Trạng thái DNS: " + sanitizeText(intel.dns_status, 40);
                    intelList.appendChild(dnsItem);
                }

                intelBox.appendChild(intelList);
                card.appendChild(intelBox);
            }
        } catch (err) {
            console.error("Error rendering passive intel:", err);
        }

        // 9. Hộp hướng dẫn U4: khi verdict là 'unverified' hoặc có mã lỗi antibot/cloaking cụ thể
        try {
            const isUnverified = (finding.verdict === "unverified");
            const ANTIBOT_ERROR_CODES = new Set([
                "antibot_challenge",
                "cloaking_suspected",
                "cf_challenge",
                "turnstile_challenge",
                "recaptcha_challenge",
                "hcaptcha_challenge",
                "datadome_challenge",
                "akamai_challenge",
                "antibot_blocked",
                "js_only_challenge"
            ]);
            let hasBotError = false;
            if (Array.isArray(finding.errors)) {
                hasBotError = finding.errors.some(function (e) {
                    return ANTIBOT_ERROR_CODES.has(String(e || "").toLowerCase().trim());
                });
            }
            if (!hasBotError && Array.isArray(finding.signals)) {
                hasBotError = finding.signals.some(function (s) {
                    return s && typeof s === "object" && (s.code === "ANTIBOT_CHALLENGE" || s.code === "CLOAKING_SUSPECTED");
                });
            }

            if (isUnverified || hasBotError) {
                const unverifiedBox = documentRef.createElement("div");
                unverifiedBox.className = "unverified-guide-box";

                const unverifiedMsg = documentRef.createElement("div");
                unverifiedMsg.className = "unverified-guide-msg";
                unverifiedMsg.textContent = "Trang chặn công cụ kiểm tra tự động. Đừng coi là an toàn. Hãy chụp màn hình trang đó rồi tải ảnh lên để SafeGuard đọc nội dung.";
                unverifiedBox.appendChild(unverifiedMsg);

                const uploadBtn = documentRef.createElement("button");
                uploadBtn.type = "button";
                uploadBtn.className = "btn-upload-screenshot";
                uploadBtn.textContent = "📸 Tải ảnh chụp màn hình lên";
                uploadBtn.addEventListener("click", function () {
                    const fileInput = documentRef.getElementById ? documentRef.getElementById("fileInput") : null;
                    if (fileInput && typeof fileInput.click === "function") {
                        fileInput.click();
                    } else {
                        const inputArea = documentRef.querySelector ? documentRef.querySelector(".input-area") : null;
                        if (inputArea && typeof inputArea.scrollIntoView === "function") {
                            inputArea.scrollIntoView({ behavior: "smooth" });
                        }
                    }
                });
                unverifiedBox.appendChild(uploadBtn);

                card.appendChild(unverifiedBox);
            }
        } catch (err) {
            console.error("Error rendering U4 guide box:", err);
        }

        return card;
    }

    /**
     * Render the list of URL findings (up to 10 cards, truncated notification, etc.)
     */
    function renderUrlAnalysis(urlAnalysis, container, doc) {
        if (!urlAnalysis || !container) return;
        const documentRef = doc || (typeof document !== "undefined" ? document : createMockDocument());

        const findings = Array.isArray(urlAnalysis.findings) ? urlAnalysis.findings : [];
        if (findings.length === 0) return;

        const section = documentRef.createElement("div");
        section.className = "url-analysis-container";

        const title = documentRef.createElement("h4");
        title.className = "url-analysis-title";
        title.textContent = "🌐 Phân tích đường link (URL Analysis):";
        section.appendChild(title);

        // Summaries if present
        if (Array.isArray(urlAnalysis.summary_vi) && urlAnalysis.summary_vi.length > 0) {
            const summaryBox = documentRef.createElement("div");
            summaryBox.className = "url-summary-box";
            urlAnalysis.summary_vi.forEach(function (sumText) {
                if (typeof sumText !== "string" && typeof sumText !== "number") return;
                const p = documentRef.createElement("p");
                p.className = "url-summary-item";
                p.textContent = "• " + defangText(sanitizeText(sumText, 300));
                summaryBox.appendChild(p);
            });
            section.appendChild(summaryBox);
        }

        // Limit to max 10 cards
        const maxCards = 10;
        const renderedFindings = findings.slice(0, maxCards);
        renderedFindings.forEach(function (f) {
            try {
                if (!f || typeof f !== "object") return;
                const card = buildLinkCard(f, documentRef);
                if (card) section.appendChild(card);
            } catch (err) {
                console.error("Error building link card:", err);
            }
        });

        // If more than 10 findings exist, notify "... và N link khác"
        if (findings.length > maxCards) {
            const remainderCount = findings.length - maxCards;
            const moreNotice = documentRef.createElement("div");
            moreNotice.className = "url-more-notice";
            moreNotice.textContent = "... và " + remainderCount + " link khác.";
            section.appendChild(moreNotice);
        }

        // Notification if truncated at engine level
        if (urlAnalysis.truncated) {
            const truncNotice = documentRef.createElement("div");
            truncNotice.className = "url-truncated-notice";
            truncNotice.textContent = "⚠️ Danh sách đường link vượt quá giới hạn xử lý và đã được cắt bớt để bảo đảm an toàn.";
            section.appendChild(truncNotice);
        }

        container.appendChild(section);
    }

    /**
     * Render the real Pipeline Trace replacing fake animations.
     * Displays Stage A ms and Stage B ms separately (does not sum parallel stages).
     */
    function renderPipelineTrace(pipelineTrace, container, doc) {
        if (!pipelineTrace || !Array.isArray(pipelineTrace) || pipelineTrace.length === 0 || !container) return;
        const documentRef = doc || (typeof document !== "undefined" ? document : createMockDocument());

        const box = documentRef.createElement("div");
        box.className = "pipeline-trace-box";

        const title = documentRef.createElement("div");
        title.className = "pipeline-trace-header";

        let aMs = 0;
        let bNetMs = 0;
        let bLlmMs = 0;
        let hasB = false;

        pipelineTrace.forEach(function (st) {
            if (!st || typeof st !== "object") return;
            if (st.stage === "A_deterministic") {
                if (typeof st.ms === "number") aMs = st.ms;
            } else if (st.stage === "B_network") {
                hasB = true;
                if (typeof st.ms === "number") bNetMs = st.ms;
            } else if (st.stage === "B_llm") {
                hasB = true;
                if (typeof st.ms === "number") bLlmMs = st.ms;
            }
        });

        let bMs = Math.max(bNetMs, bLlmMs);
        let summaryText = "A: " + aMs.toFixed(1) + "ms";
        if (hasB) {
            summaryText += ", B: " + bMs.toFixed(1) + "ms";
        }
        title.textContent = "⚡ Tiến trình phân tích thật (Pipeline Trace — " + summaryText + "):";
        box.appendChild(title);

        const list = documentRef.createElement("div");
        list.className = "pipeline-trace-list";

        const STAGE_NAMES = {
            "A_deterministic": "Tầng A — Phân tích tĩnh tất định (Rules/RAG/Offline)",
            "B_network": "Tầng B1 — Mạng & Đối soát mối đe dọa (Threat Intelligence)",
            "B_llm": "Tầng B2 — Tổng hợp Trí tuệ nhân tạo (LLM Synthesis)",
            "merge": "Tổng hợp kết quả & Đưa ra phán quyết an toàn"
        };
        const STAGE_STATUS_WHITELIST = ["ok", "skipped", "disabled", "error", "timeout", "fallback"];

        pipelineTrace.forEach(function (st) {
            if (!st || typeof st !== "object") return;
            const item = documentRef.createElement("div");
            item.className = "pipeline-trace-item";

            const nameSpan = documentRef.createElement("span");
            nameSpan.className = "stage-name";
            const rawStage = st.stage || "unknown_stage";
            nameSpan.textContent = STAGE_NAMES[rawStage] || sanitizeText(rawStage, 100);

            const msSpan = documentRef.createElement("span");
            msSpan.className = "stage-ms";
            msSpan.textContent = (typeof st.ms === "number" ? st.ms.toFixed(1) : "0.0") + "ms";

            const statusSpan = documentRef.createElement("span");
            const rawStat = String(st.status || "ok").toLowerCase().trim();
            const statusCls = STAGE_STATUS_WHITELIST.includes(rawStat) ? rawStat : "unknown";
            statusSpan.className = "stage-status status-" + statusCls;
            statusSpan.textContent = "[" + statusCls + "]";

            item.appendChild(nameSpan);
            item.appendChild(msSpan);
            item.appendChild(statusSpan);
            list.appendChild(item);
        });

        box.appendChild(list);
        container.appendChild(box);
    }

    /**
     * Render Network Actions section (only when key is defined; skips if undefined/null).
     */
    function renderNetworkActions(networkActions, container, doc) {
        if (!container || networkActions === undefined || networkActions === null) return;
        const documentRef = doc || (typeof document !== "undefined" ? document : createMockDocument());

        const box = documentRef.createElement("div");
        box.className = "network-actions-box";

        const title = documentRef.createElement("div");
        title.className = "network-actions-title";
        title.textContent = "🌐 Nhật ký truy vấn mạng (Đã truy vấn / bỏ qua):";
        box.appendChild(title);

        const actions = Array.isArray(networkActions) ? networkActions : [];
        if (actions.length === 0) {
            const emptyText = documentRef.createElement("div");
            emptyText.className = "network-empty-text";
            emptyText.textContent = "Không có truy vấn mạng nào";
            box.appendChild(emptyText);
        } else {
            const list = documentRef.createElement("div");
            list.className = "network-actions-list";
            const ACT_STATUS_WHITELIST = ["sent", "ok", "skipped", "error", "timeout", "blocked"];

            actions.forEach(function (act) {
                if (!act || typeof act !== "object") return;
                const item = documentRef.createElement("div");
                item.className = "network-action-item";

                const typeSpan = documentRef.createElement("span");
                typeSpan.className = "act-type";
                typeSpan.textContent = "• [" + sanitizeText(act.type || "req", 40) + "]";

                const statusSpan = documentRef.createElement("span");
                const rawStat = String(act.status || "sent").toLowerCase().trim();
                const actCls = ACT_STATUS_WHITELIST.includes(rawStat) ? rawStat : "unknown";
                statusSpan.className = "act-status status-" + actCls;
                statusSpan.textContent = (rawStat === "skipped") ? "bỏ qua" : actCls;

                const targetSpan = documentRef.createElement("span");
                targetSpan.className = "act-target";
                targetSpan.textContent = "Host: " + defangHost(sanitizeText(act.target || "none", 100));

                item.appendChild(typeSpan);
                item.appendChild(statusSpan);
                item.appendChild(targetSpan);
                list.appendChild(item);
            });

            box.appendChild(list);
        }

        container.appendChild(box);
    }

    /**
     * Render Image Analysis (VietQR & QR links) using safe textContent only.
     */
    function renderImageAnalysis(imageAnalysis, container, doc) {
        if (!imageAnalysis || !container) return;
        const documentRef = doc || (typeof document !== "undefined" ? document : createMockDocument());

        const hasQR = Array.isArray(imageAnalysis.qr_urls) && imageAnalysis.qr_urls.length > 0;
        const hasVietQR = Array.isArray(imageAnalysis.vietqr) && imageAnalysis.vietqr.length > 0;

        if (!hasQR && !hasVietQR) return;

        const box = documentRef.createElement("div");
        box.className = "image-analysis-box";

        const title = documentRef.createElement("h4");
        title.className = "image-analysis-title";
        title.textContent = "📷 Phân tích hình ảnh & Mã QR:";
        box.appendChild(title);

        if (hasQR) {
            try {
                const qrHeader = documentRef.createElement("div");
                qrHeader.className = "section-subtitle";
                qrHeader.textContent = "Liên kết phát hiện từ mã QR:";
                box.appendChild(qrHeader);

                const qrList = documentRef.createElement("div");
                qrList.className = "qr-links-list";
                imageAnalysis.qr_urls.forEach(function (u) {
                    if (typeof u !== "string" && typeof u !== "number") return;
                    const item = documentRef.createElement("div");
                    item.className = "qr-link-item";
                    item.textContent = "• " + defangUrl(sanitizeText(u, 300));
                    qrList.appendChild(item);
                });
                box.appendChild(qrList);
            } catch (err) {
                console.error("Error rendering QR links:", err);
            }
        }

        if (hasVietQR) {
            try {
                const vHeader = documentRef.createElement("div");
                vHeader.className = "section-subtitle";
                vHeader.textContent = "Dữ liệu hóa đơn VietQR trích xuất:";
                box.appendChild(vHeader);

                imageAnalysis.vietqr.forEach(function (v) {
                    if (!v || typeof v !== "object") return;
                    const vCard = documentRef.createElement("div");
                    vCard.className = "vietqr-card";

                    function addRow(label, val) {
                        const r = documentRef.createElement("div");
                        r.className = "vietqr-row";
                        const lb = documentRef.createElement("span");
                        lb.className = "vietqr-label";
                        lb.textContent = label + ": ";
                        const vl = documentRef.createElement("span");
                        vl.className = "vietqr-value";
                        vl.textContent = sanitizeText(val, 150);
                        r.appendChild(lb);
                        r.appendChild(vl);
                        vCard.appendChild(r);
                    }

                    addRow("Ngân hàng", v.bank_name || v.bin || "N/A");
                    addRow("Số tài khoản", v.masked_account || "N/A");
                    if (v.name) addRow("Chủ tài khoản", v.name);
                    if (v.amount) addRow("Số tiền", v.amount);
                    if (v.memo) addRow("Nội dung", v.memo);

                    const crcRow = documentRef.createElement("div");
                    crcRow.className = "vietqr-row";
                    const crcLabel = documentRef.createElement("span");
                    crcLabel.className = "vietqr-label";
                    crcLabel.textContent = "Kiểm tra mã bảo mật CRC: ";
                    const crcVal = documentRef.createElement("span");
                    if (v.crc_ok) {
                        crcVal.className = "crc-badge crc-ok";
                        crcVal.textContent = "✅ Hợp lệ";
                    } else {
                        crcVal.className = "crc-badge crc-fail";
                        crcVal.textContent = "🚨 Bị sai lệch (Nghi vấn can thiệp mã QR)";
                    }
                    crcRow.appendChild(crcLabel);
                    crcRow.appendChild(crcVal);
                    vCard.appendChild(crcRow);

                    box.appendChild(vCard);
                });
            } catch (err) {
                console.error("Error rendering VietQR:", err);
            }
        }

        container.appendChild(box);
    }

    /**
     * Render the Real Model and LLM execution status indicator in assistant message footer.
     * Skips entirely if model_used and llm_status keys are not present in result.
     * When model is offline, displays 'Chế độ: offline, không gọi LLM' instead of 'Trạng thái LLM: ok'.
     */
    function renderLLMStatus(res, container, doc) {
        if (!res || !container) return;
        if (res.model_used === undefined && res.llm_status === undefined) return;
        const documentRef = doc || (typeof document !== "undefined" ? document : createMockDocument());

        const bar = documentRef.createElement("div");
        bar.className = "llm-status-bar";

        const rawModel = String(res.model_used || "").toLowerCase().trim();
        const rawLlmStatus = String(res.llm_status || "").toLowerCase().trim();
        const isOffline = (rawModel === "offline" || rawModel === "" || rawModel === "none" || rawLlmStatus === "offline");

        if (isOffline) {
            const modeSpan = documentRef.createElement("span");
            modeSpan.className = "status-item status-flag-offline";
            modeSpan.textContent = "Chế độ: offline, không gọi LLM";
            bar.appendChild(modeSpan);
        } else {
            const modelSpan = documentRef.createElement("span");
            modelSpan.className = "status-item";
            modelSpan.textContent = "Mô hình xử lý: " + sanitizeText(res.model_used || "unknown", 60);

            const LLM_STATUS_WHITELIST = ["ok", "error", "invalid", "timeout", "fallback", "disabled", "skipped"];
            const llmCls = LLM_STATUS_WHITELIST.includes(rawLlmStatus) ? rawLlmStatus : "unknown";

            const statusSpan = documentRef.createElement("span");
            statusSpan.className = "status-item status-flag-" + llmCls;
            statusSpan.textContent = "Trạng thái LLM: " + sanitizeText(res.llm_status || "ok", 40);

            bar.appendChild(modelSpan);
            bar.appendChild(statusSpan);
        }

        container.appendChild(bar);
    }

    return {
        createMockDocument: createMockDocument,
        sanitizeText: sanitizeText,
        defangHost: defangHost,
        defangUrl: defangUrl,
        defangText: defangText,
        buildLinkCard: buildLinkCard,
        renderUrlAnalysis: renderUrlAnalysis,
        renderPipelineTrace: renderPipelineTrace,
        renderNetworkActions: renderNetworkActions,
        renderImageAnalysis: renderImageAnalysis,
        renderLLMStatus: renderLLMStatus,
        SEVERITY_ORDER: SEVERITY_ORDER
    };
});
