/* ============================================================
   SAFEGUARD AI — ENTERPRISE WEB APP JS (Vanilla JavaScript ES6+)
   ============================================================ */

document.addEventListener("DOMContentLoaded", () => {
    // Client ID management (UUID v4 with localStorage and fallback)
    let inMemoryClientId = null;

    function generateSecureUUID() {
        if (typeof crypto !== "undefined") {
            if (crypto.randomUUID) {
                return crypto.randomUUID();
            }
            if (crypto.getRandomValues) {
                const buf = new Uint8Array(16);
                crypto.getRandomValues(buf);
                buf[6] = (buf[6] & 0x0f) | 0x40; // UUID v4
                buf[8] = (buf[8] & 0x3f) | 0x80; // variant
                const hex = Array.from(buf, b => b.toString(16).padStart(2, "0")).join("");
                return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
            }
        }
        const errMsg = "Trình duyệt không hỗ trợ Web Crypto API bảo mật để tạo định danh phiên. Vui lòng sử dụng trình duyệt hiện đại hơn.";
        if (typeof alert === "function") {
            alert(errMsg);
        }
        throw new Error(errMsg);
    }

    function getClientId() {
        try {
            let cid = localStorage.getItem("safeguard_client_id");
            if (!cid) {
                cid = generateSecureUUID();
                localStorage.setItem("safeguard_client_id", cid);
            }
            return cid;
        } catch (e) {
            if (!inMemoryClientId) {
                inMemoryClientId = generateSecureUUID();
            }
            return inMemoryClientId;
        }
    }

    function generateSessionId() {
        return `session_${generateSecureUUID()}`;
    }

    // Safe sanitize helper fallback if UIRender is not loaded
    function sanitize(str, maxLen = 300) {
        if (typeof UIRender !== "undefined" && typeof UIRender.sanitizeText === "function") {
            return UIRender.sanitizeText(str, maxLen);
        }
        if (str === null || str === undefined) return "";
        let s = String(str).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, "");
        s = s.replace(/[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/g, "");
        s = s.replace(/[\u200B-\u200D\uFEFF\u00AD\u2028\u2029\u2060\u180E\u034F]/g, "");
        return s.slice(0, maxLen);
    }

    // State Variables
    let activeSessionId = generateSessionId();
    let attachedFileBase64 = null;
    let attachedFileName = "";
    let fileReadingPromise = null;
    let isProcessing = false;
    const IMAGE_SRC_REGEX = /^data:image\/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/=]+$/;

    // DOM Elements
    const btnNewChat = document.getElementById("btnNewChat");
    const sessionList = document.getElementById("sessionList");
    const landingView = document.getElementById("landingView");
    const messagesContainer = document.getElementById("messagesContainer");
    const chatViewport = document.getElementById("chatViewport");
    const chatInput = document.getElementById("chatInput");
    const btnSend = document.getElementById("btnSend");
    const fileInput = document.getElementById("fileInput");
    const filePreview = document.getElementById("filePreview");
    const fileNameText = document.getElementById("fileNameText");
    const btnRemoveFile = document.getElementById("btnRemoveFile");
    const inputContainer = document.getElementById("inputContainer");
    const onlineCheckCheckbox = document.getElementById("onlineCheckCheckbox");

    // Initialize App
    initApp();

    function initApp() {
        loadSessions();
        setupEventListeners();
        setupDragAndDrop();
    }

    function setupEventListeners() {
        // New Chat
        btnNewChat.addEventListener("click", () => {
            activeSessionId = generateSessionId();
            if (onlineCheckCheckbox) onlineCheckCheckbox.checked = false;
            renderChatView([]);
            showLanding();
            loadSessions();
        });

        // Send Button & Enter Key
        btnSend.addEventListener("click", sendMessage);
        chatInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });

        // Quick Suggestions & Quick Actions
        document.addEventListener("click", (e) => {
            const card = e.target.closest(".suggestion-card, .btn-quick-action");
            if (card && card.dataset.prompt) {
                const prompt = card.dataset.prompt;
                chatInput.value = prompt;
                sendMessage();
            }
        });

        // File Uploader
        fileInput.addEventListener("change", (e) => {
            const file = e.target.files[0];
            if (file) handleFileSelection(file);
        });

        btnRemoveFile.addEventListener("click", clearAttachedFile);

        // Image Lightbox Modal Setup
        const lightboxModal = document.getElementById("imageLightboxModal");
        const lightboxImage = document.getElementById("lightboxImage");
        const lightboxBackdrop = document.getElementById("lightboxBackdrop");
        const lightboxCloseBtn = document.getElementById("lightboxCloseBtn");
        const lightboxCaption = document.getElementById("lightboxCaption");

        function openLightbox(src, altText) {
            if (!lightboxModal || !lightboxImage || !src) return;
            const trimmedSrc = String(src).trim();
            if (!IMAGE_SRC_REGEX.test(trimmedSrc)) return;
            lightboxImage.src = trimmedSrc;
            if (lightboxCaption) lightboxCaption.textContent = altText || "Bằng chứng hình ảnh";
            lightboxModal.classList.remove("hidden");
        }

        function closeLightbox() {
            if (lightboxModal) lightboxModal.classList.add("hidden");
        }

        // Delegate click on sent chat images
        if (messagesContainer) {
            messagesContainer.addEventListener("click", (e) => {
                if (e.target && e.target.classList.contains("chat-attached-img")) {
                    openLightbox(e.target.src, e.target.alt);
                }
            });
        }

        if (lightboxBackdrop) lightboxBackdrop.addEventListener("click", closeLightbox);
        if (lightboxCloseBtn) lightboxCloseBtn.addEventListener("click", closeLightbox);

        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape") closeLightbox();
        });
    }

    // Drag & Drop File Support
    function setupDragAndDrop() {
        const dropZone = inputContainer || document.body;

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
            }, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => {
                if (inputContainer) inputContainer.classList.add('dragover');
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => {
                if (inputContainer) inputContainer.classList.remove('dragover');
            }, false);
        });

        dropZone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files && files.length > 0) {
                handleFileSelection(files[0]);
            }
        }, false);
    }

    // Handle Selected / Dropped File
    function handleFileSelection(file) {
        if (!file) return;
        if (!file.type.startsWith("image/")) {
            alert("Chỉ chấp nhận tệp hình ảnh (PNG, JPEG, GIF, WEBP). Vui lòng chọn tệp ảnh hợp lệ.");
            clearAttachedFile();
            return;
        }

        attachedFileName = file.name;
        if (fileNameText) fileNameText.textContent = sanitize(file.name, 100);
        if (filePreview) filePreview.classList.remove("hidden");

        fileReadingPromise = new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                attachedFileBase64 = e.target.result;
                resolve(attachedFileBase64);
            };
            reader.onerror = (e) => {
                attachedFileBase64 = null;
                reject(e);
            };
            reader.readAsDataURL(file);
        });
    }

    function clearAttachedFile() {
        attachedFileBase64 = null;
        attachedFileName = "";
        fileReadingPromise = null;
        if (fileInput) fileInput.value = "";
        if (filePreview) filePreview.classList.add("hidden");
    }

    // Load Session list from SQLite API
    async function loadSessions() {
        try {
            const res = await fetch("/api/sessions", {
                headers: {
                    "X-Client-Id": getClientId()
                }
            });
            if (res.ok) {
                const sessions = await res.json();
                renderSessionList(sessions);
            }
        } catch (e) {
            console.error("Failed to load sessions:", e);
        }
    }

    function renderSessionList(sessions) {
        if (!sessionList) return;
        sessionList.innerHTML = "";
        if (!sessions || sessions.length === 0) {
            const emptyDiv = document.createElement("div");
            emptyDiv.className = "empty-history-notice";
            emptyDiv.textContent = "Chưa có lịch sử chat";
            sessionList.appendChild(emptyDiv);
            return;
        }

        sessions.forEach((s) => {
            const item = document.createElement("div");
            item.className = `session-item ${s.session_id === activeSessionId ? "active" : ""}`;
            const displayTitle = sanitize(s.title || s.session_id, 80);
            item.title = displayTitle;

            const iconSpan = document.createElement("span");
            iconSpan.className = "session-icon";
            iconSpan.textContent = "💬";

            const titleSpan = document.createElement("span");
            titleSpan.className = "session-title";
            titleSpan.textContent = displayTitle;

            item.appendChild(iconSpan);
            item.appendChild(titleSpan);

            item.addEventListener("click", () => switchSession(s.session_id));
            sessionList.appendChild(item);
        });
    }

    async function switchSession(sessionId) {
        activeSessionId = sessionId;
        if (onlineCheckCheckbox) onlineCheckCheckbox.checked = false;
        loadSessions();

        try {
            const res = await fetch(`/api/history?session_id=${encodeURIComponent(sessionId)}`, {
                headers: {
                    "X-Client-Id": getClientId()
                }
            });
            if (res.ok) {
                const history = await res.json();
                if (history && history.length > 0) {
                    hideLanding();
                    renderChatView(history);
                } else {
                    showLanding();
                }
            }
        } catch (e) {
            console.error("Error loading session history:", e);
        }
    }

    function showLanding() {
        if (landingView) landingView.style.display = "block";
        if (messagesContainer) messagesContainer.innerHTML = "";
    }

    function hideLanding() {
        if (landingView) landingView.style.display = "none";
    }

    // Send Message
    async function sendMessage() {
        if (fileReadingPromise) {
            try {
                await fileReadingPromise;
            } catch (err) {
                console.error("Lỗi khi đọc file ảnh:", err);
            }
            fileReadingPromise = null;
        }

        const userText = chatInput.value.trim();
        if ((!userText && !attachedFileBase64) || isProcessing) return;

        isProcessing = true;
        hideLanding();

        const currentImageBase64 = attachedFileBase64;
        const currentFileName = attachedFileName;

        // Render User Message with Image Preview Thumbnail if attached
        appendUserMessage(userText || `[Đã đính kèm ảnh ${currentFileName || "bằng chứng"}]`, currentImageBase64);

        // Strictly boolean online_check flag (U3)
        const isOnlineCheck = Boolean(onlineCheckCheckbox && onlineCheckCheckbox.checked);

        // Reset online_check checkbox to private default (off) immediately after reading
        if (onlineCheckCheckbox) {
            onlineCheckCheckbox.checked = false;
        }

        const payload = {
            user_text: userText,
            session_id: activeSessionId,
            image_base64: currentImageBase64,
            online_check: isOnlineCheck
        };

        // Reset Input Box & File Preview
        chatInput.value = "";
        clearAttachedFile();

        // Show thinking indicator (replaces fake steps)
        showThinkingWidget();

        // Call REST API /api/analyze
        try {
            const res = await fetch("/api/analyze", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-Client-Id": getClientId()
                },
                body: JSON.stringify(payload)
            });

            hideThinkingWidget();

            if (res.ok) {
                const result = await res.json();
                appendAssistantMessage(result);
                loadSessions();
            } else {
                let errorHeadline = `⚠️ Yêu cầu thất bại (${res.status})`;
                if (res.status === 429) {
                    const retryHeader = res.headers ? res.headers.get("Retry-After") : null;
                    const retrySec = retryHeader ? parseInt(retryHeader, 10) : NaN;
                    if (!isNaN(retrySec) && retrySec > 0) {
                        errorHeadline = `⚠️ Gửi quá nhanh, thử lại sau ${retrySec} giây`;
                    } else {
                        errorHeadline = "⚠️ Gửi quá nhanh, thử lại sau";
                    }
                } else if (res.status === 413) {
                    errorHeadline = "⚠️ Ảnh/nội dung quá lớn";
                } else if (res.status === 400) {
                    errorHeadline = "⚠️ Dữ liệu không hợp lệ";
                } else if (res.status === 503) {
                    errorHeadline = "⚠️ Server đang bận";
                } else if (res.status >= 500 && res.status <= 599) {
                    errorHeadline = `⚠️ Lỗi hệ thống máy chủ (${res.status})`;
                }
                appendAssistantMessage({
                    decision: {
                        intent_type: "general_chat",
                        headline: errorHeadline
                    }
                });
            }
        } catch (e) {
            hideThinkingWidget();
            console.error("API Call error:", e);
            appendAssistantMessage({
                decision: {
                    intent_type: "general_chat",
                    headline: `⚠️ Không kết nối được tới server: ${sanitize(e.message || "Lỗi mạng", 100)}`
                }
            });
        } finally {
            isProcessing = false;
        }
    }

    // Render User Message with Thumbnail Preview or Not Stored Notice
    function appendUserMessage(text, imageBase64, showNoStoreNotice = false) {
        const row = document.createElement("div");
        row.className = "message-row user";

        const avatar = document.createElement("div");
        avatar.className = "message-avatar";
        avatar.textContent = "👤";
        row.appendChild(avatar);

        const content = document.createElement("div");
        content.className = "message-content";

        if (imageBase64 && typeof imageBase64 === "string") {
            const trimmedImg = imageBase64.trim();
            if (IMAGE_SRC_REGEX.test(trimmedImg)) {
                const img = document.createElement("img");
                img.src = trimmedImg;
                img.className = "chat-attached-img";
                img.alt = "Attached evidence";
                content.appendChild(img);
            }
        } else if (showNoStoreNotice) {
            const noticeEl = document.createElement("div");
            noticeEl.className = "image-not-stored-notice";
            noticeEl.textContent = "(ảnh không được lưu)";
            content.appendChild(noticeEl);
        }

        const p = document.createElement("p");
        p.className = "user-msg-text";
        p.textContent = sanitize(text, 5000);
        content.appendChild(p);

        row.appendChild(content);
        messagesContainer.appendChild(row);
        scrollToBottom();
    }

    // Render Assistant Output (Guaranteed ZERO innerHTML for server data)
    function appendAssistantMessage(res) {
        const row = document.createElement("div");
        row.className = "message-row assistant";

        const avatar = document.createElement("div");
        avatar.className = "message-avatar";
        const botImg = document.createElement("img");
        botImg.src = "/assets/AIScamavatar.jpg";
        botImg.className = "chatbot-avatar-img";
        botImg.alt = "SafeGuard AI";
        avatar.appendChild(botImg);
        row.appendChild(avatar);

        const content = document.createElement("div");
        content.className = "message-content";

        // U2: Real pipeline_trace instead of fake animation
        if (res.pipeline_trace && typeof UIRender !== "undefined" && typeof UIRender.renderPipelineTrace === "function") {
            try {
                UIRender.renderPipelineTrace(res.pipeline_trace, content);
            } catch (err) {
                console.error("Error rendering pipeline_trace:", err);
            }
        }

        const decision = res.decision || {};
        const intentType = decision.intent_type || "scam_analysis";
        const headline = sanitize(decision.headline || "Rủi ro không xác định", 500);

        if (intentType === "general_chat" || intentType === "refusal" || intentType === "need_more_info") {
            const headlineEl = document.createElement("p");
            headlineEl.className = "chat-headline-text";
            headlineEl.textContent = headline;
            content.appendChild(headlineEl);

            if (decision.recommendations && Array.isArray(decision.recommendations) && decision.recommendations.length > 0) {
                const recList = document.createElement("ul");
                recList.className = "chat-recommendations-list";
                decision.recommendations.forEach(rec => {
                    if (typeof rec !== "string" && typeof rec !== "number") return;
                    const li = document.createElement("li");
                    li.textContent = sanitize(rec, 300);
                    recList.appendChild(li);
                });
                content.appendChild(recList);
            }
        } else {
            const riskLevel = sanitize(decision.risk_level || "MEDIUM", 20);
            const riskScore = typeof res.risk_score === "number" ? res.risk_score : 0;
            const conf = res.confidence || null;
            const confScoreText = (conf && conf.confidence_score !== undefined && conf.confidence_score !== null)
                ? `${sanitize(String(conf.confidence_score), 10)}%`
                : "—";
            const confLevelText = (conf && conf.confidence_level)
                ? sanitize(String(conf.confidence_level), 20)
                : "—";
            const latencyText = (res.latency_ms !== undefined && res.latency_ms !== null)
                ? sanitize(String(res.latency_ms), 20)
                : "—";
            const latencyUnit = (res.latency_ms !== undefined && res.latency_ms !== null) ? "ms" : "";

            const RISK_LEVEL_WHITELIST = ["low", "medium", "high", "critical"];
            const rkLower = riskLevel.toLowerCase();
            const rkCls = RISK_LEVEL_WHITELIST.includes(rkLower) ? rkLower : "unknown";
            const iconMap = { "low": "🟢", "medium": "🟡", "high": "🔴", "critical": "🚨" };
            const icon = iconMap[rkCls] || "⚪";

            const riskHeaderEl = document.createElement("div");
            riskHeaderEl.className = `risk-header risk-level-${rkCls}`;
            riskHeaderEl.textContent = `${icon} ${riskLevel} — Điểm rủi ro: ${riskScore}%`;
            content.appendChild(riskHeaderEl);

            const riskHeadlineEl = document.createElement("div");
            riskHeadlineEl.className = "risk-headline";
            riskHeadlineEl.textContent = headline;
            content.appendChild(riskHeadlineEl);

            if (res.emergency && res.emergency.is_emergency) {
                const emergBox = document.createElement("div");
                emergBox.className = "emergency-box";

                const emergTitle = document.createElement("div");
                emergTitle.className = "emergency-title";
                emergTitle.textContent = "🚨 QUY TRÌNH ỨNG PHÓ KHẨN CẤP:";
                emergBox.appendChild(emergTitle);

                (res.emergency.protocol_steps || []).forEach(step => {
                    const stepRow = document.createElement("div");
                    stepRow.className = "emergency-step-row";
                    const tw = sanitize(step.time_window || "", 50);
                    const act = sanitize(step.action || "", 300);
                    stepRow.textContent = `• ⏱️ ${tw}: ${act}`;
                    emergBox.appendChild(stepRow);
                });
                content.appendChild(emergBox);
            }

            // Metrics Grid
            const metricsGrid = document.createElement("div");
            metricsGrid.className = "metrics-grid";

            // Card 1: Risk Score
            const m1 = document.createElement("div");
            m1.className = "metric-card";
            const m1Label = document.createElement("div");
            m1Label.className = "metric-label";
            m1Label.textContent = "Risk Score";
            const m1Val = document.createElement("div");
            m1Val.className = "metric-value";
            m1Val.textContent = `${riskScore}%`;
            m1.appendChild(m1Label);
            m1.appendChild(m1Val);
            metricsGrid.appendChild(m1);

            // Card 2: AI Confidence
            const m2 = document.createElement("div");
            m2.className = "metric-card";
            const m2Label = document.createElement("div");
            m2Label.className = "metric-label";
            m2Label.textContent = "AI Confidence";
            const m2Val = document.createElement("div");
            m2Val.className = "metric-value metric-accent";
            m2Val.textContent = confScoreText;
            const m2Sub = document.createElement("div");
            m2Sub.className = "metric-sub";
            m2Sub.textContent = confLevelText;
            m2.appendChild(m2Label);
            m2.appendChild(m2Val);
            m2.appendChild(m2Sub);
            metricsGrid.appendChild(m2);

            // Card 3: Latency
            const m3 = document.createElement("div");
            m3.className = "metric-card";
            const m3Label = document.createElement("div");
            m3Label.className = "metric-label";
            m3Label.textContent = "Latency";
            const m3Val = document.createElement("div");
            m3Val.className = "metric-value";
            m3Val.textContent = latencyText;
            const m3Sub = document.createElement("div");
            m3Sub.className = "metric-sub";
            m3Sub.textContent = latencyUnit;
            m3.appendChild(m3Label);
            m3.appendChild(m3Val);
            m3.appendChild(m3Sub);
            metricsGrid.appendChild(m3);

            content.appendChild(metricsGrid);

            // Breakdown Section (Explainable AI)
            if (res.explainable && Array.isArray(res.explainable.reasons) && res.explainable.reasons.length > 0) {
                const bdSection = document.createElement("div");
                bdSection.className = "breakdown-section";

                const bdTitle = document.createElement("h4");
                bdTitle.className = "breakdown-title";
                bdTitle.textContent = "🔍 Phân tích chi tiết rủi ro:";
                bdSection.appendChild(bdTitle);

                res.explainable.reasons.forEach(r => {
                    const cleanReason = sanitize(r, 200);
                    const parts = cleanReason.split(": +");
                    const label = parts[0];
                    const pct = parts[1] ? parseInt(parts[1], 10) : 15;

                    const rowEl = document.createElement("div");
                    rowEl.className = "breakdown-row";

                    const labelSpan = document.createElement("span");
                    labelSpan.className = "breakdown-label";
                    labelSpan.textContent = `• ${label}`;

                    const progDiv = document.createElement("div");
                    progDiv.className = "breakdown-progress";
                    const fillDiv = document.createElement("div");
                    fillDiv.className = "breakdown-fill";
                    fillDiv.style.width = `${Math.min(pct, 100)}%`;
                    progDiv.appendChild(fillDiv);

                    const pctSpan = document.createElement("span");
                    pctSpan.className = "breakdown-pct";
                    pctSpan.textContent = `+${pct}%`;

                    rowEl.appendChild(labelSpan);
                    rowEl.appendChild(progDiv);
                    rowEl.appendChild(pctSpan);
                    bdSection.appendChild(rowEl);
                });

                content.appendChild(bdSection);
            }

            // U1: Render URL Analysis Cards
            if (res.url_analysis && typeof UIRender !== "undefined" && typeof UIRender.renderUrlAnalysis === "function") {
                try {
                    UIRender.renderUrlAnalysis(res.url_analysis, content);
                } catch (err) {
                    console.error("Error rendering url_analysis:", err);
                }
            }

            // Render Image Analysis (VietQR / QR)
            if (res.image_analysis && typeof UIRender !== "undefined" && typeof UIRender.renderImageAnalysis === "function") {
                try {
                    UIRender.renderImageAnalysis(res.image_analysis, content);
                } catch (err) {
                    console.error("Error rendering image_analysis:", err);
                }
            }

            // U3: Render Network Actions (only when key exists in res)
            if (res.network_actions !== undefined && typeof UIRender !== "undefined" && typeof UIRender.renderNetworkActions === "function") {
                try {
                    UIRender.renderNetworkActions(res.network_actions, content);
                } catch (err) {
                    console.error("Error rendering network_actions:", err);
                }
            }

            // Recommendations
            if (decision.recommendations && Array.isArray(decision.recommendations) && decision.recommendations.length > 0) {
                const recsBox = document.createElement("div");
                recsBox.className = "recs-box";

                const recsTitle = document.createElement("h4");
                recsTitle.className = "recs-title";
                recsTitle.textContent = "💡 Khuyến nghị hành động:";
                recsBox.appendChild(recsTitle);

                decision.recommendations.forEach(rec => {
                    if (typeof rec !== "string" && typeof rec !== "number") return;
                    const item = document.createElement("p");
                    item.className = "rec-item";
                    item.textContent = sanitize(rec, 300);
                    recsBox.appendChild(item);
                });

                content.appendChild(recsBox);
            }

            // HITL Footer
            const hitlP = document.createElement("p");
            hitlP.className = "hitl-footer";
            hitlP.textContent = sanitize(decision.hitl_disclaimer || "SafeGuard AI — Decision Support System.", 200);
            content.appendChild(hitlP);

            // U5: LLM & Model Status Indicator (only when model_used or llm_status key exists in res)
            if ((res.model_used !== undefined || res.llm_status !== undefined) && typeof UIRender !== "undefined" && typeof UIRender.renderLLMStatus === "function") {
                try {
                    UIRender.renderLLMStatus(res, content);
                } catch (err) {
                    console.error("Error rendering LLM status:", err);
                }
            }
        }

        row.appendChild(content);
        messagesContainer.appendChild(row);
        scrollToBottom();
    }

    function renderChatView(history) {
        messagesContainer.innerHTML = "";
        history.forEach(item => {
            const hasImg = Boolean(item.has_image || item.image_base64);
            const hasBase64 = Boolean(item.image_base64 && String(item.image_base64).trim());
            const showNoStoreNotice = hasImg && !hasBase64;

            if (item.user_text || hasImg) {
                appendUserMessage(item.user_text, item.image_base64, showNoStoreNotice);
            }
            if (item.bot_response) {
                appendAssistantMessage({
                    decision: {
                        intent_type: item.risk_level === "LOW" && item.risk_score === 0 ? "general_chat" : "scam_analysis",
                        risk_level: item.risk_level,
                        headline: item.bot_response
                    },
                    risk_score: item.risk_score
                });
            }
        });
    }

    function showThinkingWidget() {
        hideThinkingWidget();

        const row = document.createElement("div");
        row.className = "message-row assistant thinking-row";
        row.id = "thinkingRow";

        const avatar = document.createElement("div");
        avatar.className = "message-avatar";
        const img = document.createElement("img");
        img.src = "/assets/AIScamavatar.jpg";
        img.className = "chatbot-avatar-img";
        img.alt = "SafeGuard AI";
        avatar.appendChild(img);

        const content = document.createElement("div");
        content.className = "message-content thinking-bubble";

        const header = document.createElement("div");
        header.className = "thinking-header";

        const spinner = document.createElement("span");
        spinner.className = "thinking-spinner";
        spinner.textContent = "🧠";

        const title = document.createElement("span");
        title.className = "thinking-title";
        title.textContent = "SafeGuard AI đang phân tích dữ liệu...";

        header.appendChild(spinner);
        header.appendChild(title);
        content.appendChild(header);

        row.appendChild(avatar);
        row.appendChild(content);

        messagesContainer.appendChild(row);
        scrollToBottom();
    }

    function hideThinkingWidget() {
        const existingRow = document.getElementById("thinkingRow");
        if (existingRow) {
            existingRow.remove();
        }
    }

    function scrollToBottom() {
        chatViewport.scrollTop = chatViewport.scrollHeight;
    }
});
