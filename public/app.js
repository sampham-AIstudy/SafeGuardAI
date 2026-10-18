/* ============================================================
   SAFEGUARD AI — ENTERPRISE WEB APP JS (Vanilla JavaScript ES6+)
   ============================================================ */

document.addEventListener("DOMContentLoaded", () => {
    // Client ID management (UUID v4 with localStorage and fallback)
    let inMemoryClientId = null;

    function fallbackUUID() {
        if (typeof crypto !== "undefined" && crypto.getRandomValues) {
            const buf = new Uint8Array(16);
            crypto.getRandomValues(buf);
            buf[6] = (buf[6] & 0x0f) | 0x40; // UUID v4
            buf[8] = (buf[8] & 0x3f) | 0x80; // variant
            const hex = Array.from(buf, b => b.toString(16).padStart(2, "0")).join("");
            return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
        }
        return "fallback-uuid-0000-000000000000";
    }

    function getClientId() {
        try {
            let cid = localStorage.getItem("safeguard_client_id");
            if (!cid) {
                cid = (typeof crypto !== "undefined" && crypto.randomUUID) 
                    ? crypto.randomUUID() 
                    : fallbackUUID();
                localStorage.setItem("safeguard_client_id", cid);
            }
            return cid;
        } catch (e) {
            if (!inMemoryClientId) {
                inMemoryClientId = (typeof crypto !== "undefined" && crypto.randomUUID)
                    ? crypto.randomUUID()
                    : fallbackUUID();
            }
            return inMemoryClientId;
        }
    }

    function generateSessionId() {
        if (typeof crypto !== "undefined" && crypto.randomUUID) {
            return `session_${crypto.randomUUID()}`;
        }
        return `session_${fallbackUUID()}`;
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
    const thinkingWidget = document.getElementById("thinkingWidget");
    const thinkingSteps = document.getElementById("thinkingSteps");
    const chatInput = document.getElementById("chatInput");
    const btnSend = document.getElementById("btnSend");
    const fileInput = document.getElementById("fileInput");
    const filePreview = document.getElementById("filePreview");
    const fileNameText = document.getElementById("fileNameText");
    const btnRemoveFile = document.getElementById("btnRemoveFile");
    const inputContainer = document.getElementById("inputContainer");

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
        
        // Mode Pill / Model Selector Toggle
        const modelSelectorBtn = document.getElementById("modelSelectorBtn");
        const modelDropdownMenu = document.getElementById("modelDropdownMenu");

        if (modelSelectorBtn && modelDropdownMenu) {
            modelSelectorBtn.addEventListener("click", (e) => {
                e.stopPropagation();
                const isHidden = modelDropdownMenu.classList.contains("hidden");
                if (isHidden) {
                    modelDropdownMenu.classList.remove("hidden");
                    modelSelectorBtn.classList.add("open");
                } else {
                    modelDropdownMenu.classList.add("hidden");
                    modelSelectorBtn.classList.remove("open");
                }
            });

            document.addEventListener("click", (e) => {
                if (!modelSelectorBtn.contains(e.target) && !modelDropdownMenu.contains(e.target)) {
                    modelDropdownMenu.classList.add("hidden");
                    modelSelectorBtn.classList.remove("open");
                }
            });

            const modelOptions = modelDropdownMenu.querySelectorAll(".model-option");
            modelOptions.forEach(opt => {
                opt.addEventListener("click", () => {
                    modelOptions.forEach(o => {
                        o.classList.remove("active");
                        const chk = o.querySelector(".check-icon");
                        if (chk) chk.textContent = "";
                    });
                    opt.classList.add("active");
                    const chk = opt.querySelector(".check-icon");
                    if (chk) chk.textContent = "✓";

                    const titleEl = opt.querySelector(".model-title");
                    const badgeEl = opt.querySelector(".badge-tag");
                    
                    const title = titleEl ? titleEl.textContent : "SafeGuard Agent 3.5";
                    const badgeText = badgeEl ? badgeEl.textContent : "";

                    const nameTextEl = modelSelectorBtn.querySelector(".model-name-text");
                    const badgeTextEl = modelSelectorBtn.querySelector(".model-badge");

                    if (nameTextEl) nameTextEl.textContent = title;
                    if (badgeTextEl) badgeTextEl.textContent = badgeText;

                    modelDropdownMenu.classList.add("hidden");
                    modelSelectorBtn.classList.remove("open");
                });
            });
        }

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
        if (fileNameText) fileNameText.textContent = file.name;
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

    // Load Session list from MySQL API
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
            emptyDiv.style.fontSize = "12px";
            emptyDiv.style.color = "var(--text-muted)";
            emptyDiv.style.padding = "12px 8px";
            emptyDiv.style.textAlign = "center";
            sessionList.appendChild(emptyDiv);
            return;
        }

        sessions.forEach((s) => {
            const item = document.createElement("div");
            item.className = `session-item ${s.session_id === activeSessionId ? "active" : ""}`;
            const displayTitle = s.title || s.session_id;
            item.title = displayTitle;
            item.innerHTML = `
                <span class="session-icon">💬</span>
                <span class="session-title">${escapeHtml(displayTitle)}</span>
            `;
            item.addEventListener("click", () => switchSession(s.session_id));
            sessionList.appendChild(item);
        });
    }

    async function switchSession(sessionId) {
        activeSessionId = sessionId;
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

        const payload = {
            user_text: userText,
            session_id: activeSessionId,
            image_base64: currentImageBase64
        };

        // Reset Input Box & File Preview
        chatInput.value = "";
        clearAttachedFile();

        // Show thinking indicator
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
                appendAssistantMessage({
                    decision: {
                        intent_type: "general_chat",
                        headline: "⚠️ Đã xảy ra lỗi kết nối với Backend Server. Vui lòng kiểm tra lại dịch vụ."
                    }
                });
            }
        } catch (e) {
            hideThinkingWidget();
            console.error("API Call error:", e);
            appendAssistantMessage({
                decision: {
                    intent_type: "general_chat",
                    headline: `⚠️ Không thể kết nối tới Server: ${e.message}`
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
        
        let imgHtml = "";
        if (imageBase64 && typeof imageBase64 === "string") {
            const trimmedImg = imageBase64.trim();
            if (IMAGE_SRC_REGEX.test(trimmedImg)) {
                imgHtml = `<img src="${trimmedImg}" class="chat-attached-img" alt="Attached evidence">`;
            }
        } else if (showNoStoreNotice) {
            imgHtml = `<div class="image-not-stored-notice">(ảnh không được lưu)</div>`;
        }

        row.innerHTML = `
            <div class="message-avatar">👤</div>
            <div class="message-content">
                ${imgHtml}
                <p class="user-msg-text">${escapeHtml(text)}</p>
            </div>
        `;

        const userMsgP = row.querySelector(".user-msg-text");
        if (userMsgP) {
            userMsgP.style.margin = "0";
        }

        const noticeEl = row.querySelector(".image-not-stored-notice");
        if (noticeEl) {
            noticeEl.style.fontSize = "12px";
            noticeEl.style.color = "var(--text-muted)";
            noticeEl.style.fontStyle = "italic";
            noticeEl.style.marginBottom = "6px";
        }

        messagesContainer.appendChild(row);
        scrollToBottom();
    }

    // Render Assistant Output
    function appendAssistantMessage(res) {
        const row = document.createElement("div");
        row.className = "message-row assistant";
        
        const decision = res.decision || {};
        const intentType = decision.intent_type || "scam_analysis";
        const headline = decision.headline || "Rủi ro không xác định";

        let html = `<div class="message-avatar"><img src="/assets/AIScamavatar.jpg" class="chatbot-avatar-img" alt="SafeGuard AI"></div><div class="message-content">`;

        // Render Thought Accordion ONLY when real tool calls were returned by server
        const toolCallsMade = (res.tool_calls_made && Array.isArray(res.tool_calls_made)) ? res.tool_calls_made : [];
        if (toolCallsMade.length > 0) {
            const latencySec = res.latency_ms ? (res.latency_ms / 1000).toFixed(1) : "0.0";
            const toolCount = toolCallsMade.length;

            html += `
                <div class="thought-accordion">
                    <button class="thought-header-btn" type="button">
                        <span class="thought-header-left">
                            🧠 <b>Đã suy nghĩ trong ${latencySec}s</b> · Đã thực thi ${toolCount} Agentic Tools
                        </span>
                        <span class="thought-toggle-icon">▼</span>
                    </button>
                    <div class="thought-details-content">
            `;

            toolCallsMade.forEach(t => {
                const toolName = typeof t === "string" ? t : (t.tool || t.name || "agent_tool");
                const toolDesc = typeof t === "object" && t.desc ? t.desc : `Executed sub-agent [${toolName}]`;
                html += `
                    <div class="thought-log-item">
                        <span class="thought-log-tag">▶ [${escapeHtml(toolName)}]</span>
                        <span>${escapeHtml(toolDesc)}</span>
                    </div>
                `;
            });

            html += `
                    </div>
                </div>
            `;
        }

        if (intentType === "general_chat" || intentType === "refusal" || intentType === "need_more_info") {
            html += `<p class="chat-headline-text">${escapeHtml(headline)}</p>`;
            if (decision.recommendations && decision.recommendations.length > 0) {
                html += `<ul class="chat-recommendations-list">`;
                decision.recommendations.forEach(rec => {
                    html += `<li>${escapeHtml(rec)}</li>`;
                });
                html += `</ul>`;
            }
        } else {
            const riskLevel = decision.risk_level || "MEDIUM";
            const riskScore = res.risk_score ?? 0;
            const conf = res.confidence || null;
            const confScoreText = (conf && conf.confidence_score !== undefined && conf.confidence_score !== null)
                ? `${escapeHtml(String(conf.confidence_score))}%`
                : "—";
            const confLevelText = (conf && conf.confidence_level)
                ? escapeHtml(String(conf.confidence_level))
                : "—";
            const latencyText = (res.latency_ms !== undefined && res.latency_ms !== null)
                ? `${escapeHtml(String(res.latency_ms))}`
                : "—";
            const latencyUnit = (res.latency_ms !== undefined && res.latency_ms !== null) ? "ms" : "";

            const iconMap = { "LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "CRITICAL": "🚨" };
            const icon = iconMap[riskLevel] || "⚪";

            html += `<div class="risk-header">${icon} ${escapeHtml(riskLevel)} — Risk Score: ${escapeHtml(String(riskScore))}%</div>`;
            html += `<div class="risk-headline">${escapeHtml(headline)}</div>`;

            if (res.emergency && res.emergency.is_emergency) {
                html += `<div class="emergency-box">🚨 <b>QUY TRÌNH ỨNG PHÓ KHẨN CẤP:</b><br>`;
                (res.emergency.protocol_steps || []).forEach(step => {
                    html += `• ⏱️ <b>${escapeHtml(step.time_window || '')}</b>: ${escapeHtml(step.action || '')}<br>`;
                });
                html += `</div>`;
            }

            html += `
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-label">Risk Score</div>
                        <div class="metric-value">${escapeHtml(String(riskScore))}%</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-label">AI Confidence</div>
                        <div class="metric-value metric-accent">${confScoreText}</div>
                        <div class="metric-sub">${confLevelText}</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-label">Latency</div>
                        <div class="metric-value">${latencyText}</div>
                        <div class="metric-sub">${latencyUnit}</div>
                    </div>
                </div>
            `;

            if (res.explainable && res.explainable.reasons && res.explainable.reasons.length > 0) {
                html += `<div class="breakdown-section"><h4 class="breakdown-title">🔍 Phân tích chi tiết rủi ro:</h4>`;
                res.explainable.reasons.forEach(r => {
                    const parts = r.split(": +");
                    const label = parts[0];
                    const pct = parts[1] ? parseInt(parts[1], 10) : 15;
                    html += `
                        <div class="breakdown-row" data-pct="${pct}">
                            <span class="breakdown-label">• ${escapeHtml(label)}</span>
                            <div class="breakdown-progress">
                                <div class="breakdown-fill"></div>
                            </div>
                            <span class="breakdown-pct">+${pct}%</span>
                        </div>
                    `;
                });
                html += `</div>`;
            }

            if (decision.recommendations && decision.recommendations.length > 0) {
                html += `<div class="recs-box"><h4 class="recs-title">💡 Khuyến nghị hành động:</h4>`;
                decision.recommendations.forEach(rec => {
                    html += `<p class="rec-item">${escapeHtml(rec)}</p>`;
                });
                html += `</div>`;
            }

            html += `<p class="hitl-footer">${escapeHtml(decision.hitl_disclaimer || "SafeGuard AI — Decision Support System.")}</p>`;
        }

        html += `</div>`;
        row.innerHTML = html;

        // Apply CSSOM styles (CSP safe)
        const headlineEl = row.querySelector(".chat-headline-text");
        if (headlineEl) {
            headlineEl.style.fontSize = "15px";
            headlineEl.style.lineHeight = "1.6";
        }
        const recListEl = row.querySelector(".chat-recommendations-list");
        if (recListEl) {
            recListEl.style.fontSize = "13px";
            recListEl.style.lineHeight = "1.6";
            recListEl.style.margin = "8px 0 0 18px";
            recListEl.style.color = "var(--text-secondary)";
        }
        const metricAccentEl = row.querySelector(".metric-accent");
        if (metricAccentEl) {
            metricAccentEl.style.color = "var(--accent)";
        }
        row.querySelectorAll(".metric-sub").forEach(el => {
            el.style.fontSize = "10px";
            el.style.color = "var(--text-muted)";
        });
        const bdTitle = row.querySelector(".breakdown-title");
        if (bdTitle) {
            bdTitle.style.fontSize = "13px";
            bdTitle.style.color = "var(--text-primary)";
            bdTitle.style.marginBottom = "8px";
        }
        row.querySelectorAll(".breakdown-row").forEach(brow => {
            const pct = parseInt(brow.dataset.pct, 10) || 15;
            const fillEl = brow.querySelector(".breakdown-fill");
            if (fillEl) {
                fillEl.style.width = Math.min(pct, 100) + "%";
            }
            const pctSpan = brow.querySelector(".breakdown-pct");
            if (pctSpan) {
                pctSpan.style.fontSize = "12px";
                pctSpan.style.fontWeight = "600";
            }
        });
        const recsBox = row.querySelector(".recs-box");
        if (recsBox) {
            recsBox.style.marginTop = "12px";
        }
        const recsTitle = row.querySelector(".recs-title");
        if (recsTitle) {
            recsTitle.style.fontSize = "13px";
            recsTitle.style.color = "var(--text-primary)";
            recsTitle.style.marginBottom = "6px";
        }
        row.querySelectorAll(".rec-item").forEach(el => {
            el.style.fontSize = "13px";
            el.style.color = "var(--text-secondary)";
            el.style.margin = "4px 0";
        });
        const hitlFooter = row.querySelector(".hitl-footer");
        if (hitlFooter) {
            hitlFooter.style.fontSize = "11px";
            hitlFooter.style.color = "var(--text-muted)";
            hitlFooter.style.marginTop = "12px";
            hitlFooter.style.borderTop = "1px solid var(--border)";
            hitlFooter.style.paddingTop = "8px";
        }

        // Attach event listener for thought accordion collapse/expand
        const thoughtBtn = row.querySelector(".thought-header-btn");
        if (thoughtBtn) {
            thoughtBtn.addEventListener("click", () => {
                const acc = thoughtBtn.closest(".thought-accordion");
                if (acc) acc.classList.toggle("open");
            });
        }

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

        row.innerHTML = `
            <div class="message-avatar"><img src="/assets/AIScamavatar.jpg" class="chatbot-avatar-img" alt="SafeGuard AI"></div>
            <div class="message-content thinking-bubble">
                <div class="thinking-header">
                    <span class="thinking-spinner">🧠</span>
                    <span class="thinking-title">SafeGuard AI đang phân tích dữ liệu...</span>
                </div>
            </div>
        `;
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

    function escapeHtml(text) {
        if (!text) return "";
        return String(text)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
