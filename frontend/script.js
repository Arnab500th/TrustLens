/*
 * TrustLens - plain JavaScript frontend
 * --------------------------------------
 * This file controls page navigation, URL scanning, QR decoding, scan results,
 * scan history, the threat feed and community reports.
 *
 * The API paths and request fields follow the TrustLens project blueprint:
 * POST /api/scan with { url, source }, then GET /api/scan/{scan_id} or
 * listen to /api/scan/{scan_id}/stream for the final result.
 */

// Automatic origin resolution: works seamlessly on Render/production, FastAPI (port 8000), and Live Server (port 5500)
const API_BASE = (
    window.TRUSTLENS_API_BASE ||
    (["5500", "5501", "3000", "5173"].includes(window.location.port)
        ? "http://localhost:8000"
        : (window.location.protocol.startsWith("http") ? window.location.origin : "http://localhost:8000"))
).replace(/\/$/, "");

// Open the page with ?mock=1 to test the interface without a running backend.
// Mock results are simulated and must not be treated as real security verdicts.
const USE_MOCK = new URLSearchParams(window.location.search).get("mock") === "1";

// Small helpers keep DOM access consistent throughout the file.
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

let lastResult = null;
let currentReport = null;
let toastTimer = null;
let cameraStream = null;
let cameraFrameRequest = null;
let cameraFrameBusy = false;
let barcodeDetector = null;


/* ---------------------------------------------------------
   1. NOTIFICATIONS AND PAGE NAVIGATION
   These functions switch the visible page and show messages.
--------------------------------------------------------- */

function showToast(title, message, symbol = "✓") {
    $("#toast-title").textContent = title;
    $("#toast-message").textContent = message;
    $("#toast-symbol").textContent = symbol;
    $("#toast-backdrop").classList.add("show");

    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
        $("#toast-backdrop").classList.remove("show");
    }, 3200);
}

$("#toast-close").addEventListener("click", () => {
    $("#toast-backdrop").classList.remove("show");
});

function setView(name) {
    // Stop the camera whenever the user leaves the scan page.
    if (name !== "scan") {
        stopCamera();
    }

    $$(".view").forEach((view) => {
        view.classList.toggle("active", view.id === `view-${name}`);
    });

    $$(".nav-item").forEach((button) => {
        button.classList.toggle("active", button.dataset.view === name);
    });

    const labels = {
        scan: "Scan a link",
        feed: "Live threat feed",
        history: "Scan history",
        report: "Report a link",
        message: "Check a message",
        result: "Scan report"
    };

    $("#crumb-current").textContent = labels[name] || "Workspace";

    if (name === "history") renderHistory();
    if (name === "feed") renderFeed();
    if (name === "result") renderReport();
}

$$(".nav-item").forEach((button) => {
    button.addEventListener("click", () => setView(button.dataset.view));
});

$("#help-btn").addEventListener("click", () => {
    $("#about-modal").classList.add("show");
});

$("#modal-close").addEventListener("click", () => {
    $("#about-modal").classList.remove("show");
});

$("#modal-ok").addEventListener("click", () => {
    $("#about-modal").classList.remove("show");
});

$("#about-modal").addEventListener("click", (event) => {
    if (event.target.id === "about-modal") {
        event.currentTarget.classList.remove("show");
    }
});


/* ---------------------------------------------------------
   2. URL VALIDATION AND RESULT HELPERS
   A QR code is never opened automatically. Its URL is submitted
   to the TrustLens scanner and displayed as an analysis result.
--------------------------------------------------------- */

function normalizeURL(value) {
    let url = String(value || "").trim();

    if (!/^https?:\/\//i.test(url)) {
        url = `https://${url}`;
    }

    return url;
}

function isValidWebURL(value) {
    try {
        const url = new URL(value);
        return url.protocol === "http:" || url.protocol === "https:";
    } catch {
        return false;
    }
}

function extractWebURL(qrText) {
    // Some QR codes contain a URL directly; others include text around a URL.
    const text = String(qrText || "").trim();

    if (isValidWebURL(text)) {
        return new URL(text).href;
    }

    const match = text.match(/https?:\/\/[^\s<>"']+/i);

    if (match) {
        // Remove common punctuation that may follow a link in a text message.
        const cleaned = match[0].replace(/[),.;!?]+$/, "");
        return isValidWebURL(cleaned) ? new URL(cleaned).href : null;
    }

    // Also accept a bare domain such as example.com if the QR contains only that.
    if (/^(?:[a-z0-9-]+\.)+[a-z]{2,}(?:[/:?#].*)?$/i.test(text)) {
        const candidate = normalizeURL(text);
        return isValidWebURL(candidate) ? new URL(candidate).href : null;
    }

    return null;
}

function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, (character) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    }[character]));
}

function formatConfidence(value) {
    if (value === null || value === undefined || value === "") {
        return "Not provided";
    }

    const confidence = Number(value);

    if (!Number.isFinite(confidence)) {
        return String(value);
    }

    const percent = confidence <= 1 ? confidence * 100 : confidence;
    return `${Math.round(percent)}%`;
}

function verdictFromScore(score) {
    // The project blueprint defines these fallback risk-score bands.
    if (score <= 30) return "SAFE";
    if (score <= 65) return "SUSPICIOUS";
    return "MALICIOUS";
}

function normalizeVerdict(value, score) {
    const raw = String(value || "").toLowerCase();

    if (raw === "safe" || raw === "clean" || raw === "low risk") return "SAFE";
    if (raw === "suspicious" || raw === "warning" || raw === "inconclusive") return "SUSPICIOUS";
    if (raw === "malicious" || raw === "unsafe" || raw === "high risk" || raw === "confirmed malicious") return "MALICIOUS";

    return verdictFromScore(score);
}

function normalizeResult(data, fallbackURL, source) {
    const scoreValue = Number(data.risk_score ?? data.score ?? 0);
    const score = Math.max(0, Math.min(100, Number.isFinite(scoreValue) ? scoreValue : 0));
    const modules = Array.isArray(data.modules) ? data.modules : [];
    const simpleChecks = Array.isArray(data.checks) ? data.checks : [];

    return {
        scan_id: data.scan_id || "",
        url: data.url || fallbackURL,
        host: data.host || "",
        verdict: normalizeVerdict(data.verdict, score),
        risk_score: score,
        confidence: data.confidence,
        explanation: data.explanation || data.summary || "",
        matched_brand: data.matched_brand || null,
        modules,
        simple_checks: simpleChecks,
        source: source || "web",
        created_at: data.created_at || new Date().toISOString(),
        status: data.status || "done",
        confirmed_malicious: data.confirmed_malicious === true,
        confirmed_by: Array.isArray(data.confirmed_by) ? data.confirmed_by : [],
        cached: Boolean(data.cached),
        cached_at: data.cached_at || "",
        kind: data.kind || "url",
        snippet: data.snippet || "",
        category: data.category || ""
    };
}


/* ---------------------------------------------------------
   3. MOCK SCAN MODE
   This is only for checking the interface when the API is offline.
   It does not contact threat-intelligence providers or verify a site.
--------------------------------------------------------- */

function mockScan(url, source) {
    const host = new URL(url).hostname.toLowerCase();
    const suspicious = /login|secure|verify|account|update|free|gift|wallet|bank|support|signin/.test(host)
        || host.endsWith(".test");
    const score = suspicious ? 78 : (host === "example.com" ? 8 : 17);
    const listed = host.includes("phish");
    const verdict = verdictFromScore(score).toLowerCase();

    const sampleFindings = suspicious
        ? [
            {
                id: "URL_SUSPICIOUS_WORDS",
                severity: "high",
                message: "The domain contains words often used in deceptive login or account messages."
            },
            {
                id: "REPUTATION_UNVERIFIED",
                severity: "medium",
                message: "No live reputation provider was contacted in demo mode."
            }
        ]
        : [];

    return {
        scan_id: `demo-${Date.now()}`,
        url,
        host,
        status: "done",
        verdict,
        risk_score: score,
        confidence: 0.55,
        explanation: "This is a simulated result for testing the frontend only. It is not a real assessment of the website.",
        matched_brand: null,
        modules: [
            { module: "url", status: "ok", score: suspicious ? 30 : 0, findings: sampleFindings },
            { module: "certificate", status: "ok", score: 0, findings: [] },
            { module: "headers_tls", status: "ok", score: suspicious ? 10 : 0, findings: [] },
            {
                module: "reputation",
                status: listed ? "ok" : "skipped",
                score: listed ? 100 : 0,
                detail: "Demo mode: no live reputation provider was contacted.",
                findings: listed
                    ? [{ id: "PHISHTANK_VERIFIED", severity: "critical", source: "PhishTank (demo entry)", message: "Listed as a verified phishing page. Simulated demo entry." }]
                    : []
            }
        ],
        source
    };
}


/* ---------------------------------------------------------
   4. BACKEND SCAN FLOW
   The backend first returns a scan_id. The frontend then listens
   for SSE events and falls back to GET /api/scan/{id} polling.
--------------------------------------------------------- */

function updateProgress(title, detail) {
    $("#scan-progress").hidden = false;
    $("#progress-title").textContent = title;
    $("#progress-detail").textContent = detail;
}

function hideProgress() {
    $("#scan-progress").hidden = true;
}

function delay(milliseconds) {
    return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function pollForFinalResult(scanId, onProgress) {
    const endpoint = `${API_BASE}/api/scan/${encodeURIComponent(scanId)}`;

    // Stop after 90 seconds rather than waiting indefinitely on a stalled scan.
    for (let attempt = 0; attempt < 90; attempt += 1) {
        const response = await fetch(endpoint, {
            method: "GET",
            headers: { "Accept": "application/json" }
        });

        if (!response.ok) {
            throw new Error(`Result endpoint returned HTTP ${response.status}.`);
        }

        const result = await response.json();

        if (result.status === "error") {
            throw new Error(result.message || "The backend could not complete this scan.");
        }

        if (typeof onProgress === "function") {
            onProgress(result);
        }

        if (result.verdict && (result.status === "done" || result.status === undefined)) {
            return result;
        }

        await delay(1000);
    }

    throw new Error("The scan is taking longer than expected. Please try again.");
}

function streamFinalResult(scanId, onModule) {
    return new Promise((resolve, reject) => {
        if (!("EventSource" in window)) {
            pollForFinalResult(scanId, onModule).then(resolve).catch(reject);
            return;
        }

        const streamURL = `${API_BASE}/api/scan/${encodeURIComponent(scanId)}/stream`;
        const eventStream = new EventSource(streamURL);
        let completed = false;
        let fallbackStarted = false;
        let fallbackTimer = null;

        function closeStream() {
            eventStream.close();
            if (fallbackTimer) clearTimeout(fallbackTimer);
        }

        function finish(result) {
            if (completed) return;
            completed = true;
            closeStream();
            resolve(result);
        }

        function usePollingFallback() {
            if (completed || fallbackStarted) return;
            fallbackStarted = true;
            closeStream();

            pollForFinalResult(scanId, onModule)
                .then(finish)
                .catch((error) => {
                    if (!completed) {
                        completed = true;
                        reject(error);
                    }
                });
        }

        eventStream.addEventListener("module_result", (event) => {
            try {
                const moduleResult = JSON.parse(event.data);
                if (typeof onModule === "function") onModule(moduleResult);
            } catch (error) {
                console.warn("Could not read module_result event:", error);
            }
        });

        eventStream.addEventListener("final", (event) => {
            try {
                finish(JSON.parse(event.data));
            } catch {
                usePollingFallback();
            }
        });

        eventStream.addEventListener("error", (event) => {
            // The blueprint also defines an application-level SSE error event.
            if (event.data) {
                try {
                    const message = JSON.parse(event.data).message;
                    if (message) console.warn("Scan stream reported:", message);
                } catch {
                    // A browser network error has no JSON event data.
                }
            }
            usePollingFallback();
        });

        // If no final event arrives, switch to the documented result endpoint.
        fallbackTimer = setTimeout(usePollingFallback, 12000);
    });
}

async function requestScan(url, source, force = false) {
    if (USE_MOCK) {
        await delay(900);
        return mockScan(url, source);
    }

    const response = await fetch(`${API_BASE}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, source, force })
    });

    if (!response.ok) {
        let detail = "";
        try {
            const rawText = await response.text();
            try {
                const errData = JSON.parse(rawText);
                detail = errData.detail || errData.error || errData.message || "";
            } catch {
                // If it's an HTML error page from Cloudflare or Render, strip tags or keep first 120 chars
                detail = rawText.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim().slice(0, 160);
            }
        } catch (e) {
            detail = `HTTP ${response.status}`;
        }
        throw new Error(detail || `Scan request returned HTTP ${response.status}.`);
    }

    const startData = await response.json();

    // The FastAPI backend returns the complete scan result directly
    if (startData.verdict) {
        return startData;
    }

    if (!startData.scan_id) {
        throw new Error("The scan API response did not include a scan_id.");
    }

    updateProgress("Analyzing the destination…", "TrustLens is checking the submitted URL.");

    return await streamFinalResult(startData.scan_id, (moduleResult) => {
        const moduleName = moduleResult.module || "analysis module";
        const status = moduleResult.status || "running";
        updateProgress("Analysis in progress…", `${moduleName}: ${status}`);
    });
}

async function performScan(rawURL, source = "web", triggerButton = null, force = false) {
    const url = normalizeURL(rawURL);

    if (!isValidWebURL(url)) {
        showToast("Invalid web address", "Only HTTP and HTTPS website links can be scanned.", "!");
        return;
    }

    if (triggerButton) triggerButton.disabled = true;

    $("#url-input").value = url;
    $("#result-area").hidden = true;
    updateProgress(
        source === "qr" ? "Checking QR destination…" : (force ? "Performing fresh live scan…" : "Starting link analysis…"),
        source === "qr" ? "The decoded address is being checked. It has not been opened." : "Checking destination against threat intelligence."
    );

    try {
        const rawResult = await requestScan(url, source, force);
        const result = normalizeResult(rawResult, url, source);

        hideProgress();
        renderResult(result);
        saveHistory(result);
        if (result.cached) {
            showToast("Instant Result (Cached)", `Retrieved from database · ${result.risk_score}/100 pts`, "⚡");
        } else {
            showToast(
                "Scan complete",
                `${RISK_LABELS[riskLabelKey(result)].name} · ${result.risk_score}/100 points`
            );
        }
    } catch (error) {
        hideProgress();
        console.error("TrustLens scan failed:", error);

        const message = USE_MOCK
            ? "The sample scan could not be completed."
            : error.message;

        showToast("Could not complete scan", message, "!");
    } finally {
        if (triggerButton) triggerButton.disabled = false;
    }
}

// Manual URL form submission uses source="web" as defined in the API contract.
$("#scan-form").addEventListener("submit", async (event) => {
    event.preventDefault();

    const button = event.submitter || $("#scan-form button[type='submit']");
    await performScan($("#url-input").value, "web", button);
});

// Example buttons fill the URL field; users still choose when to scan.
$$(".example").forEach((button) => {
    button.addEventListener("click", () => {
        $("#url-input").value = button.dataset.url;
        $("#url-input").focus();
    });
});


/* ---------------------------------------------------------
   5. RESULT DISPLAY
   Displays the verdict, risk score, confidence, top findings,
   all findings grouped by the four project evidence pillars,
   and modules that did not finish successfully.
--------------------------------------------------------- */

function getAllFindings(modules) {
    return modules.flatMap((module) => {
        const findings = Array.isArray(module.findings) ? module.findings : [];

        return findings.map((finding) => ({
            ...finding,
            moduleName: module.module || "analysis",
            moduleStatus: module.status || "unknown"
        }));
    });
}

function severityRank(severity) {
    const value = String(severity || "info").toLowerCase();
    const ranks = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return ranks[value] ?? 5;
}

function pillarForModule(moduleName) {
    const name = String(moduleName || "").toLowerCase();

    if (name.includes("certificate") || name === "cert") {
        return "Certificate validation";
    }

    if (name.includes("header") || name.includes("tls") || name.includes("web_security")) {
        return "Web security assessment";
    }

    if (name.includes("reputation") || name.includes("intel") || name.includes("report")) {
        return "Collaborative threat intelligence";
    }

    return "Threat analysis";
}

function findingDetails(finding) {
    const data = finding.data;

    if (!data || typeof data !== "object" || Array.isArray(data)) {
        return "";
    }

    const details = Object.entries(data)
        .slice(0, 5)
        .map(([key, value]) => `${key}: ${typeof value === "object" ? JSON.stringify(value) : value}`)
        .join(" · ");

    return details;
}

function renderTopFindings(findings) {
    const container = $("#top-findings");

    if (!findings.length) {
        container.innerHTML = '<div class="no-findings">No findings were returned by the completed modules. This does not guarantee that the website is harmless.</div>';
        return;
    }

    const topFive = [...findings]
        .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
        .slice(0, 5);

    container.innerHTML = topFive.map((finding) => {
        const severity = String(finding.severity || "info").toLowerCase();
        const message = finding.message || finding.id || "Potential risk signal";
        const details = findingDetails(finding);

        return `
            <article class="finding-card">
                <span class="finding-severity ${escapeHTML(severity)}">${escapeHTML(severity.toUpperCase())}</span>
                <div class="finding-copy">
                    <b>${escapeHTML(message)}</b>
                    <small>${escapeHTML(finding.moduleName)}${details ? ` · ${escapeHTML(details)}` : ""}</small>
                </div>
            </article>
        `;
    }).join("");
}

function renderFindingsByPillar(findings) {
    const container = $("#all-findings-groups");

    if (!findings.length) {
        container.innerHTML = '<p class="pillar-finding">No findings were returned.</p>';
        return;
    }

    const groups = new Map();

    findings.forEach((finding) => {
        const pillar = pillarForModule(finding.moduleName);
        if (!groups.has(pillar)) groups.set(pillar, []);
        groups.get(pillar).push(finding);
    });

    container.innerHTML = [...groups.entries()].map(([pillar, items]) => `
        <section class="pillar-group">
            <h4>${escapeHTML(pillar)}</h4>
            ${items.map((finding) => `
                <p class="pillar-finding">
                    <strong>${escapeHTML(String(finding.severity || "info").toUpperCase())}:</strong>
                    ${escapeHTML(finding.message || finding.id || "Finding")}
                    <span> (${escapeHTML(finding.moduleName)})</span>
                </p>
            `).join("")}
        </section>
    `).join("");
}

function renderModules(modules, simpleChecks = []) {
    const container = $("#evidence-grid");
    const moduleItems = modules.length ? modules : simpleChecks;

    if (!moduleItems.length) {
        container.innerHTML = '<div class="empty-state">The backend did not return module details for this scan.</div>';
        return;
    }

    container.innerHTML = moduleItems.map((module) => {
        const name = module.module || module.name || "Analysis";
        const status = String(module.status || module.result || "unknown").toLowerCase();
        const isGood = ["ok", "passed", "pass", "success", "done", "complete"].includes(status);
        const isBad = ["error", "timeout", "failed", "fail"].includes(status);
        const icon = isGood ? "✓" : isBad ? "!" : "◈";
        const color = isGood ? "var(--green)" : isBad ? "var(--red)" : "#a99cff";
        const count = Array.isArray(module.findings) ? module.findings.length : 0;
        const detail = module.detail || module.message || `${count} finding${count === 1 ? "" : "s"} · ${status}`;

        return `
            <div class="evidence">
                <span class="e-icon" style="color:${color}">${icon}</span>
                <b>${escapeHTML(name)}</b>
                <small>${escapeHTML(detail)}</small>
            </div>
        `;
    }).join("");
}

function renderUnavailableModules(modules) {
    const container = $("#unavailable-modules");
    const unavailable = modules.filter((module) => {
        const status = String(module.status || "").toLowerCase();
        return ["timeout", "error", "failed", "unavailable"].includes(status);
    });

    if (!unavailable.length) {
        container.hidden = true;
        container.textContent = "";
        return;
    }

    const names = unavailable.map((module) => `${module.module || "module"} (${module.status})`);
    container.textContent = `Some checks were unavailable: ${names.join(", ")}. A low score with missing evidence should not be over-trusted.`;
    container.hidden = false;
}

function renderResult(result) {
    lastResult = currentReport = result;

    const score = result.risk_score;
    const label = RISK_LABELS[riskLabelKey(result)];
    const accent = label.color;
    const allFindings = getAllFindings(result.modules);

    $("#result-area").hidden = false;
    $("#verdict-label").textContent = label.name.toUpperCase();
    $("#verdict-label").style.color = accent;
    $("#verdict-title").textContent = label.title;
    $("#verdict-desc").textContent = label.desc;

    $("#verdict-icon").textContent = label.icon;
    $("#verdict-icon").style.background = label.bg;
    $("#verdict-icon").style.color = accent;

    $("#score-number").innerHTML = `${String(score).padStart(2, "0")}<span>/100</span>`;
    $("#score-number").style.color = accent;
    $("#score-meter").style.width = `${score}%`;
    $("#score-meter").style.background = accent;

    $("#confidence-value").textContent = formatConfidence(result.confidence);
    $("#scan-source-value").textContent = String(result.source || "web").toUpperCase();
    const explanationPrefix = result.cached ? "⚡ [Instant result from database cache] " : "";
    $("#result-explanation").textContent = explanationPrefix + (result.explanation || "The backend did not return a plain-English explanation for this scan.");

    if (result.matched_brand) {
        $("#matched-brand-value").textContent = result.matched_brand;
        $("#matched-brand-wrap").hidden = false;
    } else {
        $("#matched-brand-wrap").hidden = true;
    }

    const scanDate = result.created_at ? new Date(result.created_at) : new Date();
    $("#result-time").textContent = result.cached ? "⚡ CACHED RESULT" : (Number.isNaN(scanDate.getTime())
        ? "COMPLETED"
        : scanDate.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));

    renderTopFindings(allFindings);
    renderFindingsByPillar(allFindings);
    renderModules(result.modules, result.simple_checks);
    renderUnavailableModules(result.modules);

    $("#all-findings-details").open = false;
    $("#result-area").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function saveHistory(result) {
    try {
        const history = JSON.parse(localStorage.getItem("trustlens_history") || "[]");
        history.unshift({ ...result, scanned_at: new Date().toISOString() });
        localStorage.setItem("trustlens_history", JSON.stringify(history.slice(0, 30)));
    } catch (error) {
        console.warn("Could not save scan history:", error);
    }
}

$("#copy-result").addEventListener("click", async () => {
    if (!lastResult) return;

    const summary = reportSummary(lastResult);

    try {
        await navigator.clipboard.writeText(summary);
        showToast("Copied", "The scan summary was copied to your clipboard.");
    } catch {
        showToast("Copy unavailable", "Select and copy the result manually.", "!");
    }
});

const exportStixBtn = $("#export-stix-btn");
if (exportStixBtn) {
    exportStixBtn.addEventListener("click", () => {
        if (!lastResult || !lastResult.scan_id) {
            showToast("No scan selected", "Scan a link first before exporting STIX threat intelligence.", "!");
            return;
        }
        window.open(`${API_BASE}/api/scan/${encodeURIComponent(lastResult.scan_id)}/stix`, "_blank");
    });
}

const stixFeedLink = $("#stix-feed-link");
if (stixFeedLink) {
    stixFeedLink.href = `${API_BASE}/api/export/stix`;
}


/* ---------------------------------------------------------
   6. QR CODE SCANNING
   Camera flow: getUserMedia -> video -> canvas -> jsQR -> URL.
   Users can also upload a QR image. A decoded address is sent
   to the same scan pipeline using source="qr".
--------------------------------------------------------- */

function setQRHint(message) {
    $("#qr-hint").textContent = message;
    $("#qr-camera-status").textContent = message;
}

function stopCamera() {
    if (cameraFrameRequest !== null) {
        cancelAnimationFrame(cameraFrameRequest);
        cameraFrameRequest = null;
    }

    if (cameraStream) {
        cameraStream.getTracks().forEach((track) => track.stop());
        cameraStream = null;
    }

    const video = $("#qr-video");
    if (video) video.srcObject = null;

    const stopButton = $("#qr-stop-button");
    if (stopButton) stopButton.disabled = true;

    const cameraBox = $("#qr-camera-box");
    if (cameraBox) cameraBox.hidden = true;

    cameraFrameBusy = false;
}

function decodeCanvas(canvas) {
    const context = canvas.getContext("2d", { willReadFrequently: true });
    const imageData = context.getImageData(0, 0, canvas.width, canvas.height);

    // jsQR is the primary decoder required by the project blueprint.
    if (typeof window.jsQR === "function") {
        const code = window.jsQR(
            imageData.data,
            imageData.width,
            imageData.height,
            { inversionAttempts: "attemptBoth" }
        );

        if (code && code.data) return code.data;
    }

    return null;
}

async function decodeCanvasWithFallback(canvas) {
    const jsqrResult = decodeCanvas(canvas);
    if (jsqrResult) return jsqrResult;

    // BarcodeDetector is an optional native-browser fallback if the CDN is unavailable.
    if ("BarcodeDetector" in window) {
        try {
            if (!barcodeDetector) {
                barcodeDetector = new BarcodeDetector({ formats: ["qr_code"] });
            }

            const codes = await barcodeDetector.detect(canvas);
            if (codes.length > 0) return codes[0].rawValue;
        } catch (error) {
            console.warn("Native QR decoder was unavailable:", error);
        }
    }

    return null;
}

async function handleDecodedQR(qrText) {
    stopCamera();

    const url = extractWebURL(qrText);

    if (!url) {
        showToast(
            "QR code does not contain a website link",
            "TrustLens can assess HTTP or HTTPS website addresses. Other QR content was not opened.",
            "!"
        );
        setQRHint("No web address was found in that QR code. Try a QR code containing a website link.");
        return;
    }

    $("#url-input").value = url;
    setQRHint("QR code decoded. Checking the website destination now.");
    showToast("QR code decoded", "The embedded website link will be checked without opening it.");

    await performScan(url, "qr");
}

async function scanCameraFrame() {
    if (!cameraStream) return;

    if (cameraFrameBusy) {
        cameraFrameRequest = requestAnimationFrame(scanCameraFrame);
        return;
    }

    const video = $("#qr-video");
    const canvas = $("#qr-canvas");

    if (video.readyState >= HTMLMediaElement.HAVE_ENOUGH_DATA && video.videoWidth > 0) {
        cameraFrameBusy = true;

        try {
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;

            const context = canvas.getContext("2d", { willReadFrequently: true });
            context.drawImage(video, 0, 0, canvas.width, canvas.height);

            const decodedText = await decodeCanvasWithFallback(canvas);

            if (decodedText) {
                await handleDecodedQR(decodedText);
                return;
            }
        } catch (error) {
            console.warn("QR frame could not be decoded:", error);
        } finally {
            cameraFrameBusy = false;
        }
    }

    if (cameraStream) {
        cameraFrameRequest = requestAnimationFrame(scanCameraFrame);
    }
}

async function startCamera() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        showToast("Camera not available", "Open this page using HTTPS or localhost and check browser support.", "!");
        return;
    }

    if (typeof window.jsQR !== "function" && !("BarcodeDetector" in window)) {
        showToast("QR decoder unavailable", "Connect to the internet to load the QR decoder library, or use a supported browser.", "!");
        return;
    }

    stopCamera();
    $("#qr-camera-box").hidden = false;
    setQRHint("Waiting for camera permission…");

    try {
        cameraStream = await navigator.mediaDevices.getUserMedia({
            video: {
                facingMode: { ideal: "environment" },
                width: { ideal: 1280 },
                height: { ideal: 720 }
            },
            audio: false
        });

        const video = $("#qr-video");
        video.srcObject = cameraStream;
        await video.play();

        $("#qr-stop-button").disabled = false;
        setQRHint("Point the camera at a QR code. Keep it inside the frame.");
        cameraFrameRequest = requestAnimationFrame(scanCameraFrame);
    } catch (error) {
        stopCamera();
        console.error("Camera could not start:", error);

        if (error.name === "NotAllowedError") {
            showToast("Camera permission blocked", "Allow camera access in your browser settings and try again.", "!");
        } else {
            showToast("Could not start camera", error.message || "Check that your camera is available.", "!");
        }

        setQRHint("Camera could not be started. You can upload a QR image instead.");
    }
}

async function decodeQRImage(file) {
    if (!file || !file.type.startsWith("image/")) {
        showToast("Choose an image", "Upload a PNG, JPG or another supported image containing a QR code.", "!");
        return;
    }

    try {
        let imageBitmap;

        if ("createImageBitmap" in window) {
            imageBitmap = await createImageBitmap(file);
        } else {
            imageBitmap = await new Promise((resolve, reject) => {
                const image = new Image();
                const objectURL = URL.createObjectURL(file);

                image.onload = () => {
                    URL.revokeObjectURL(objectURL);
                    resolve(image);
                };
                image.onerror = () => {
                    URL.revokeObjectURL(objectURL);
                    reject(new Error("The selected image could not be opened."));
                };
                image.src = objectURL;
            });
        }

        const canvas = $("#qr-canvas");
        canvas.width = imageBitmap.width;
        canvas.height = imageBitmap.height;

        const context = canvas.getContext("2d", { willReadFrequently: true });
        context.drawImage(imageBitmap, 0, 0, canvas.width, canvas.height);

        if (typeof imageBitmap.close === "function") imageBitmap.close();

        const decodedText = await decodeCanvasWithFallback(canvas);

        if (!decodedText) {
            showToast("No QR code detected", "Try a clearer image with the entire QR code visible.", "!");
            setQRHint("No QR code was detected in that image. Choose another image.");
            return;
        }

        await handleDecodedQR(decodedText);
    } catch (error) {
        console.error("QR image could not be decoded:", error);
        showToast("Could not read QR image", error.message || "Try another image.", "!");
    }
}

$("#qr-start-button").addEventListener("click", startCamera);
$("#qr-stop-button").addEventListener("click", () => {
    stopCamera();
    setQRHint("Camera stopped. You can start it again or upload a QR image.");
});

$("#qr-file-input").addEventListener("change", async (event) => {
    stopCamera();
    const file = event.target.files && event.target.files[0];
    await decodeQRImage(file);
    event.target.value = "";
});


/* ---------------------------------------------------------
   7. SCAN HISTORY
   Keeps the last 30 results in this browser using localStorage.
--------------------------------------------------------- */

function renderHistory() {
    const container = $("#history-list");
    let history = [];

    try {
        history = JSON.parse(localStorage.getItem("trustlens_history") || "[]");
    } catch {
        history = [];
    }

    if (!history.length) {
        container.innerHTML = '<div class="empty-state">No scans yet. Your results will appear here.</div>';
        return;
    }

    container.innerHTML = history.map((item, index) => `
        <div class="list-row">
            <div class="row-icon">${item.source === "qr" ? "▦" : item.source === "sms" ? "✉" : "⌕"}</div>
            <div class="row-content">
                <b>${escapeHTML(item.url)}</b>
                <small>${escapeHTML(new Date(item.scanned_at).toLocaleString())} · ${escapeHTML(item.source || "web")}</small>
            </div>
            <span class="row-status ${riskLabelKey(item) === "low" ? "" : "risky"}">
                ${escapeHTML(RISK_LABELS[riskLabelKey(item)].name)} · ${Number(item.risk_score)}/100
            </span>
            ${item.kind === "message" ? "" : `<button class="text-button revisit" data-index="${index}">Rescan</button>`}
            <button class="text-button open-report" data-index="${index}">Report</button>
        </div>
    `).join("");

    $$(".open-report").forEach((button) => {
        button.addEventListener("click", () => {
            currentReport = history[Number(button.dataset.index)] || null;
            setView("result");
        });
    });

    $$(".revisit").forEach((button) => {
        button.addEventListener("click", async () => {
            const item = history[Number(button.dataset.index)];
            if (!item) return;
            setView("scan");
            await performScan(item.url, item.source || "web", null, true);
        });
    });
}

$("#clear-history").addEventListener("click", () => {
    localStorage.removeItem("trustlens_history");
    renderHistory();
    showToast("History cleared", "Saved scans were removed from this browser.");
});


/* ---------------------------------------------------------
   8. LIVE THREAT FEED
   Reads the CT feed endpoint defined in the blueprint. If the
   backend is unavailable, clearly labelled sample rows are shown.
--------------------------------------------------------- */

async function renderFeed() {
    const container = $("#feed-list");
    const badge = $("#feed-mode");

    if (!USE_MOCK) {
        try {
            const response = await fetch(`${API_BASE}/api/feed?limit=50`);
            if (!response.ok) throw new Error(`Feed endpoint returned HTTP ${response.status}`);

            const payload = await response.json();
            const items = Array.isArray(payload) ? payload : (payload.items || payload.results || []);

            if (items.length) {
                if (badge) badge.textContent = "LIVE API";
                container.innerHTML = items.map((item) => {
                    const domain = item.domain || "Unknown domain";
                    const reasons = Array.isArray(item.reasons) ? item.reasons.join(", ") : "Certificate transparency signal";
                    const brand = item.matched_brand ? ` · Possible brand: ${item.matched_brand}` : "";

                    return `
                        <div class="list-row">
                            <div class="row-icon">⚑</div>
                            <div class="row-content">
                                <b>${escapeHTML(domain)}</b>
                                <small>${escapeHTML(reasons + brand)}</small>
                            </div>
                            <span class="row-status risky">REVIEW</span>
                        </div>
                    `;
                }).join("");
                return;
            }
        } catch (error) {
            console.warn("Live feed unavailable:", error);
        }
    }

    if (badge) badge.textContent = "";

    const samples = [
        ["login-account-check.example", "Sample credential-phishing pattern", "HIGH RISK", "risky"],
        ["free-reward-claim.example", "Sample suspicious reward lure", "HIGH RISK", "risky"],
        ["example.com", "Reference domain · sample entry", "LOW RISK", ""],
        ["verify-user-session.test", "Sample lookalike / verification wording", "REVIEW", "risky"]
    ];

    container.innerHTML = samples.map((item) => `
        <div class="list-row">
            <div class="row-icon">⚑</div>
            <div class="row-content">
                <b>${escapeHTML(item[0])}</b>
                <small>${escapeHTML(item[1])}</small>
            </div>
            <span class="row-status ${item[3]}">${escapeHTML(item[2])}</span>
        </div>
    `).join("");
}


/* ---------------------------------------------------------
   9. COMMUNITY REPORT FORM
   Sends the documented fields {url, note} to POST /api/report.
--------------------------------------------------------- */

$("#report-form").addEventListener("submit", async (event) => {
    event.preventDefault();

    const payload = {
        url: $("#report-url").value.trim(),
        note: `${$("#report-reason").value}. ${$("#report-notes").value.trim()}`.trim()
    };

    try {
        if (USE_MOCK) {
            showToast("Demo report received", "This sample report was not sent to a server.");
        } else {
            const response = await fetch(`${API_BASE}/api/report`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                throw new Error(`Report endpoint returned HTTP ${response.status}.`);
            }

            showToast("Report submitted", "Thank you for contributing a community report.");
        }

        event.target.reset();
    } catch (error) {
        console.error("Report submission failed:", error);
        showToast("Report failed", error.message || "Could not connect to the report endpoint.", "!");
    }
});


/* ---------------------------------------------------------
   11. RISK LABELS
   Labels and point bands follow blueprint section 4. They live in
   one place so the result page, history and legend always agree.
   The wording never says "safe": a low score is not a guarantee.
--------------------------------------------------------- */

const RISK_LABELS = {
    low: {
        name: "Low Risk", icon: "✓", color: "var(--green)", bg: "#16382f", band: "0 to 30",
        title: "Nothing significant found",
        desc: "The checks we ran found nothing significant. That is not a guarantee.",
        rule: "Total points 0 to 30. Nothing significant found in the checks we ran. We never say safe.",
        next: [
            "Stay careful: open the institute's official app or type its website yourself instead of using links in messages.",
            "Never share an OTP, PIN, CVV or password because a message asks for it."
        ]
    },
    suspicious: {
        name: "Suspicious", icon: "⚠", color: "#ffbf70", bg: "#3b3020", band: "31 to 60",
        title: "Something needs a closer look",
        desc: "Check with the sender directly before you tap, reply or pay.",
        rule: "Total points 31 to 60. Something needs a closer look.",
        next: [
            "Do not tap the link, reply or call any number given in the message.",
            "Read the findings below to see what raised the score."
        ]
    },
    high: {
        name: "High Risk", icon: "!", color: "var(--red)", bg: "#3b202d", band: "61 or more",
        title: "Several strong warning signs",
        desc: "Treat this as a likely scam. Do not open the link or share details.",
        rule: "Total points 61 or more. Several strong signs together.",
        next: [
            "Do not open the link, reply or share any details. Delete the message.",
            "If you already shared details or paid, call your bank right away and change your passwords.",
            "Report it on the Report a link page so others are warned."
        ]
    },
    confirmed: {
        name: "Confirmed Malicious", icon: "✕", color: "#ff5c7a", bg: "#4a1f2c", band: "",
        title: "Listed by a trusted source",
        desc: "A trusted threat list names this link. Do not open it.",
        rule: "A trusted source lists the link (PhishTank verified, URLhaus). This overrides the points.",
        next: [
            "Do not open the link or reply. Delete the message.",
            "If you already opened it or entered details, change those passwords and call your bank now.",
            "If money or data was lost, report it to your local cybercrime authority (in India: cybercrime.gov.in or helpline 1930)."
        ]
    },
    inconclusive: {
        name: "Inconclusive", icon: "?", color: "#a99cff", bg: "#262749", band: "",
        title: "Not enough information",
        desc: "Too few checks worked to give a fair label. This is not a pass.",
        rule: "Fewer than 3 checks worked. We do not have enough information.",
        next: [
            "Do not treat this as a pass. Add the sender and any link, then check again.",
            "Until then, confirm with the institute using a contact you already trust."
        ]
    }
};

// Shown as an extra "what to do next" step, based on who the message claims to be.
const CONTACT_HINTS = {
    bank: "the number on the back of your card or the bank's official app",
    university: "the contact details on the official university website",
    government: "the official government website that you type in yourself",
    courier: "the tracking page on the courier's official website or app",
    telecom: "your operator's official app or the customer-care number on your bill",
    wallet: "the help section inside the official app",
    shop: "the orders page in the official app",
    job: "company contact details you already have, not the ones in the message"
};

const CHECK_TITLES = {
    sender: "Sender check",
    wording: "Message wording",
    institute: "Institute match",
    links: "Link structure",
    reputation: "Trusted-source lookup (PhishTank, URLhaus)",
    url: "URL analysis",
    certificate: "Certificate check",
    headers_tls: "Headers and TLS"
};

const checkTitle = (name) => CHECK_TITLES[name] || String(name || "Analysis").replace(/_/g, " ");
const OK_STATES = ["ok", "passed", "pass", "success", "done", "complete"];
const moduleRan = (module) => OK_STATES.includes(String(module.status || "").toLowerCase());

function trustedListings(result) {
    // Confirmed Malicious needs a trusted-source listing. The backend can send
    // confirmed_malicious: true, or a high/critical PhishTank or URLhaus finding.
    const hits = [];

    if (result.confirmed_malicious === true) {
        const sources = result.confirmed_by || [];
        hits.push(...(sources.length ? sources : ["A trusted source"]));
    }

    getAllFindings(result.modules || []).forEach((finding) => {
        const origin = `${finding.id || ""} ${finding.source || ""} ${finding.moduleName || ""}`;
        const severe = ["high", "critical"].includes(String(finding.severity || "").toLowerCase());
        const negated = /not (listed|found)|no match/i.test(finding.message || "");

        if (severe && !negated && /phishtank|urlhaus/i.test(origin)) {
            hits.push(/urlhaus/i.test(origin) ? "URLhaus" : "PhishTank (verified)");
        }
    });

    return [...new Set(hits)];
}

function riskLabelKey(result) {
    if (trustedListings(result).length) return "confirmed";

    const modules = result.modules || [];
    if (modules.length && modules.filter(moduleRan).length < 3) return "inconclusive";

    const points = Math.round(Number(result.risk_score) || 0);
    return points <= 30 ? "low" : points <= 60 ? "suspicious" : "high";
}


/* ---------------------------------------------------------
   12. MESSAGE CHECK
   Rule-based checks run in the browser. If the message has a
   link, only that link is sent to the backend (source "web") so
   PhishTank, URLhaus and the other modules can look it up.
--------------------------------------------------------- */

// Known institutes and their official websites. Add or edit entries as needed.
const BRANDS = [
    { name: "HDFC Bank", keys: ["hdfc"], domains: ["hdfcbank.com"] },
    { name: "State Bank of India", keys: ["sbi", "state bank"], domains: ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"] },
    { name: "ICICI Bank", keys: ["icici"], domains: ["icicibank.com"] },
    { name: "Axis Bank", keys: ["axis bank"], domains: ["axisbank.com"] },
    { name: "Paytm", keys: ["paytm"], domains: ["paytm.com"] },
    { name: "PhonePe", keys: ["phonepe"], domains: ["phonepe.com"] },
    { name: "Amazon", keys: ["amazon"], domains: ["amazon.in", "amazon.com"] },
    { name: "Income Tax Department", keys: ["income tax"], domains: ["incometax.gov.in", "incometaxindia.gov.in"] },
    { name: "Aadhaar (UIDAI)", keys: ["aadhaar", "uidai"], domains: ["uidai.gov.in"] },
    { name: "India Post", keys: ["india post"], domains: ["indiapost.gov.in"] },
    { name: "FedEx", keys: ["fedex"], domains: ["fedex.com"] },
    { name: "DHL", keys: ["dhl"], domains: ["dhl.com"] },
    { name: "Jio", keys: ["jio"], domains: ["jio.com", "jiomart.com"] },
    { name: "Airtel", keys: ["airtel"], domains: ["airtel.in", "airtel.com"] }
];

const SHORTENERS = /^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rb\.gy|shorturl\.at|ow\.ly|tiny\.cc|t\.ly)$/;
const ODD_TLDS = /\.(xyz|top|click|icu|vip|cfd|sbs|buzz|link|rest|tk|ml|ga|cf|gq|cyou|monster)$/;

const MESSAGE_EXAMPLES = {
    bank: {
        sender: "+91 98765 43210",
        claim: "bank",
        text: "Dear customer, your HDFC Bank account will be blocked today. Update your KYC immediately: http://hdfc-kyc-update.xyz/login"
    },
    parcel: {
        sender: "+91 91234 56789",
        claim: "courier",
        text: "India Post: your parcel is on hold. Pay a Rs.25 redelivery fee within 24 hours at bit.ly/3xYzAbC or it will be returned."
    },
    real: {
        sender: "VM-HDFCBK",
        claim: "bank",
        text: "Rs.1,250.00 debited from a/c XX1234 on 08-11-26 via UPI. If this was not you, call the number on the back of your card. -HDFC Bank"
    }
};

function extractLinks(text) {
    const found = text.match(/\b(?:https?:\/\/)?(?:[a-z0-9-]+\.)+[a-z]{2,24}\b(?:\/[^\s]*)?/gi) || [];
    const urls = [];

    found.forEach((item) => {
        try {
            const url = new URL(normalizeURL(item.replace(/[),.;!?]+$/, "")));
            if (!urls.some((known) => known.href === url.href)) urls.push(url);
        } catch {
            // Ignore text that only looks like a web address.
        }
    });

    return urls.slice(0, 3);
}

async function analyzeMessage(senderInput, text, category) {
    const sender = senderInput.trim();
    const senderLetters = sender.replace(/[^a-z]/gi, "").toLowerCase();
    const isNumber = /^\+?[\d\s()-]{10,}$/.test(sender);
    const brand = BRANDS.find((item) => item.keys.some((key) => {
        return new RegExp(`\\b${key}\\b`, "i").test(text) || senderLetters.includes(key.replace(/\s/g, ""));
    }));

    const local = [];
    const rule = (id, severity, points, message) => ({
        id, severity, points, message, source: "TrustLens rules (in your browser)"
    });
    const addCheck = (module, status, findings, detail) => local.push({
        module, status, detail, findings,
        score: findings.reduce((sum, item) => sum + item.points, 0)
    });

    // 1. Sender check
    if (!sender) {
        addCheck("sender", "skipped", [], "No sender was entered.");
    } else {
        addCheck("sender", "ok", isNumber ? [rule("SENDER_PERSONAL_NUMBER", "high", 20,
            "Sent from an ordinary mobile number. Banks, colleges and couriers usually send from a registered sender name.")] : []);
    }

    // 2. Message wording
    const wording = [
        ["URGENT_LANGUAGE", "medium", 10, /urgent|immediately|within \d+ ?(hours?|hrs?|minutes?|mins?)|last (warning|chance)|final notice|expires?\b|today only|act now/i, "Uses urgency or a deadline to rush you."],
        ["THREAT_LANGUAGE", "high", 15, /suspend|blocked|deactivat|disconnect|legal action|arrest|penalt|terminated|frozen/i, "Threatens to block, suspend or take action against you."],
        ["ASKS_SENSITIVE_INFO", "high", 20, /\b(otp|pin|cvv|password|passcode)\b|card number|net ?banking|log ?in|sign in|verify (your )?(account|identity|details)|update (your )?(kyc|pan|aadhaar|details)|\bkyc\b/i, "Asks you to share or confirm sensitive details."],
        ["REWARD_OR_FEE", "medium", 10, /prize|winner|\bwon\b|lottery|cashback|reward|refund|free gift|claim|customs|redelivery|processing fee/i, "Promises a reward or asks for a small payment."]
    ];
    const warnsNotToShare = /(do not|don't|never) share/i;
    addCheck("wording", "ok", wording
        .filter(([id, , , pattern]) => pattern.test(text) && !(id === "ASKS_SENSITIVE_INFO" && warnsNotToShare.test(text)))
        .map(([id, severity, points, , message]) => rule(id, severity, points, message)));

    // 3. Institute match: does the sender name fit the institute the message names?
    const mismatch = brand && sender && !isNumber && !senderLetters.includes(brand.keys[0].replace(/\s/g, ""));
    addCheck("institute", "ok", mismatch ? [rule("SENDER_NAME_MISMATCH", "medium", 10,
        `The message names ${brand.name}, but the sender name does not contain it.`)] : [],
        brand ? `Message names ${brand.name}` : "No known institute named");

    // 4. Link structure
    const urls = extractLinks(text);

    if (!urls.length) {
        addCheck("links", "skipped", [], "No link was found in the message.");
    } else {
        const linkFindings = [];

        urls.forEach((url) => {
            const host = url.hostname.replace(/^www\./, "").toLowerCase();
            const flat = host.replace(/[-.]/g, "");
            const official = (item) => item.domains.some((domain) => host === domain || host.endsWith(`.${domain}`));
            const lookalike = BRANDS.find((item) => !official(item) && item.keys.some((key) => flat.includes(key.replace(/\s/g, ""))));
            const note = (id, severity, points, message) => linkFindings.push(rule(id, severity, points, `${host}: ${message}`));

            if (SHORTENERS.test(host)) note("LINK_SHORTENED", "medium", 15, "a shortened link hides where it really goes.");
            if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) note("LINK_RAW_IP", "high", 25, "the link uses a number address instead of a name.");
            if (host.includes("xn--") || url.username) note("LINK_DISGUISED", "high", 20, "the address uses a disguised or look-alike format.");
            if (lookalike) note("LINK_LOOKALIKE", "high", 25, `imitates ${lookalike.name} but is not its known website.`);
            else if (brand && !official(brand) && !SHORTENERS.test(host)) note("LINK_NOT_OFFICIAL", "high", 20, `the message names ${brand.name}, but this is not its known website.`);
            if (ODD_TLDS.test(host)) note("LINK_ODD_ENDING", "medium", 10, "the ending is often used for throwaway sites.");
            if (/kyc|verify|update|secure|login|refund|claim|reward|bonus/.test(flat)) note("LINK_VERIFY_WORDS", "medium", 10, "the name contains words often used on fake verification pages.");
            if (url.protocol === "http:") note("LINK_NO_HTTPS", "low", 5, "the page does not use an encrypted connection.");
        });

        addCheck("links", "ok", linkFindings, `${urls.length} link${urls.length === 1 ? "" : "s"} checked`);
    }

    // 5. Trusted-source lookup: needs the TrustLens backend, so it can fail.
    let backend = null;

    if (!urls.length) {
        addCheck("reputation", "skipped", [], "No link to look up.");
    } else {
        try {
            backend = await Promise.race([
                requestScan(urls[0].href, "web"),
                delay(25000).then(() => { throw new Error("The link lookup timed out."); })
            ]);
        } catch (error) {
            addCheck("reputation", "unavailable", [], "PhishTank and URLhaus were not checked because the TrustLens backend could not be reached.");
        } finally {
            hideProgress();
        }
    }

    const localPoints = local.reduce((sum, item) => sum + item.score, 0);
    const modules = backend && Array.isArray(backend.modules) ? [...local, ...backend.modules] : local;
    const found = modules.flatMap((item) => item.findings || []).length;

    return {
        scan_id: `msg-${Date.now()}`,
        url: `SMS from ${sender || "unknown sender"}`,
        risk_score: Math.min(100, Math.max(localPoints, Number(backend && backend.risk_score) || 0)),
        explanation: `${found} warning sign${found === 1 ? "" : "s"} found${brand ? ` in a message that names ${brand.name}` : ""}. Official-looking messages can still be fake, so verify before you act.`,
        matched_brand: brand ? brand.name : null,
        modules,
        confirmed_malicious: Boolean(backend && backend.confirmed_malicious),
        confirmed_by: backend && backend.confirmed_by,
        kind: "message",
        snippet: text.slice(0, 200),
        category
    };
}

$("#msg-form").addEventListener("submit", async (event) => {
    event.preventDefault();

    const text = $("#msg-text").value.trim();
    if (!text) return;

    const button = $("#msg-submit");
    button.disabled = true;
    button.firstElementChild.textContent = "Checking…";

    try {
        let raw = null;
        if (!USE_MOCK) {
            try {
                const response = await fetch(`${API_BASE}/api/message`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        text,
                        sender: $("#msg-sender").value.trim(),
                        claim: $("#msg-claim").value
                    })
                });
                if (response.ok) {
                    raw = await response.json();
                }
            } catch (err) {
                console.warn("Backend /api/message unreachable, using local fallback:", err);
            }
        }

        if (!raw) {
            raw = await analyzeMessage($("#msg-sender").value, text, $("#msg-claim").value);
        }

        const result = normalizeResult(raw, raw.url || "Message Check", "sms");

        currentReport = result;
        saveHistory(result);
        setView("result");
        showToast("Message checked", `${RISK_LABELS[riskLabelKey(result)].name} · ${result.risk_score}/100 points`);
    } catch (error) {
        console.error("Message check failed:", error);
        showToast("Could not check message", error.message || "Please try again.", "!");
    } finally {
        button.disabled = false;
        button.firstElementChild.textContent = "Check message";
    }
});

$$(".msg-example").forEach((button) => {
    button.addEventListener("click", () => {
        const sample = MESSAGE_EXAMPLES[button.dataset.ex];
        $("#msg-sender").value = sample.sender;
        $("#msg-claim").value = sample.claim;
        $("#msg-text").value = sample.text;
    });
});


/* ---------------------------------------------------------
   13. SCAN REPORT PAGE
   Full result for the latest scan (URL, QR or message) or any item
   opened from Scan history: risk label, points, time of check, the
   source of each finding, checks that could not run, next steps.
--------------------------------------------------------- */

function formatCheckTime(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime())
        ? "Not recorded"
        : date.toLocaleString([], { dateStyle: "medium", timeStyle: "medium" });
}

function reportNextSteps(result, key) {
    const steps = [...RISK_LABELS[key].next];

    if (CONTACT_HINTS[result.category]) {
        steps.push(`To confirm, contact the institute using ${CONTACT_HINTS[result.category]}.`);
    }

    return steps;
}

function reportSummary(result) {
    const key = riskLabelKey(result);
    const modules = result.modules || [];
    const findings = getAllFindings(modules);
    const missing = modules.filter((item) => !moduleRan(item)).map((item) => checkTitle(item.module));

    return [
        "TrustLens scan report",
        `Checked: ${result.url}`,
        `Time of check: ${formatCheckTime(result.created_at || result.scanned_at)}`,
        `Risk label: ${RISK_LABELS[key].name} (${Math.round(Number(result.risk_score) || 0)}/100 points)`,
        `Findings: ${findings.length ? findings.map((item) => `${item.message || item.id} [${checkTitle(item.moduleName)}]`).join("; ") : "none"}`,
        `Checks that could not run: ${missing.join(", ") || "none"}`,
        `What to do next: ${reportNextSteps(result, key).join(" ")}`
    ].join("\n");
}

function renderLabelTable(activeKey) {
    $("#label-table").innerHTML = `
        <div class="label-row head"><b>Label</b><span>When we use it</span></div>
        ${Object.entries(RISK_LABELS).map(([key, label]) => `
            <div class="label-row ${key === activeKey ? "current" : ""}" style="--accent:${label.color}">
                <b>${label.name}</b><span>${label.rule}</span>
            </div>
        `).join("")}
    `;
}

function checkItem(module, ran) {
    const count = (module.findings || []).length;
    const reasons = { skipped: "Skipped.", timeout: "Timed out.", error: "The check failed.", failed: "The check failed.", unavailable: "Unavailable." };
    const reason = module.detail || module.message || reasons[String(module.status || "").toLowerCase()] || "Did not run.";
    const detail = ran ? `${count} finding${count === 1 ? "" : "s"} · ${Number(module.score) || 0} points` : reason;

    return `
        <div class="evidence ${ran ? "" : "warn"}">
            <span class="e-icon">${ran ? "✓" : "!"}</span>
            <b>${escapeHTML(checkTitle(module.module))}</b>
            <small>${escapeHTML(detail)}</small>
        </div>
    `;
}

function reportHTML(result) {
    const key = riskLabelKey(result);
    const label = RISK_LABELS[key];
    const points = Math.round(Number(result.risk_score) || 0);
    const modules = result.modules || [];
    const ran = modules.filter(moduleRan);
    const notRan = modules.filter((item) => !moduleRan(item));
    const findings = getAllFindings(modules).sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
    const isMessage = result.kind === "message";
    const hasConfidence = result.confidence !== undefined && result.confidence !== null && result.confidence !== "";
    const why = key === "confirmed"
        ? `${trustedListings(result).join(" and ")} lists this link. A trusted-source listing overrides the points.`
        : key === "inconclusive"
            ? `Only ${ran.length} of ${modules.length} checks worked and at least 3 are needed.`
            : `${points} total points falls in the ${label.band} band.`;

    const findingCards = findings.length ? findings.map((item) => {
        const severity = String(item.severity || "info").toLowerCase();
        const pts = Number(item.points ?? item.score);

        return `
            <article class="finding-card">
                <span class="finding-severity ${escapeHTML(severity)}">${escapeHTML(severity.toUpperCase())}</span>
                <div class="finding-copy">
                    <b>${escapeHTML(item.message || item.id || "Potential risk signal")}</b>
                    <small>Source: ${escapeHTML(checkTitle(item.moduleName))} · ${escapeHTML(item.source || "TrustLens backend")}</small>
                </div>
                ${Number.isFinite(pts) ? `<span class="finding-pts">+${pts} pts</span>` : ""}
            </article>
        `;
    }).join("") : '<div class="no-findings">No warning signs were found by the checks that ran. That is not a guarantee, so keep verifying with the institute directly.</div>';

    return `
        <div class="result-card">
            <div class="report-target">
                <small>${isMessage ? "MESSAGE CHECKED" : "LINK CHECKED"}</small>
                <b>${escapeHTML(result.url)}</b>
                ${result.snippet ? `<p>“${escapeHTML(result.snippet)}”</p>` : ""}
            </div>
            <div class="result-main">
                <div class="verdict-icon" style="background:${label.bg};color:${label.color}">${label.icon}</div>
                <div class="verdict-copy">
                    <div class="verdict-label" style="color:${label.color}">RISK LABEL</div>
                    <h2>${label.name}</h2>
                    <p>${label.desc}</p>
                </div>
                <div class="score">
                    <div class="score-number" style="color:${label.color}">${String(points).padStart(2, "0")}<span>/100</span></div>
                    <small>TOTAL POINTS</small>
                </div>
            </div>
            <div class="meter scaled"><span style="width:${points}%;background:${label.color}"></span></div>
            <div class="meter-scale"><span style="width:31%">0 to 30 Low Risk</span><span style="width:30%">31 to 60 Suspicious</span><span style="width:39%">61+ High Risk</span></div>
            <div class="result-meta">
                <div><small>TIME OF CHECK</small><b>${escapeHTML(formatCheckTime(result.created_at || result.scanned_at))}</b></div>
                <div><small>SCAN SOURCE</small><b>${escapeHTML(String(result.source || "web").toUpperCase())}</b></div>
                <div><small>CHECKS THAT RAN</small><b>${modules.length ? `${ran.length} of ${modules.length}` : "Not reported"}</b></div>
                ${hasConfidence ? `<div><small>CONFIDENCE</small><b>${escapeHTML(formatConfidence(result.confidence))}</b></div>` : ""}
                ${result.matched_brand ? `<div><small>MATCHED BRAND</small><b>${escapeHTML(result.matched_brand)}</b></div>` : ""}
            </div>
            <p class="result-explanation"><strong>Why this label.</strong> ${escapeHTML(why)} ${escapeHTML(result.explanation || "")}</p>
            <div class="findings-section">
                <div class="findings-heading"><b>What to do next</b><span>RECOMMENDED STEPS</span></div>
                <ol class="next-list">${reportNextSteps(result, key).map((step) => `<li>${escapeHTML(step)}</li>`).join("")}</ol>
            </div>
            <div class="findings-section">
                <div class="findings-heading"><b>What we found</b><span>FINDINGS AND THEIR SOURCES</span></div>
                <div class="top-findings">${findingCards}</div>
            </div>
            ${notRan.length ? `
            <div class="findings-section">
                <div class="findings-heading"><b>Checks that could not run</b><span>${notRan.length} MISSING</span></div>
                <div class="evidence-grid">${notRan.map((item) => checkItem(item, false)).join("")}</div>
            </div>` : ""}
            ${ran.length ? `
            <div class="findings-section">
                <div class="findings-heading"><b>Checks that ran</b><span>${ran.length} COMPLETED</span></div>
                <div class="evidence-grid">${ran.map((item) => checkItem(item, true)).join("")}</div>
            </div>` : ""}
            <div class="result-footer">
                <span>ⓘ Results are signals, not a guarantee.</span>
                <span class="footer-actions">
                    ${result.scan_id ? `<a class="text-button" href="${API_BASE}/api/scan/${encodeURIComponent(result.scan_id)}/stix" target="_blank" style="text-decoration:none;">Export STIX 2.1 ⭳</a>` : ""}
                    <button id="report-copy">Copy summary ↗</button>
                    <button data-go="${isMessage ? "message" : "scan"}">Check another →</button>
                </span>
            </div>
        </div>
    `;
}

function renderReport() {
    const body = $("#report-body");
    let result = currentReport;

    if (!result) {
        try {
            result = JSON.parse(localStorage.getItem("trustlens_history") || "[]")[0] || null;
        } catch {
            result = null;
        }
    }

    renderLabelTable(result ? riskLabelKey(result) : "");

    body.innerHTML = result ? reportHTML(result) : `
        <div class="section-card">
            <div class="empty-state">No scan result yet. Scan a link or check a message and the full report will appear here.</div>
            <div class="report-empty-actions">
                <button class="scan-button" data-go="scan">Scan a link <span>→</span></button>
                <button class="scan-button" data-go="message">Check a message <span>→</span></button>
            </div>
        </div>
    `;

    body.querySelectorAll("[data-go]").forEach((button) => {
        button.addEventListener("click", () => setView(button.dataset.go));
    });

    const copyButton = $("#report-copy");

    if (copyButton) {
        copyButton.addEventListener("click", async () => {
            try {
                await navigator.clipboard.writeText(reportSummary(result));
                showToast("Copied", "The report summary was copied to your clipboard.");
            } catch {
                showToast("Copy unavailable", "Select and copy the report manually.", "!");
            }
        });
    }
}

$("#open-report").addEventListener("click", () => setView("result"));


/* ---------------------------------------------------------
   10. INITIAL PAGE SETUP
   Allows an optional URL or shared text to be passed in the
   query string, and announces demo mode when it is enabled.
--------------------------------------------------------- */

const pageParameters = new URLSearchParams(window.location.search);
const sharedText = pageParameters.get("text") || "";
const sharedURL = pageParameters.get("url") || extractWebURL(sharedText);

if (sharedURL && isValidWebURL(normalizeURL(sharedURL))) {
    $("#url-input").value = normalizeURL(sharedURL);
}

window.addEventListener("pagehide", stopCamera);

if (USE_MOCK) {
    showToast(
        "Demo mode enabled",
        "Sample scan outcomes are simulated. Connect the backend for real analysis."
    );
}
