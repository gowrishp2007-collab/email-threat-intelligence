// =========================================================
// EMAIL THREAT INTELLIGENCE - FRONTEND
// =========================================================

// Backend API
const API_URL = "http://127.0.0.1:8000/api/analyze-eml";


// =========================================================
// ANALYZE EMAIL
// =========================================================

async function analyzeEmail() {

    const fileInput = document.getElementById("emailFile");
    const loading = document.getElementById("loading");
    const error = document.getElementById("error");
    const result = document.getElementById("result");

    if (!fileInput) {
        console.error("emailFile element not found");
        return;
    }

    const file = fileInput.files[0];

    // -------------------------------------------------------
    // VALIDATION
    // -------------------------------------------------------

    if (!file) {
        error.textContent = "Please select an .eml file.";
        return;
    }

    if (!file.name.toLowerCase().endsWith(".eml")) {
        error.textContent = "Only .eml files are supported.";
        return;
    }

    // Clear previous error
    error.textContent = "";

    // Show loading
    if (loading) {
        loading.style.display = "flex";
    }

    // Hide old result
    if (result) {
        result.style.display = "none";
    }

    // -------------------------------------------------------
    // FORM DATA
    // -------------------------------------------------------

    const formData = new FormData();
    formData.append("file", file);

    // -------------------------------------------------------
    // BACKEND REQUEST
    // -------------------------------------------------------

    try {

        const response = await fetch(
            API_URL,
            {
                method: "POST",
                body: formData
            }
        );

        if (!response.ok) {
            throw new Error(
                "Backend returned error: " + response.status
            );
        }

        const data = await response.json();

        console.log("Backend response:", data);

        if (data.status !== "success") {
            throw new Error(
                data.message || "Email analysis failed"
            );
        }

        // Display result
        displayResult(data);

    }

    catch (err) {

        console.error(
            "Email analysis error:",
            err
        );

        error.textContent =
            "Failed to fetch backend: " +
            err.message;
    }

    finally {

        if (loading) {
            loading.style.display = "none";
        }
    }
}


// =========================================================
// DISPLAY RESULT
// =========================================================

function displayResult(data) {

    const parsed = data.parsed_email || {};
    const analysis = data.analysis || {};

    // =======================================================
    // BASIC EMAIL INFORMATION
    // =======================================================

    setText(
        "sender",
        parsed.sender
    );

    setText(
        "receiver",
        parsed.receiver
    );

    setText(
        "subject",
        parsed.subject
    );

    setText(
        "replyTo",
        parsed.reply_to
    );

    setText(
        "returnPath",
        parsed.return_path
    );


    // =======================================================
    // THREAT INFORMATION
    // =======================================================

    const threatLevel =
        analysis.threat_level || "-";

    const threatScore =
        analysis.threat_score ?? "-";

    setText(
        "threatLevel",
        threatLevel
    );

    setText(
        "threatScore",
        threatScore
    );

    updateThreatLevel(threatLevel);


    // =======================================================
    // COUNTS
    // =======================================================

    setText(
        "keywordCount",
        analysis.keyword_count ?? 0
    );

    setText(
        "hopCount",
        analysis
            .received_header_analysis
            ?.hop_count ?? 0
    );

    setText(
        "attachmentCount",
        analysis
            .attachment_analysis
            ?.attachment_count ?? 0
    );


    // =======================================================
    // AUTHENTICATION
    // =======================================================

    const authentication =
        analysis.authentication_analysis || {};

    const spfStatus =
        authentication.spf?.status || "-";

    const dmarcStatus =
        authentication.dmarc?.status || "-";

    const dkimPresent =
        Boolean(
            authentication.dkim_signature_present
        );


    setText(
        "spfStatus",
        spfStatus
    );

    setText(
        "dmarcStatus",
        dmarcStatus
    );

    setText(
        "dkimStatus",
        dkimPresent
            ? "PRESENT"
            : "NOT PRESENT"
    );


    // Authentication colors
    updateAuthStatus(
        "spfStatus",
        spfStatus
    );

    updateAuthStatus(
        "dmarcStatus",
        dmarcStatus
    );

    updateAuthStatus(
        "dkimStatus",
        dkimPresent
            ? "PRESENT"
            : "NOT PRESENT"
    );


    // =======================================================
    // HEADER / DOMAIN ANALYSIS
    // =======================================================

    const headerAnalysis =
        analysis.header_analysis || {};

    const senderDomain =
        headerAnalysis.sender_domain || "-";

    const replyDomain =
        headerAnalysis.reply_to_domain || "-";

    const returnDomain =
        headerAnalysis.return_path_domain || "-";


    setText(
        "senderDomain",
        senderDomain
    );

    setText(
        "replyDomain",
        replyDomain
    );

    setText(
        "returnDomain",
        returnDomain
    );


    // =======================================================
    // DOMAIN MISMATCH DETECTION
    // =======================================================

    const riskFlags =
        Array.isArray(headerAnalysis.risk_flags)
            ? headerAnalysis.risk_flags
            : [];


    const replyMismatch =
        riskFlags.includes(
            "reply_to_domain_mismatch"
        );


    const returnMismatch =
        riskFlags.includes(
            "return_path_domain_mismatch"
        );


    // Reply-To
    createDomainStatus(
        "replyDomain",
        "replyDomainStatus",
        replyMismatch,
        replyMismatch
            ? "⚠ MISMATCH"
            : "✓ MATCH"
    );


    // Return-Path
    createDomainStatus(
        "returnDomain",
        "returnDomainStatus",
        returnMismatch,
        returnMismatch
            ? "⚠ MISMATCH"
            : "✓ MATCH"
    );


    // Sender
    createSenderDomainStatus(
        "senderDomain",
        senderDomain
    );


    // =======================================================
    // SUSPICIOUS KEYWORDS
    // =======================================================

    renderKeywords(
        analysis.suspicious_keywords || []
    );


    // =======================================================
    // FORENSIC SUMMARY
    // =======================================================

    renderSummary(
        analysis.forensic_summary || []
    );


    // =======================================================
    // URL ANALYSIS
    // =======================================================

    renderUrls(
        analysis.url_analysis || []
    );


    // =======================================================
    // IP ANALYSIS
    // =======================================================

    renderIps(
        analysis.ip_analysis || []
    );


    // =======================================================
    // FORENSIC INDICATORS
    // =======================================================

    renderIndicators(
        analysis.forensic_indicators || [],
        analysis.forensic_indicator_count
    );


    // =======================================================
    // RECOMMENDATION
    // =======================================================

    setText(
        "recommendation",
        analysis.recommendation || "-"
    );


    // =======================================================
    // SHOW RESULT
    // =======================================================

    if (resultExists()) {

        document.getElementById(
            "result"
        ).style.display = "block";
    }
}


// =========================================================
// ELEMENT EXISTENCE
// =========================================================

function resultExists() {

    return Boolean(
        document.getElementById("result")
    );
}


// =========================================================
// SET TEXT HELPER
// =========================================================

function setText(
    elementId,
    value
) {

    const element =
        document.getElementById(
            elementId
        );

    if (!element) {
        return;
    }

    element.textContent =
        value ?? "-";
}


// =========================================================
// THREAT LEVEL STYLE
// =========================================================

function updateThreatLevel(
    level
) {

    const element =
        document.getElementById(
            "threatLevel"
        );

    if (!element) {
        return;
    }

    element.classList.remove(
        "threat-low",
        "threat-medium",
        "threat-high"
    );


    const normalized =
        String(level || "")
            .trim()
            .toUpperCase();


    if (normalized === "HIGH") {

        element.classList.add(
            "threat-high"
        );

    }

    else if (normalized === "MEDIUM") {

        element.classList.add(
            "threat-medium"
        );

    }

    else if (normalized === "LOW") {

        element.classList.add(
            "threat-low"
        );
    }
}


// =========================================================
// AUTHENTICATION STATUS STYLE
// =========================================================

function updateAuthStatus(
    elementId,
    status
) {

    const element =
        document.getElementById(
            elementId
        );

    if (!element) {
        return;
    }


    element.classList.remove(
        "auth-pass",
        "auth-fail",
        "auth-error",
        "auth-present"
    );


    const normalized =
        String(status || "")
            .trim()
            .toUpperCase();


    if (normalized === "PASS") {

        element.classList.add(
            "auth-pass"
        );
    }

    else if (normalized === "PRESENT") {

        element.classList.add(
            "auth-present"
        );
    }

    else if (normalized === "FAIL") {

        element.classList.add(
            "auth-fail"
        );
    }

    else {

        element.classList.add(
            "auth-error"
        );
    }
}


// =========================================================
// CREATE DOMAIN STATUS
// =========================================================

function createDomainStatus(
    domainElementId,
    statusId,
    isMismatch,
    text
) {

    const domainElement =
        document.getElementById(
            domainElementId
        );

    if (!domainElement) {
        return;
    }


    let statusElement =
        document.getElementById(
            statusId
        );


    // Create only once
    if (!statusElement) {

        statusElement =
            document.createElement(
                "span"
            );

        statusElement.id =
            statusId;

        statusElement.className =
            "domain-status";


        // Put status beside domain
        if (domainElement.parentNode) {

            domainElement.parentNode.appendChild(
                statusElement
            );
        }
    }


    statusElement.textContent =
        text;


    statusElement.classList.remove(
        "domain-status-warning",
        "domain-status-safe"
    );


    if (isMismatch) {

        statusElement.classList.add(
            "domain-status-warning"
        );

    }

    else {

        statusElement.classList.add(
            "domain-status-safe"
        );
    }
}


// =========================================================
// SENDER DOMAIN STATUS
// =========================================================

function createSenderDomainStatus(
    domainElementId,
    domain
) {

    const domainElement =
        document.getElementById(
            domainElementId
        );

    if (!domainElement) {
        return;
    }


    let statusElement =
        document.getElementById(
            "senderDomainStatus"
        );


    if (!statusElement) {

        statusElement =
            document.createElement(
                "span"
            );

        statusElement.id =
            "senderDomainStatus";

        statusElement.className =
            "domain-status";


        if (domainElement.parentNode) {

            domainElement.parentNode.appendChild(
                statusElement
            );
        }
    }


    if (
        !domain ||
        domain === "-"
    ) {

        statusElement.textContent =
            "";

        return;
    }


    statusElement.textContent =
        "✓ SENDER";


    statusElement.classList.remove(
        "domain-status-warning",
        "domain-status-safe"
    );

    statusElement.classList.add(
        "domain-status-safe"
    );
}


// =========================================================
// SUSPICIOUS KEYWORDS
// =========================================================

function renderKeywords(
    keywords
) {

    const container =
        document.getElementById(
            "keywords"
        );

    if (!container) {
        return;
    }


    container.innerHTML = "";


    if (
        !Array.isArray(keywords) ||
        keywords.length === 0
    ) {

        container.innerHTML =
            '<span class="empty-state">' +
            'No suspicious keywords detected' +
            '</span>';

        return;
    }


    keywords.forEach(
        keyword => {

            const tag =
                document.createElement(
                    "span"
                );

            tag.className =
                "keyword-tag";

            tag.textContent =
                String(keyword);

            container.appendChild(
                tag
            );
        }
    );
}


// =========================================================
// FORENSIC SUMMARY
// =========================================================

function renderSummary(
    summary
) {

    const container =
        document.getElementById(
            "summary"
        );

    if (!container) {
        return;
    }


    container.innerHTML = "";


    if (
        !Array.isArray(summary) ||
        summary.length === 0
    ) {

        const li =
            document.createElement(
                "li"
            );

        li.textContent =
            "No major indicators detected.";

        container.appendChild(
            li
        );

        return;
    }


    summary.forEach(
        item => {

            const li =
                document.createElement(
                    "li"
                );

            li.textContent =
                String(item);

            container.appendChild(
                li
            );
        }
    );
}


// =========================================================
// URL ANALYSIS
// =========================================================

function renderUrls(
    urls
) {

    const container =
        document.getElementById(
            "urlAnalysis"
        );

    if (!container) {
        return;
    }


    container.innerHTML = "";


    if (
        !Array.isArray(urls) ||
        urls.length === 0
    ) {

        container.innerHTML =
            '<span class="empty-state">' +
            'No URLs detected' +
            '</span>';

        return;
    }


    urls.forEach(
        item => {

            const row =
                document.createElement(
                    "div"
                );

            row.className =
                "network-item";


            // Left side
            const wrapper =
                document.createElement(
                    "div"
                );


            const strong =
                document.createElement(
                    "strong"
                );

            strong.textContent =
                item.url || "-";


            const small =
                document.createElement(
                    "small"
                );

            small.textContent =
                item.hostname || "";


            wrapper.appendChild(
                strong
            );

            wrapper.appendChild(
                small
            );


            // Risk
            const risk =
                document.createElement(
                    "span"
                );


            const riskScore =
                Number(
                    item.url_risk_score ?? 0
                );


            risk.textContent =
                "Risk: " + riskScore;


            if (riskScore >= 3) {

                risk.classList.add(
                    "risk-high"
                );

            }

            else if (riskScore > 0) {

                risk.classList.add(
                    "risk-medium"
                );

            }

            else {

                risk.classList.add(
                    "risk-low"
                );
            }


            row.appendChild(
                wrapper
            );

            row.appendChild(
                risk
            );


            container.appendChild(
                row
            );
        }
    );
}


// =========================================================
// IP ANALYSIS
// =========================================================

function renderIps(
    ips
) {

    const container =
        document.getElementById(
            "ipAnalysis"
        );

    if (!container) {
        return;
    }


    container.innerHTML = "";


    if (
        !Array.isArray(ips) ||
        ips.length === 0
    ) {

        container.innerHTML =
            '<span class="empty-state">' +
            'No IP addresses detected' +
            '</span>';

        return;
    }


    ips.forEach(
        item => {

            const row =
                document.createElement(
                    "div"
                );

            row.className =
                "network-item";


            const wrapper =
                document.createElement(
                    "div"
                );


            const strong =
                document.createElement(
                    "strong"
                );

            strong.textContent =
                item.ip || "-";


            const small =
                document.createElement(
                    "small"
                );


            const geo =
                item.geolocation || {};


            let location = "";


            if (
                geo.status === "success"
            ) {

                const city =
                    geo.city || "";

                const country =
                    geo.country || "";


                if (
                    city &&
                    country
                ) {

                    location =
                        city +
                        ", " +
                        country;

                }

                else {

                    location =
                        city ||
                        country;
                }
            }


            small.textContent =
                "Type: " +
                (
                    item.ip_type ||
                    "-"
                ) +
                (
                    location
                        ? " • " + location
                        : ""
                );


            wrapper.appendChild(
                strong
            );

            wrapper.appendChild(
                small
            );


            row.appendChild(
                wrapper
            );


            container.appendChild(
                row
            );
        }
    );
}


// =========================================================
// FORENSIC INDICATORS
// =========================================================

function renderIndicators(
    indicators,
    indicatorCount
) {

    const container =
        document.getElementById(
            "indicators"
        );

    if (!container) {
        return;
    }


    container.innerHTML = "";


    const safeIndicators =
        Array.isArray(indicators)
            ? indicators
            : [];


    const count =
        indicatorCount ??
        safeIndicators.length;


    setText(
        "indicatorCount",
        count
    );


    if (
        safeIndicators.length === 0
    ) {

        container.innerHTML =
            '<span class="empty-state">' +
            'No forensic indicators detected' +
            '</span>';

        return;
    }


    safeIndicators.forEach(
        indicator => {

            const row =
                document.createElement(
                    "div"
                );

            row.className =
                "indicator-item";


            // -------------------------------------------------
            // CONTENT
            // -------------------------------------------------

            const type =
                document.createElement(
                    "strong"
                );

            type.className =
                "indicator-type";

            type.textContent =
                indicator.type || "-";


            const value =
                document.createElement(
                    "span"
                );

            value.className =
                "indicator-value";

            value.textContent =
                indicator.value || "-";


            // -------------------------------------------------
            // FLAGS
            // -------------------------------------------------

            const flags =
                document.createElement(
                    "small"
                );

            if (
                Array.isArray(
                    indicator.flags
                ) &&
                indicator.flags.length > 0
            ) {

                const flags =
                    "indicator-flags";

                flags.textContent =
                    indicator.flags.join(
                        ", "
                    );

            }

            else {

                flags.className =
                    "indicator-flags indicator-flags-empty";

                flags.textContent =
                    "-";

            }


            // -------------------------------------------------
            // SEVERITY
            // -------------------------------------------------

            const severity =
                document.createElement(
                    "b"
                );


            const severityValue =
                String(
                    indicator.severity ||
                    "INFO"
                ).toUpperCase();


            severity.textContent =
                severityValue;


            severity.className =
                "indicator-severity " +
                getSeverityClass(
                    severityValue
                );


            // -------------------------------------------------
            // APPEND
            // -------------------------------------------------

            row.appendChild(
                type
            );

            row.appendChild(
                value
            );

            row.appendChild(
                flags
            );

            row.appendChild(
                severity
            );


            container.appendChild(
                row
            );
        }
    );
}


// =========================================================
// SEVERITY CLASS
// =========================================================

function getSeverityClass(
    severity
) {

    switch (
        String(severity)
            .toUpperCase()
    ) {

        case "HIGH":
            return "severity-high";

        case "MEDIUM":
            return "severity-medium";

        case "LOW":
            return "severity-low";

        default:
            return "severity-info";
    }
}


// =========================================================
// FILE SELECT
// =========================================================

const emailFile =
    document.getElementById(
        "emailFile"
    );


if (emailFile) {

    emailFile.addEventListener(
        "change",
        function () {

            const file =
                this.files[0];


            const selectedFile =
                document.getElementById(
                    "selectedFile"
                );


            if (!selectedFile) {
                return;
            }


            if (file) {

                selectedFile.textContent =
                    "Selected: " +
                    file.name;

            }

            else {

                selectedFile.textContent =
                    "";
            }
        }
    );
}


// =========================================================
// RESET ANALYSIS
// =========================================================

function resetAnalysis() {

    const fileInput =
        document.getElementById(
            "emailFile"
        );


    if (fileInput) {

        fileInput.value =
            "";
    }


    const selectedFile =
        document.getElementById(
            "selectedFile"
        );


    if (selectedFile) {

        selectedFile.textContent =
            "";
    }


    const error =
        document.getElementById(
            "error"
        );


    if (error) {

        error.textContent =
            "";
    }


    const result =
        document.getElementById(
            "result"
        );


    if (result) {

        result.style.display =
            "none";
    }


    const loading =
        document.getElementById(
            "loading"
        );


    if (loading) {

        loading.style.display =
            "none";
    }


    // Remove dynamic status elements
    removeDynamicStatus(
        "replyDomainStatus"
    );

    removeDynamicStatus(
        "returnDomainStatus"
    );

    removeDynamicStatus(
        "senderDomainStatus"
    );


    window.scrollTo({
        top: 0,
        behavior: "smooth"
    });
}


// =========================================================
// REMOVE DYNAMIC STATUS
// =========================================================

function removeDynamicStatus(
    id
) {

    const element =
        document.getElementById(
            id
        );


    if (element) {

        element.remove();
    }
}


// =========================================================
// HTML ESCAPE
// =========================================================

function escapeHtml(
    value
) {

    const div =
        document.createElement(
            "div"
        );


    div.textContent =
        value ?? "";


    return div.innerHTML;
}


// =========================================================
// PAGE LOAD CHECK
// =========================================================

document.addEventListener(
    "DOMContentLoaded",
    function () {

        console.log(
            "Email Threat Intelligence frontend loaded."
        );

        console.log(
            "Backend API:",
            API_URL
        );
    }
);