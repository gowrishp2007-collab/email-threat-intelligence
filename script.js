const API_URL = "https://email-threat-intelligence-api.onrender.com/api/analyze-email";
let selectedEmailFile = null;


// ============================================================
// FILE SELECT
// ============================================================

document.addEventListener("DOMContentLoaded", () => {

    const fileInput = document.getElementById("emailFile");
    const dropZone = document.getElementById("dropZone");

    if (fileInput) {
        fileInput.addEventListener("change", handleFileSelect);
    }

    if (dropZone) {

        dropZone.addEventListener("dragover", (event) => {
            event.preventDefault();
            dropZone.classList.add("dragging");
        });

        dropZone.addEventListener("dragleave", () => {
            dropZone.classList.remove("dragging");
        });

        dropZone.addEventListener("drop", (event) => {

            event.preventDefault();

            dropZone.classList.remove("dragging");

            const files = event.dataTransfer.files;

            if (files.length > 0) {
                selectedEmailFile = files[0];
                showSelectedFile(selectedEmailFile);
            }
        });
    }

    // Initial state
    hideElement("loading");
    hideElement("error");
    hideElement("result");
});


// ============================================================
// FILE SELECTION
// ============================================================

function handleFileSelect(event) {

    const file = event.target.files[0];

    if (!file) {
        return;
    }

    selectedEmailFile = file;

    showSelectedFile(file);
}


function showSelectedFile(file) {

    const selectedFile = document.getElementById("selectedFile");

    if (!selectedFile) {
        return;
    }

    selectedFile.textContent =
        `Selected: ${file.name}`;

    selectedFile.style.display = "block";
}


// ============================================================
// MAIN ANALYZE FUNCTION
// ============================================================

async function analyzeEmail() {

    clearError();

    const sender = document
        .getElementById("textSender")
        ?.value
        .trim();

    const receiver = document
        .getElementById("textReceiver")
        ?.value
        .trim();

    const subject = document
        .getElementById("textSubject")
        ?.value
        .trim();

    const replyTo = document
        .getElementById("textReplyTo")
        ?.value
        .trim();

    const returnPath = document
        .getElementById("textReturnPath")
        ?.value
        .trim();

    const body = document
        .getElementById("textBody")
        ?.value
        .trim();


    // ========================================================
    // VALIDATE INPUT
    // ========================================================

    if (
        !selectedEmailFile &&
        !sender &&
        !subject &&
        !body
    ) {

        showError(
            "Please paste an email or upload an .eml file."
        );

        return;
    }


    showLoading();


    try {

        let emailData;

        // ====================================================
        // EML FILE ANALYSIS
        // ====================================================

        if (selectedEmailFile) {

            const fileText =
                await selectedEmailFile.text();

            emailData =
                parseEMLFile(fileText);

        }

        // ====================================================
        // TEXT INPUT ANALYSIS
        // ====================================================

        else {

            emailData = {

                sender: sender || "",

                receiver: receiver || "",

                subject: subject || "",

                body: body || "",

                reply_to: replyTo || null,

                return_path: returnPath || null,

                received_hops: 0,

                attachment_count: 0
            };
        }


        // ====================================================
        // SEND TO FASTAPI
        // ====================================================

        const response = await fetch(
            API_URL,
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({

                    sender: emailData.sender,

                    subject: emailData.subject,

                    body: emailData.body,

                    reply_to: emailData.reply_to,

                    return_path: emailData.return_path
                })
            }
        );


        if (!response.ok) {

            const errorText =
                await response.text();

            throw new Error(
                `Backend error ${response.status}: ${errorText}`
            );
        }


        const result =
            await response.json();


        // ====================================================
        // DISPLAY EVERYTHING
        // ====================================================

        displayResults(
            result,
            emailData
        );


        hideLoading();

        showElement("result");


        // Scroll automatically to result
        document
            .getElementById("result")
            ?.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });

    }

    catch (error) {

        console.error(error);

        hideLoading();

        showError(
            "Unable to analyze email. Make sure FastAPI server is running at 127.0.0.1:8000."
        );
    }
}


// ============================================================
// EML PARSER
// ============================================================

function parseEMLFile(content) {

    const separator =
        content.includes("\r\n\r\n")
            ? "\r\n\r\n"
            : "\n\n";

    const parts =
        content.split(separator);

    const headerText =
        parts.shift() || "";

    const body =
        parts.join(separator).trim();


    // --------------------------------------------------------
    // Handle folded email headers
    // --------------------------------------------------------

    const unfoldedHeaders =
        headerText.replace(
            /\r?\n[ \t]+/g,
            " "
        );


    const headers = {};


    unfoldedHeaders
        .split(/\r?\n/)
        .forEach(line => {

            const index =
                line.indexOf(":");

            if (index === -1) {
                return;
            }

            const key =
                line
                    .substring(0, index)
                    .trim()
                    .toLowerCase();

            const value =
                line
                    .substring(index + 1)
                    .trim();

            headers[key] = value;
        });


    // --------------------------------------------------------
    // Count Received headers
    // --------------------------------------------------------

    const receivedHops =
        (
            unfoldedHeaders.match(
                /^received\s*:/gim
            ) || []
        ).length;


    // --------------------------------------------------------
    // Count attachments
    // --------------------------------------------------------

    const attachmentCount =
        (
            content.match(
                /Content-Disposition:\s*attachment/gi
            ) || []
        ).length;


    return {

        sender:
            headers["from"] || "",

        receiver:
            headers["to"] || "",

        subject:
            headers["subject"] || "",

        reply_to:
            headers["reply-to"] || null,

        return_path:
            headers["return-path"] || null,

        body: body,

        received_hops:
            receivedHops,

        attachment_count:
            attachmentCount
    };
}


// ============================================================
// DISPLAY RESULTS
// ============================================================

function displayResults(
    data,
    emailData
) {

    // ========================================================
    // THREAT
    // ========================================================

    setText(
        "threatLevel",
        data.threat_level || "-"
    );

    setText(
        "threatScore",
        data.threat_score ?? 0
    );

    setText(
        "keywordCount",
        data.keyword_count ?? 0
    );


    // ========================================================
    // EMAIL METADATA
    // ========================================================

    setText(
        "sender",
        data.email_information?.sender
        || emailData.sender
        || "-"
    );

    setText(
        "receiver",
        emailData.receiver
        || "-"
    );

    setText(
        "subject",
        data.email_information?.subject
        || emailData.subject
        || "-"
    );

    setText(
        "replyTo",
        data.header_analysis?.reply_to
        || emailData.reply_to
        || "-"
    );

    setText(
        "returnPath",
        data.header_analysis?.return_path
        || emailData.return_path
        || "-"
    );


    // ========================================================
    // STATS
    // ========================================================

    setText(
        "hopCount",
        emailData.received_hops ?? 0
    );

    setText(
        "attachmentCount",
        emailData.attachment_count ?? 0
    );


    // ========================================================
    // AUTHENTICATION
    // ========================================================

    // SPF/DKIM/DMARC backend checks not added yet
    setText(
        "spfStatus",
        "NOT CHECKED"
    );

    setText(
        "dmarcStatus",
        "NOT CHECKED"
    );

    setText(
        "dkimStatus",
        "NOT CHECKED"
    );


    // ========================================================
    // HEADER FORENSICS
    // ========================================================

    const header =
        data.header_analysis || {};

    setText(
        "senderDomain",
        header.sender_domain || "-"
    );

    setText(
        "replyDomain",
        header.reply_to_domain || "-"
    );

    setText(
        "returnDomain",
        header.return_path_domain || "-"
    );


    // ========================================================
    // SUSPICIOUS KEYWORDS
    // ========================================================

    const keywordContainer =
        document.getElementById("keywords");

    if (keywordContainer) {

        keywordContainer.innerHTML = "";

        const keywords =
            data.suspicious_keywords || [];

        if (keywords.length === 0) {

            keywordContainer.innerHTML =
                `<span class="empty-state">
                    No suspicious keywords detected
                </span>`;

        } else {

            keywords.forEach(keyword => {

                const tag =
                    document.createElement("span");

                tag.className = "tag";

                tag.textContent = keyword;

                keywordContainer.appendChild(tag);
            });
        }
    }


    // ========================================================
    // FORENSIC SUMMARY
    // ========================================================

    const summaryContainer =
        document.getElementById("summary");

    if (summaryContainer) {

        summaryContainer.innerHTML = "";

        const summary =
            data.forensic_analysis?.summary || [];

        if (summary.length === 0) {

            summaryContainer.innerHTML =
                "<li>No forensic summary available.</li>";

        } else {

            summary.forEach(item => {

                const li =
                    document.createElement("li");

                li.textContent = item;

                summaryContainer.appendChild(li);
            });
        }
    }


    // ========================================================
    // URL ANALYSIS
    // ========================================================

    const urlContainer =
        document.getElementById("urlAnalysis");

    if (urlContainer) {

        urlContainer.innerHTML = "";

        const urls =
            data.url_analysis || [];

        if (urls.length === 0) {

            urlContainer.innerHTML =
                `<span class="empty-state">
                    No URLs analyzed
                </span>`;

        } else {

            urls.forEach(item => {

                const div =
                    document.createElement("div");

                div.className =
                    "network-item";

                div.innerHTML = `
                    <strong>${escapeHTML(item.url)}</strong>
                    <br>
                    <small>
                        Host:
                        ${escapeHTML(item.hostname || "-")}
                    </small>
                    <br>
                    <small>
                        Risk Score:
                        ${item.url_risk_score ?? 0}
                    </small>
                    <br>
                    <small>
                        Flags:
                        ${escapeHTML(
                            (item.risk_flags || []).join(", ")
                            || "None"
                        )}
                    </small>
                `;

                urlContainer.appendChild(div);
            });
        }
    }


    // ========================================================
    // IP ANALYSIS
    // ========================================================

    const ipContainer =
        document.getElementById("ipAnalysis");

    if (ipContainer) {

        ipContainer.innerHTML = "";

        const ips =
            data.ip_analysis || [];

        if (ips.length === 0) {

            ipContainer.innerHTML =
                `<span class="empty-state">
                    No IP addresses detected
                </span>`;

        } else {

            ips.forEach(item => {

                const geo =
                    item.geolocation || {};

                const div =
                    document.createElement("div");

                div.className =
                    "network-item";

                let geoText =
                    "Geolocation unavailable";

                if (
                    geo.geolocation_available
                    === true
                ) {

                    geoText = `
                        ${escapeHTML(geo.country || "-")},
                        ${escapeHTML(geo.region || "-")},
                        ${escapeHTML(geo.city || "-")}
                        <br>
                        ISP:
                        ${escapeHTML(geo.isp || "-")}
                    `;
                }

                div.innerHTML = `
                    <strong>
                        ${escapeHTML(item.ip)}
                    </strong>

                    <br>

                    <small>
                        Type:
                        ${escapeHTML(item.ip_type || "-")}
                    </small>

                    <br>

                    <small>
                        ${geoText}
                    </small>
                `;

                ipContainer.appendChild(div);
            });
        }
    }


    // ========================================================
    // FORENSIC INDICATORS
    // ========================================================

    const indicatorContainer =
        document.getElementById("indicators");

    const indicatorCount =
        document.getElementById("indicatorCount");

    const indicators =
        data.forensic_analysis?.indicators || [];


    if (indicatorCount) {

        indicatorCount.textContent =
            indicators.length;
    }


    if (indicatorContainer) {

        indicatorContainer.innerHTML = "";

        if (indicators.length === 0) {

            indicatorContainer.innerHTML =
                `<span class="empty-state">
                    No forensic indicators detected
                </span>`;

        } else {

            indicators.forEach(item => {

                const div =
                    document.createElement("div");

                div.className =
                    "indicator-item";

                div.innerHTML = `
                    <strong>
                        ${escapeHTML(item.type || "UNKNOWN")}
                    </strong>

                    <span>
                        ${escapeHTML(item.indicator || "-")}
                    </span>

                    <small>
                        ${escapeHTML(item.severity || "-")}
                    </small>

                    <p>
                        ${escapeHTML(
                            item.description || "-"
                        )}
                    </p>
                `;

                indicatorContainer.appendChild(div);
            });
        }
    }


    // ========================================================
    // SECURITY RECOMMENDATION
    // ========================================================

    let recommendation =
        "No major suspicious indicators detected.";

    if (data.threat_level === "HIGH") {

        recommendation =
            "High-risk email detected. Do not click links or provide sensitive information. Investigate the forensic indicators before trusting this email.";

    } else if (
        data.threat_level === "MEDIUM"
    ) {

        recommendation =
            "Some suspicious indicators were detected. Verify the sender and email headers before taking action.";

    }

    setText(
        "recommendation",
        recommendation
    );
}


// ============================================================
// RESET
// ============================================================

function resetAnalysis() {

    selectedEmailFile = null;

    const fileInput =
        document.getElementById("emailFile");

    if (fileInput) {
        fileInput.value = "";
    }

    const selectedFile =
        document.getElementById("selectedFile");

    if (selectedFile) {

        selectedFile.textContent = "";

        selectedFile.style.display =
            "none";
    }


    [
        "textSender",
        "textReceiver",
        "textSubject",
        "textReplyTo",
        "textReturnPath",
        "textBody"
    ].forEach(id => {

        const element =
            document.getElementById(id);

        if (element) {
            element.value = "";
        }
    });


    hideElement("result");

    clearError();

    window.scrollTo({
        top: 0,
        behavior: "smooth"
    });
}


// ============================================================
// HELPERS
// ============================================================

function setText(
    id,
    value
) {

    const element =
        document.getElementById(id);

    if (element) {

        element.textContent =
            value ?? "-";
    }
}


function showElement(id) {

    const element =
        document.getElementById(id);

    if (element) {

        element.style.display =
            "block";
    }
}


function hideElement(id) {

    const element =
        document.getElementById(id);

    if (element) {

        element.style.display =
            "none";
    }
}


function showLoading() {

    hideElement("result");

    hideElement("error");

    showElement("loading");
}


function hideLoading() {

    hideElement("loading");
}


function showError(message) {

    const error =
        document.getElementById("error");

    if (!error) {
        return;
    }

    error.textContent = message;

    error.style.display =
        "block";
}


function clearError() {

    const error =
        document.getElementById("error");

    if (error) {

        error.textContent = "";

        error.style.display =
            "none";
    }
}


function escapeHTML(value) {

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
// ============================================================
// SIDEBAR NAVIGATION
// ============================================================

document.addEventListener("DOMContentLoaded", () => {

    const navItems = document.querySelectorAll(".nav-item");

    navItems.forEach((item, index) => {

        item.addEventListener("click", () => {

            // Remove active from all
            navItems.forEach(nav => {
                nav.classList.remove("active");
            });

            // Add active to clicked item
            item.classList.add("active");

            // Dashboard
            if (index === 0) {

                window.scrollTo({
                    top: 0,
                    behavior: "smooth"
                });
            }

            // Email Analysis
            else if (index === 1) {

                const uploadCard =
                    document.querySelector(".upload-card");

                if (uploadCard) {

                    uploadCard.scrollIntoView({
                        behavior: "smooth",
                        block: "start"
                    });
                }
            }

            // Forensics
            else if (index === 2) {

                const result =
                    document.getElementById("result");

                if (result) {

                    // If analysis is not done
                    if (
                        result.style.display === "none" ||
                        !result.style.display
                    ) {

                        const message =
                            document.getElementById("error");

                        if (message) {
                            message.textContent =
                                "Analyze an email first to view forensic results.";
                            message.style.display = "block";
                        }

                    } else {

                        result.scrollIntoView({
                            behavior: "smooth",
                            block: "start"
                        });
                    }
                }
            }

            // Settings
            else if (index === 3) {

                alert(
                    "Settings panel will be available soon."
                );
            }
        });
    });
});