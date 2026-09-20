from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from urllib.parse import urlparse
from email import policy
from email.parser import BytesParser

import re
import ipaddress
import json
from urllib.request import urlopen, Request

import dns.resolver


# =========================================================
# FASTAPI APP
# =========================================================

app = FastAPI(
    title="AI Email Threat Detection & Forensic Intelligence API",
    version="1.3.0"
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# REQUEST MODEL
# =========================================================

class EmailRequest(BaseModel):
    sender: str
    subject: str
    body: str
    reply_to: str | None = None
    return_path: str | None = None


# =========================================================
# SUSPICIOUS KEYWORDS
# =========================================================

SUSPICIOUS_KEYWORDS = [
    "urgent",
    "verify",
    "password",
    "login",
    "otp",
    "bank",
    "click here",
    "account suspended",
    "winner",
    "prize",
    "confirm",
    "security alert",
    "reset password"
]


# =========================================================
# HOME
# =========================================================

@app.get("/")
def home():
    return {
        "message": "AI Email Threat Detection API is running",
        "version": "1.3.0"
    }


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "email-threat-detection"
    }


# =========================================================
# EXTRACT URLS
# =========================================================

def extract_urls(text):

    if not text:
        return []

    pattern = r'https?://[^\s<>"\']+'

    urls = re.findall(pattern, text)

    return list(dict.fromkeys(urls))


# =========================================================
# EXTRACT IP ADDRESSES
# =========================================================

def extract_ip_addresses(text):

    if not text:
        return []

    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    possible_ips = re.findall(
        pattern,
        text
    )

    valid_ips = []

    for ip in possible_ips:

        try:
            ipaddress.ip_address(ip)

            if ip not in valid_ips:
                valid_ips.append(ip)

        except ValueError:
            pass

    return valid_ips


# =========================================================
# IP TYPE
# =========================================================

def get_ip_type(ip):

    try:

        address = ipaddress.ip_address(ip)

        if address.is_loopback:
            return "LOOPBACK"

        if address.is_private:
            return "PRIVATE"

        if address.is_reserved:
            return "RESERVED"

        if address.is_multicast:
            return "MULTICAST"

        if address.is_global:
            return "PUBLIC"

        return "OTHER"

    except ValueError:

        return "INVALID"


# =========================================================
# GEOLOCATION
# =========================================================

def geolocate_ip(ip):

    ip_type = get_ip_type(ip)

    if ip_type != "PUBLIC":

        return {
            "status": "not_available",
            "reason": f"{ip_type} IP address"
        }

    try:

        url = f"https://ipwho.is/{ip}"

        request = Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        with urlopen(
            request,
            timeout=5
        ) as response:

            data = json.loads(
                response.read().decode("utf-8")
            )

        if not data.get("success", False):

            return {
                "status": "failed",
                "message": data.get(
                    "message",
                    "Geolocation failed"
                )
            }

        timezone = data.get("timezone")

        connection = data.get("connection")

        if not isinstance(timezone, dict):
            timezone = {}

        if not isinstance(connection, dict):
            connection = {}

        return {

            "status": "success",

            "country":
                data.get("country"),

            "country_code":
                data.get("country_code"),

            "region":
                data.get("region"),

            "city":
                data.get("city"),

            "postal":
                data.get("postal"),

            "latitude":
                data.get("latitude"),

            "longitude":
                data.get("longitude"),

            "timezone":
                timezone.get("id"),

            "isp":
                connection.get("isp"),

            "organization":
                connection.get("org")
        }

    except Exception as e:

        return {
            "status": "failed",
            "message": str(e)
        }


# =========================================================
# URL ANALYSIS
# =========================================================

def analyze_url(url):

    risk_score = 0
    risk_flags = []

    try:

        parsed = urlparse(url)

        hostname = parsed.hostname or ""

        # HTTP
        if parsed.scheme.lower() == "http":

            risk_score += 1

            risk_flags.append(
                "uses_http"
            )

        # IP hostname
        try:

            ipaddress.ip_address(hostname)

            risk_score += 2

            risk_flags.append(
                "ip_based_hostname"
            )

        except ValueError:
            pass

        # @ symbol
        if "@" in url:

            risk_score += 2

            risk_flags.append(
                "contains_at_symbol"
            )

        # Suspicious URL words
        suspicious_url_words = [
            "login",
            "verify",
            "account",
            "password",
            "secure",
            "update",
            "confirm",
            "bank",
            "wallet",
            "signin"
        ]

        lower_url = url.lower()

        for word in suspicious_url_words:

            if word in lower_url:

                risk_score += 1

                risk_flags.append(
                    f"contains_{word}"
                )

        # Long URL
        if len(url) > 100:

            risk_score += 1

            risk_flags.append(
                "very_long_url"
            )

        # Many subdomains
        if hostname.count(".") >= 3:

            risk_score += 1

            risk_flags.append(
                "many_subdomains"
            )

        return {

            "url": url,

            "hostname": hostname,

            "scheme": parsed.scheme,

            "url_risk_score":
                risk_score,

            "risk_flags":
                risk_flags
        }

    except Exception as e:

        return {

            "url": url,

            "error": str(e),

            "url_risk_score": 0,

            "risk_flags": []
        }


# =========================================================
# SENDER ANALYSIS
# =========================================================

def analyze_sender(sender):

    risk_flags = []

    sender = sender or ""

    sender_lower = sender.lower()

    valid_email = bool(
        re.match(
            r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
            sender
        )
    )

    if not valid_email:

        risk_flags.append(
            "invalid_email_format"
        )

    suspicious_sender_words = [
        "security",
        "support",
        "admin",
        "verify",
        "account",
        "alert",
        "notification"
    ]

    for word in suspicious_sender_words:

        if word in sender_lower:

            risk_flags.append(
                f"contains_{word}"
            )

    if "@" in sender:

        username, domain = sender.rsplit(
            "@",
            1
        )

    else:

        username = sender
        domain = ""

    return {

        "sender": sender,

        "valid_format":
            valid_email,

        "username":
            username,

        "domain":
            domain,

        "risk_flags":
            risk_flags
    }


# =========================================================
# EXTRACT DOMAIN
# =========================================================

def extract_domain(email_address):

    if not email_address:
        return ""

    match = re.search(
        r"@([^>\s]+)",
        email_address
    )

    if match:

        return match.group(1).lower()

    return ""


# =========================================================
# HEADER ANALYSIS
# =========================================================

def analyze_email_headers(
    sender,
    reply_to=None,
    return_path=None
):

    indicators = []

    risk_score = 0

    sender_domain = extract_domain(
        sender
    )

    reply_domain = extract_domain(
        reply_to
    )

    return_domain = extract_domain(
        return_path
    )

    # Reply-To mismatch
    if (
        reply_domain
        and sender_domain
        and reply_domain != sender_domain
    ):

        indicators.append(
            "reply_to_domain_mismatch"
        )

        risk_score += 1

    # Return-Path mismatch
    if (
        return_domain
        and sender_domain
        and return_domain != sender_domain
    ):

        indicators.append(
            "return_path_domain_mismatch"
        )

        risk_score += 1

    return {

        "sender_domain":
            sender_domain,

        "reply_to_domain":
            reply_domain,

        "return_path_domain":
            return_domain,

        "header_risk_score":
            risk_score,

        "risk_flags":
            indicators
    }


# =========================================================
# SPF CHECK
# =========================================================

def check_spf(domain):

    if not domain:

        return {

            "spf_found": False,

            "spf_record": None,

            "status": "ERROR",

            "message":
                "Domain not available"
        }

    try:

        answers = dns.resolver.resolve(
            domain,
            "TXT",
            lifetime=5
        )

        spf_records = []

        for answer in answers:

            try:

                text = b"".join(
                    answer.strings
                ).decode(
                    "utf-8",
                    errors="ignore"
                )

            except Exception:

                text = str(answer)

            if text.lower().startswith(
                "v=spf1"
            ):

                spf_records.append(
                    text
                )

        if spf_records:

            return {

                "spf_found": True,

                "spf_record":
                    spf_records[0],

                "status": "PASS"
            }

        return {

            "spf_found": False,

            "spf_record": None,

            "status": "FAIL",

            "message":
                "No SPF record found"
        }

    except Exception as e:

        return {

            "spf_found": False,

            "spf_record": None,

            "status": "ERROR",

            "message": str(e)
        }


# =========================================================
# DMARC CHECK
# =========================================================

def check_dmarc(domain):

    if not domain:

        return {

            "dmarc_found": False,

            "dmarc_record": None,

            "status": "ERROR",

            "message":
                "Domain not available"
        }

    dmarc_domain = (
        f"_dmarc.{domain}"
    )

    try:

        answers = dns.resolver.resolve(
            dmarc_domain,
            "TXT",
            lifetime=5
        )

        dmarc_records = []

        for answer in answers:

            try:

                text = b"".join(
                    answer.strings
                ).decode(
                    "utf-8",
                    errors="ignore"
                )

            except Exception:

                text = str(answer)

            if text.lower().startswith(
                "v=dmarc1"
            ):

                dmarc_records.append(
                    text
                )

        if dmarc_records:

            return {

                "dmarc_found": True,

                "dmarc_record":
                    dmarc_records[0],

                "status": "PASS"
            }

        return {

            "dmarc_found": False,

            "dmarc_record": None,

            "status": "FAIL",

            "message":
                "No DMARC record found"
        }

    except Exception as e:

        return {

            "dmarc_found": False,

            "dmarc_record": None,

            "status": "ERROR",

            "message": str(e)
        }


# =========================================================
# EML FILE PARSER
# =========================================================

def parse_eml_file(file_bytes):

    message = BytesParser(
        policy=policy.default
    ).parsebytes(file_bytes)

    sender = message.get(
        "From",
        ""
    )

    receiver = message.get(
        "To",
        ""
    )

    subject = message.get(
        "Subject",
        ""
    )

    reply_to = message.get(
        "Reply-To"
    )

    return_path = message.get(
        "Return-Path"
    )

    received_headers = (
        message.get_all(
            "Received",
            []
        )
    )

    authentication_results = (
        message.get_all(
            "Authentication-Results",
            []
        )
    )

    dkim_signatures = (
        message.get_all(
            "DKIM-Signature",
            []
        )
    )

    # -----------------------------------------------------
    # BODY
    # -----------------------------------------------------

    plain_body = ""

    html_body = ""

    if message.is_multipart():

        for part in message.walk():

            content_type = (
                part.get_content_type()
            )

            disposition = (
                part.get_content_disposition()
            )

            if disposition == "attachment":
                continue

            if content_type == "text/plain":

                try:

                    plain_body += (
                        part.get_content()
                    )

                except Exception:
                    pass

            elif content_type == "text/html":

                try:

                    html_body += (
                        part.get_content()
                    )

                except Exception:
                    pass

    else:

        try:

            content_type = (
                message.get_content_type()
            )

            if content_type == "text/html":

                html_body = (
                    message.get_content()
                )

            else:

                plain_body = (
                    message.get_content()
                )

        except Exception:
            pass

    body = plain_body

    if not body.strip():

        body = html_body

    # -----------------------------------------------------
    # ATTACHMENTS
    # -----------------------------------------------------

    attachments = []

    for part in message.iter_attachments():

        filename = part.get_filename()

        content_type = (
            part.get_content_type()
        )

        try:

            payload = part.get_payload(
                decode=True
            )

            size = (
                len(payload)
                if payload
                else 0
            )

        except Exception:

            size = 0

        attachments.append({

            "filename":
                filename,

            "content_type":
                content_type,

            "size_bytes":
                size
        })

    return {

        "sender":
            sender,

        "receiver":
            receiver,

        "subject":
            subject,

        "reply_to":
            reply_to,

        "return_path":
            return_path,

        "body":
            body,

        "received_headers":
            received_headers,

        "authentication_results":
            authentication_results,

        "dkim_signature_present":
            len(dkim_signatures) > 0,

        "attachments":
            attachments
    }


# =========================================================
# RECEIVED HEADER ANALYSIS
# =========================================================

def analyze_received_headers(
    received_headers
):

    extracted_ips = []

    for header in received_headers:

        ips = extract_ip_addresses(
            header
        )

        for ip in ips:

            if ip not in extracted_ips:

                extracted_ips.append(ip)

    server_chain = []

    for index, header in enumerate(
        received_headers,
        start=1
    ):

        server_chain.append({

            "hop":
                index,

            "received_header":
                header
        })

    return {

        "hop_count":
            len(received_headers),

        "extracted_ips":
            extracted_ips,

        "server_chain":
            server_chain
    }


# =========================================================
# ATTACHMENT ANALYSIS
# =========================================================

def analyze_attachments(
    attachments
):

    suspicious_extensions = [

        ".exe",
        ".bat",
        ".cmd",
        ".scr",
        ".js",
        ".vbs",
        ".ps1",
        ".jar",
        ".msi",
        ".dll"
    ]

    results = []

    risk_score = 0

    for attachment in attachments:

        filename = (
            attachment.get(
                "filename"
            )
            or ""
        )

        lower_filename = (
            filename.lower()
        )

        flags = []

        for extension in (
            suspicious_extensions
        ):

            if lower_filename.endswith(
                extension
            ):

                flags.append(
                    f"suspicious_extension_{extension}"
                )

                risk_score += 2

        results.append({

            "filename":
                filename,

            "content_type":
                attachment.get(
                    "content_type"
                ),

            "size_bytes":
                attachment.get(
                    "size_bytes",
                    0
                ),

            "risk_flags":
                flags
        })

    return {

        "attachment_count":
            len(attachments),

        "attachment_risk_score":
            risk_score,

        "attachments":
            results
    }


# =========================================================
# FORENSIC INDICATORS
# =========================================================

def build_forensic_indicators(
    found_keywords,
    url_analysis,
    ip_analysis,
    sender_analysis,
    header_analysis,
    spf_analysis,
    dmarc_analysis,
    attachment_analysis
):

    indicators = []

    # Keywords
    for keyword in found_keywords:

        indicators.append({

            "type":
                "suspicious_keyword",

            "value":
                keyword,

            "severity":
                "MEDIUM"
        })

    # URLs
    for item in url_analysis:

        if item["url_risk_score"] > 0:

            indicators.append({

                "type":
                    "suspicious_url",

                "value":
                    item["url"],

                "severity":
                    (
                        "HIGH"
                        if item["url_risk_score"] >= 3
                        else "MEDIUM"
                    ),

                "flags":
                    item["risk_flags"]
            })

    # IP
    for item in ip_analysis:

        if item["ip_type"] == "PUBLIC":

            indicators.append({

                "type":
                    "public_ip",

                "value":
                    item["ip"],

                "severity":
                    "INFO"
            })

    # Sender
    for flag in sender_analysis[
        "risk_flags"
    ]:

        indicators.append({

            "type":
                "sender",

            "value":
                flag,

            "severity":
                "MEDIUM"
        })

    # Headers
    for flag in header_analysis[
        "risk_flags"
    ]:

        indicators.append({

            "type":
                "header",

            "value":
                flag,

            "severity":
                "HIGH"
        })

    # SPF
    if spf_analysis[
        "status"
    ] == "FAIL":

        indicators.append({

            "type":
                "spf",

            "value":
                "SPF record not found",

            "severity":
                "MEDIUM"
        })

    # DMARC
    if dmarc_analysis[
        "status"
    ] == "FAIL":

        indicators.append({

            "type":
                "dmarc",

            "value":
                "DMARC record not found",

            "severity":
                "MEDIUM"
        })

    # Attachments
    for attachment in (
        attachment_analysis[
            "attachments"
        ]
    ):

        for flag in attachment[
            "risk_flags"
        ]:

            indicators.append({

                "type":
                    "attachment",

                "value":
                    flag,

                "severity":
                    "HIGH"
            })

    return indicators


# =========================================================
# FORENSIC SUMMARY
# =========================================================

def generate_forensic_summary(
    found_keywords,
    url_analysis,
    ip_analysis,
    sender_analysis,
    header_analysis,
    spf_analysis,
    dmarc_analysis,
    attachment_analysis
):

    summary = []

    if found_keywords:

        summary.append(
            f"Detected "
            f"{len(found_keywords)} "
            f"suspicious keyword(s)."
        )

    suspicious_urls = [

        item
        for item in url_analysis
        if item["url_risk_score"] > 0
    ]

    if suspicious_urls:

        summary.append(
            f"Detected "
            f"{len(suspicious_urls)} "
            f"suspicious URL(s)."
        )

    public_ips = [

        item
        for item in ip_analysis
        if item["ip_type"] == "PUBLIC"
    ]

    if public_ips:

        summary.append(
            f"Detected "
            f"{len(public_ips)} "
            f"public IP address(es)."
        )

    if sender_analysis[
        "risk_flags"
    ]:

        summary.append(
            "Sender contains suspicious "
            "characteristics."
        )

    if header_analysis[
        "risk_flags"
    ]:

        summary.append(
            "Email header domain mismatch "
            "detected."
        )

    if spf_analysis[
        "status"
    ] == "FAIL":

        summary.append(
            "SPF record was not found."
        )

    if dmarc_analysis[
        "status"
    ] == "FAIL":

        summary.append(
            "DMARC record was not found."
        )

    if attachment_analysis[
        "attachment_risk_score"
    ] > 0:

        summary.append(
            "Potentially dangerous "
            "attachment type detected."
        )

    if not summary:

        summary.append(
            "No major suspicious indicators "
            "were detected."
        )

    return summary


# =========================================================
# COMMON EMAIL ANALYSIS ENGINE
# =========================================================

def analyze_email_data(
    sender,
    subject,
    body,
    reply_to=None,
    return_path=None,
    received_headers=None,
    attachments=None,
    authentication_results=None,
    dkim_signature_present=False
):

    received_headers = (
        received_headers or []
    )

    attachments = (
        attachments or []
    )

    authentication_results = (
        authentication_results or []
    )

    # -----------------------------------------------------
    # KEYWORDS
    # -----------------------------------------------------

    combined_text = (
        f"{subject} {body}"
    ).lower()

    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword.lower() in combined_text:

            found_keywords.append(
                keyword
            )

    # -----------------------------------------------------
    # URLS
    # -----------------------------------------------------

    urls = extract_urls(
        f"{subject} {body}"
    )

    url_analysis = [

        analyze_url(url)

        for url in urls
    ]

    # -----------------------------------------------------
    # IPS
    # -----------------------------------------------------

    all_text = (
        f"{subject}\n"
        f"{body}\n"
        f"{' '.join(received_headers)}"
    )

    ip_addresses = (
        extract_ip_addresses(
            all_text
        )
    )

    ip_analysis = []

    for ip in ip_addresses:

        ip_type = get_ip_type(
            ip
        )

        geolocation = geolocate_ip(
            ip
        )

        ip_analysis.append({

            "ip":
                ip,

            "ip_type":
                ip_type,

            "geolocation":
                geolocation
        })

    # -----------------------------------------------------
    # SENDER
    # -----------------------------------------------------

    sender_analysis = analyze_sender(
        sender
    )

    # -----------------------------------------------------
    # HEADERS
    # -----------------------------------------------------

    header_analysis = (
        analyze_email_headers(
            sender,
            reply_to,
            return_path
        )
    )

    # -----------------------------------------------------
    # RECEIVED HEADERS
    # -----------------------------------------------------

    received_analysis = (
        analyze_received_headers(
            received_headers
        )
    )

    # -----------------------------------------------------
    # ATTACHMENTS
    # -----------------------------------------------------

    attachment_analysis = (
        analyze_attachments(
            attachments
        )
    )

    # -----------------------------------------------------
    # DOMAIN
    # -----------------------------------------------------

    sender_domain = extract_domain(
        sender
    )

    # -----------------------------------------------------
    # SPF
    # -----------------------------------------------------

    spf_analysis = check_spf(
        sender_domain
    )

    # -----------------------------------------------------
    # DMARC
    # -----------------------------------------------------

    dmarc_analysis = check_dmarc(
        sender_domain
    )

    # -----------------------------------------------------
    # SCORING
    # -----------------------------------------------------

    keyword_score = len(
        found_keywords
    )

    url_score = sum(
        item["url_risk_score"]
        for item in url_analysis
    )

    ip_score = sum(

        1

        for item in ip_analysis

        if item["ip_type"] == "PUBLIC"
    )

    sender_score = len(
        sender_analysis[
            "risk_flags"
        ]
    )

    header_score = (
        header_analysis[
            "header_risk_score"
        ]
    )

    spf_score = (

        1

        if spf_analysis[
            "status"
        ] == "FAIL"

        else 0
    )

    dmarc_score = (

        1

        if dmarc_analysis[
            "status"
        ] == "FAIL"

        else 0
    )

    attachment_score = (
        attachment_analysis[
            "attachment_risk_score"
        ]
    )

    total_score = (

        keyword_score
        + url_score
        + ip_score
        + sender_score
        + header_score
        + spf_score
        + dmarc_score
        + attachment_score
    )

    # -----------------------------------------------------
    # THREAT LEVEL
    # -----------------------------------------------------

    if total_score >= 5:

        threat_level = "HIGH"

    elif total_score >= 1:

        threat_level = "MEDIUM"

    else:

        threat_level = "LOW"

    # -----------------------------------------------------
    # FORENSIC INDICATORS
    # -----------------------------------------------------

    forensic_indicators = (
        build_forensic_indicators(

            found_keywords,

            url_analysis,

            ip_analysis,

            sender_analysis,

            header_analysis,

            spf_analysis,

            dmarc_analysis,

            attachment_analysis
        )
    )

    # -----------------------------------------------------
    # FORENSIC SUMMARY
    # -----------------------------------------------------

    forensic_summary = (
        generate_forensic_summary(

            found_keywords,

            url_analysis,

            ip_analysis,

            sender_analysis,

            header_analysis,

            spf_analysis,

            dmarc_analysis,

            attachment_analysis
        )
    )

    # -----------------------------------------------------
    # RECOMMENDATION
    # -----------------------------------------------------

    if threat_level == "HIGH":

        recommendation = (
            "Do not click links or open "
            "attachments. Verify the sender "
            "through an independent trusted "
            "channel."
        )

    elif threat_level == "MEDIUM":

        recommendation = (
            "Review the sender, links, headers "
            "and authentication information "
            "carefully before taking action."
        )

    else:

        recommendation = (
            "No major suspicious indicators "
            "were detected. Continue normal "
            "email security practices."
        )

    # -----------------------------------------------------
    # RESULT
    # -----------------------------------------------------

    return {

        "email_information": {

            "sender":
                sender,

            "subject":
                subject,

            "reply_to":
                reply_to,

            "return_path":
                return_path,

            "body_length":
                len(body)
        },

        "threat_level":
            threat_level,

        "threat_score":
            total_score,

        "suspicious_keywords":
            found_keywords,

        "keyword_count":
            len(found_keywords),

        "sender_analysis":
            sender_analysis,

        "header_analysis":
            header_analysis,

        "url_analysis":
            url_analysis,

        "ip_analysis":
            ip_analysis,

        "received_header_analysis":
            received_analysis,

        "authentication_analysis": {

            "spf":
                spf_analysis,

            "dmarc":
                dmarc_analysis,

            "authentication_results":
                authentication_results,

            "dkim_signature_present":
                dkim_signature_present
        },

        "attachment_analysis":
            attachment_analysis,

        "forensic_indicators":
            forensic_indicators,

        "forensic_indicator_count":
            len(
                forensic_indicators
            ),

        "forensic_summary":
            forensic_summary,

        "recommendation":
            recommendation
    }


# =========================================================
# JSON EMAIL ANALYSIS API
# =========================================================

@app.post("/api/analyze-email")
def analyze_email(
    request: EmailRequest
):

    return analyze_email_data(

        sender=request.sender,

        subject=request.subject,

        body=request.body,

        reply_to=request.reply_to,

        return_path=request.return_path
    )


# =========================================================
# EML FILE ANALYSIS API
# =========================================================

@app.post("/api/analyze-eml")
async def analyze_eml(
    file: UploadFile = File(...)
):

    # -----------------------------------------------------
    # FILE NAME CHECK
    # -----------------------------------------------------

    if not file.filename:

        return {

            "status":
                "error",

            "message":
                "File name is missing"
        }

    # -----------------------------------------------------
    # EXTENSION CHECK
    # -----------------------------------------------------

    if not file.filename.lower().endswith(
        ".eml"
    ):

        return {

            "status":
                "error",

            "message":
                "Only .eml files are supported"
        }

    try:

        # -------------------------------------------------
        # READ FILE
        # -------------------------------------------------

        file_bytes = await file.read()

        if not file_bytes:

            return {

                "status":
                    "error",

                "message":
                    "Uploaded file is empty"
            }

        # -------------------------------------------------
        # PARSE EMAIL
        # -------------------------------------------------

        parsed_email = parse_eml_file(
            file_bytes
        )

        # -------------------------------------------------
        # ANALYZE EMAIL
        # -------------------------------------------------

        analysis = analyze_email_data(

            sender=
                parsed_email[
                    "sender"
                ],

            subject=
                parsed_email[
                    "subject"
                ],

            body=
                parsed_email[
                    "body"
                ],

            reply_to=
                parsed_email[
                    "reply_to"
                ],

            return_path=
                parsed_email[
                    "return_path"
                ],

            received_headers=
                parsed_email[
                    "received_headers"
                ],

            attachments=
                parsed_email[
                    "attachments"
                ],

            authentication_results=
                parsed_email[
                    "authentication_results"
                ],

            dkim_signature_present=
                parsed_email[
                    "dkim_signature_present"
                ]
        )

        # -------------------------------------------------
        # FINAL RESPONSE
        # -------------------------------------------------

        return {

            "status":
                "success",

            "filename":
                file.filename,

            "parsed_email": {

                "sender":
                    parsed_email[
                        "sender"
                    ],

                "receiver":
                    parsed_email[
                        "receiver"
                    ],

                "subject":
                    parsed_email[
                        "subject"
                    ],

                "reply_to":
                    parsed_email[
                        "reply_to"
                    ],

                "return_path":
                    parsed_email[
                        "return_path"
                    ],

                "received_header_count":
                    len(
                        parsed_email[
                            "received_headers"
                        ]
                    ),

                "dkim_signature_present":
                    parsed_email[
                        "dkim_signature_present"
                    ],

                "attachment_count":
                    len(
                        parsed_email[
                            "attachments"
                        ]
                    )
            },

            "analysis":
                analysis
        }

    except Exception as e:

        return {

            "status":
                "error",

            "filename":
                file.filename,

            "message":
                str(e)
        }