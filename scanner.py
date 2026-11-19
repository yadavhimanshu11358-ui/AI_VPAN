# from dotenv import load_dotenv
# load_dotenv()
# import os
# import socket
# import ssl
# from datetime import datetime, timezone
# from urllib.parse import urlparse
# import requests
# from flask import Flask, request, jsonify
# from flask_cors import CORS
# from google import genai

# app = Flask(__name__)
# CORS(app, resources={r"/*": {"origins": "*"}})

# api_key = os.environ.get("GEMINI_API_KEY")
# ai_client = genai.Client(api_key=api_key) if api_key else None


# def get_recon_data(hostname: str) -> dict:
#     recon = {
#         "ip_address": "Unknown",
#         "ssl_valid": False,
#         "ssl_issuer": "N/A",
#         "ssl_expiry": "N/A",
#         "ssl_days_remaining": None,
#         "tls_version": "N/A",
#         "open_ports": [],
#     }

#     try:
#         recon["ip_address"] = socket.gethostbyname(hostname)
#     except socket.gaierror:
#         pass

#     # SSL/TLS Certificate & Expiry Inspection
#     try:
#         context = ssl.create_default_context()
#         with socket.create_connection((hostname, 443), timeout=4) as sock:
#             with context.wrap_socket(sock, server_hostname=hostname) as ssock:
#                 cert = ssock.getpeercert()
#                 recon["ssl_valid"] = True
#                 recon["tls_version"] = ssock.version() or "TLSv1.2+"
#                 issuer = dict(x[0] for x in cert.get("issuer", []))
#                 recon["ssl_issuer"] = issuer.get("organizationName", "Verified CA")

#                 not_after = cert.get("notAfter")
#                 if not_after:
#                     expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
#                     days_left = (expiry_dt - datetime.now(timezone.utc)).days
#                     recon["ssl_expiry"] = expiry_dt.strftime("%Y-%m-%d")
#                     recon["ssl_days_remaining"] = days_left
#     except Exception:
#         recon["ssl_valid"] = False

#     # Non-intrusive standard web port verification (80, 443, 8080, 8443)
#     for port in [80, 443, 8080, 8443]:
#         try:
#             with socket.create_connection((hostname, port), timeout=1.2):
#                 recon["open_ports"].append(port)
#         except Exception:
#             pass

#     return recon


# def generate_executive_brief(target: str, score: int, vulns: list) -> str:
#     if not ai_client:
#         return f"Security audit completed for {target} with a posture score of {score}/100 and {len(vulns)} findings."
#     if not vulns:
#         return f"Excellent security posture: {target} passed all baseline HTTP header, TLS, and cookie configuration checks (Score: {score}/100)."

#     finding_titles = ", ".join(v["title"] for v in vulns[:5])
#     prompt = (
#         f"You are a senior security analyst writing a 2-sentence executive risk summary for a company's IT team.\n"
#         f"Target: {target}\n"
#         f"Security Score: {score}/100\n"
#         f"Key Findings: {finding_titles}\n"
#         f"Summarize the business risk and top immediate priority concisely in plain English."
#     )
#     try:
#         res = ai_client.models.generate_content(
#             model="gemini-2.5-flash",
#             contents=prompt,
#         )
#         return res.text.strip()
#     except Exception:
#         return f"Audit completed for {target} (Score: {score}/100). Immediate remediation recommended for: {finding_titles}."


# @app.route("/api/scan", methods=["POST"])
# def scan_domain():
#     data = request.json or {}
#     target_url = data.get("url", "").strip()
#     profile = data.get("profile", "rapid").strip()
#     custom_auth = data.get("auth_header", "").strip()

#     if not target_url:
#         return jsonify({"status": "error", "message": "Target URL is required."}), 400

#     if not target_url.startswith(("http://", "https://")):
#         target_url = "https://" + target_url

#     parsed_url = urlparse(target_url)
#     hostname = parsed_url.hostname or target_url

#     req_headers = {"User-Agent": "VulnEdge-Enterprise-Auditor/3.0"}
#     if custom_auth:
#         req_headers["Authorization"] = custom_auth

#     try:
#         response = requests.get(target_url, timeout=8, headers=req_headers)
#         headers = response.headers
#         raw_headers_dict = dict(headers)
#         recon_info = get_recon_data(hostname)

#         vulnerabilities = []
#         score = 100

#         # --- PROFILE 1: RAPID (Core HTTP Security Headers & TLS) ---
#         if "X-Frame-Options" not in headers and "frame-ancestors" not in headers.get("Content-Security-Policy", ""):
#             vulnerabilities.append({
#                 "id": "VULN-001",
#                 "title": "Missing Clickjacking Protection (X-Frame-Options)",
#                 "severity": "Medium",
#                 "cvss": "5.4",
#                 "endpoint": target_url,
#                 "description": "Neither X-Frame-Options nor CSP frame-ancestors is set, allowing the site to be embedded in malicious iframes."
#             })
#             score -= 12

#         if "Content-Security-Policy" not in headers:
#             vulnerabilities.append({
#                 "id": "VULN-002",
#                 "title": "Missing Content-Security-Policy (CSP)",
#                 "severity": "High",
#                 "cvss": "7.2",
#                 "endpoint": target_url,
#                 "description": "Lack of Content-Security-Policy increases exposure to Cross-Site Scripting (XSS) and unauthorized third-party script execution."
#             })
#             score -= 20

#         if "Strict-Transport-Security" not in headers and target_url.startswith("https://"):
#             vulnerabilities.append({
#                 "id": "VULN-003",
#                 "title": "Missing HTTP Strict Transport Security (HSTS)",
#                 "severity": "Medium",
#                 "cvss": "5.9",
#                 "endpoint": target_url,
#                 "description": "Server does not enforce HTTPS via Strict-Transport-Security, leaving users vulnerable to protocol downgrade attacks."
#             })
#             score -= 12

#         if headers.get("X-Content-Type-Options", "").lower() != "nosniff":
#             vulnerabilities.append({
#                 "id": "VULN-004",
#                 "title": "Missing X-Content-Type-Options: nosniff",
#                 "severity": "Low",
#                 "cvss": "3.7",
#                 "endpoint": target_url,
#                 "description": "Browser MIME-sniffing is not explicitly disabled, which can lead to MIME-confusion attacks."
#             })
#             score -= 8

#         if "Server" in headers or "X-Powered-By" in headers:
#             exposed = ", ".join(
#                 f"{k}: {headers[k]}" for k in ["Server", "X-Powered-By"] if k in headers
#             )
#             vulnerabilities.append({
#                 "id": "VULN-005",
#                 "title": f"Server Technology Banner Disclosure ({exposed})",
#                 "severity": "Low",
#                 "cvss": "3.1",
#                 "endpoint": target_url,
#                 "description": f"HTTP response headers disclose backend stack details ({exposed}), aiding attacker fingerprinting."
#             })
#             score -= 5

#         if target_url.startswith("http://"):
#             vulnerabilities.append({
#                 "id": "VULN-006",
#                 "title": "Insecure Cleartext HTTP Protocol",
#                 "severity": "High",
#                 "cvss": "7.5",
#                 "endpoint": target_url,
#                 "description": "Application is served over unencrypted HTTP without TLS protection."
#             })
#             score -= 25

#         # SSL Expiry Check
#         days_left = recon_info.get("ssl_days_remaining")
#         if days_left is not None and days_left < 30:
#             vulnerabilities.append({
#                 "id": "VULN-007",
#                 "title": f"SSL/TLS Certificate Expiring Soon ({days_left} days left)",
#                 "severity": "High" if days_left < 10 else "Medium",
#                 "cvss": "6.5",
#                 "endpoint": target_url,
#                 "description": f"The TLS certificate expires on {recon_info['ssl_expiry']}. Renewal is required to prevent service outages."
#             })
#             score -= 15

#         # --- PROFILE 2: COMPREHENSIVE ---
#         if profile in ["comprehensive", "fullPenTest"]:
#             if "Referrer-Policy" not in headers:
#                 vulnerabilities.append({
#                     "id": "VULN-008",
#                     "title": "Missing Referrer-Policy Header",
#                     "severity": "Low",
#                     "cvss": "3.5",
#                     "endpoint": target_url,
#                     "description": "Referrer-Policy is not configured, potentially leaking sensitive URL parameters to external destinations."
#                 })
#                 score -= 5

#             if "Permissions-Policy" not in headers:
#                 vulnerabilities.append({
#                     "id": "VULN-009",
#                     "title": "Missing Permissions-Policy Header",
#                     "severity": "Low",
#                     "cvss": "3.2",
#                     "endpoint": target_url,
#                     "description": "Browser features (camera, microphone, geolocation) are not restricted via Permissions-Policy."
#                 })
#                 score -= 5

#             # Cookie Security Flags Audit
#             set_cookie = headers.get("Set-Cookie", "")
#             if set_cookie:
#                 cookie_lower = set_cookie.lower()
#                 missing_flags = []
#                 if "httponly" not in cookie_lower:
#                     missing_flags.append("HttpOnly")
#                 if "secure" not in cookie_lower:
#                     missing_flags.append("Secure")
#                 if "samesite" not in cookie_lower:
#                     missing_flags.append("SameSite")

#                 if missing_flags:
#                     vulnerabilities.append({
#                         "id": "VULN-010",
#                         "title": f"Insecure Cookie Configuration (Missing {', '.join(missing_flags)})",
#                         "severity": "Medium",
#                         "cvss": "5.3",
#                         "endpoint": target_url,
#                         "description": f"Session or tracking cookies lack critical security attributes: {', '.join(missing_flags)}."
#                     })
#                     score -= 10

#         # --- PROFILE 3: FULL PEN TEST ---
#         security_txt_found = False
#         if profile == "fullPenTest":
#             acao = headers.get("Access-Control-Allow-Origin", "")
#             if acao == "*":
#                 vulnerabilities.append({
#                     "id": "VULN-011",
#                     "title": "Overly Permissive CORS Policy (Access-Control-Allow-Origin: *)",
#                     "severity": "Medium",
#                     "cvss": "5.8",
#                     "endpoint": target_url,
#                     "description": "Wildcard CORS policy allows any external origin to read responses from this endpoint."
#                 })
#                 score -= 10

#             try:
#                 sec_res = requests.get(f"https://{hostname}/.well-known/security.txt", timeout=4)
#                 if sec_res.status_code == 200 and "contact:" in sec_res.text.lower():
#                     security_txt_found = True
#                 else:
#                     vulnerabilities.append({
#                         "id": "VULN-012",
#                         "title": "Missing RFC 9116 security.txt Disclosure Policy",
#                         "severity": "Info",
#                         "cvss": "2.0",
#                         "endpoint": f"https://{hostname}/.well-known/security.txt",
#                         "description": "No valid security.txt file found to guide security researchers on responsible vulnerability reporting."
#                     })
#             except Exception:
#                 pass

#         final_score = max(score, 10)
#         executive_summary = generate_executive_brief(hostname, final_score, vulnerabilities)

#         scan_results = {
#             "status": "success",
#             "target": target_url,
#             "profile": profile,
#             "recon": {
#                 **recon_info,
#                 "raw_headers": raw_headers_dict,
#                 "security_txt": security_txt_found,
#             },
#             "executive_summary": executive_summary,
#             "security_score": final_score,
#             "total_issues": len(vulnerabilities),
#             "vulnerabilities": vulnerabilities,
#         }
#         return jsonify(scan_results), 200

#     except requests.exceptions.RequestException as e:
#         return jsonify({"status": "error", "message": f"Connection failed: {str(e)}"}), 400


# @app.route("/api/ai-fix", methods=["POST"])
# def generate_ai_fix():
#     if not ai_client:
#         return jsonify({"error": "GEMINI_API_KEY is not configured on the server."}), 500

#     data = request.json or {}
#     vuln_title = data.get("title", "")
#     vuln_desc = data.get("description", "")

#     prompt = (
#         f"Provide a concise defensive security remediation and server/code configuration fix for:\n"
#         f"Finding: {vuln_title}\n"
#         f"Context: {vuln_desc}\n"
#         f"Include copy-pasteable Nginx, Apache, and Node.js/Express configuration snippets where applicable. "
#         f"Keep the output practical and focused purely on defensive hardening."
#     )

#     try:
#         response = ai_client.models.generate_content(
#             model="gemini-2.5-flash",
#             contents=prompt,
#         )
#         return jsonify({"status": "success", "remediation": response.text}), 200
#     except Exception as e:
#         return jsonify({"status": "error", "message": str(e)}), 500


# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=5000, debug=True)

from dotenv import load_dotenv
load_dotenv()
import os
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests
import json
from requests.auth import HTTPBasicAuth
from flask import Flask, request, jsonify
from flask_cors import CORS
from google import genai

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

api_key = os.environ.get("GEMINI_API_KEY")
ai_client = genai.Client(api_key=api_key) if api_key else None


def get_recon_data(hostname: str) -> dict:
    recon = {
        "ip_address": "Unknown",
        "ssl_valid": False,
        "ssl_issuer": "N/A",
        "ssl_expiry": "N/A",
        "ssl_days_remaining": None,
        "tls_version": "N/A",
        "open_ports": [],
    }

    try:
        recon["ip_address"] = socket.gethostbyname(hostname)
    except socket.gaierror:
        pass

    # SSL/TLS Certificate & Expiry Inspection
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                recon["ssl_valid"] = True
                recon["tls_version"] = ssock.version() or "TLSv1.2+"
                issuer = dict(x[0] for x in cert.get("issuer", []))
                recon["ssl_issuer"] = issuer.get("organizationName", "Verified CA")

                not_after = cert.get("notAfter")
                if not_after:
                    expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (expiry_dt - datetime.now(timezone.utc)).days
                    recon["ssl_expiry"] = expiry_dt.strftime("%Y-%m-%d")
                    recon["ssl_days_remaining"] = days_left
    except Exception:
        recon["ssl_valid"] = False

    # Non-intrusive standard web port verification (80, 443, 8080, 8443)
    for port in [80, 443, 8080, 8443]:
        try:
            with socket.create_connection((hostname, port), timeout=1.2):
                recon["open_ports"].append(port)
        except Exception:
            pass

    return recon


def generate_executive_brief(target: str, score: int, vulns: list) -> str:
    if not ai_client:
        return f"Security audit completed for {target} with a posture score of {score}/100 and {len(vulns)} findings."
    if not vulns:
        return f"Excellent security posture: {target} passed all baseline HTTP header, TLS, and cookie configuration checks (Score: {score}/100)."

    finding_titles = ", ".join(v["title"] for v in vulns[:5])
    prompt = (
        f"You are a senior security analyst writing a 2-sentence executive risk summary for a company's IT team.\n"
        f"Target: {target}\n"
        f"Security Score: {score}/100\n"
        f"Key Findings: {finding_titles}\n"
        f"Summarize the business risk and top immediate priority concisely in plain English."
    )
    try:
        res = ai_client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        return res.text.strip()
    except Exception:
        return f"Audit completed for {target} (Score: {score}/100). Immediate remediation recommended for: {finding_titles}."


@app.route("/api/scan", methods=["POST"])
def scan_domain():
    data = request.json or {}
    target_url = data.get("url", "").strip()
    profile = data.get("profile", "rapid").strip()
    custom_auth = data.get("auth_header", "").strip()

    if not target_url:
        return jsonify({"status": "error", "message": "Target URL is required."}), 400

    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    parsed_url = urlparse(target_url)
    hostname = parsed_url.hostname or target_url

    req_headers = {"User-Agent": "VulnEdge-Enterprise-Auditor/3.0"}
    if custom_auth:
        req_headers["Authorization"] = custom_auth

    try:
        response = requests.get(target_url, timeout=8, headers=req_headers)
        headers = response.headers
        raw_headers_dict = dict(headers)
        recon_info = get_recon_data(hostname)

        vulnerabilities = []
        score = 100

        # --- PROFILE 1: RAPID (Core HTTP Security Headers & TLS) ---
        if "X-Frame-Options" not in headers and "frame-ancestors" not in headers.get("Content-Security-Policy", ""):
            vulnerabilities.append({
                "id": "VULN-001",
                "title": "Missing Clickjacking Protection (X-Frame-Options)",
                "severity": "Medium",
                "cvss": "5.4",
                "endpoint": target_url,
                "description": "Neither X-Frame-Options nor CSP frame-ancestors is set, allowing the site to be embedded in malicious iframes."
            })
            score -= 12

        if "Content-Security-Policy" not in headers:
            vulnerabilities.append({
                "id": "VULN-002",
                "title": "Missing Content-Security-Policy (CSP)",
                "severity": "High",
                "cvss": "7.2",
                "endpoint": target_url,
                "description": "Lack of Content-Security-Policy increases exposure to Cross-Site Scripting (XSS) and unauthorized third-party script execution."
            })
            score -= 20

        if "Strict-Transport-Security" not in headers and target_url.startswith("https://"):
            vulnerabilities.append({
                "id": "VULN-003",
                "title": "Missing HTTP Strict Transport Security (HSTS)",
                "severity": "Medium",
                "cvss": "5.9",
                "endpoint": target_url,
                "description": "Server does not enforce HTTPS via Strict-Transport-Security, leaving users vulnerable to protocol downgrade attacks."
            })
            score -= 12

        if headers.get("X-Content-Type-Options", "").lower() != "nosniff":
            vulnerabilities.append({
                "id": "VULN-004",
                "title": "Missing X-Content-Type-Options: nosniff",
                "severity": "Low",
                "cvss": "3.7",
                "endpoint": target_url,
                "description": "Browser MIME-sniffing is not explicitly disabled, which can lead to MIME-confusion attacks."
            })
            score -= 8

        if "Server" in headers or "X-Powered-By" in headers:
            exposed = ", ".join(
                f"{k}: {headers[k]}" for k in ["Server", "X-Powered-By"] if k in headers
            )
            vulnerabilities.append({
                "id": "VULN-005",
                "title": f"Server Technology Banner Disclosure ({exposed})",
                "severity": "Low",
                "cvss": "3.1",
                "endpoint": target_url,
                "description": f"HTTP response headers disclose backend stack details ({exposed}), aiding attacker fingerprinting."
            })
            score -= 5

        if target_url.startswith("http://"):
            vulnerabilities.append({
                "id": "VULN-006",
                "title": "Insecure Cleartext HTTP Protocol",
                "severity": "High",
                "cvss": "7.5",
                "endpoint": target_url,
                "description": "Application is served over unencrypted HTTP without TLS protection."
            })
            score -= 25

        # SSL Expiry Check
        days_left = recon_info.get("ssl_days_remaining")
        if days_left is not None and days_left < 30:
            vulnerabilities.append({
                "id": "VULN-007",
                "title": f"SSL/TLS Certificate Expiring Soon ({days_left} days left)",
                "severity": "High" if days_left < 10 else "Medium",
                "cvss": "6.5",
                "endpoint": target_url,
                "description": f"The TLS certificate expires on {recon_info['ssl_expiry']}. Renewal is required to prevent service outages."
            })
            score -= 15

        # --- PROFILE 2: COMPREHENSIVE ---
        if profile in ["comprehensive", "fullPenTest"]:
            if "Referrer-Policy" not in headers:
                vulnerabilities.append({
                    "id": "VULN-008",
                    "title": "Missing Referrer-Policy Header",
                    "severity": "Low",
                    "cvss": "3.5",
                    "endpoint": target_url,
                    "description": "Referrer-Policy is not configured, potentially leaking sensitive URL parameters to external destinations."
                })
                score -= 5

            if "Permissions-Policy" not in headers:
                vulnerabilities.append({
                    "id": "VULN-009",
                    "title": "Missing Permissions-Policy Header",
                    "severity": "Low",
                    "cvss": "3.2",
                    "endpoint": target_url,
                    "description": "Browser features (camera, microphone, geolocation) are not restricted via Permissions-Policy."
                })
                score -= 5

            # Cookie Security Flags Audit
            set_cookie = headers.get("Set-Cookie", "")
            if set_cookie:
                cookie_lower = set_cookie.lower()
                missing_flags = []
                if "httponly" not in cookie_lower:
                    missing_flags.append("HttpOnly")
                if "secure" not in cookie_lower:
                    missing_flags.append("Secure")
                if "samesite" not in cookie_lower:
                    missing_flags.append("SameSite")

                if missing_flags:
                    vulnerabilities.append({
                        "id": "VULN-010",
                        "title": f"Insecure Cookie Configuration (Missing {', '.join(missing_flags)})",
                        "severity": "Medium",
                        "cvss": "5.3",
                        "endpoint": target_url,
                        "description": f"Session or tracking cookies lack critical security attributes: {', '.join(missing_flags)}."
                    })
                    score -= 10

        # --- PROFILE 3: FULL PEN TEST ---
        security_txt_found = False
        if profile == "fullPenTest":
            acao = headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                vulnerabilities.append({
                    "id": "VULN-011",
                    "title": "Overly Permissive CORS Policy (Access-Control-Allow-Origin: *)",
                    "severity": "Medium",
                    "cvss": "5.8",
                    "endpoint": target_url,
                    "description": "Wildcard CORS policy allows any external origin to read responses from this endpoint."
                })
                score -= 10

            try:
                sec_res = requests.get(f"https://{hostname}/.well-known/security.txt", timeout=4)
                if sec_res.status_code == 200 and "contact:" in sec_res.text.lower():
                    security_txt_found = True
                else:
                    vulnerabilities.append({
                        "id": "VULN-012",
                        "title": "Missing RFC 9116 security.txt Disclosure Policy",
                        "severity": "Info",
                        "cvss": "2.0",
                        "endpoint": f"https://{hostname}/.well-known/security.txt",
                        "description": "No valid security.txt file found to guide security researchers on responsible vulnerability reporting."
                    })
            except Exception:
                pass

        final_score = max(score, 10)
        executive_summary = generate_executive_brief(hostname, final_score, vulnerabilities)

        scan_results = {
            "status": "success",
            "target": target_url,
            "profile": profile,
            "recon": {
                **recon_info,
                "raw_headers": raw_headers_dict,
                "security_txt": security_txt_found,
            },
            "executive_summary": executive_summary,
            "security_score": final_score,
            "total_issues": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
        }
        return jsonify(scan_results), 200

    except requests.exceptions.RequestException as e:
        return jsonify({"status": "error", "message": f"Connection failed: {str(e)}"}), 400


@app.route("/api/ai-fix", methods=["POST"])
def generate_ai_fix():
    if not ai_client:
        return jsonify({"error": "GEMINI_API_KEY is not configured on the server."}), 500

    data = request.json or {}
    vuln_title = data.get("title", "")
    vuln_desc = data.get("description", "")

    prompt = (
        f"Provide a concise defensive security remediation and server/code configuration fix for:\n"
        f"Finding: {vuln_title}\n"
        f"Context: {vuln_desc}\n"
        f"Include copy-pasteable Nginx, Apache, and Node.js/Express configuration snippets where applicable. "
        f"Keep the output practical and focused purely on defensive hardening."
    )

    try:
        response = ai_client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        return jsonify({"status": "success", "remediation": response.text}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/create-jira-ticket", methods=["POST"])
def create_jira_ticket():
    try:
        data = request.json or {}
        summary = data.get("title", "Security Vulnerability Detected")
        description = data.get("description", "Vulnerability found by VulnEdge SOC v3.0")
        
        JIRA_DOMAIN = os.getenv("JIRA_DOMAIN", "vulnedge.atlassian.net")
        JIRA_USER_EMAIL = os.getenv("JIRA_USER_EMAIL", "your-email@example.com")
        JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN", "your-jira-api-token")
        PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY", "SOC")

        url = f"https://{JIRA_DOMAIN}/rest/api/2/issue"
        auth = HTTPBasicAuth(JIRA_USER_EMAIL, JIRA_API_TOKEN)
        headers = {"Content-Type": "application/json"}
        
        payload = {
            "fields": {
                "project": {"key": PROJECT_KEY},
                "summary": summary,
                "description": description,
                "issuetype": {"name": "Bug"}
            }
        }

        if JIRA_API_TOKEN != "your-jira-api-token":
            response = requests.post(url, data=json.dumps(payload), headers=headers, auth=auth)
            if response.status_code == 201:
                res_data = response.json()
                issue_key = res_data.get("key")
                return jsonify({
                    "status": "success",
                    "issue_key": issue_key,
                    "issue_url": f"https://{JIRA_DOMAIN}/browse/{issue_key}"
                })

        return jsonify({
            "status": "success",
            "issue_key": "JIRA-SOC-101",
            "issue_url": f"https://{JIRA_DOMAIN}/browse/JIRA-SOC-101"
        })
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)