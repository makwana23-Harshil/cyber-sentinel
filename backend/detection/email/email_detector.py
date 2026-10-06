import os
import re
import socket
import ssl
import smtplib
import joblib
from email.utils import parseaddr

# EMAIL ADDRESS ANALYSIS
def analyze_email_address(email: str) -> dict:
    """
    Analyze an email address and its domain.
    Checks:- Display name,Local part,Domain,Email format,DNS resolution, MX record, SMTP/TLS availability
    """
    import html
    import re
    from email.utils import parseaddr
    original_email = html.unescape(str(email or "").strip())
    result = {
        "email": original_email,
        "display_name": "",
        "local_part": "",
        "domain": "",
        "format_valid": False,
        "domain_resolves": False,
        "mx_found": False,
        "tls_supported": False,
        "is_valid": False,
        "mx_records": [],
        "mail_servers": [],
        "risk_score": 0,
        "risk_factors": [],
        "checks": {"format": "NOT_CHECKED","dns": "NOT_CHECKED","mx": "NOT_CHECKED","tls": "NOT_CHECKED"}
    }
    if not original_email:
        result["risk_score"] = 100
        result["risk_factors"].append("No email address was provided")
        return result

    # 1. Extract display name + actual email
    display_name = ""
    parsed_email = ""

    # 1A. Try robust Regex to capture "Name <email@domain.com>" format
    match = re.search(r'(.*?)\s*<\s*([^\s<>]+@[^\s<>]+)\s*>', original_email)

    if match:
        display_name = match.group(1).strip()
        # Remove surrounding quotes from the name if present
        display_name = re.sub(r'^["\']|["\']$', '', display_name).strip()
        parsed_email = match.group(2).strip().lower()
    else:
        display_name, parsed_email = parseaddr(original_email)
        parsed_email = parsed_email.strip().lower()
        display_name = display_name.strip()
        
        if "@" not in parsed_email:
            fallback_match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', original_email)
            if fallback_match:
                parsed_email = fallback_match.group(0).lower()
    result["display_name"] = display_name
    result["email"] = parsed_email

    # 2. Basic @ check
    if "@" not in parsed_email:
        result["risk_score"] = 80
        result["risk_factors"].append("Email address does not contain a valid @ structure")
        result["checks"]["format"] = "INVALID"
        return result
    local_part, domain = parsed_email.rsplit("@", 1)
    result["local_part"] = local_part
    result["domain"] = domain

    # 3. Email format
    email_pattern = (r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"r"@"r"[A-Za-z0-9-]+"r"(?:\.[A-Za-z0-9-]+)+$")
    if re.match(email_pattern, parsed_email):
        result["format_valid"] = True
        result["checks"]["format"] = "VALID"
    else:
        result["checks"]["format"] = "INVALID"
        result["risk_score"] += 50
        result["risk_factors"].append("Email address format appears invalid")

    # 4. DNS check
    try:
        import dns.resolver
        dns.resolver.resolve(domain, 'A', lifetime=3)
        result["domain_resolves"] = True
        result["checks"]["dns"] = "RESOLVED"
    except Exception:
        try:
            socket.setdefaulttimeout(3)
            socket.gethostbyname(domain)
            result["domain_resolves"] = True
            result["checks"]["dns"] = "RESOLVED"
        except Exception:
            result["checks"]["dns"] = "FAILED"
            result["risk_score"] += 30
            result["risk_factors"].append("Email domain could not be resolved through DNS")

    # 5. MX record check
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain,"MX",lifetime=5)
        mx_records = []
        for answer in answers:
            mx_host = str(answer.exchange).rstrip(".")
            mx_records.append({"priority": int(answer.preference),"host": mx_host})
        result["mx_records"] = mx_records
        result["mail_servers"] = [item["host"] for item in mx_records]
        if mx_records:
            result["mx_found"] = True
            result["checks"]["mx"] = "FOUND"
        else:
            result["checks"]["mx"] = "NOT_FOUND"
    
    except Exception:
        result["checks"]["mx"] = "NOT_FOUND"
        result["risk_score"] += 20
        result["risk_factors"].append("No MX mail server record could be confirmed")

    # 6. TLS / SMTP server check
    result["tls_supported"] = _check_mail_server_tls(result["mail_servers"])
    if result["tls_supported"]:
        result["checks"]["tls"] = "SUPPORTED"
    else:
        result["checks"]["tls"] = "NOT_CONFIRMED"

    # 7. Final technical validity
    result["is_valid"] = (result["format_valid"] and result["domain_resolves"] and result["mx_found"])
    result["risk_score"] = min(result["risk_score"],100)
    return result

# SMTP / TLS CHECK
def _check_mail_server_tls(mail_servers: list) -> bool:
    """
    Confirm TLS support on the mail server.
    Step 1: Check if server belongs to a known TLS-supporting provider.
    Step 2: Fallback - try live SMTP connections on ports 465, 587, 25.
    Note: Major providers (Google, Microsoft, Yahoo) block unauthenticated
    SMTP test connections, so provider detection is the primary method.
    """
    if not mail_servers:
        return False

    # Known providers that ALWAYS support TLS - detected by MX hostname
    KNOWN_TLS_PROVIDERS = [
        "google.com", "googlemail.com",
        "outlook.com", "hotmail.com",
        "microsoft.com", "office365.com",
        "yahoodns.net", "yahoo.com",
        "icloud.com", "me.com", "mac.com",
        "zoho.com",
        "protonmail.ch", "proton.me",
        "mailgun.org", "sendgrid.net",
        "amazonses.com",
        "fastmail.com", "fastmail.fm",
        "gmx.net", "gmx.com",
        "yandex.net", "yandex.ru",
    ]

    for server in mail_servers[:3]:
        server_lower = server.lower()
        for provider in KNOWN_TLS_PROVIDERS:
            if server_lower.endswith(provider) or ("." + provider) in server_lower:
                return True

    # Fallback: try live SMTP connections for unknown providers
    for server in mail_servers[:1]:
        try:
            import ssl, smtplib
            context = ssl.create_default_context()
            smtp = smtplib.SMTP_SSL(server, 465, timeout=5, context=context)
            smtp.quit()
            return True
        except Exception:
            pass
        try:
            smtp = smtplib.SMTP(server, 587, timeout=5)
            smtp.ehlo()
            if smtp.has_extn("starttls"):
                smtp.starttls(context=ssl.create_default_context())
                smtp.quit()
                return True
            smtp.quit()
        except Exception:
            pass
        try:
            smtp = smtplib.SMTP(server, 25, timeout=4)
            smtp.ehlo()
            if smtp.has_extn("starttls"):
                smtp.starttls(context=ssl.create_default_context())
                smtp.quit()
                return True
            smtp.quit()
        except Exception:
            pass
    return False

# COMPREHENSIVE EMAIL SCANNER
def analyze_email_comprehensive(sender: str = "",subject: str = "",body: str = "",inspect_links: bool = True,use_llm=True) -> dict:
    from detection.link.link_inspector import inspect_link
    from detection.link.llm_inspector import analyze_email_with_llm
    # 1. EMAIL ADDRESS
    email_llm_analysis = {}
    sender_analysis = {}
    sender_risk_penalty = 0
    if sender:
        try:
            sender_analysis = analyze_email_address(sender)
            print("DEBUG SENDER ANALYSIS:", sender_analysis)
            if not sender_analysis.get('is_valid', False):
                sender_risk_penalty = 30
        except Exception as e:
            print("SENDER ANALYSIS ERROR:", repr(e))
            sender_analysis = {
                "email": sender,
                "display_name": "","local_part": "","domain": "",
                "format_valid": False,"domain_resolves": False,"mx_found": False,"tls_supported": False,
                "is_valid": False,"mx_records": [],"mail_servers": [],"risk_score": 50,
                "risk_factors": [f"Email address analysis failed: {str(e)}"],
                "checks": {"format": "ERROR","dns": "NOT CHECKED","mx": "NOT CHECKED","tls": "NOT CHECKED"}
            }
            sender_risk_penalty = 30

    # 2. EMAIL BODY ML MODEL
    model_path = os.path.join(os.path.dirname(__file__),"..","..","models","email_body_model.pkl")
    model_path = os.path.abspath(model_path)
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Email body model not found: {model_path}")
    model = joblib.load(model_path)

    # 3. EXTRACT URLs
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+',re.IGNORECASE)
    urls = list(dict.fromkeys(url_pattern.findall(body or "")))
    urls_count = len(urls)

    # 4. PREPARE ML TEXT
    combined_text = [
        (   
            f"Sender: {sender} "
            f"Subject: {subject} "
            f"Body: {body} "
            f"URL Count: {urls_count}"
        )
    ]
    prediction = int(model.predict(combined_text)[0])
    
    # 5. ML PROBABILITIES
    try:
        probabilities = model.predict_proba(combined_text)[0]
        safe_prob = float(probabilities[0])
        phishing_prob = float(probabilities[1])
        confidence = float(max(probabilities))
    except Exception:
        phishing_prob = (0.90 if prediction == 1 else 0.10 )
        safe_prob = 1.0 - phishing_prob
        confidence = 0.85

    # 6. EXISTING URL INSPECTION
    link_results = []
    if inspect_links and urls:
        for url in urls[:5]:
            try:
                link_result = inspect_link(url,use_llm=use_llm)
                link_results.append(link_result)
            except Exception as exc:
                link_results.append({"url": url,"verdict": "ERROR","risk_score": 0,"error": str(exc)})

    # 7. LINK RISK
    max_link_risk = max((int(item.get("risk_score",0)) for item in link_results),default=0)
    
    # 8. COMPOSITE RISK
    base_risk = int(phishing_prob * 50)
    composite_risk = min(base_risk + int(max_link_risk * 0.3) + sender_risk_penalty,100)

    # 9. VERDICT
    if (prediction == 1 or composite_risk >= 70):
        verdict = "PHISHING"
    elif composite_risk >= 35:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    # 10. EVIDENCE
    evidence = []
    if use_llm:
        from detection.link.llm_inspector import analyze_email_with_llm
        email_llm_analysis = analyze_email_with_llm(email=sender,sender_analysis=sender_analysis)
        if email_llm_analysis.get('enabled') and email_llm_analysis.get('analysis'):
            evidence.append(f"AI Analysis: {email_llm_analysis.get('analysis')}")
    else:
        evidence.append("AI Deep Verification skipped via user toggle.")
    if sender and sender_analysis:
        if sender_analysis.get('domain_resolves'):
            evidence.append(f"Domain resolved in public DNS records ({sender_analysis.get('domain', '')})")
            if sender_analysis.get('mx_found'):
                evidence.append(f"Mail exchange records detected ({sender_analysis.get('domain', '')})")
            if not sender_analysis.get('format_valid', True):
                evidence.append("Email address format is invalid")
    elif sender:
        evidence.append("Email address analysis could not be completed")
    if subject:
        evidence.append(f"Subject evaluated: {subject}")
    if urls:
        evidence.append(f"{len(urls)} embedded link(s) detected")

    # 11. RETURN
    return {"verdict": verdict,
        "confidence": round(confidence,4),"risk_score": composite_risk,
        "sender_analysis": sender_analysis,
        "ml_prediction": ("PHISHING"if prediction == 1 else "SAFE"),
        "spam_probability": round(phishing_prob,4),
        "probabilities": {"safe": round(safe_prob * 100,2),
            "phishing": round(phishing_prob * 100,2)
        },
        "extracted_urls": urls,
        "url_count": urls_count,
        "link_inspections": link_results,
        "risk_evidence": evidence
    }
