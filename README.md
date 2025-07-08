# Email Validation API

This project provides a robust API endpoint to validate email addresses using multiple heuristics, DNS lookups, and live SMTP checks—similar to what professional services like ZeroBounce and Hunter.io do.

## Features

- **Syntax validation** (regex-based)
- **Disposable email detection**
- **Role-based account detection**
- **Blocklist checks**
- **MX record (DNS) lookup**
- **Live SMTP check** (checks if the mailbox exists)
- **Heuristic/ML-style checks for suspicious patterns**
- **Historical bounce check**
- **Step-by-step log of the validation process**

---

## Setup & Usage

### 1. Install Dependencies

First, create and activate a Python virtual environment (recommended):
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate

Here is the full backend app.py without any wrapping:

import re
import dns.resolver
import smtplib
import socket

DISPOSABLE_DOMAINS = {
    "10minutemail.com", "tempmail.com", "mailinator.com", "guerrillamail.com",
    "yopmail.com", "trashmail.com", "temp-mail.org", "maildrop.cc"
}

ROLE_ACCOUNTS = {
    "admin", "support", "info", "sales", "contact", "help", "webmaster", "office"
}

BLOCKLISTED_EMAILS = {
    "baduser@scam.com",  # Example blocklisted addresses
}
BLOCKLISTED_DOMAINS = {
    "spammydomain.com"
}

HISTORICAL_BOUNCES = {
    "bounce@oldcompany.com",
    "test@companybounced.com"
}

def is_valid_syntax(email):
    regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(regex, email) is not None

def get_domain(email):
    return email.split('@')[-1].lower()

def is_disposable(email):
    return get_domain(email) in DISPOSABLE_DOMAINS

def is_role_account(email):
    local = email.split('@')[0].lower()
    prefix = local.split('+')[0].split('.')[0].split('_')[0]
    return prefix in ROLE_ACCOUNTS

def is_blocklisted(email):
    domain = get_domain(email)
    return email in BLOCKLISTED_EMAILS or domain in BLOCKLISTED_DOMAINS

def has_mx_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return len(answers) > 0
    except Exception as e:
        print(f"[MX CHECK] MX record check failed: {e}")
        return False

def smtp_check(email, from_address="test@example.com"):
    domain = get_domain(email)
    smtp_debug_log = []
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_host = str(mx_records[0].exchange)
        smtp_debug_log.append(f"[SMTP] MX Host: {mx_host}")
    except Exception as e:
        msg = f"[SMTP] No MX record found: {e}"
        smtp_debug_log.append(msg)
        print(msg)
        return False, "\n".join(smtp_debug_log)

    server = None
    try:
        server = smtplib.SMTP(timeout=10)
        smtp_debug_log.append(f"[SMTP] Connecting to {mx_host}...")
        server.connect(mx_host)
        smtp_debug_log.append("[SMTP] Connected!")

        code, resp = server.helo(server.local_hostname)
        smtp_debug_log.append(f"[SMTP] HELO response: {code} {resp}")

        code, resp = server.mail(from_address)
        smtp_debug_log.append(f"[SMTP] MAIL FROM response: {code} {resp}")

        code, resp = server.rcpt(email)
        smtp_debug_log.append(f"[SMTP] RCPT TO response: {code} {resp}")

        server.quit()
        smtp_debug_log.append("[SMTP] Connection closed (QUIT)")

        if code in [250, 251]:
            return True, "\n".join(smtp_debug_log) + "\n[SMTP] Mailbox accepted by server."
        elif code == 550:
            return False, "\n".join(smtp_debug_log) + "\n[SMTP] User not found (550 response)."
        else:
            msg = resp.decode(errors='ignore') if isinstance(resp, bytes) else str(resp)
            return False, "\n".join(smtp_debug_log) + f"\n[SMTP] SMTP code {code}: {msg}"

    except (socket.timeout, smtplib.SMTPException, Exception) as e:
        smtp_debug_log.append(f"[SMTP] Exception: {e}")
        return False, "\n".join(smtp_debug_log) + f"\n[SMTP] SMTP check failed: {e}"
    finally:
        if server:
            try:
                server.close()
            except Exception:
                pass

def historical_bounce_check(email):
    return email in HISTORICAL_BOUNCES

def ml_heuristic_check(email):
    weird_patterns = ['test', 'fake', 'random', 'xxxx', '123', 'qwerty']
    email_lower = email.lower()
    for pattern in weird_patterns:
        if pattern in email_lower:
            print(f"[ML CHECK] Pattern '{pattern}' found in email.")
            return True, f"Pattern '{pattern}' detected, looks suspicious."
    return False, ""

def validate_email(email):
    result = {
        "email": email,
        "syntax_valid": None,
        "disposable": None,
        "role_account": None,
        "blocklisted": None,
        "mx_valid": None,
        "smtp_valid": None,
        "smtp_info": "",
        "historical_bounce": None,
        "ml_flagged": None,
        "ml_info": "",
        "final_status": ""
    }
    logs = []

    # Syntax check
    result["syntax_valid"] = is_valid_syntax(email)
    logs.append(f"Syntax valid: {result['syntax_valid']}")
    print(f"[LOG] Syntax valid: {result['syntax_valid']}")
    if not result["syntax_valid"]:
        result["final_status"] = "NOT VALID (bad format)"
        logs.append(result["final_status"])
        return result, logs

    # Blocklist check
    result["blocklisted"] = is_blocklisted(email)
    logs.append(f"Blocklisted: {result['blocklisted']}")
    print(f"[LOG] Blocklisted: {result['blocklisted']}")
    if result["blocklisted"]:
        result["final_status"] = "NOT VALID (blocklisted)"
        logs.append(result["final_status"])
        return result, logs

    # Disposable check
    result["disposable"] = is_disposable(email)
    logs.append(f"Disposable: {result['disposable']}")
    print(f"[LOG] Disposable: {result['disposable']}")

    # Role account check
    result["role_account"] = is_role_account(email)
    logs.append(f"Role account: {result['role_account']}")
    print(f"[LOG] Role account: {result['role_account']}")

    # Historical bounce check
    result["historical_bounce"] = historical_bounce_check(email)
    logs.append(f"Historical bounce: {result['historical_bounce']}")
    print(f"[LOG] Historical bounce: {result['historical_bounce']}")
    if result["historical_bounce"]:
        result["final_status"] = "NOT VALID (previous bounce)"
        logs.append(result["final_status"])
        return result, logs

    # ML heuristic check
    result["ml_flagged"], result["ml_info"] = ml_heuristic_check(email)
    logs.append(f"ML flagged: {result['ml_flagged']} | Info: {result['ml_info']}")
    print(f"[LOG] ML flagged: {result['ml_flagged']} | Info: {result['ml_info']}")

    # MX record check
    domain = get_domain(email)
    result["mx_valid"] = has_mx_record(domain)
    logs.append(f"MX valid: {result['mx_valid']}")
    print(f"[LOG] MX valid: {result['mx_valid']}")
    if not result["mx_valid"]:
        result["final_status"] = "NOT VALID (no MX record)"
        logs.append(result["final_status"])
        return result, logs

    # SMTP check
    result["smtp_valid"], result["smtp_info"] = smtp_check(email)
    logs.append(f"SMTP valid: {result['smtp_valid']} | Info:\n{result['smtp_info']}")
    print(f"[LOG] SMTP valid: {result['smtp_valid']} | Info:\n{result['smtp_info']}")

    # Final status logic (print all risks)
    status = []
    if result["disposable"]:
        status.append("RISKY (disposable email)")
    if result["role_account"]:
        status.append("RISKY (role-based email)")
    if result["ml_flagged"]:
        status.append("RISKY (ML heuristic flagged)")
    if result["smtp_valid"]:
        status.append("VALID")
    else:
        status.append("RISKY (SMTP uncertain)")

    result["final_status"] = " | ".join(status)
    logs.append(f"Final status: {result['final_status']}")
    print(f"[LOG] Final status: {result['final_status']}")

    return result, logs

if __name__ == "__main__":
    email = input("Enter the email address to validate: ").strip()
    print("\nRunning ALL validation checks...\n")
    result, logs = validate_email(email)
    print("\n===== Step-by-Step Log =====")
    for log in logs:
        print(log)
    print("\n===== Email Validation Result =====")
    for k, v in result.items():
        print(f"{k}: {v}")
    print("===================================")
