import re                            # For regex syntax validation
import dns.resolver                  # To resolve MX DNS records
import smtplib                       # For SMTP server communication
import socket                        # For handling network exceptions
import pandas as pd                  # For reading/writing CSV files
from io import StringIO, BytesIO     # For in-memory file handling

from flask import Flask, request, jsonify, send_file  # Flask web stuff

from flask_cors import CORS          # For handling CORS during local/frontend testing

# Heuristic Datasets 
DISPOSABLE_DOMAINS = {
    "10minutemail.com", "tempmail.com", "mailinator.com", "guerrillamail.com",
    "yopmail.com", "trashmail.com", "temp-mail.org", "maildrop.cc"
}
ROLE_ACCOUNTS = {
    "admin", "support", "info", "sales", "contact", "help", "webmaster", "office"
}
BLOCKLISTED_EMAILS = {
    "baduser@scam.com",
}
BLOCKLISTED_DOMAINS = {
    "spammydomain.com"
}
HISTORICAL_BOUNCES = {
    "bounce@oldcompany.com",
    "test@companybounced.com"
}

# Email Validation Functions
def is_valid_syntax(email):
    """Check if the email format is valid using regex."""
    regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(regex, email) is not None

def get_domain(email):
    """Extract domain part from email."""
    return email.split('@')[-1].lower()

def is_disposable(email):
    """Check if domain is in known disposable domains."""
    return get_domain(email) in DISPOSABLE_DOMAINS

def is_role_account(email):
    """Check if email is a generic/role-based account."""
    local = email.split('@')[0].lower()
    prefix = local.split('+')[0].split('.')[0].split('_')[0]
    return prefix in ROLE_ACCOUNTS

def is_blocklisted(email):
    """Check if email or domain is blocklisted."""
    domain = get_domain(email)
    return email in BLOCKLISTED_EMAILS or domain in BLOCKLISTED_DOMAINS

def has_mx_record(domain):
    """Check if domain has a valid MX record (for receiving emails)."""
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return len(answers) > 0
    except Exception as e:
        print(f"[MX CHECK] MX record check failed: {e}")
        return False

def smtp_check(email, from_address="test@example.com"):
    """
    Check SMTP server for recipient validity.
    Will simulate sending an email to see if the mailbox exists.
    """
    domain = get_domain(email)
    smtp_debug_log = []
    try:
        # Resolve MX host for the recipient domain
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
        # Open connection with a timeout
        server = smtplib.SMTP(timeout=10)
        smtp_debug_log.append(f"[SMTP] Connecting to {mx_host}...")
        server.connect(mx_host)
        smtp_debug_log.append("[SMTP] Connected!")

        # Greet SMTP server
        code, resp = server.helo(server.local_hostname)
        smtp_debug_log.append(f"[SMTP] HELO response: {code} {resp}")

        # Set MAIL FROM
        code, resp = server.mail(from_address)
        smtp_debug_log.append(f"[SMTP] MAIL FROM response: {code} {resp}")

        # Attempt RCPT TO (recipient check)
        code, resp = server.rcpt(email)
        smtp_debug_log.append(f"[SMTP] RCPT TO response: {code} {resp}")

        # Cleanly close the connection
        server.quit()
        smtp_debug_log.append("[SMTP] Connection closed (QUIT)")

        # Interpret SMTP status code
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
    """Check if this email is in a list of previously bounced addresses."""
    return email in HISTORICAL_BOUNCES

def ml_heuristic_check(email):
    """Very basic ML-style heuristics for suspicious emails (e.g., random patterns)."""
    weird_patterns = ['test', 'fake', 'random', 'xxxx', '123', 'qwerty']
    email_lower = email.lower()
    for pattern in weird_patterns:
        if pattern in email_lower:
            print(f"[ML CHECK] Pattern '{pattern}' found in email.")
            return True, f"Pattern '{pattern}' detected, looks suspicious."
    return False, ""

def validate_email(email):
    """Runs all checks on the email address and returns result and log."""
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

    # Step 1: Syntax
    result["syntax_valid"] = is_valid_syntax(email)
    logs.append(f"Syntax valid: {result['syntax_valid']}")
    print(f"[LOG] Syntax valid: {result['syntax_valid']}")
    if not result["syntax_valid"]:
        result["final_status"] = "NOT VALID (bad format)"
        logs.append(result["final_status"])
        return result, logs

    # Step 2: Blocklist
    result["blocklisted"] = is_blocklisted(email)
    logs.append(f"Blocklisted: {result['blocklisted']}")
    print(f"[LOG] Blocklisted: {result['blocklisted']}")
    if result["blocklisted"]:
        result["final_status"] = "NOT VALID (blocklisted)"
        logs.append(result["final_status"])
        return result, logs

    # Step 3: Disposable
    result["disposable"] = is_disposable(email)
    logs.append(f"Disposable: {result['disposable']}")
    print(f"[LOG] Disposable: {result['disposable']}")

    # Step 4: Role
    result["role_account"] = is_role_account(email)
    logs.append(f"Role account: {result['role_account']}")
    print(f"[LOG] Role account: {result['role_account']}")

    # Step 5: Historical bounce
    result["historical_bounce"] = historical_bounce_check(email)
    logs.append(f"Historical bounce: {result['historical_bounce']}")
    print(f"[LOG] Historical bounce: {result['historical_bounce']}")
    if result["historical_bounce"]:
        result["final_status"] = "NOT VALID (previous bounce)"
        logs.append(result["final_status"])
        return result, logs

    # Step 6: ML heuristic
    result["ml_flagged"], result["ml_info"] = ml_heuristic_check(email)
    logs.append(f"ML flagged: {result['ml_flagged']} | Info: {result['ml_info']}")
    print(f"[LOG] ML flagged: {result['ml_flagged']} | Info: {result['ml_info']}")

    # Step 7: MX
    domain = get_domain(email)
    result["mx_valid"] = has_mx_record(domain)
    logs.append(f"MX valid: {result['mx_valid']}")
    print(f"[LOG] MX valid: {result['mx_valid']}")
    if not result["mx_valid"]:
        result["final_status"] = "NOT VALID (no MX record)"
        logs.append(result["final_status"])
        return result, logs

    # Step 8: SMTP
    result["smtp_valid"], result["smtp_info"] = smtp_check(email)
    logs.append(f"SMTP valid: {result['smtp_valid']} | Info:\n{result['smtp_info']}")
    print(f"[LOG] SMTP valid: {result['smtp_valid']} | Info:\n{result['smtp_info']}")

    # Step 9: Final Status Logic
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

# Flask App Setup 
app = Flask(__name__)     # Create Flask web app instance
CORS(app)                 # Enable CORS for frontend integration (remove if not needed)

@app.route('/validate', methods=['POST'])
def api_validate():
    """
    REST endpoint to validate an email address (for single email POST).
    Accepts JSON: { "email": "someone@email.com" }
    Returns JSON with validation result and step-by-step log.
    """
    data = request.get_json()
    if not data or 'email' not in data:
        return jsonify({"error": "Missing 'email' in request body"}), 400

    email = data['email'].strip()
    result, logs = validate_email(email)
    return jsonify({"result": result, "logs": logs})

@app.route('/validate-csv', methods=['POST'])
def validate_csv():
    """
    REST endpoint to validate a batch of emails via CSV upload.
    Accepts CSV file with 'email' column. Returns a CSV with an added 'final_status' column.
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # Read the uploaded CSV file into pandas DataFrame
    try:
        df = pd.read_csv(file)
    except Exception as e:
        return jsonify({"error": f"Error reading CSV: {e}"}), 400

    if 'email' not in df.columns:
        return jsonify({"error": "CSV must have an 'email' column"}), 400

    # Validate each email and collect results
    final_statuses = []
    for email in df['email']:
        email = str(email).strip()
        result, logs = validate_email(email)
        final_statuses.append(result['final_status'])

    # Add new column to DataFrame with final results
    df['final_status'] = final_statuses

    # Write result DataFrame to CSV in memory
    output = StringIO()
    df.to_csv(output, index=False)
    output.seek(0)

    # Return the new CSV as a downloadable file
    return send_file(
        BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name='validated_emails.csv'
    )

# Run Flask Server 
if __name__ == "__main__":
    app.run(debug=True, port=5000)
