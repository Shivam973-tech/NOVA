# Backend/main.py
# Scam Checker backend - Python 3, standard library only.
# Run with:  python Backend/main.py

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import re

# ---------------------------------------------------------------
# 1. RISK DATABASE (a small made-up list; add your own entries)
# ---------------------------------------------------------------
RISK_DOMAINS = [
    "free-gift-claim.xyz",
    "sbi-kyc-update.top",
    "paytm-rewards.click",
    "lucky-winner-india.live",
]

RISK_PAYMENT_IDS = [
    "refund.support@paytm",
    "lottery.claim@ybl",
    "kyc.update@okaxis",
    "cashback.offer@upi",
]

# ---------------------------------------------------------------
# 2. SCAM KEYWORDS: (keyword, points added, explanation)
# ---------------------------------------------------------------
SCAM_KEYWORDS = [
    ("urgent", 10, "Uses urgency to pressure you ('urgent')"),
    ("immediately", 10, "Pressures you to act immediately"),
    ("account blocked", 20, "Threatens that your account will be blocked"),
    ("account suspended", 20, "Threatens that your account will be suspended"),
    ("kyc", 15, "Mentions KYC update, a very common scam trick"),
    ("lottery", 25, "Mentions a lottery, which is usually fake"),
    ("you have won", 25, "Claims that you have won a prize"),
    ("winner", 15, "Calls you a 'winner'"),
    ("prize", 15, "Mentions a prize"),
    ("otp", 20, "Asks about your OTP (never share it with anyone)"),
    ("pin", 10, "Mentions a PIN (never share it)"),
    ("cvv", 25, "Asks for your CVV (never share it)"),
    ("refund", 10, "Mentions a refund, often used to trick people"),
    ("click here", 15, "Asks you to 'click here'"),
    ("verify your", 10, "Asks you to verify your details"),
    ("send money", 20, "Asks you to send money"),
    ("gift card", 20, "Asks for gift cards"),
    ("free", 5, "Offers something 'free'"),
]

# Link shorteners hide the real destination
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "cutt.ly", "rb.gy"]

# Domain endings that are often used in scams
SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".live", ".tk", ".ml", ".gq", ".cf", ".work"]

# Brand names scammers like to copy
BRAND_WORDS = ["sbi", "hdfc", "icici", "paytm", "phonepe", "gpay", "amazon", "netflix"]

# Words that look suspicious inside a payment ID (UPI ID)
SUSPICIOUS_ID_WORDS = ["refund", "lottery", "kyc", "cashback", "reward", "support", "care", "winner"]


# ---------------------------------------------------------------
# 3. HELPER FUNCTIONS
# ---------------------------------------------------------------
def get_host(url):
    """Return only the domain part of a URL, e.g. 'www.site.com'."""
    url = url.lower()
    url = re.sub(r"^https?://", "", url)   # remove http:// or https://
    host = url.split("/")[0]                # cut off the path
    host = host.split("?")[0]               # cut off the query
    host = host.split(":")[0]               # cut off the port
    if "@" in host:                         # user@host trick
        host = host.split("@")[-1]
    return host


def check_url(url, reasons):
    """Check one URL and return the points to add to the risk score."""
    points = 0
    lower_url = url.lower()
    host = get_host(url)

    # Is the domain in our risk database?
    for bad in RISK_DOMAINS:
        if bad in host:
            points += 50
            reasons.append("Link '" + host + "' is in our known scam database")

    # Does the URL not use HTTPS?
    if lower_url.startswith("http://"):
        points += 10
        reasons.append("Link uses plain HTTP, which is not secure: " + host)

    # Is the host a raw IP address like 192.168.1.1?
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        points += 30
        reasons.append("Link uses an IP address instead of a real domain name")

    # Link shorteners
    for short in URL_SHORTENERS:
        if host == short:
            points += 20
            reasons.append("Link shortener '" + host + "' hides the real destination")

    # Suspicious domain endings
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            points += 20
            reasons.append("Domain ending '" + tld + "' is often used in scams")

    # '@' symbol inside the link can hide the real site
    if "@" in lower_url.split("?")[0].replace("://", ""):
        points += 20
        reasons.append("Link contains '@', a trick used to hide the real website")

    # Too many hyphens or too long
    if host.count("-") >= 3:
        points += 15
        reasons.append("Domain has many hyphens, which looks fake: " + host)
    if len(lower_url) > 100:
        points += 10
        reasons.append("Link is unusually long")

    # Brand name used in a domain that is not the official one
    for brand in BRAND_WORDS:
        if brand in host and not host.endswith(brand + ".com") and not host.endswith(brand + ".in"):
            points += 20
            reasons.append("Domain pretends to be '" + brand + "' but is not the official site")
            break

    return points


def check_payment_id(pid, reasons):
    """Check one payment ID (like name@bank) and return points."""
    points = 0
    pid = pid.lower()

    if pid in RISK_PAYMENT_IDS:
        points += 60
        reasons.append("Payment ID '" + pid + "' is in our known scam database")
    else:
        for word in SUSPICIOUS_ID_WORDS:
            if word in pid:
                points += 25
                reasons.append("Payment ID '" + pid + "' contains the suspicious word '" + word + "'")
                break
    return points


def scan(text):
    """Scan the text and return the result dictionary."""
    score = 0
    reasons = []
    lower = text.lower()

    # Step 1: scam keywords
    for word, points, why in SCAM_KEYWORDS:
        if word in lower:
            score += points
            reasons.append(why)

    # Step 2: find links and check each one
    urls = re.findall(r"(?:https?://|www\.)[^\s]+", text)
    for url in urls:
        score += check_url(url, reasons)

    # Step 3: bare domains in the risk database (no http:// in the text)
    if not urls:
        for bad in RISK_DOMAINS:
            if bad in lower:
                score += 50
                reasons.append("'" + bad + "' is in our known scam database")

    # Step 4: payment IDs like name@bank (skip text that is part of a link)
    text_without_urls = re.sub(r"(?:https?://|www\.)[^\s]+", " ", text)
    pids = re.findall(r"[a-zA-Z0-9._\-]{2,}@[a-zA-Z]{2,}", text_without_urls)
    for pid in pids:
        score += check_payment_id(pid, reasons)

    # Keep score between 0 and 100
    if score > 100:
        score = 100

    # Step 5: choose the verdict and color
    if score >= 60:
        verdict, color = "DANGEROUS", "red"
    elif score >= 25:
        verdict, color = "SUSPICIOUS", "orange"
    else:
        verdict, color = "SAFE", "green"
        if len(reasons) == 0:
            reasons.append("No scam keywords, bad links or risky payment IDs found")

    return {"score": score, "verdict": verdict, "color": color, "reasons": reasons}


# ---------------------------------------------------------------
# 4. WEB SERVER
# (BaseHTTPRequestHandler is the one class Python's http.server needs)
# ---------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):

    def send_cors_headers(self):
        # CORS headers let the browser page talk to this server
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        # Browser asks permission first (preflight request)
        self.send_response(204)
        self.send_cors_headers()
        self.end_headers()

    def do_POST(self):
        if self.path != "/api/scan":
            self.send_response(404)
            self.send_cors_headers()
            self.end_headers()
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            text = str(body.get("text", "")).strip()
            if text == "":
                result = {"error": "Please paste some text first"}
                status = 400
            else:
                result = scan(text)
                status = 200
        except Exception:
            result = {"error": "Invalid request"}
            status = 400

        data = json.dumps(result).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    server = HTTPServer(("localhost", 8000), Handler)
    print("Scam Checker backend running at http://localhost:8000")
    server.serve_forever()