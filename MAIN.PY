# Backend/main.py
# Scam Checker backend - Python 3, standard library only.
# Run with:  python Backend/main.py

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import re

# ---------------------------------------------------------------
# 1. RISK DATABASE (add your own entries)
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
# 2. SCAM / SPAM KEYWORDS: (keyword, points, explanation)
# ---------------------------------------------------------------
SCAM_KEYWORDS = [
    ("urgent", 10, "Uses urgency to pressure you ('urgent')"),
    ("immediately", 10, "Pressures you to act immediately"),
    ("act now", 10, "Pressures you to 'act now'"),
    ("limited offer", 10, "Uses a 'limited offer' pressure tactic"),
    ("last chance", 10, "Uses a 'last chance' pressure tactic"),
    ("account blocked", 20, "Threatens that your account will be blocked"),
    ("account suspended", 20, "Threatens that your account will be suspended"),
    ("account will be closed", 20, "Threatens to close your account"),
    ("kyc", 15, "Mentions KYC update, a very common scam trick"),
    ("lottery", 25, "Mentions a lottery, which is usually fake"),
    ("you have won", 25, "Claims that you have won a prize"),
    ("congratulations", 10, "Starts with 'congratulations', common in prize scams"),
    ("winner", 15, "Calls you a 'winner'"),
    ("prize", 15, "Mentions a prize"),
    ("claim your", 15, "Asks you to claim something"),
    ("otp", 20, "Asks about your OTP (never share it with anyone)"),
    ("pin", 10, "Mentions a PIN (never share it)"),
    ("cvv", 25, "Asks for your CVV (never share it)"),
    ("password", 15, "Mentions your password (never share it)"),
    ("refund", 10, "Mentions a refund, often used to trick people"),
    ("loan approved", 20, "Mentions a surprise loan approval"),
    ("click here", 15, "Asks you to 'click here'"),
    ("verify your", 10, "Asks you to verify your details"),
    ("update your", 10, "Asks you to update your details"),
    ("send money", 20, "Asks you to send money"),
    ("gift card", 20, "Asks for gift cards"),
    ("work from home", 15, "Mentions an easy 'work from home' job offer"),
    ("earn money", 15, "Promises easy money"),
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


def has_word(word, text):
    """True if the word appears as a whole word (so 'pin' does not match 'shipping')."""
    return re.search(r"\b" + re.escape(word) + r"\b", text) is not None


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
            reasons.append("Domain pretends to be")