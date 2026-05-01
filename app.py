from flask import Flask, render_template, request
import pickle
import email
from email import policy
import os
import requests
import re
from PyPDF2 import PdfReader

app = Flask(__name__)

# -------------------------------
# Load ML model
# -------------------------------
model = pickle.load(open("phishing_model.pkl", "rb"))

# -------------------------------
# Dashboard counters
# -------------------------------
total_checks = 0
phishing_count = 0
safe_count = 0

# -------------------------------
# Google Safe Browsing API
# -------------------------------
API_KEY = "YOUR_API_KEY_HERE"

def check_url_safety(url):
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

    payload = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(endpoint, json=payload)
        if response.status_code == 200:
            if "matches" in response.json():
                return True
    except:
        pass

    return False

# -------------------------------
# Extract URLs
# -------------------------------
def extract_urls(text):
    return re.findall(r'https?://\S+', text)

# -------------------------------
# Rule-based detection
# -------------------------------
def check_phishing_rules(email_text):
    score = 0
    words = ["urgent", "verify", "password", "click", "bank"]

    for w in words:
        if w in email_text.lower():
            score += 0.2

    if "http" in email_text:
        score += 0.3

    return min(score, 1)

# -------------------------------
# Feature extraction
# -------------------------------
def extract_features(email_text):
    return [
        len(email_text),
        email_text.count("http"),
        email_text.count("!"),
        sum(word in email_text.lower() for word in ["urgent", "verify", "password"])
    ]

# -------------------------------
# EML reader
# -------------------------------
def extract_eml_text(file):
    msg = email.message_from_bytes(file.read(), policy=policy.default)
    text = ""

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                text += part.get_content()
    else:
        text = msg.get_content()

    return text

# -------------------------------
# PDF reader
# -------------------------------
def extract_pdf_text(file):
    reader = PdfReader(file)
    text = ""

    for page in reader.pages:
        text += page.extract_text() or ""

    return text

# -------------------------------
# MAIN ROUTE
# -------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    global total_checks, phishing_count, safe_count

    result = None
    score = 0
    reasons = []

    if request.method == "POST":

        # Input handling
        if "file" in request.files and request.files["file"].filename != "":
            file = request.files["file"]

            if file.filename.endswith(".eml"):
                email_text = extract_eml_text(file)

            elif file.filename.endswith(".pdf"):
                email_text = extract_pdf_text(file)

            else:
                email_text = file.read().decode("utf-8", errors="ignore")
        else:
            email_text = request.form.get("email", "")

        # ML prediction
        features = extract_features(email_text)
        ml_prediction = model.predict([features])[0]

        # Rule score
        rule_score = check_phishing_rules(email_text)

        # Hybrid
        score = (rule_score * 0.4) + (ml_prediction * 0.6)

        # URL safety check
        urls = extract_urls(email_text)
        for url in urls:
            if check_url_safety(url):
                reasons.append(f"Unsafe URL detected: {url}")
                score += 0.3

        # Result
        if score > 0.5:
            result = "Phishing Email"
            phishing_count += 1
        else:
            result = "Safe Email"
            safe_count += 1

        total_checks += 1

        # Reasons
        if "urgent" in email_text.lower():
            reasons.append("Contains urgent words")

        if "http" in email_text:
            reasons.append("Contains suspicious link")

        if "password" in email_text.lower():
            reasons.append("Asks for sensitive information")

    return render_template("index.html", result=result, score=score, reasons=reasons)

# -------------------------------
# DASHBOARD
# -------------------------------
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html",
                           total=total_checks,
                           phishing=phishing_count,
                           safe=safe_count)

# -------------------------------
# RUN
# -------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
