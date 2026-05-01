from flask import Flask, render_template, request
import pickle
import email
from email import policy
import os
import re
from PyPDF2 import PdfReader

app = Flask(__name__)

# Load ML model
model = pickle.load(open("phishing_model.pkl", "rb"))

# Dashboard counters
total_checks = 0
phishing_count = 0
safe_count = 0

# -------------------------------
# Extract URLs
# -------------------------------
def extract_urls(text):
    return re.findall(r'https?://\S+', text)

# -------------------------------
# Rule-based detection
# -------------------------------
def check_phishing_rules(text):
    score = 0
    words = ["urgent", "verify", "password", "click", "bank"]

    for w in words:
        if w in text.lower():
            score += 0.2

    if "http" in text:
        score += 0.3

    return min(score, 1)

# -------------------------------
# ✅ FIXED Feature extraction (6 features)
# -------------------------------
def extract_features(text):
    return [
        len(text),                          # 1
        text.count("http"),                # 2
        text.count("!"),                   # 3
        text.count("@"),                   # 4
        text.count("https"),               # 5
        sum(word in text.lower() for word in ["urgent", "verify", "password"])  # 6
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
# AI Explanation
# -------------------------------
def generate_ai_explanation(reasons, result):
    if not reasons:
        return "This email appears safe with no strong phishing indicators."

    if "Phishing" in result:
        return "This email appears to be phishing because it " + ", ".join(reasons) + "."
    else:
        return "This email seems safe but has minor indicators like " + ", ".join(reasons) + "."

# -------------------------------
# MAIN ROUTE
# -------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    global total_checks, phishing_count, safe_count

    result = None
    score = 0
    reasons = []
    explanation = ""

    if request.method == "POST":

        # Input handling
        if "file" in request.files and request.files["file"].filename != "":
            file = request.files["file"]

            if file.filename.endswith(".eml"):
                text = extract_eml_text(file)

            elif file.filename.endswith(".pdf"):
                text = extract_pdf_text(file)

            else:
                text = file.read().decode("utf-8", errors="ignore")
        else:
            text = request.form.get("email") or ""

        # ML prediction
        features = extract_features(text)
        ml_prediction = model.predict([features])[0]

        # Rule score
        rule_score = check_phishing_rules(text)

        # Hybrid score
        score = (rule_score * 0.4) + (ml_prediction * 0.6)

        # Result
        if score > 0.5:
            result = "Phishing Email"
            phishing_count += 1
        else:
            result = "Safe Email"
            safe_count += 1

        total_checks += 1

        # Reasons
        if "urgent" in text.lower():
            reasons.append("contains urgent words")

        if "http" in text:
            reasons.append("contains suspicious link")

        if "password" in text.lower():
            reasons.append("asks for sensitive information")

        # AI Explanation
        explanation = generate_ai_explanation(reasons, result)

    return render_template("index.html", result=result, score=score,
                           reasons=reasons, explanation=explanation)

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
