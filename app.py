from flask import Flask, render_template, request
import pickle
import email
from email import policy
import os

app = Flask(__name__)

# Load ML model
model = pickle.load(open("phishing_model.pkl", "rb"))

# -------------------------------
# Rule-based detection
# -------------------------------
def check_phishing_rules(email_text):
    score = 0
    suspicious_words = ["urgent", "verify", "password", "click", "bank"]

    for word in suspicious_words:
        if word in email_text.lower():
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
# .eml file reader
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
# Main route
# -------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    score = 0
    reasons = []

    if request.method == "POST":

        # Get email text OR .eml file
        if "file" in request.files and request.files["file"].filename != "":
            file = request.files["file"]
            email_text = extract_eml_text(file)
        else:
            email_text = request.form.get("email", "")

        # ML prediction
        features = extract_features(email_text)
        ml_prediction = model.predict([features])[0]

        # Rule score
        rule_score = check_phishing_rules(email_text)

        # Hybrid score
        final_score = (rule_score * 0.4) + (ml_prediction * 0.6)
        score = final_score

        # Result
        if final_score > 0.5:
            result = "Phishing Email"
        else:
            result = "Safe Email"

        # Reasons
        if "urgent" in email_text.lower():
            reasons.append("Contains urgent words")

        if "http" in email_text:
            reasons.append("Contains suspicious link")

        if "password" in email_text.lower():
            reasons.append("Asks for sensitive information")

    return render_template("index.html", result=result, score=score, reasons=reasons)

# -------------------------------
# Run app (Render compatible)
# -------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
