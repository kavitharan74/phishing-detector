from flask import Flask, render_template, request
import pickle

app = Flask(__name__)

# Load model
model = pickle.load(open("phishing_model.pkl", "rb"))

# Simple rule-based check
def check_phishing_rules(email_text):
    score = 0

    suspicious_words = ["urgent", "verify", "password", "click", "bank"]

    for word in suspicious_words:
        if word in email_text.lower():
            score += 0.2

    if "http" in email_text:
        score += 0.3

    return min(score, 1)


# Extract features (simple fallback if your module fails)
def extract_features(email_text):
    return [
        len(email_text),                          # length
        email_text.count("http"),                # links
        email_text.count("!"),                   # exclamation
        sum(word in email_text.lower() for word in ["urgent", "verify", "password"])
    ]


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    score = 0
    reasons = []

    if request.method == "POST":
        email_text = request.form["email"]

        # ML Prediction
        features = extract_features(email_text)
        ml_prediction = model.predict([features])[0]

        # Rule score
        rule_score = check_phishing_rules(email_text)

        # Combine
        final_score = (rule_score * 0.4) + (ml_prediction * 0.6)

        # Result
        if final_score > 0.5:
            result = "Phishing Email"
        else:
            result = "Safe Email"

        score = final_score

        # Reasons
        if "urgent" in email_text.lower():
            reasons.append("Contains urgent words")

        if "http" in email_text:
            reasons.append("Contains suspicious link")

        if "password" in email_text.lower():
            reasons.append("Asks for sensitive info")

    return render_template("index.html", result=result, score=score, reasons=reasons)


if __name__ == "__main__":
    app.run(debug=True, port=8000)