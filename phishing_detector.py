import re

URGENT_WORDS = [
    "urgent", "immediate", "act now", "limited time", "expires",
    "verify your account", "suspended", "unusual activity", "click here",
    "confirm your identity", "winner", "congratulations", "free gift",
    "you have been selected"
]

SUSPICIOUS_DOMAINS = [
    "bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly",
    "paypa1.com", "amaz0n.com", "secure-login", "account-verify"
]

def analyze_email(sender, subject, body):
    score = 0
    warnings = []

    full_text = (subject + " " + body).lower()

    for word in URGENT_WORDS:
        if word in full_text:
            score += 1
            warnings.append(f"Urgent language detected: '{word}'")

    urls = re.findall(r'https?://\S+', body)
    for url in urls:
        for domain in SUSPICIOUS_DOMAINS:
            if domain in url.lower():
                score += 2
                warnings.append(f"Suspicious URL detected: {url}")

    if re.search(r'\d+', sender.split("@")[0]):
        score += 1
        warnings.append(f"Sender address contains numbers: {sender}")

    if not re.search(r'@[\w.-]+\.[a-zA-Z]{2,}', sender):
        score += 2
        warnings.append("Sender email address looks invalid")

    print("\n--- Phishing Analysis Results ---")
    print(f"Sender: {sender}")
    print(f"Subject: {subject}")
    print()

    if warnings:
        print("Red flags found:")
        for w in warnings:
            print(f"  - {w}")
    else:
        print("No red flags found.")

    print()
    if score == 0:
        print("Verdict: SAFE - This email looks legitimate.")
    elif score <= 2:
        print("Verdict: SUSPICIOUS - Proceed with caution.")
    else:
        print("Verdict: LIKELY PHISHING - Do not click any links or reply.")

    print("---------------------------------")

print("Phishing Email Detector")
print("-----------------------")
sender = input("Enter sender email: ").strip()
subject = input("Enter email subject: ").strip()
print("Enter email body (press Enter twice when done):")

lines = []
while True:
    line = input()
    if line == "":
        break
    lines.append(line)
body = " ".join(lines)

analyze_email(sender, subject, body)
