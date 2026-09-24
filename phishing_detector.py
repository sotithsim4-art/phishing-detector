import re
from urllib.parse import urlparse

URGENT_WORDS = [
    "urgent", "immediate", "act now", "limited time", "expires",
    "verify your account", "suspended", "unusual activity", "click here",
    "confirm your identity", "winner", "congratulations", "free gift",
    "you have been selected",
]

SUSPICIOUS_DOMAINS = [
    "bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly",
    "paypa1.com", "amaz0n.com", "secure-login", "account-verify",
]


def host_matches(host, marker):
    labels = host.lower().rstrip(".").split(".")
    marker = marker.lower()
    if "." in marker:
        dotted = ".".join(labels)
        return dotted == marker or dotted.endswith("." + marker)
    return marker in labels


def suspicious_url(url):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    reasons = []
    if "@" in (parsed.netloc or ""):
        reasons.append("the real site is hidden before an @ sign")
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        reasons.append("the link uses a raw IP address")
    for marker in SUSPICIOUS_DOMAINS:
        if host_matches(host, marker):
            reasons.append(f"known suspicious domain '{marker}'")
            break
    return reasons


def extract_address(sender):
    if not isinstance(sender, str):
        return ""
    match = re.search(
        r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
        sender,
    )
    if not match:
        return ""
    return match.group(0)


def find_urls(text):
    urls = re.findall(r"https?://[^\s<>'\"]+", text or "")
    return [url.rstrip(".,);]") for url in urls]


def analyze_email(sender, subject, body):
    score = 0
    warnings = []
    subject = subject if isinstance(subject, str) else ""
    body = body if isinstance(body, str) else ""
    full_text = f"{subject} {body}".lower()

    for word in URGENT_WORDS:
        if word in full_text:
            score += 1
            warnings.append(f"Urgent language detected: '{word}'")

    for url in find_urls(f"{subject}\n{body}"):
        reasons = suspicious_url(url)
        if reasons:
            score += 2
            warnings.append(f"Suspicious URL detected: {url} ({'; '.join(reasons)})")

    address = extract_address(sender)
    if not address:
        score += 2
        warnings.append("Sender email address looks invalid")
    else:
        local, domain = address.rsplit("@", 1)
        if re.search(r"\d", local):
            score += 1
            warnings.append(f"Sender address contains numbers: {address}")
        for marker in SUSPICIOUS_DOMAINS:
            if host_matches(domain, marker):
                score += 3
                warnings.append(f"Sender domain looks suspicious: {domain}")
                break

    if score == 0:
        verdict = "SAFE"
    elif score <= 2:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY PHISHING"
    return score, warnings, verdict


def report(sender, subject, body):
    score, warnings, verdict = analyze_email(sender, subject, body)
    print("\n--- Phishing Analysis Results ---")
    print(f"Sender: {sender}")
    print(f"Subject: {subject}")
    print()
    if warnings:
        print("Red flags found:")
        for warning in warnings:
            print(f"  - {warning}")
    else:
        print("No red flags found.")
    print()
    if verdict == "SAFE":
        print("Verdict: SAFE - This email looks legitimate.")
    elif verdict == "SUSPICIOUS":
        print("Verdict: SUSPICIOUS - Proceed with caution.")
    else:
        print("Verdict: LIKELY PHISHING - Do not click any links or reply.")
    print("---------------------------------")
    return score, warnings, verdict


def read_body():
    print("Enter email body (press Enter twice when done):")
    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)
    return " ".join(lines)


if __name__ == "__main__":
    print("Phishing Email Detector")
    print("-----------------------")
    sender = input("Enter sender email: ").strip()
    subject = input("Enter email subject: ").strip()
    report(sender, subject, read_body())
