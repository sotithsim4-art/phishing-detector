# Phishing Email Detector

A Python tool that analyzes an email for common phishing red flags and gives a verdict on whether it is safe, suspicious, or likely phishing.

## What it checks
- Urgent or manipulative language
- Suspicious URLs and shortened links
- Suspicious sender email addresses
- Known phishing domain patterns

## How to run

```
python phishing_detector.py
```

## Example

```
Phishing Email Detector
-----------------------
Enter sender email: security123@paypa1.com
Enter email subject: URGENT: Verify your account now
Enter email body: Click here to confirm your identity immediately or your account will be suspended.

--- Phishing Analysis Results ---
Sender: security123@paypa1.com
Subject: URGENT: Verify your account now

Red flags found:
  - Urgent language detected: 'urgent'
  - Urgent language detected: 'immediate'
  - Urgent language detected: 'verify your account'
  - Urgent language detected: 'suspended'
  - Urgent language detected: 'click here'
  - Urgent language detected: 'confirm your identity'
  - Sender address contains numbers: security123@paypa1.com
  - Sender domain looks suspicious: paypa1.com

Verdict: LIKELY PHISHING - Do not click any links or reply.
---------------------------------
```

Checks also cover links in the subject, lookalike sender domains such as `paypa1.com`, and links that hide the real site before an `@` sign. A shortened name that only appears inside a longer path, such as `mybit.ly`, is not treated as `bit.ly`.

Broken and improved with Grok Build.

## Why this matters

Phishing is one of the most common attack vectors in cybersecurity. This tool demonstrates awareness of social engineering techniques used by attackers.
