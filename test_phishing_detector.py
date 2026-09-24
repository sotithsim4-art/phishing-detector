import unittest

import phishing_detector


class PhishingDetectorTests(unittest.TestCase):
    def test_lookalike_sender_domain_is_not_safe(self):
        score, warnings, verdict = phishing_detector.analyze_email(
            "security@paypa1.com",
            "Account notice",
            "Please review your statement.",
        )
        self.assertEqual(verdict, "LIKELY PHISHING")
        self.assertGreaterEqual(score, 3)
        self.assertTrue(any("paypa1.com" in warning for warning in warnings))

    def test_path_lookalike_is_not_a_shortener(self):
        _, warnings, verdict = phishing_detector.analyze_email(
            "user@example.com",
            "Notes",
            "See https://example.com/mybit.ly-notes",
        )
        self.assertEqual(verdict, "SAFE")
        self.assertEqual(warnings, [])

    def test_subject_short_link_is_flagged(self):
        _, warnings, verdict = phishing_detector.analyze_email(
            "user@example.com",
            "See https://bit.ly/x",
            "",
        )
        self.assertNotEqual(verdict, "SAFE")
        self.assertTrue(any("bit.ly" in warning for warning in warnings))

    def test_at_sign_hides_the_real_host(self):
        _, warnings, verdict = phishing_detector.analyze_email(
            "user@example.com",
            "Hello",
            "Log in at https://paypal.com@evil.example/login",
        )
        self.assertNotEqual(verdict, "SAFE")
        self.assertTrue(any("@" in warning for warning in warnings))

    def test_missing_sender_does_not_crash(self):
        _, warnings, verdict = phishing_detector.analyze_email(None, "Hi", "Hi")
        self.assertEqual(verdict, "SUSPICIOUS")
        self.assertTrue(any("invalid" in warning.lower() for warning in warnings))

    def test_ordinary_mail_stays_safe(self):
        _, warnings, verdict = phishing_detector.analyze_email(
            "user@example.com",
            "Hello",
            "Hello from your bank.",
        )
        self.assertEqual(verdict, "SAFE")
        self.assertEqual(warnings, [])


if __name__ == "__main__":
    unittest.main()
