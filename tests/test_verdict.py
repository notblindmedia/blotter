import re
import unittest

from blotter.findings import CLEAR, ERROR, MALICIOUS, SUSPICIOUS, UNKNOWN, Finding
from blotter.verdict import VERDICTS, decide


def f(level, text="A sentence."):
    return Finding("x", level, text)


class VerdictTests(unittest.TestCase):
    def test_malicious_wins(self):
        self.assertEqual(decide([f(CLEAR), f(SUSPICIOUS), f(MALICIOUS), f(ERROR)])["verdict"], "malicious")

    def test_suspicious(self):
        self.assertEqual(decide([f(CLEAR), f(SUSPICIOUS)])["verdict"], "suspicious")

    def test_no_known_detections_even_with_some_errors(self):
        v = decide([f(CLEAR, "Ran fine."), f(ERROR, "Couldn't run.")])
        self.assertEqual(v["verdict"], "no_known_detections")
        self.assertEqual(v["reasons"], ["Ran fine.", "Couldn't run."])

    def test_unknown_counts_as_ran(self):
        self.assertEqual(decide([f(UNKNOWN), f(ERROR)])["verdict"], "no_known_detections")

    def test_all_errors(self):
        self.assertEqual(decide([f(ERROR), f(ERROR)])["verdict"], "couldnt_check")
        self.assertEqual(decide([])["verdict"], "couldnt_check")

    def test_reasons_put_detections_first(self):
        v = decide([f(ERROR, "e."), f(CLEAR, "c."), f(MALICIOUS, "m.")])
        self.assertEqual(v["reasons"][0], "m.")

    def test_never_says_safe(self):
        for title, summary in VERDICTS.values():
            self.assertNotRegex((title + summary).lower(), r"\bsafe")


class NoSafeWordInSourceTests(unittest.TestCase):
    """No sentence a person can read may call a file safe."""

    def test_sources(self):
        from pathlib import Path
        root = Path(__file__).parent.parent / "blotter"
        for path in list(root.rglob("*.py")) + list(root.rglob("*.html")) + list(root.rglob("*.js")):
            text = path.read_text(encoding="utf-8").lower()
            self.assertIsNone(re.search(r"\bsafe\b|100%", text), f"'safe' or '100%' found in {path.name}")


if __name__ == "__main__":
    unittest.main()
