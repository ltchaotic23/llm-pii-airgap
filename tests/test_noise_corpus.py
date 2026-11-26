"""False alarms: realistic snippets that must come through unchanged.

Over-redaction makes a scrubbed transcript less useful, so the snippets an agent transcript is
full of are checked here. Known over-redaction is asserted in test_misses_corpus.py instead.
"""

from __future__ import annotations

import json
import unittest

from support import PIIAirgap, redact_secrets, sample_profile, scrub_jsonl_stream

SCRUBBER_NOISE = [
    # code that talks about tokens, secrets and passwords
    "response = client.messages.create(model=m, max_tokens=4096)",
    "tokenizer = AutoTokenizer.from_pretrained(name)",
    "usage.input_tokens + usage.output_tokens",
    "set max_tokens: 1024 and temperature: 0.2",
    "if not token:",
    "Error: invalid token",
    "the token count is 512",
    "I passed the token to the function.",
    "Bearer authentication uses a token",
    "The secret sauce is testing.",
    "Use the `secret` field.",
    "passphrase-protected key",
    "def test_password_reset(self):",
    "PASSWORD=",
    '"token": null',
    "use_secret: false",
    "def refresh(token: str = None):",
    # identifiers, versions and links
    "git log --oneline: a1b2c3d Fix the tokenizer",
    "pip install requests==2.32.3 and python 3.12.10",
    "see https://docs.python.org/3/library/re.html",
    "https://github.com/example/repo/blob/main/src/llm_pii_airgap/tokenizer.py",
    "C:\\Users\\exampleuser\\project\\src\\module\\file.py",
    "@dataclass(frozen=True)",
    "font-size: 12px; color: #ff0000",
    "range 10-20, ratio 1:2",
    "localhost:8080",
    "Traceback (most recent call last):\n  File \"main.py\", line 12, in <module>",
    # package specs, Actions refs, timestamps, uppercase identifiers, browser UA, Markdown links
    "npm install typescript@5.6.3 react@18.3.1",
    "pnpm add @types/node@22.9.0",
    "npx create-next-app@14.2.0 my-app",
    "uses: actions/checkout@v4.2.2",
    "go install golang.org/x/tools/gopls@v0.16.2",
    "cargo install ripgrep@14.1.1",
    "+2026-11-25 14:30:00 INFO Starting worker",
    "+2026-11-25: bump version to 0.2.0",
    "User-Agent: Mozilla/5.0 Chrome/131.0.677.86 Safari/537.36",
    "token_type = 'Bearer'",
    "TOKENIZER = AutoTokenizer.from_pretrained('bert-base-uncased')",
    "SECRETARY = 'Alex'",
    "PASS_RATE = 0.95",
    "[Image of architecture diagram](docs/arch.png)",
    "![Image comparison](before-after.png)",
]


class TestScrubberNoise(unittest.TestCase):
    def test_snippets_stay_unchanged(self) -> None:
        for sample in SCRUBBER_NOISE:
            with self.subTest(sample=sample):
                self.assertEqual(redact_secrets(sample), (sample, {}))

    def test_a_transcript_of_noise_reports_no_redactions(self) -> None:
        lines = [json.dumps({"type": "user", "uuid": str(i), "message": {"content": s}}) for i, s in enumerate(SCRUBBER_NOISE)]
        rows, summary = scrub_jsonl_stream(lines)
        self.assertEqual(summary["redactions"], {})
        self.assertEqual([row["text"] for row in rows], [s.strip() for s in SCRUBBER_NOISE])

    def test_base64_image_parts_in_a_transcript_are_not_scanned(self) -> None:
        image = {"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                             "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"}}
        record = {"type": "user", "message": {"content": [{"type": "text", "text": "what is in this picture?"}, image]}}
        rows, summary = scrub_jsonl_stream([json.dumps(record)])
        self.assertEqual((rows[0]["text"], summary["redactions"]), ("what is in this picture?", {}))


class TestTokenizerNoise(unittest.TestCase):
    def test_ordinary_words_that_contain_a_profile_value(self) -> None:
        airgap = PIIAirgap(sample_profile())
        for text in (
            "Alexander Examples",
            "Alexample",
            "123456 and 012345",
            "EMP-90421",
            "xalex.example@example.invalid",
            "+1 202 555 01430",
            "Maple Avenue is a street name",
            "Springfield",
        ):
            with self.subTest(text=text):
                self.assertEqual(airgap.sanitize_prompt(text), text)

    def test_short_values_never_match_inside_words(self) -> None:
        from support import IdentityProfile
        airgap = PIIAirgap(IdentityProfile(custom_fields={"nick": "Ann", "code": "ABC"}))
        self.assertEqual(airgap.sanitize_prompt("Annual banner, Joanna, ABCD, xabc"), "Annual banner, Joanna, ABCD, xabc")


if __name__ == "__main__":
    unittest.main()
