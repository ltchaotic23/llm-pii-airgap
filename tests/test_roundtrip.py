"""Sanitise then rehydrate gives back the original text.

The random tests use fixed seeds (standard library `random`), so a failure always reproduces.
What is not preserved exactly: a matched value comes back in the profile's own spelling, so
its letter case and the whitespace inside it are not kept (test_case_and_whitespace_are_not_kept).
"""

from __future__ import annotations

import random
import unittest

from support import SAMPLE_PROFILE_DATA, IdentityProfile, PIIAirgap, sample_profile

WORDS = (
    "the a draft letter please write reply about project meeting notes on for to with and "
    "invoice support ticket thanks regards review code test build release plan 2026 v1.2 #42"
).split()
SEPARATORS = [" ", " ", " ", ", ", ". ", "\n", " (", ") ", ": ", " - ", "\t", "\"", "'"]


def profile_values() -> list[str]:
    data = SAMPLE_PROFILE_DATA
    return [data["full_name"], data["email"], data["phone"], data["street_address"], data["postal_code"],
            *data["custom_fields"].values()]


class TestRoundTrip(unittest.TestCase):
    def test_sanitize_and_rehydrate_roundtrip(self) -> None:
        airgap = PIIAirgap(sample_profile())
        outbound = (
            "Draft a cover letter for Alex Example living at 100 Maple Avenue, Springfield "
            "(postal_code 12345). Contact alex.example@example.invalid or +1 202 555 0143, "
            "ref EMP-9042."
        )
        sanitized = airgap.sanitize_prompt(outbound)
        self.assertEqual(airgap.contains_raw_pii(sanitized), [])
        for token in ("[FULL_NAME]", "[ADDRESS]", "[POSTAL_CODE]", "[EMAIL]", "[PHONE]", "[CUSTOM_EMPLOYEE_ID]"):
            self.assertIn(token, sanitized)
        self.assertNotIn("Alex Example", sanitized)

        restored = airgap.rehydrate(sanitized, allow=airgap.placeholders_in(sanitized))
        self.assertEqual(restored, outbound)

    def test_random_text_with_profile_values(self) -> None:
        airgap = PIIAirgap(sample_profile())
        values = profile_values()
        for seed in range(300):
            rng = random.Random(seed)
            pieces = []
            for _ in range(rng.randint(1, 30)):
                pieces.append(rng.choice(values) if rng.random() < 0.3 else rng.choice(WORDS))
                pieces.append(rng.choice(SEPARATORS))
            original = "".join(pieces)
            with self.subTest(seed=seed):
                sanitized = airgap.sanitize_prompt(original)
                for value in values:
                    self.assertNotIn(value, sanitized)
                self.assertEqual(airgap.contains_raw_pii(sanitized), [])
                self.assertEqual(airgap.rehydrate(sanitized, allow=airgap.placeholders_in(sanitized)), original)

    def test_random_json_payloads(self) -> None:
        airgap = PIIAirgap(sample_profile())
        values = profile_values()
        everything = airgap.profile.placeholder_map().keys()
        for seed in range(100):
            rng = random.Random(seed)

            def build(depth: int):
                kind = rng.random()
                if depth > 3 or kind < 0.4:
                    return rng.choice(values + WORDS) + rng.choice(["", " " + rng.choice(WORDS)])
                if kind < 0.7:
                    return [build(depth + 1) for _ in range(rng.randint(0, 4))]
                return {f"{rng.choice(WORDS)}{i}": build(depth + 1) for i in range(rng.randint(0, 4))}

            payload = build(0)
            with self.subTest(seed=seed):
                sanitized = airgap.sanitize_payload(payload)
                self.assertEqual(airgap.rehydrate(sanitized, allow=everything), payload)

    def test_case_and_whitespace_are_not_kept(self) -> None:
        airgap = PIIAirgap(IdentityProfile(full_name="Alex Example"))
        sent = airgap.sanitize_prompt("Hi ALEX\n   example!")
        self.assertEqual(sent, "Hi [FULL_NAME]!")
        self.assertEqual(airgap.rehydrate(sent, allow={"[FULL_NAME]"}), "Hi Alex Example!")


if __name__ == "__main__":
    unittest.main()
