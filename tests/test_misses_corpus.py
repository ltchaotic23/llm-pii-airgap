"""Known limits: one test per item in the README's Limits section.

Each test asserts what the tool does today with the README's own example. If a limit is fixed
or gets worse, its test fails, and the README has to change with it.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from support import IdentityProfile, PIIAirgap, j, redact_secrets, run_cli, sample_profile, scrub_jsonl_stream, strip_harness_tags, write_json

from llm_pii_airgap.cli import _profile_fields_in


class TestTokenizerLimits(unittest.TestCase):
    def setUp(self) -> None:
        self.airgap = PIIAirgap(sample_profile())

    def assert_missed(self, text: str, airgap: PIIAirgap | None = None) -> None:
        airgap = airgap or self.airgap
        with self.subTest(text=text):
            self.assertEqual(airgap.sanitize_prompt(text), text)
            self.assertEqual(_profile_fields_in(airgap, text), [])

    def test_only_exact_profile_values_are_found(self) -> None:
        for text in (
            "Alex wrote this",  # a first name alone, when only full_name is set
            "A. Example",  # initials
            "Alex Exmaple",  # a misspelling
            "Al\N{CYRILLIC SMALL LETTER IE}x Example",  # a look-alike letter
            "Sam Sample, 200 Oak Road",  # anything not in the profile
        ):
            self.assert_missed(text)

    def test_phone_numbers_follow_the_digits_as_written(self) -> None:
        for text in ("202 555 0143", "001 202 555 0143"):
            self.assert_missed(text)

    def test_split_or_reformatted_values_are_missed(self) -> None:
        for text in (
            json.dumps({"first": "Alex", "last": "Example"}),
            "100 Maple Avenue Springfield",  # the comma is missing
            "**Alex** Example",
            "<b>Alex</b> Example",
        ):
            self.assert_missed(text)

    def test_encoded_values_are_missed(self) -> None:
        for text in ("alex.example&#64;example.invalid", "alex.example%40example.invalid", "QWxleCBFeGFtcGxl"):
            self.assert_missed(text)

    def test_unicode_variants_that_no_normalisation_maps(self) -> None:
        sharp = PIIAirgap(IdentityProfile(street_address="Gro\N{LATIN SMALL LETTER SHARP S}e Stra\N{LATIN SMALL LETTER SHARP S}e 5"))
        self.assert_missed("GROSSE STRASSE 5", sharp)
        apostrophe = PIIAirgap(IdentityProfile(full_name="Sam O'Brien"))
        self.assert_missed("Sam O\N{RIGHT SINGLE QUOTATION MARK}Brien", apostrophe)

    def test_overlapping_values_that_start_at_different_points(self) -> None:
        airgap = PIIAirgap(IdentityProfile(full_name="Alex Example", street_address="Example Street 42"))
        result = airgap.sanitize_prompt("Alex Example Street 42")
        self.assertEqual(result, "[FULL_NAME] Street 42")
        self.assertEqual(_profile_fields_in(airgap, result), [])  # the rest of the address is not reported

    def test_json_escapes_nested_json_and_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile = write_json(Path(tmp) / "p.json", {"full_name": "Jos\N{LATIN SMALL LETTER E WITH ACUTE} Example",
                                                        "postal_code": "12345"})
            escaped = json.dumps({"to": "Jos\N{LATIN SMALL LETTER E WITH ACUTE} Example"})
            code, _, err = run_cli(["sanitize", "-p", str(profile), "-t", escaped])
            self.assertEqual(code, 2)
            self.assertIn("--json", err)
            nested = json.dumps({"inner": escaped})
            code, _, err = run_cli(["sanitize", "-p", str(profile), "--json", "-t", nested])
            self.assertEqual(code, 2)
            self.assertIn("nested inside a string", err)
            deep = escaped
            for level in range(1, 6):
                deep = json.dumps({f"l{level}": deep})
            code, out, _ = run_cli(["check", "-p", str(profile), "-t", deep])
            self.assertEqual((code, json.loads(out)["clean"]), (0, True))
        airgap = PIIAirgap(IdentityProfile(postal_code="12345"))
        restored = airgap.rehydrate(airgap.sanitize_payload({"zip": 12345}), allow={"[POSTAL_CODE]"})
        self.assertEqual(restored, {"zip": "12345"})

    def test_rehydrate_restores_the_profile_spelling(self) -> None:
        sent = self.airgap.sanitize_prompt("Signed, ALEX\n  EXAMPLE")
        self.assertEqual(self.airgap.rehydrate(sent, allow=self.airgap.placeholders_in(sent)), "Signed, Alex Example")

    def test_literal_placeholder_in_the_prompt_is_restored(self) -> None:
        sent = self.airgap.sanitize_prompt("Keep [EMAIL] as a slot for alex.example@example.invalid")
        self.assertEqual(sent, "Keep [EMAIL] as a slot for [EMAIL]")
        reply = self.airgap.rehydrate("Keep [EMAIL]", allow=self.airgap.placeholders_in(sent))
        self.assertEqual(reply, "Keep alex.example@example.invalid")


class TestScrubberLimits(unittest.TestCase):
    def assert_missed(self, *samples: str) -> None:
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertEqual(redact_secrets(sample), (sample, {}))

    def test_unknown_formats_are_missed(self) -> None:
        self.assert_missed(
            j("glpat-", "FAKEfake1234FAKEfake"),
            j("hf_", "FAKEfakeFAKEfakeFAKEfake12"),
            j("-----BEGIN PGP ", "PRIVATE KEY BLOCK-----\nlQOYBFAKE\n-----END PGP ", "PRIVATE KEY BLOCK-----"),
            j("-----BEGIN RSA ", "PRIVATE KEY-----\nMIIEowFAKE"),  # no END line
            j("eyJhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiIxIn0", ".", "FAKEsig"),  # a short JSON Web Token
            "2001:db8::1",
            "call 202 555 0143",
            "C:\\Users\\exampleuser\\notes.txt",
            "/home/exampleuser/notes.txt",
        )

    def test_long_key_lines_are_caught_only_by_the_generic_rule(self) -> None:
        line = "aB3dE6fG8hZ9" * 5
        block = j("-----BEGIN PGP ", "PRIVATE KEY BLOCK-----\n", line, "\n-----END PGP ", "PRIVATE KEY BLOCK-----")
        self.assertEqual(redact_secrets(block)[1], {"<LONG_TOKEN>": 1})
        self.assertIn("-----BEGIN PGP", redact_secrets(block)[0])
        unterminated = j("-----BEGIN RSA ", "PRIVATE KEY-----\n", line, "\n", line)
        self.assertEqual(redact_secrets(unterminated), (j("-----BEGIN RSA ", "PRIVATE KEY-----\n<LONG_TOKEN>\n<LONG_TOKEN>"),
                                                        {"<LONG_TOKEN>": 2}))

    def test_secret_rule_needs_a_name_next_to_the_value(self) -> None:
        value = j("hunter2", "secret")
        self.assert_missed(
            f"the password is {value}",
            f"mysql -p{value}",
            f"token:\n  value: {value}",
            j("sk-", "\n", "FAKEFAKEFAKEFAKEFAKE"),
            json.dumps({"key_part1": "sk-", "key_part2": "FAKEFAKEFAKEFAKEFAKE"}),
        )
        listed = f"password:\n  - first{value}\n  - second{value}"
        self.assertEqual(redact_secrets(listed)[0], f"password:\n  - <SECRET>\n  - second{value}")

    def test_over_redaction(self) -> None:
        sha = j("e3b0c44298fc1c149afbf4c8", "996fb92427ae41e4")
        image = j("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ", "AAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")
        for sample, expected in (
            (f"commit {sha}", "commit <LONG_TOKEN>"),
            (f"sha256: {sha}{sha[:24]}", "sha256: <LONG_TOKEN>"),
            ("/home/exampleuser/project/src/module/file_name_2.py", "/<LONG_TOKEN>.py"),
            (f"x = data:image/png;base64,{image}", "x = data:image/png;base64,<LONG_TOKEN>"),
            ("version 1.26.4.0", "version <IP>"),
            ("git@github.com:example/repo.git", "<EMAIL>:example/repo.git"),
            ("def login(password: str) -> bool:", "def login(password: <SECRET> -> bool:"),
            ("API_KEY=os.environ['API_KEY']", "API_KEY=<SECRET>"),
            ("secret_name: my-tls-cert", "secret_name: <SECRET>"),
            ("Here is the secret: keep it simple", "Here is the secret: <SECRET> it simple"),
            (f"https://example.invalid/org/repo/pull/123/commits/{sha}", "https://example.<LONG_TOKEN>"),
            ("systemctl status openvpn@server.service", "systemctl status <EMAIL>"),
            ("+1000000000", "<PHONE>"),
            ("password_hash = hashlib.sha256(raw).hexdigest()", "password_hash = <SECRET>"),
            ("interface AuthConfig { accessToken: string; refreshToken: string; }",
             "interface AuthConfig { accessToken: <SECRET> refreshToken: <SECRET> }"),
        ):
            with self.subTest(sample=sample):
                self.assertEqual(redact_secrets(sample)[0], expected)

    def test_harness_tag_gaps(self) -> None:
        self.assertEqual(strip_harness_tags("<system-reminder>hidden context"), "<system-reminder>hidden context")
        self.assertEqual(
            strip_harness_tags("<system-reminder>a<system-reminder>b</system-reminder>c</system-reminder>d"),
            "c</system-reminder>d",
        )
        self.assertEqual(strip_harness_tags("hello <command-name>/x</command-name> world"),
                         "hello <command-name>/x</command-name> world")
        rows, _ = scrub_jsonl_stream([json.dumps({"type": "user", "message": {"content": "<command-name>/x</command-name>"}})])
        self.assertEqual(rows, [])  # dropped when the message starts with it

    def test_scrub_copies_uuid_and_timestamp(self) -> None:
        record = {"type": "user", "uuid": "203.0.113.9", "timestamp": "alex@example.invalid", "message": {"content": "hi"}}
        rows, _ = scrub_jsonl_stream([json.dumps(record)])
        self.assertEqual(rows[0], {"uuid": "203.0.113.9", "timestamp": "alex@example.invalid", "text": "hi"})


if __name__ == "__main__":
    unittest.main()
