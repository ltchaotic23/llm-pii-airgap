"""Offline unit test suite for llm-pii-airgap (zero external API calls)."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from llm_pii_airgap import (  # noqa: E402
    IdentityProfile,
    PIIAirgap,
    redact_secrets,
    scrub_jsonl_stream,
    strip_harness_tags,
)
from llm_pii_airgap.cli import main as cli_main  # noqa: E402


def _sample_profile() -> IdentityProfile:
    return IdentityProfile(
        full_name="Alex Example",
        email="alex.example@example.invalid",
        phone="+1 202 555 0143",
        street_address="100 Maple Avenue, Springfield",
        postal_code="12345",
        custom_fields={"employee_id": "EMP-9042"},
    )


class TestPIIAirgap(unittest.TestCase):
    def test_sanitize_and_rehydrate_roundtrip(self) -> None:
        airgap = PIIAirgap(_sample_profile())
        outbound = (
            "Draft a cover letter for Alex Example living at 100 Maple Avenue, Springfield "
            "(postal_code 12345). Contact alex.example@example.invalid or +1 202 555 0143, "
            "ref EMP-9042."
        )
        sanitized = airgap.sanitize_prompt(outbound)
        self.assertEqual(airgap.contains_raw_pii(sanitized), [])
        self.assertIn("[FULL_NAME]", sanitized)
        self.assertIn("[ADDRESS]", sanitized)
        self.assertIn("[POSTAL_CODE]", sanitized)
        self.assertIn("[EMAIL]", sanitized)
        self.assertIn("[PHONE]", sanitized)
        self.assertIn("[CUSTOM_EMPLOYEE_ID]", sanitized)
        self.assertNotIn("Alex Example", sanitized)

        restored = airgap.rehydrate(sanitized)
        self.assertIn("Alex Example", restored)
        self.assertIn("100 Maple Avenue, Springfield", restored)
        self.assertIn("12345", restored)
        self.assertIn("alex.example@example.invalid", restored)
        self.assertIn("+1 202 555 0143", restored)
        self.assertIn("EMP-9042", restored)

    def test_longest_match_prevents_fragment_leak(self) -> None:
        # street_address overlaps with postal_code; longest-first ensures full address wins.
        profile = IdentityProfile(
            street_address="200 Oak Road, Riverside, 54321",
            postal_code="54321",
        )
        airgap = PIIAirgap(profile)
        sanitized = airgap.sanitize_prompt("Send to 200 Oak Road, Riverside, 54321 today.")
        self.assertEqual(sanitized, "Send to [ADDRESS] today.")
        self.assertEqual(airgap.contains_raw_pii(sanitized), [])

    def test_rehydrate_nested_structures(self) -> None:
        airgap = PIIAirgap(_sample_profile())
        payload = {
            "header": {"name": "[FULL_NAME]", "email": "[EMAIL]"},
            "lines": ["Call [PHONE]", ["Post to [ADDRESS], [POSTAL_CODE]"], 42],
        }
        result = airgap.rehydrate(payload)
        self.assertEqual(result["header"]["name"], "Alex Example")
        self.assertEqual(result["header"]["email"], "alex.example@example.invalid")
        self.assertEqual(result["lines"][0], "Call +1 202 555 0143")
        self.assertEqual(result["lines"][1][0], "Post to 100 Maple Avenue, Springfield, 12345")
        self.assertEqual(result["lines"][2], 42)


class TestSecretScrubber(unittest.TestCase):
    def test_all_eleven_redaction_rules(self) -> None:
        # Construct synthetic fixtures dynamically so secret scanners never flag test code.
        fake_priv = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END " + "RSA PRIVATE KEY-----"
        fake_discord = "MTI" + "AbCdEfGhIjKlMnOpQrStUvW" + ".XaBcDe." + "1234567890abcdefGHIJKLMNOPQRstuvwx"
        fake_gh = "ghp_" + ("A1b2C3d4E5" * 4)
        fake_google = "AIza" + ("0123456789abcde" * 2) + "12345"
        fake_sk = "sk-" + ("abc123XYZ_" * 3)
        fake_url = "https://" + "alice:superpass123" + "@registry.example.invalid/pkg"
        fake_proxy = "vless://" + "11112222-3333-4444-5555-666677778888@203.0.113.10:443?security=reality#test"
        fake_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        fake_long = "Z9" + ("aB3dE6fG8h" * 4) + "=="

        sample = "\n".join(
            [
                fake_priv,
                f"bot={fake_discord}",
                f"gh={fake_gh} google={fake_google} openai={fake_sk}",
                f"repo={fake_url}",
                f"node={fake_proxy}",
                f"id={fake_uuid}",
                "mail=dev.user@example.invalid",
                "host=198.51.100.42",
                "tel=+1 202 555 0178",
                "password = my_local_dev_pw",
                f"blob={fake_long}",
            ]
        )
        scrubbed, counts = redact_secrets(sample)
        expected_tags = [
            "<PRIVATE_KEY>",
            "<DISCORD_TOKEN>",
            "<API_KEY>",
            "<URL_WITH_CREDS>",
            "<PROXY_URI>",
            "<UUID>",
            "<EMAIL>",
            "<IP>",
            "<PHONE>",
            "<SECRET>",
            "<LONG_TOKEN>",
        ]
        for tag in expected_tags:
            self.assertIn(tag, scrubbed)
            self.assertGreaterEqual(counts.get(tag, 0), 1)
        self.assertNotIn("superpass123", scrubbed)
        self.assertNotIn("my_local_dev_pw", scrubbed)
        self.assertNotIn("198.51.100.42", scrubbed)

    def test_strip_harness_tags(self) -> None:
        raw = (
            "Hello world\n"
            "<system-reminder>Internal prompt</system-reminder>\n"
            "<pasted_content_1>Secret dump</pasted_content_1>\n"
            "[Image #1] Keep this sentence."
        )
        cleaned = strip_harness_tags(raw)
        self.assertNotIn("Internal prompt", cleaned)
        self.assertNotIn("Secret dump", cleaned)
        self.assertNotIn("[Image #1]", cleaned)
        self.assertIn("Hello world", cleaned)
        self.assertIn("Keep this sentence.", cleaned)

    def test_scrub_jsonl_stream_filtering_and_dedup(self) -> None:
        fake_key = "ghp_" + ("Z9y8X7w6V5" * 4)
        records = [
            {"type": "assistant", "uuid": "u0", "message": {"content": "Model reply"}},
            {"type": "user", "uuid": "u1", "isSidechain": True, "message": {"content": "Skip me"}},
            {
                "type": "user",
                "uuid": "u2",
                "message": {"content": [{"type": "tool_result", "content": "output"}]},
            },
            {
                "type": "user",
                "uuid": "u3",
                "timestamp": "2026-11-15T12:00:00Z",
                "message": {"content": f"<system-reminder>ctx</system-reminder>Use {fake_key} on 10.0.0.5"},
            },
            # Duplicate uuid u3 should be dropped
            {
                "type": "user",
                "uuid": "u3",
                "timestamp": "2026-11-15T12:00:00Z",
                "message": {"content": "Duplicate"},
            },
            {"type": "user", "uuid": "u4", "message": {"content": "<task-notification>Ignore</task-notification>"}},
        ]
        lines = [json.dumps(r) for r in records] + ["{bad json"]
        rows, summary = scrub_jsonl_stream(lines)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["uuid"], "u3")
        self.assertEqual(rows[0]["text"], "Use <API_KEY> on <IP>")
        self.assertEqual(summary["duplicates_skipped"], 1)
        self.assertEqual(summary["invalid_json"], 1)
        self.assertEqual(summary["rows_kept"], 1)
        self.assertEqual(summary["redactions"]["<API_KEY>"], 1)
        self.assertEqual(summary["redactions"]["<IP>"], 1)


class TestCLI(unittest.TestCase):
    def test_cli_sanitize_rehydrate_check_and_scrub(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            profile_path = tmp_dir / "profile.json"
            profile_path.write_text(
                json.dumps(
                    {
                        "full_name": "Alex Example",
                        "email": "alex.example@example.invalid",
                        "phone": "+1 202 555 0143",
                        "street_address": "100 Maple Avenue",
                        "postal_code": "12345",
                    }
                ),
                encoding="utf-8",
            )
            prompt_file = tmp_dir / "prompt.txt"
            sanitized_file = tmp_dir / "sanitized.txt"
            rehydrated_file = tmp_dir / "rehydrated.txt"
            prompt_file.write_text("Email Alex Example at alex.example@example.invalid", encoding="utf-8")

            self.assertEqual(
                cli_main(["sanitize", "-p", str(profile_path), "-i", str(prompt_file), "-o", str(sanitized_file)]),
                0,
            )
            sanitized_text = sanitized_file.read_text(encoding="utf-8")
            self.assertEqual(sanitized_text, "Email [FULL_NAME] at [EMAIL]")

            # check returns 1 on raw PII and 0 on clean text without echoing raw PII
            buf_leak = io.StringIO()
            with contextlib.redirect_stdout(buf_leak):
                rc_leak = cli_main(["check", "-p", str(profile_path), "-i", str(prompt_file)])
            self.assertEqual(rc_leak, 1)
            self.assertNotIn("Alex Example", buf_leak.getvalue())
            self.assertEqual(json.loads(buf_leak.getvalue())["clean"], False)

            buf_clean = io.StringIO()
            with contextlib.redirect_stdout(buf_clean):
                rc_clean = cli_main(["check", "-p", str(profile_path), "-i", str(sanitized_file)])
            self.assertEqual(rc_clean, 0)
            self.assertEqual(json.loads(buf_clean.getvalue())["clean"], True)

            self.assertEqual(
                cli_main(["rehydrate", "-p", str(profile_path), "-i", str(sanitized_file), "-o", str(rehydrated_file)]),
                0,
            )
            self.assertEqual(
                rehydrated_file.read_text(encoding="utf-8"),
                "Email Alex Example at alex.example@example.invalid",
            )

            in_jsonl = tmp_dir / "in.jsonl"
            out_jsonl = tmp_dir / "out.jsonl"
            in_jsonl.write_text(
                json.dumps({"type": "user", "uuid": "1", "message": {"content": "Ping 203.0.113.9"}}) + "\n",
                encoding="utf-8",
            )
            buf_scrub = io.StringIO()
            with contextlib.redirect_stdout(buf_scrub):
                rc_scrub = cli_main(["scrub", "-i", str(in_jsonl), "-o", str(out_jsonl)])
            self.assertEqual(rc_scrub, 0)
            self.assertEqual(json.loads(buf_scrub.getvalue())["rows_kept"], 1)
            scrubbed_row = json.loads(out_jsonl.read_text(encoding="utf-8").strip())
            self.assertEqual(scrubbed_row["text"], "Ping <IP>")


if __name__ == "__main__":
    unittest.main()
