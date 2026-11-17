"""Offline unit test suite for llm-pii-airgap (zero external API calls)."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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


class TestTokeniserBoundaries(unittest.TestCase):
    def test_value_is_not_replaced_inside_other_words(self) -> None:
        airgap = PIIAirgap(IdentityProfile(custom_fields={"nick": "Ann"}))
        sanitized = airgap.sanitize_prompt("Annual planning with Ann, then Joanna and ann.")
        self.assertEqual(sanitized, "Annual planning with [CUSTOM_NICK], then Joanna and [CUSTOM_NICK].")

    def test_whitespace_reflow_still_matches(self) -> None:
        airgap = PIIAirgap(_sample_profile())
        sanitized = airgap.sanitize_prompt("Signed,\nAlex\n  Example\n100 Maple\tAvenue, Springfield")
        self.assertNotIn("Alex", sanitized)
        self.assertNotIn("Avenue", sanitized)
        self.assertEqual(airgap.contains_raw_pii(sanitized), [])

    def test_phone_number_formatting_variants(self) -> None:
        airgap = PIIAirgap(_sample_profile())
        for variant in ("+12025550143", "+1-202-555-0143", "+1 (202) 555 0143", "1 202.555.0143"):
            with self.subTest(variant=variant):
                self.assertEqual(airgap.sanitize_prompt(f"Call {variant} now"), "Call [PHONE] now")
                self.assertEqual(airgap.contains_raw_pii(f"Call {variant} now"), ["[PHONE]"])
        # A longer number that merely contains the digits is a different number.
        self.assertEqual(airgap.sanitize_prompt("ref 912025550143"), "ref 912025550143")

    def test_too_short_value_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            PIIAirgap(IdentityProfile(custom_fields={"initials": "AE"}))

    def test_rehydrate_allow_list_blocks_injected_placeholders(self) -> None:
        airgap = PIIAirgap(_sample_profile())
        sent = airgap.sanitize_prompt("Write a greeting for Alex Example.")
        allow = airgap.placeholders_in(sent)
        self.assertEqual(allow, {"[FULL_NAME]"})
        # The model reply asks for a field the prompt never contained.
        reply = {"text": "Hi [FULL_NAME]!", "note": ["Ship to [ADDRESS]", "[EMAIL]"]}
        restored = airgap.rehydrate(reply, allow=allow)
        self.assertEqual(restored["text"], "Hi Alex Example!")
        self.assertEqual(restored["note"], ["Ship to [ADDRESS]", "[EMAIL]"])


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

            # --allow-from restores only placeholders present in the prompt that was sent
            reply_file = tmp_dir / "reply.txt"
            guarded_file = tmp_dir / "guarded.txt"
            reply_file.write_text("Dear [FULL_NAME], your address is [ADDRESS]", encoding="utf-8")
            sent_file = tmp_dir / "sent.txt"
            sent_file.write_text("Greet [FULL_NAME]", encoding="utf-8")
            self.assertEqual(
                cli_main(
                    ["rehydrate", "-p", str(profile_path), "-i", str(reply_file),
                     "--allow-from", str(sent_file), "-o", str(guarded_file)]
                ),
                0,
            )
            self.assertEqual(
                guarded_file.read_text(encoding="utf-8"),
                "Dear Alex Example, your address is [ADDRESS]",
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


def _run_cli(argv: list[str]) -> tuple[int, str, str]:
    """Run the CLI in-process and return (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli_main(argv)
    return code, out.getvalue(), err.getvalue()


def _write_json(path: Path, data: object, *, ascii_escapes: bool = False) -> Path:
    path.write_text(json.dumps(data, ensure_ascii=ascii_escapes), encoding="utf-8")
    return path


# Synthetic values, built from pieces like the fixtures above.
_FAKE_SECRET = "hunter2" + "secret"
_ACCENTED_NAME = "Jos\u00e9 Mu\u00f1oz"


class TestSecretRuleCoverage(unittest.TestCase):
    """The <SECRET> rule must fire on the shapes secrets really arrive in."""

    def test_secret_names_inside_longer_names_json_headers_and_flags(self) -> None:
        v = _FAKE_SECRET
        samples = [
            f"DB_PASSWORD={v}",
            f"OPENAI_API_KEY={v}",
            f"GITHUB_TOKEN={v}",
            f"access_token={v}",
            f"client_secret: {v}",
            f"export SECRET_KEY={v}",
            f"passphrase={v}",
            f"SMTP_PASS={v}",
            f"STRIPE_KEY={v}",
            f'{{"password": "{v}", "user": "bob"}}',
            f'{{"apiKey":"{v}"}}',
            f'{{"accessToken": "{v}"}}',
            f'{{\\"password\\": \\"{v} two\\"}}',
            f'os.environ["API_KEY"] = "{v}"',
            f'password == "{v}"',
            f"token => {v}",
            f"password: ={v}",
            f"Authorization: Bearer {v}",
            f"Authorization: Basic {v}==",
            f'"Authorization": "Bearer {v}"',
            f"send Bearer abc123def456ghi789{v} now",
            f"mysql -u root --password {v}",
            f"tool --api-key {v} --verbose",
            f"https://api.example.invalid/x?access_token={v}&page=1",
        ]
        for sample in samples:
            with self.subTest(sample=sample.replace(v, "<value>")):
                scrubbed, counts = redact_secrets(sample)
                self.assertNotIn(v, scrubbed)
                self.assertEqual(counts, {"<SECRET>": 1})
                # A second pass finds nothing, so `check` on scrubbed output reports clean.
                self.assertEqual(redact_secrets(scrubbed), (scrubbed, {}))

    def test_secret_named_parent_never_swallows_the_next_key(self) -> None:
        # Taking a nested key as the "value" would redact the key and leave the secret bare.
        v = _FAKE_SECRET
        samples = [
            f"credentials:\n  password: {v}",
            f"secret:\n  api_key: {v}",
            f"credentials:\n  DB_PASSWORD={v}",
            json.dumps({"token": {"access_token": v}}),
            json.dumps({"token": {"access_token": v}}, indent=2),
            json.dumps({"credentials": [{"password": v}]}),
            f"token = {{\n  'password': '{v}'\n}}",
        ]
        for sample in samples:
            with self.subTest(sample=sample.replace(v, "<value>")):
                scrubbed, counts = redact_secrets(sample)
                self.assertNotIn(v, scrubbed)
                self.assertEqual(counts, {"<SECRET>": 1})
                self.assertEqual(redact_secrets(scrubbed), (scrubbed, {}))
        self.assertEqual(
            redact_secrets(f"credentials:\n  password: {v}")[0],
            "credentials:\n  password: <SECRET>",
        )

        # A plain value on the following line is still redacted: base64 padding and a YAML list item included.
        for sample in (
            f"password:\n  {v}",
            f"password:\r\n{v}==",
            f"password:\n  - {v}",
            f"token: https://x.example.invalid/{v}",
        ):
            with self.subTest(sample=sample.replace(v, "<value>")):
                scrubbed, counts = redact_secrets(sample)
                self.assertNotIn(v, scrubbed)
                self.assertEqual(counts, {"<SECRET>": 1})
                self.assertEqual(redact_secrets(scrubbed), (scrubbed, {}))

    def test_key_name_is_kept_and_quoted_value_removed_whole(self) -> None:
        v = _FAKE_SECRET
        self.assertEqual(redact_secrets(f"DB_PASSWORD={v}")[0], "DB_PASSWORD=<SECRET>")
        self.assertEqual(redact_secrets(f'password = "{v} two words"')[0], "password = <SECRET>")
        self.assertEqual(redact_secrets(f"password = '{v} two words'")[0], "password = <SECRET>")
        self.assertEqual(
            redact_secrets(f'{{"password": "{v}", "user": "bob"}}')[0],
            '{"password": <SECRET>, "user": "bob"}',
        )
        self.assertEqual(redact_secrets(f"tool --api-key {v} --verbose")[0], "tool --api-key <SECRET> --verbose")

    def test_ordinary_words_and_placeholders_are_left_alone(self) -> None:
        for sample in (
            "max_tokens = 4096",
            '"input_tokens": 1234, "output_tokens": 55',
            "MAX_TOKENS=4096",
            "tokenizer = PIIAirgap(profile)",
            '"token": null',
            "use_secret: false",
            "the secretary: Jane",
            "tests PASSED: 12",
            "passwords: see the vault",
            "--max-tokens 100",
            "--no-password --verbose",
            "basic authentication is fine",
            "API_KEY=<YOUR_API_KEY>",
            '"api_key": "<API_KEY>"',
            'password: "<SECRET>"',
        ):
            with self.subTest(sample=sample):
                self.assertEqual(redact_secrets(sample), (sample, {}))


class TestProfileValidation(unittest.TestCase):
    """A profile that would protect less than its author thinks must be refused."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.prompt = self.tmp / "prompt.txt"
        self.prompt.write_text("Write to Alex Example please", encoding="utf-8")

    def test_unknown_or_misspelt_key_is_rejected(self) -> None:
        for bad_key in ("name", "fullname", "Email", "full-name"):
            with self.subTest(key=bad_key):
                path = _write_json(self.tmp / "p.json", {bad_key: "Alex Example"})
                with self.assertRaises(ValueError) as caught:
                    IdentityProfile.from_json_file(path)
                self.assertIn(bad_key, str(caught.exception))
                self.assertNotIn("Alex Example", str(caught.exception))

                # The CLI stops with exit 2 instead of passing the text through untouched.
                out_file = self.tmp / "out.txt"
                code, out, err = _run_cli(["sanitize", "-p", str(path), "-i", str(self.prompt), "-o", str(out_file)])
                self.assertEqual(code, 2)
                self.assertFalse(out_file.exists())
                self.assertNotIn("Alex Example", out + err)
                code, out, err = _run_cli(["check", "-p", str(path), "-i", str(self.prompt)])
                self.assertEqual(code, 2)
                self.assertNotIn('"clean": true', out)

    def test_non_string_values_are_rejected(self) -> None:
        for data in (
            {"full_name": ["Alex", "Example"]},
            {"phone": 12025550143},
            {"custom_fields": {"employee_id": 9042}},
            {"custom_fields": ["EMP-9042"]},
        ):
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    IdentityProfile.from_json_file(_write_json(self.tmp / "p.json", data))
        with self.assertRaises(ValueError):
            IdentityProfile(full_name=["Alex", "Example"])  # type: ignore[arg-type]

    def test_duplicate_json_key_is_rejected(self) -> None:
        path = self.tmp / "p.json"
        path.write_text('{"full_name": "Alex Example", "full_name": "Sam Sample"}', encoding="utf-8")
        with self.assertRaises(ValueError):
            IdentityProfile.from_json_file(path)
        path.write_text('{"custom_fields": {"id": "EMP-1111", "id": "EMP-2222"}}', encoding="utf-8")
        with self.assertRaises(ValueError):
            IdentityProfile.from_json_file(path)

    def test_null_means_unset(self) -> None:
        path = _write_json(self.tmp / "p.json", {"full_name": "Alex Example", "email": None, "custom_fields": None})
        self.assertEqual(IdentityProfile.from_json_file(path).placeholder_map(), {"[FULL_NAME]": "Alex Example"})

    def test_empty_profile_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            PIIAirgap(IdentityProfile())
        with self.assertRaises(ValueError):
            PIIAirgap(IdentityProfile(full_name="   ", custom_fields={"note": ""}))
        path = _write_json(self.tmp / "p.json", {})
        code, out, _ = _run_cli(["sanitize", "-p", str(path), "-i", str(self.prompt)])
        self.assertEqual((code, out), (2, ""))
        code, out, _ = _run_cli(["check", "-p", str(path), "-i", str(self.prompt)])
        self.assertEqual((code, out), (2, ""))

    def test_colliding_custom_field_names_are_rejected(self) -> None:
        # Both names normalise to [CUSTOM_EMPLOYEE_ID]; keeping one would leak the other value.
        with self.assertRaises(ValueError) as caught:
            IdentityProfile(custom_fields={"employee id": "EMP-1111", "employee-id": "EMP-2222"})
        message = str(caught.exception)
        self.assertIn("employee id", message)
        self.assertIn("employee-id", message)
        self.assertNotIn("EMP-1111", message)
        self.assertNotIn("EMP-2222", message)

        path = _write_json(self.tmp / "p.json", {"custom_fields": {"Employee ID": "EMP-1111", "employee_id": "EMP-2222"}})
        with self.assertRaises(ValueError):
            IdentityProfile.from_json_file(path)

        # Distinct names still work, and both values are replaced.
        airgap = PIIAirgap(IdentityProfile(custom_fields={"employee id": "EMP-1111", "badge id": "EMP-2222"}))
        self.assertEqual(
            airgap.sanitize_prompt("ids EMP-1111 and EMP-2222"),
            "ids [CUSTOM_EMPLOYEE_ID] and [CUSTOM_BADGE_ID]",
        )


class TestPipedInputEncoding(unittest.TestCase):
    """Piped text is UTF-8 even where the console default is a legacy code page."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.profile = _write_json(Path(tmp.name) / "p.json", {"full_name": _ACCENTED_NAME})

    @staticmethod
    def _legacy_stdin(data: bytes) -> io.TextIOWrapper:
        # What a default Windows Python hands the program for piped input: a cp1252 reader.
        return io.TextIOWrapper(io.BytesIO(data), encoding="cp1252")

    def test_utf8_bytes_on_a_legacy_code_page_stdin_still_match(self) -> None:
        piped = f"Write to {_ACCENTED_NAME} please".encode("utf-8")
        with mock.patch.object(sys, "stdin", self._legacy_stdin(piped)):
            code, out, _ = _run_cli(["sanitize", "-p", str(self.profile), "-i", "-"])
        self.assertEqual((code, out), (0, "Write to [FULL_NAME] please\n"))

        with mock.patch.object(sys, "stdin", self._legacy_stdin(piped)):
            code, out, _ = _run_cli(["check", "-p", str(self.profile), "-i", "-"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["raw_profile_fields_detected"], ["[FULL_NAME]"])

    def test_stdin_that_is_not_utf8_is_an_error_not_a_guess(self) -> None:
        piped = f"Write to {_ACCENTED_NAME} please".encode("cp1252")
        with mock.patch.object(sys, "stdin", self._legacy_stdin(piped)):
            code, out, _ = _run_cli(["sanitize", "-p", str(self.profile), "-i", "-"])
        self.assertEqual((code, out), (2, ""))


class TestJsonBlindSpots(unittest.TestCase):
    """PII in JSON keys, numbers and escape sequences must be seen."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.profile_data = {
            "full_name": _ACCENTED_NAME,
            "phone": "+1 202 555 0143",
            "street_address": "100 Maple Avenue, Springfield",
        }
        self.profile = _write_json(self.tmp / "p.json", self.profile_data)
        # Only visible once decoded: \u escapes in the name, "\n" inside the address.
        self.payload = {"msg": f"Write to {_ACCENTED_NAME} at 100 Maple Avenue,\nSpringfield", "tel": 12025550143}

    def test_payload_keys_numbers_and_tuples_are_sanitized_and_restored(self) -> None:
        airgap = PIIAirgap(_sample_profile())
        payload = {"Alex Example": "note", "phone": 12025550143, "pair": ("Alex Example", 7), "ok": True, "n": None}
        sanitized = airgap.sanitize_payload(payload)
        self.assertEqual(
            sanitized,
            {"[FULL_NAME]": "note", "phone": "[PHONE]", "pair": ("[FULL_NAME]", 7), "ok": True, "n": None},
        )
        restored = airgap.rehydrate(sanitized)
        self.assertEqual(restored["Alex Example"], "note")
        self.assertEqual(restored["pair"], ("Alex Example", 7))
        self.assertEqual(restored["phone"], "+1 202 555 0143")

    def test_payload_that_cannot_be_inspected_is_refused(self) -> None:
        airgap = PIIAirgap(_sample_profile())
        with self.assertRaises(TypeError):
            airgap.sanitize_payload({"blob": b"Alex Example"})
        with self.assertRaises(ValueError):
            airgap.sanitize_payload({"Alex Example": 1, "[FULL_NAME]": 2})

    def test_check_looks_inside_json_and_json_lines_escapes(self) -> None:
        as_json = _write_json(self.tmp / "payload.json", self.payload, ascii_escapes=True)
        self.assertNotIn(_ACCENTED_NAME, as_json.read_text(encoding="utf-8"))  # hidden behind \u escapes
        as_jsonl = self.tmp / "payload.jsonl"
        as_jsonl.write_text(
            json.dumps({"id": 1, "msg": "nothing here"}) + "\n" + json.dumps(self.payload) + "\n",
            encoding="utf-8",
        )
        for path in (as_json, as_jsonl):
            with self.subTest(file=path.name):
                code, out, _ = _run_cli(["check", "-p", str(self.profile), "-i", str(path)])
                self.assertEqual(code, 1)
                self.assertEqual(
                    json.loads(out)["raw_profile_fields_detected"],
                    ["[FULL_NAME]", "[PHONE]", "[ADDRESS]"],
                )
                self.assertNotIn(_ACCENTED_NAME, out)

    def test_check_finds_secrets_inside_json_escapes(self) -> None:
        fake_url = "https://" + "alice:superpass123" + "@registry.example.invalid/pkg"
        # "@" hides the @ of the credentialed URL from a raw-text scan.
        raw = json.dumps({"cmd": f"pip install --index-url {fake_url}"}).replace("@", "\\u0040")
        code, out, _ = _run_cli(["check", "-t", raw])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["secret_pattern_counts"], {"<URL_WITH_CREDS>": 1})

    def test_plain_sanitize_refuses_escaped_json_and_json_mode_handles_it(self) -> None:
        for name, text, lines in (
            ("payload.json", json.dumps(self.payload), 1),
            ("payload.jsonl", json.dumps({"id": 1}) + "\n" + json.dumps(self.payload) + "\n", 2),
        ):
            with self.subTest(file=name):
                source = self.tmp / name
                source.write_text(text, encoding="utf-8")
                out_file = self.tmp / f"out_{name}"

                # Text mode cannot see the escaped values, so it must not report success.
                code, out, err = _run_cli(["sanitize", "-p", str(self.profile), "-i", str(source), "-o", str(out_file)])
                self.assertEqual(code, 2)
                self.assertFalse(out_file.exists())
                self.assertIn("--json", err)
                self.assertNotIn(_ACCENTED_NAME, out + err)

                # --json is the way out: keys, strings and numbers are all replaced.
                code, _, _ = _run_cli(
                    ["sanitize", "-p", str(self.profile), "-i", str(source), "--json", "-o", str(out_file)]
                )
                self.assertEqual(code, 0)
                written = out_file.read_text(encoding="utf-8")
                docs = [json.loads(line) for line in written.splitlines()] if lines > 1 else [json.loads(written)]
                self.assertEqual(len(docs), lines)
                self.assertEqual(docs[-1], {"msg": "Write to [FULL_NAME] at [ADDRESS]", "tel": "[PHONE]"})
                code, _, _ = _run_cli(["check", "-p", str(self.profile), "-i", str(out_file)])
                self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
