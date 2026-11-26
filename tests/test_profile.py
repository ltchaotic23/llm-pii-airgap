"""Profile validation: every way a profile is refused, and the message it gives."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from support import IdentityProfile, PIIAirgap, run_cli as _run_cli, write_json as _write_json

# Every message a profile can be refused with. The README's profile reference lists them all
# (test_docs checks that).
MESSAGES = {
    "duplicate": "Duplicate key 'full_name' in identity profile JSON.",
    "root": "Identity profile JSON must contain an object at the root.",
    "unknown": (
        "Unknown profile field(s): fullname. Known fields are full_name, email, phone, street_address, "
        "postal_code; put anything else under 'custom_fields'."
    ),
    "not a string": "Profile field 'phone' must be a string.",
    "phone no digits": "Profile field 'phone' must contain at least one digit.",
    "custom not object": "'custom_fields' must be an object mapping names to strings.",
    "custom not string": "Custom field 'employee_id' must map a string name to a string value.",
    "collision": "Custom fields 'employee id' and 'employee-id' both map to placeholder [CUSTOM_EMPLOYEE_ID]; rename one.",
    "empty": "Identity profile has no values to protect.",
    "too short": (
        "Profile value for [CUSTOM_INITIALS] is shorter than 3 characters and cannot be matched without "
        "corrupting unrelated text."
    ),
}


class TestErrorMessages(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def load(self, text: str) -> None:
        path = self.tmp / "p.json"
        path.write_text(text, encoding="utf-8")
        PIIAirgap(IdentityProfile.from_json_file(path))

    def assert_message(self, key: str, text: str) -> None:
        with self.subTest(key=key):
            with self.assertRaises(ValueError) as caught:
                self.load(text)
            self.assertEqual(str(caught.exception), MESSAGES[key])

    def test_each_message(self) -> None:
        self.assert_message("duplicate", '{"full_name": "Alex Example", "full_name": "Sam Sample"}')
        self.assert_message("root", '["Alex Example"]')
        self.assert_message("unknown", '{"fullname": "Alex Example"}')
        self.assert_message("not a string", '{"phone": 12025550143}')
        self.assert_message("phone no digits", '{"phone": "\\u2460\\u2461\\u2462\\u2463\\u2464\\u2465\\u2466"}')
        self.assert_message("phone no digits", '{"phone": "ext-abc"}')
        self.assert_message("custom not object", '{"custom_fields": ["EMP-9042"]}')
        self.assert_message("custom not string", '{"custom_fields": {"employee_id": 9042}}')
        self.assert_message("collision", '{"custom_fields": {"employee id": "EMP-1111", "employee-id": "EMP-2222"}}')
        self.assert_message("empty", '{"full_name": null, "custom_fields": {"note": "   "}}')
        self.assert_message("too short", '{"full_name": "Alex Example", "custom_fields": {"initials": "AE"}}')

    def test_invalid_json_and_missing_file(self) -> None:
        with self.assertRaises(ValueError):
            self.load('{"full_name": "Alex Example"')
        with self.assertRaises(OSError):
            IdentityProfile.from_json_file(self.tmp / "missing.json")


class TestProfileFormat(unittest.TestCase):
    def test_placeholders_for_every_field(self) -> None:
        profile = IdentityProfile(
            full_name="Alex Example", email="alex.example@example.invalid", phone="+1 202 555 0143",
            street_address="100 Maple Avenue, Springfield", postal_code="12345",
            custom_fields={"employee id": "EMP-9042", "!!!": "value-x"},
        )
        self.assertEqual(
            list(profile.placeholder_map()),
            ["[FULL_NAME]", "[EMAIL]", "[PHONE]", "[ADDRESS]", "[POSTAL_CODE]", "[CUSTOM_EMPLOYEE_ID]", "[CUSTOM_FIELD]"],
        )

    def test_values_are_trimmed_and_blank_values_unset(self) -> None:
        profile = IdentityProfile(full_name="  Alex Example \n", email="   ", custom_fields={"note": ""})
        self.assertEqual(profile.placeholder_map(), {"[FULL_NAME]": "Alex Example"})

    def test_three_characters_is_enough(self) -> None:
        airgap = PIIAirgap(IdentityProfile(custom_fields={"code": "ABC"}))
        self.assertEqual(airgap.sanitize_prompt("code ABC"), "code [CUSTOM_CODE]")

    def test_null_custom_values_are_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_json(Path(tmp) / "p.json", {"full_name": "Alex Example", "custom_fields": {"note": None}})
            self.assertEqual(IdentityProfile.from_json_file(path).custom_fields, {})

    def test_non_ascii_custom_field_names(self) -> None:
        profile = IdentityProfile(custom_fields={"pr\u00e9nom": "Alex", "\u59d3\u540d": "Sam"})
        self.assertEqual(list(profile.placeholder_map()), ["[CUSTOM_PR_NOM]", "[CUSTOM_FIELD]"])
        with self.assertRaises(ValueError):
            IdentityProfile(custom_fields={"\u59d3\u540d": "val-one", "\u90e8\u95e8": "val-two"})



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


if __name__ == "__main__":
    unittest.main()
