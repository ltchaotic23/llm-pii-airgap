"""Adversarial input: ways to slip a profile value or a secret past the tool.

Every case here is caught, by `sanitize` itself or by the re-check that `check` and `sanitize`
run on their result. The cases that are not caught are documented limits, asserted in
test_misses_corpus.py and listed in the README.
"""

from __future__ import annotations

import json
import tempfile
import unicodedata
import unittest
from pathlib import Path

from support import FAKE_SECRET, IdentityProfile, PIIAirgap, j, redact_secrets, run_cli, write_json

from llm_pii_airgap.cli import _profile_fields_in

E_ACUTE = "\N{LATIN SMALL LETTER E WITH ACUTE}"
NAME = f"Jos{E_ACUTE} Example"
PHONE = "+1 202 555 0143"


def fullwidth(text: str) -> str:
    return "".join(chr(ord(ch) + 0xFEE0) if "0" <= ch <= "9" or ch == "+" else ch for ch in text)


class TestVariantsSanitizeReplaces(unittest.TestCase):
    def setUp(self) -> None:
        self.airgap = PIIAirgap(IdentityProfile(
            full_name=NAME, phone=PHONE, custom_fields={"nick": "Isabel", "street": "Stra\N{LATIN SMALL LETTER SHARP S}e Town"},
        ))

    def test_case_and_whitespace(self) -> None:
        for text in (NAME.upper(), NAME.lower(), f"Jos{E_ACUTE}\N{NO-BREAK SPACE}Example", f"Jos{E_ACUTE}\n\tExample"):
            with self.subTest(text=text):
                self.assertEqual(self.airgap.sanitize_prompt(text), "[FULL_NAME]")

    def test_case_folding_letters_that_python_matches(self) -> None:
        for text in ("\N{LATIN CAPITAL LETTER I WITH DOT ABOVE}SABEL", "Isabel".replace("i", "\N{LATIN SMALL LETTER DOTLESS I}"),
                     "STRA\N{LATIN CAPITAL LETTER SHARP S}E TOWN"):
            with self.subTest(text=text):
                self.assertTrue(self.airgap.sanitize_prompt(text).startswith("[CUSTOM_"))


class TestProfileWrittenInAVariant(unittest.TestCase):
    """The profile itself may hold a decomposed accent or full-width digits (pasted from elsewhere)."""

    def test_decomposed_profile_value_matches_composed_text(self) -> None:
        airgap = PIIAirgap(IdentityProfile(full_name=unicodedata.normalize("NFD", NAME)))
        for text in (NAME, unicodedata.normalize("NFD", NAME)):
            with self.subTest(form=unicodedata.is_normalized("NFC", text)):
                self.assertEqual(airgap.sanitize_prompt(f"to {text}"), "to [FULL_NAME]")
                self.assertEqual(_profile_fields_in(airgap, f"to {text}"), ["[FULL_NAME]"])

    def test_full_width_profile_phone_matches_ascii_digits(self) -> None:
        airgap = PIIAirgap(IdentityProfile(phone=fullwidth(PHONE)))
        self.assertEqual(airgap.sanitize_prompt(f"call {PHONE}"), "call [PHONE]")
        # The digits go; a full-width plus sign in front of them stays.
        self.assertEqual(airgap.sanitize_prompt(f"call {fullwidth(PHONE)}"), "call \N{FULLWIDTH PLUS SIGN}[PHONE]")

    def test_full_width_profile_letters_match_ascii_text(self) -> None:
        fw_name = "".join(chr(ord(ch) + 0xFEE0) if ch.isascii() and ch.isalpha() else ch for ch in "Alex Example")
        airgap = PIIAirgap(IdentityProfile(full_name=fw_name))
        self.assertEqual(airgap.sanitize_prompt("Hello Alex Example!"), "Hello [FULL_NAME]!")

    def test_rehydrate_gives_back_the_profile_as_written(self) -> None:
        stored = unicodedata.normalize("NFD", NAME)
        airgap = PIIAirgap(IdentityProfile(full_name=stored))
        self.assertEqual(airgap.rehydrate(airgap.sanitize_prompt(NAME), allow={"[FULL_NAME]"}), stored)


class TestVariantsTheRecheckCatches(unittest.TestCase):
    """sanitize does not replace these, so it refuses to write; check reports them."""

    VARIANTS = {
        "decomposed accent (NFD)": unicodedata.normalize("NFD", NAME),
        "zero-width space": f"Jo\N{ZERO WIDTH SPACE}s{E_ACUTE} Example",
        "zero-width joiner": f"Jos{E_ACUTE} Ex\N{ZERO WIDTH JOINER}ample",
        "right-to-left mark": f"Jos{E_ACUTE}\N{RIGHT-TO-LEFT MARK} Example",
        "soft hyphen": f"Jo\N{SOFT HYPHEN}s{E_ACUTE} Example",
        "word joiner": f"Jos{E_ACUTE} Exam\N{WORD JOINER}ple",
        "variation selector FE00": f"Jo\uFE00s{E_ACUTE} Example",
        "variation selector FE0F": f"Jos{E_ACUTE}\uFE0F Example",
        "variation selector supplement": f"Jo\U000E0100s{E_ACUTE} Example",
        "tag character E0020": f"Jo\U000E0020s{E_ACUTE} Example",
        "full-width digits": fullwidth(PHONE),
        "full-width letters": "".join(chr(ord(ch) + 0xFEE0) if ch.isascii() and ch.isalpha() else ch for ch in NAME),
    }

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.profile = write_json(self.tmp / "p.json", {"full_name": NAME, "phone": PHONE})
        self.airgap = PIIAirgap(IdentityProfile.from_json_file(self.profile))

    def test_check_finds_each_variant(self) -> None:
        for label, text in self.VARIANTS.items():
            with self.subTest(variant=label):
                self.assertNotEqual(_profile_fields_in(self.airgap, f"Hello {text}!"), [])
                source = self.tmp / "in.txt"
                source.write_text(f"Hello {text}!", encoding="utf-8")
                code, out, _ = run_cli(["check", "-p", str(self.profile), "-i", str(source)])
                self.assertEqual(code, 1)
                self.assertFalse(json.loads(out)["clean"])

    def test_sanitize_refuses_rather_than_writing_a_variant(self) -> None:
        for label, text in self.VARIANTS.items():
            with self.subTest(variant=label):
                source = self.tmp / "in.txt"
                source.write_text(f"Hello {text}!", encoding="utf-8")
                target = self.tmp / "out.txt"
                code, out, err = run_cli(["sanitize", "-p", str(self.profile), "-i", str(source), "-o", str(target)])
                self.assertEqual((code, out), (2, ""))
                self.assertIn("Unicode variants", err)
                self.assertFalse(target.exists())

    def test_variant_inside_json_escapes(self) -> None:
        escaped = json.dumps({"to": unicodedata.normalize("NFD", NAME)})  # the accent becomes two escapes
        code, out, _ = run_cli(["check", "-p", str(self.profile), "-t", escaped])
        self.assertEqual((code, json.loads(out)["raw_profile_fields_detected"]), (1, ["[FULL_NAME]"]))


class TestScrubberEvasion(unittest.TestCase):
    def test_upper_case_url_scheme(self) -> None:
        url = j("HTTPS://", "exampleuser:FAKE", "@registry.example.invalid/simple")
        self.assertEqual(redact_secrets(url), ("<URL_WITH_CREDS>", {"<URL_WITH_CREDS>": 1}))

    def test_unusual_quoting(self) -> None:
        for sample in (f"password = `{FAKE_SECRET}`", f"password=\\'{FAKE_SECRET}\\'", f"password: '''{FAKE_SECRET}'''",
                       f'password = """{FAKE_SECRET} two words"""', f'password = r"{FAKE_SECRET}"',
                       f'password = """\n{FAKE_SECRET}\ntwo words\n"""', f"password = '''\n{FAKE_SECRET} two words'''"):
            with self.subTest(sample=sample.replace(FAKE_SECRET, "<value>")):
                self.assertNotIn(FAKE_SECRET, redact_secrets(sample)[0])
                self.assertNotIn("two words", redact_secrets(sample)[0])

    def test_secret_at_the_end_of_a_very_long_line(self) -> None:
        line = "x" * 1_000_000 + f" DB_PASSWORD={FAKE_SECRET}"
        self.assertNotIn(FAKE_SECRET, redact_secrets(line)[0])

    def test_secret_hidden_behind_json_escapes_is_found_by_check(self) -> None:
        raw = json.dumps({"env": f"DB_PASSWORD={FAKE_SECRET}"}).replace("=", "\\u003d")
        code, out, _ = run_cli(["check", "-t", raw])
        self.assertEqual((code, json.loads(out)["secret_pattern_counts"]), (1, {"<SECRET>": 1}))

    def test_secret_written_with_full_width_letters_is_found_by_check(self) -> None:
        text = "".join(chr(ord(ch) + 0xFEE0) if ch.isascii() and ch.isalnum() else ch for ch in f"DB_PASSWORD={FAKE_SECRET}")
        self.assertEqual(redact_secrets(text)[1], {})  # the scrubber alone misses it
        code, out, _ = run_cli(["check", "-t", text])
        self.assertEqual((code, json.loads(out)["secret_pattern_counts"]), (1, {"<SECRET>": 1}))


class TestPlaceholderCollision(unittest.TestCase):
    """The prompt already contains text that looks like a placeholder."""

    def setUp(self) -> None:
        self.airgap = PIIAirgap(IdentityProfile(full_name="Alex Example", email="alex.example@example.invalid"))

    def test_a_literal_placeholder_enters_the_allow_list(self) -> None:
        original = "Fill in this template: Dear [FULL_NAME]. Sign it from alex.example@example.invalid."
        sent = self.airgap.sanitize_prompt(original)
        self.assertEqual(sent, "Fill in this template: Dear [FULL_NAME]. Sign it from [EMAIL].")
        self.assertEqual(self.airgap.placeholders_in(sent), {"[FULL_NAME]", "[EMAIL]"})
        # The reply's [FULL_NAME] is restored even though the user only typed it as a literal.
        reply = "Dear [FULL_NAME], from [EMAIL]"
        self.assertEqual(
            self.airgap.rehydrate(reply, allow=self.airgap.placeholders_in(sent)),
            "Dear Alex Example, from alex.example@example.invalid",
        )

    def test_subtracting_the_original_keeps_only_real_substitutions(self) -> None:
        original = "Fill in this template: Dear [FULL_NAME]. Sign it from alex.example@example.invalid."
        sent = self.airgap.sanitize_prompt(original)
        allow = self.airgap.placeholders_in(sent) - self.airgap.placeholders_in(original)
        self.assertEqual(allow, {"[EMAIL]"})
        self.assertEqual(self.airgap.rehydrate("Dear [FULL_NAME], from [EMAIL]", allow=allow),
                         "Dear [FULL_NAME], from alex.example@example.invalid")

    def test_placeholder_shaped_text_that_is_not_known(self) -> None:
        sent = self.airgap.sanitize_prompt("Use [ADDRESS] and [CUSTOM_X] and [full_name] as you like.")
        self.assertEqual(self.airgap.placeholders_in(sent), set())

    def test_a_value_that_looks_like_a_placeholder_is_not_matched_twice(self) -> None:
        airgap = PIIAirgap(IdentityProfile(full_name="Alex Example", custom_fields={"code": "FULL_NAME"}))
        self.assertEqual(airgap.sanitize_prompt("Alex Example and FULL_NAME"), "[FULL_NAME] and [CUSTOM_CODE]")


if __name__ == "__main__":
    unittest.main()
