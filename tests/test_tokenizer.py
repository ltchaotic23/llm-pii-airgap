"""Tokeniser matching: longest-first, whole tokens, whitespace, case and phone numbers."""

from __future__ import annotations

import unittest

from support import IdentityProfile, PIIAirgap, sample_profile



class TestLongestFirst(unittest.TestCase):
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

    def test_longer_value_wins_at_the_same_start_whatever_the_field_order(self) -> None:
        airgap = PIIAirgap(IdentityProfile(full_name="Alex Example", custom_fields={"signature": "Alex Example Jr"}))
        self.assertEqual(airgap.sanitize_prompt("from Alex Example Jr and Alex Example"),
                         "from [CUSTOM_SIGNATURE] and [FULL_NAME]")

    def test_inserted_placeholders_are_never_matched_again(self) -> None:
        airgap = PIIAirgap(IdentityProfile(full_name="Alex Example", custom_fields={"tag": "FULL_NAME"}))
        self.assertEqual(airgap.sanitize_prompt("Alex Example"), "[FULL_NAME]")


class TestLetterCase(unittest.TestCase):
    def test_values_match_in_any_letter_case(self) -> None:
        airgap = PIIAirgap(sample_profile())
        for text in ("ALEX EXAMPLE", "alex example", "aLeX eXaMpLe", "ALEX.EXAMPLE@EXAMPLE.INVALID", "emp-9042"):
            with self.subTest(text=text):
                self.assertTrue(airgap.sanitize_prompt(text).startswith("["))


class TestBoundaries(unittest.TestCase):
    def test_values_with_punctuation_at_the_edges(self) -> None:
        airgap = PIIAirgap(sample_profile())
        self.assertEqual(airgap.sanitize_prompt("<alex.example@example.invalid>"), "<[EMAIL]>")
        self.assertEqual(airgap.sanitize_prompt("(EMP-9042)"), "([CUSTOM_EMPLOYEE_ID])")
        # An edge that is not a letter or digit is not anchored, so the value can sit inside other text.
        edge = PIIAirgap(IdentityProfile(custom_fields={"lang": "C++"}))
        self.assertEqual(edge.sanitize_prompt("C++ and C++20"), "[CUSTOM_LANG] and [CUSTOM_LANG]20")

    def test_whitespace_kinds(self) -> None:
        airgap = PIIAirgap(sample_profile())
        for gap in (" ", "  ", "\t", "\n", "\r\n", "\N{NO-BREAK SPACE}", "\N{EM SPACE}"):
            with self.subTest(gap=repr(gap)):
                self.assertEqual(airgap.sanitize_prompt(f"Alex{gap}Example"), "[FULL_NAME]")
        self.assertEqual(airgap.sanitize_prompt("AlexExample"), "AlexExample")

    def test_value_is_not_replaced_inside_other_words(self) -> None:
        airgap = PIIAirgap(IdentityProfile(custom_fields={"nick": "Ann"}))
        sanitized = airgap.sanitize_prompt("Annual planning with Ann, then Joanna and ann.")
        self.assertEqual(sanitized, "Annual planning with [CUSTOM_NICK], then Joanna and [CUSTOM_NICK].")

    def test_whitespace_reflow_still_matches(self) -> None:
        airgap = PIIAirgap(sample_profile())
        sanitized = airgap.sanitize_prompt("Signed,\nAlex\n  Example\n100 Maple\tAvenue, Springfield")
        self.assertNotIn("Alex", sanitized)
        self.assertNotIn("Avenue", sanitized)
        self.assertEqual(airgap.contains_raw_pii(sanitized), [])

    def test_phone_number_formatting_variants(self) -> None:
        airgap = PIIAirgap(sample_profile())
        for variant in ("+12025550143", "+1-202-555-0143", "+1 (202) 555 0143", "1 202.555.0143"):
            with self.subTest(variant=variant):
                self.assertEqual(airgap.sanitize_prompt(f"Call {variant} now"), "Call [PHONE] now")
                self.assertEqual(airgap.contains_raw_pii(f"Call {variant} now"), ["[PHONE]"])
        # A longer number that merely contains the digits is a different number.
        self.assertEqual(airgap.sanitize_prompt("ref 912025550143"), "ref 912025550143")

    def test_combining_mark_word_boundaries(self) -> None:
        nfd_jose = "Jose\u0301"
        nfd_josephine = "Jose\u0301phine"
        airgap_nfd = PIIAirgap(IdentityProfile(custom_fields={"first": nfd_jose}))
        self.assertEqual(airgap_nfd.sanitize_prompt(nfd_josephine), nfd_josephine)
        self.assertEqual(airgap_nfd.sanitize_prompt("Jos\u00e9phine"), "Jos\u00e9phine")
        self.assertEqual(airgap_nfd.sanitize_prompt(f"hi {nfd_jose}!"), "hi [CUSTOM_FIRST]!")

        airgap_ascii = PIIAirgap(IdentityProfile(custom_fields={"first": "Jose"}))
        self.assertEqual(airgap_ascii.sanitize_prompt(nfd_jose), nfd_jose)

    def test_too_short_value_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            PIIAirgap(IdentityProfile(custom_fields={"initials": "AE"}))


class TestPhones(unittest.TestCase):
    def test_a_phone_with_fewer_than_seven_digits_is_matched_as_written(self) -> None:
        airgap = PIIAirgap(IdentityProfile(phone="555-01"))
        self.assertEqual(airgap.sanitize_prompt("ext 555-01 or 55501"), "ext [PHONE] or 55501")

    def test_plus_sign_is_optional_but_extra_digits_are_not(self) -> None:
        airgap = PIIAirgap(IdentityProfile(phone="+1 202 555 0143"))
        self.assertEqual(airgap.sanitize_prompt("12025550143"), "[PHONE]")
        self.assertEqual(airgap.sanitize_prompt("++1 (202) 555-0143"), "+[PHONE]")
        self.assertEqual(airgap.sanitize_prompt("++1 202 555 0143"), "+[PHONE]")
        self.assertEqual(airgap.sanitize_prompt("+120255501439"), "+120255501439")
        self.assertEqual(airgap.sanitize_prompt("a+12025550143"), "a+12025550143")


class TestPlaceholdersIn(unittest.TestCase):
    def test_returns_only_known_placeholders(self) -> None:
        airgap = PIIAirgap(sample_profile())
        self.assertEqual(airgap.placeholders_in("[FULL_NAME] [ADDRESS] [OTHER] [email]"), {"[FULL_NAME]", "[ADDRESS]"})
        self.assertEqual(airgap.placeholders_in(""), set())


if __name__ == "__main__":
    unittest.main()
