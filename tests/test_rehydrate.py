"""rehydrate(): the allow-list, nested structures and placeholders injected by a model."""

from __future__ import annotations

import unittest

from support import PIIAirgap, sample_profile


class TestRehydrate(unittest.TestCase):
    def setUp(self) -> None:
        self.airgap = PIIAirgap(sample_profile())
        # The explicit way to restore every placeholder the profile knows.
        self.everything = self.airgap.profile.placeholder_map().keys()

    def test_rehydrate_nested_structures(self) -> None:
        payload = {
            "header": {"name": "[FULL_NAME]", "email": "[EMAIL]"},
            "lines": ["Call [PHONE]", ["Post to [ADDRESS], [POSTAL_CODE]"], 42],
        }
        result = self.airgap.rehydrate(payload, allow=self.everything)
        self.assertEqual(result["header"]["name"], "Alex Example")
        self.assertEqual(result["header"]["email"], "alex.example@example.invalid")
        self.assertEqual(result["lines"][0], "Call +1 202 555 0143")
        self.assertEqual(result["lines"][1][0], "Post to 100 Maple Avenue, Springfield, 12345")
        self.assertEqual(result["lines"][2], 42)

    def test_keys_tuples_and_other_types(self) -> None:
        payload = {"[FULL_NAME]": ("[EMAIL]", 7, None, True, 1.5), 3: "[CUSTOM_EMPLOYEE_ID]"}
        result = self.airgap.rehydrate(payload, allow=self.everything)
        self.assertEqual(
            result,
            {"Alex Example": ("alex.example@example.invalid", 7, None, True, 1.5), 3: "EMP-9042"},
        )

    def test_rehydrate_allow_list_blocks_injected_placeholders(self) -> None:
        sent = self.airgap.sanitize_prompt("Write a greeting for Alex Example.")
        allow = self.airgap.placeholders_in(sent)
        self.assertEqual(allow, {"[FULL_NAME]"})
        # The model reply asks for a field the prompt never contained.
        reply = {"text": "Hi [FULL_NAME]!", "note": ["Ship to [ADDRESS]", "[EMAIL]"]}
        restored = self.airgap.rehydrate(reply, allow=allow)
        self.assertEqual(restored["text"], "Hi Alex Example!")
        self.assertEqual(restored["note"], ["Ship to [ADDRESS]", "[EMAIL]"])

    def test_allow_list_is_required(self) -> None:
        # Restoring everything by default would hand an injected [ADDRESS] the real address.
        with self.assertRaises(TypeError):
            self.airgap.rehydrate("Hi [FULL_NAME]")  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            self.airgap.rehydrate("Hi [FULL_NAME]", allow=None)  # type: ignore[arg-type]

    def test_a_string_is_not_accepted_as_an_allow_list(self) -> None:
        # "[EMAIL]" in "[FULL_NAME] [EMAIL]" is a substring test: a string would allow too much.
        with self.assertRaises(TypeError):
            self.airgap.rehydrate("[EMAIL]", allow="[FULL_NAME] [EMAIL]")

    def test_any_collection_works_as_an_allow_list(self) -> None:
        for allow in ({"[EMAIL]"}, ["[EMAIL]"], ("[EMAIL]",), frozenset({"[EMAIL]"}), {"[EMAIL]": 1}.keys()):
            with self.subTest(allow=type(allow).__name__):
                self.assertEqual(
                    self.airgap.rehydrate("[FULL_NAME] [EMAIL]", allow=allow),
                    "[FULL_NAME] alex.example@example.invalid",
                )

    def test_empty_allow_list_restores_nothing(self) -> None:
        self.assertEqual(self.airgap.rehydrate("Hi [FULL_NAME]", allow=set()), "Hi [FULL_NAME]")

    def test_only_exact_known_placeholders_are_restored(self) -> None:
        reply = "[full_name] [ FULL_NAME ] [FULL NAME] [CUSTOM_OTHER] [FULL_NAME][EMAIL] [[POSTAL_CODE]]"
        self.assertEqual(
            self.airgap.rehydrate(reply, allow=self.everything | {"[CUSTOM_OTHER]"}),
            "[full_name] [ FULL_NAME ] [FULL NAME] [CUSTOM_OTHER] "
            "Alex Examplealex.example@example.invalid [12345]",
        )

    def test_empty_and_placeholder_free_input(self) -> None:
        self.assertEqual(self.airgap.rehydrate("", allow=self.everything), "")
        self.assertEqual(self.airgap.rehydrate("no placeholders", allow=self.everything), "no placeholders")

    def test_unsupported_payload_and_non_string_allow_items_raise_type_error(self) -> None:
        for bad_payload in (b"[FULL_NAME]", {"[FULL_NAME]"}, object()):
            with self.subTest(payload=type(bad_payload).__name__):
                with self.assertRaises(TypeError):
                    self.airgap.rehydrate(bad_payload, allow=self.everything)
        for bad_allow in (bytearray(b"[EMAIL]"), [123], {"[EMAIL]", None}):
            with self.subTest(allow=type(bad_allow).__name__):
                with self.assertRaises(TypeError):
                    self.airgap.rehydrate("[EMAIL]", allow=bad_allow)  # type: ignore[arg-type]

    def test_colliding_dict_keys_raise_value_error(self) -> None:
        with self.assertRaises(ValueError):
            self.airgap.rehydrate({"[FULL_NAME]": 1, "Alex Example": 2}, allow={"[FULL_NAME]"})
        # When the placeholder is not in allow, the keys do not collide.
        self.assertEqual(
            self.airgap.rehydrate({"[FULL_NAME]": 1, "Alex Example": 2}, allow={"[EMAIL]"}),
            {"[FULL_NAME]": 1, "Alex Example": 2},
        )


if __name__ == "__main__":
    unittest.main()
