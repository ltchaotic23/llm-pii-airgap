"""Speed: large transcripts, crafted worst cases for every regular expression, big profiles.

The limits are generous so slow CI machines pass. What they catch is time that grows with the
square of the input (catastrophic backtracking), which turns a 200 KB string into minutes.
"""

from __future__ import annotations

import json
import time
import unittest

from support import IdentityProfile, PIIAirgap, REDACT_RULES, j, redact_secrets, scrub_jsonl_stream, strip_harness_tags

from llm_pii_airgap.cli import _profile_fields_in, _redaction_counts_in
from llm_pii_airgap.scrubber import _apply_rule

SIZE = 200_000
LIMIT = 5.0  # seconds; linear code takes a small fraction of this
MEASURABLE = 0.05  # seconds; shorter timings are too noisy on shared CI machines to compare
MAX_SCALED_LENGTH = 16 * SIZE  # stop growing a crafted input here


def repeat(unit: str, size: int = SIZE) -> str:
    return unit * (size // len(unit))


# Strings built to make a backtracking regex try every start position against the rest of the text.
CRAFTED = {
    "dotted letters": repeat("a."),
    "dotted digits": repeat("1."),
    "dashed letters": repeat("a-"),
    "plus letters": repeat("a+"),
    "slash letters": repeat("a/"),
    "dashed digits": repeat("0-"),
    "underscore dots": repeat("a_b."),
    "at signs": repeat("a@"),
    "domain dots": "a@b" + repeat(".-"),
    "hex groups": repeat("aaaaaaaa-"),
    "key headers": repeat(j("-----BEGIN ", "RSA PRIVATE KEY-----\n")),
    "key header letters": repeat("-----BEGIN " + "A" * 50 + "\n"),
    "discord-like": repeat("M" + "a" * 25 + "."),
    "sk prefixes": repeat("sk-"),
    "sk dashes": "sk-" + repeat("-"),
    "slack prefixes": repeat("xoxb-"),
    "url schemes": repeat("a://x:" + "y" * 50),
    "url userinfo": "a://x:" + repeat("y:"),
    "proxy schemes": repeat("vless://"),
    "plus digits": repeat("+1 "),
    "spaced digits": "+1" + repeat(" 1") + " a",
    "secret word gaps": repeat("password" + " " * 200),
    "open quote": 'password="' + repeat("a"),
    "secret words": repeat("password="),
    "secret colons": repeat("password:\n"),
    "token words": repeat("token "),
    "bearer words": repeat("bearer "),
    "secret flags": repeat("--password "),
    "nested keys": repeat("token:\n  " + "a" * 80 + ":\n"),
    "escaped quotes": repeat('\\"password\\": \\"'),
    "triple quotes": repeat('token = """a\n'),
    "unclosed triple quote": 'password = """' + repeat("a\n"),
    "unclosed triple quotes": repeat("password = '''a\n") + repeat('password = """b\n'),
    "letters": repeat("a"),
    "prose": repeat("the quick brown fox jumps over the lazy dog "),
}

CRAFTED_TAGS = {
    "unclosed blocks": repeat("<system-reminder>"),
    "openers without >": repeat("<system-reminder "),
    "mixed unclosed blocks": repeat("<attachment><ide_selection><pasted_content1>"),
    "closer without >": "<system-reminder>x" + repeat("</system-reminder "),
    "distinct pasted tags": "".join(f"<pasted_content_{i}>" for i in range(10_000)),
    "distinct ide tags": "".join(f"<ide_a{i % 26}_{chr(97 + (i // 26) % 26)}>" for i in range(15_000)),
    "image markers": repeat("[Image "),
    "pasted markers": repeat("[Pasted text"),
}


def timed(func, *args) -> float:
    start = time.perf_counter()
    func(*args)
    return time.perf_counter() - start


class TimedTestCase(unittest.TestCase):
    def assert_fast(self, label: str, func, *args, limit: float = LIMIT) -> None:
        elapsed = timed(func, *args)
        self.assertLess(elapsed, limit, f"{label} took {elapsed:.1f}s")

    def assert_linear(self, label: str, func, text: str, *before: object) -> None:
        """Four times the input must take less than eight times as long.

        Linear code gives 4x and quadratic code 16x, so the limit of 8 sits well clear of
        both. Comparing a quarter with the whole, rather than a half, keeps the busy shared
        machines used for CI (where one slow run can stretch 2x to over 3x) from failing
        linear code, while quadratic code still fails by a wide margin. Machines differ in
        speed, so only growth is judged, plus a generous absolute ceiling.
        """
        full = timed(func, *before, text)
        self.assertLess(full, 30.0, f"{label} took {full:.1f}s")
        if full < 0.05:
            return
        # Grow the input until the quarter-size run is long enough to measure, then compare
        # the best of three runs at each size.
        while timed(func, *before, text[: len(text) // 4]) < MEASURABLE and len(text) < MAX_SCALED_LENGTH:
            text = text + text
        quarter = min(timed(func, *before, text[: len(text) // 4]) for _ in range(3))
        full = min(timed(func, *before, text) for _ in range(3))
        self.assertLess(full / quarter, 8.0,
                        f"{label}: {quarter:.3f}s for a quarter of the input, {full:.3f}s for all of it")


class TestEveryRegexIsLinear(TimedTestCase):
    def test_each_scrubber_rule_on_crafted_input(self) -> None:
        for placeholder, pattern in REDACT_RULES:
            for name, text in CRAFTED.items():
                with self.subTest(rule=placeholder, input=name):
                    self.assert_linear(f"{placeholder} on {name}", _apply_rule, text, placeholder, pattern)

    def test_line_continuations_on_crafted_input(self) -> None:
        for name, text in {
            "one long continued value": "password=" + "a\\\n" * 100_000,
            "many continued assignments": "password=a\\\n" * 60_000,
            "backslashes without newlines": "password=" + "\\" * 400_000,
            "continuations then spaces": "password=" + "a\\\n   " * 80_000,
        }.items():
            with self.subTest(input=name):
                self.assert_linear(name, redact_secrets, text)

    def test_harness_tag_stripping_on_crafted_input(self) -> None:
        for name, text in CRAFTED_TAGS.items():
            with self.subTest(input=name):
                self.assert_linear(name, strip_harness_tags, text)
        many_distinct = "".join(f"<pasted_content_{i}>" for i in range(40_000))
        self.assert_linear("40k distinct pasted tags", strip_harness_tags, many_distinct)

    def test_tokenizer_patterns_on_crafted_input(self) -> None:
        airgap = PIIAirgap(IdentityProfile(
            full_name="Alex Example", phone="+1 202 555 0143", street_address="100 Maple Avenue, Springfield",
        ))
        for name, text in {
            **CRAFTED,
            "spaced name": repeat("Alex" + " " * 100),
            "spaced phone digits": repeat("1 2 0 2 5 5 5 0 1 4 " + " " * 20),
            "phone separators": "+1" + repeat("(-) ."),
        }.items():
            with self.subTest(input=name):
                self.assert_linear(name, airgap.sanitize_prompt, text)

    def test_check_views_on_crafted_input(self) -> None:
        airgap = PIIAirgap(IdentityProfile(full_name="Alex Example"))
        for name, text in {"escapes": repeat("\\\\u0041"), "unicode escapes": repeat("\\u00e9"), **CRAFTED}.items():
            with self.subTest(input=name):
                self.assert_linear(name, _redaction_counts_in, text)
                self.assert_linear(name, _profile_fields_in, text, airgap)


class TestLargeInputs(TimedTestCase):
    def test_ten_megabyte_transcript(self) -> None:
        message = (
            "Please refactor the tokenizer module and keep max_tokens at 4096. The build at "
            "https://ci.example.invalid/jobs/build failed with exit code 1; see commit a1b2c3d. "
        ) * 10
        lines = []
        size = 0
        index = 0
        while size < 10_000_000:
            line = json.dumps({"type": "user", "uuid": f"u{index}", "message": {"content": message}})
            lines.append(line)
            size += len(line) + 1
            index += 1
        start = time.perf_counter()
        rows, summary = scrub_jsonl_stream(lines)
        elapsed = time.perf_counter() - start
        self.assertEqual(summary["rows_kept"], len(lines))
        self.assertEqual(summary["redactions"], {})
        self.assertLess(elapsed, 120, f"10 MB took {elapsed:.1f}s")

    def test_one_long_line(self) -> None:
        line = "word " * 400_000 + j("DB_PASS", "WORD=", "FAKE")
        self.assert_fast("2 MB line", redact_secrets, line, limit=20.0)

    def test_profile_with_many_custom_fields(self) -> None:
        fields = {f"field {i}": f"value-{i:04d}-example" for i in range(200)}
        airgap = PIIAirgap(IdentityProfile(full_name="Alex Example", custom_fields=fields))
        text = repeat("the quick brown fox jumps over the lazy dog value-0042-example ", 100_000)
        start = time.perf_counter()
        result = airgap.sanitize_prompt(text)
        elapsed = time.perf_counter() - start
        self.assertIn("[CUSTOM_FIELD_42]", result)
        self.assertLess(elapsed, 10, f"200 fields took {elapsed:.1f}s")


if __name__ == "__main__":
    unittest.main()
