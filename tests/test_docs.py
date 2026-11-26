"""The README tells the truth: its examples run, its samples match real output, its tables match the code."""

from __future__ import annotations

import json
import re
import shlex
import tempfile
import tomllib
import unittest
from pathlib import Path

from support import REDACT_RULES, ROOT, IdentityProfile, PIIAirgap, run_cli

import llm_pii_airgap
import test_misses_corpus
from test_profile import MESSAGES

README = (ROOT / "README.md").read_text(encoding="utf-8")
EXAMPLE_PROFILE = ROOT / "examples" / "profile.example.json"


def section(title: str) -> str:
    start = README.index(f"\n## {title}\n")
    end = README.find("\n## ", start + 1)
    return README[start:end if end != -1 else None]


def sample(name: str) -> str:
    """The fenced block that follows <!-- sample: name -->."""
    match = re.search(rf"<!-- sample: {re.escape(name)} -->\n```\w*\n(.*?)```", README, re.S)
    assert match, name
    return match.group(1)


def run_sample(name: str, cwd: Path, replacements: dict[str, str] | None = None) -> tuple[int, str, str, str]:
    """Run the '$ command' line of a sample and compare what it prints with the rest of the block."""
    block = sample(name)
    command, expected = block.split("\n", 1)
    assert command.startswith("$ llm-pii-airgap "), command
    argv = shlex.split(command[len("$ llm-pii-airgap "):])
    argv = [(replacements or {}).get(arg, str(cwd / arg) if (cwd / arg).exists() else arg) for arg in argv]
    code, out, err = run_cli(argv)
    return code, out, err, expected


class TestReadmeExamples(unittest.TestCase):
    def test_python_examples_run(self) -> None:
        blocks = re.findall(r"```python\n(.*?)```", README, re.S)
        self.assertGreaterEqual(len(blocks), 3)
        for index, block in enumerate(blocks):
            with self.subTest(block=index):
                exec(compile(block, f"README.md python block {index}", "exec"), {})

    def test_command_samples_match_real_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            (tmp_dir / "sent.txt").write_text("Write to [FULL_NAME] at [EMAIL]", encoding="utf-8")
            (tmp_dir / "examples").mkdir()
            (tmp_dir / "examples" / "profile.example.json").write_bytes(EXAMPLE_PROFILE.read_bytes())
            for name, exit_code in (("sanitize", 0), ("rehydrate", 0), ("check", 1)):
                with self.subTest(sample=name):
                    code, out, err, expected = run_sample(name, tmp_dir)
                    self.assertEqual((code, out, err), (exit_code, expected, ""))

            (tmp_dir / "session.jsonl").write_text(sample("scrub-input"), encoding="utf-8")
            code, out, err, expected = run_sample("scrub-summary", tmp_dir,
                                                  {"session.clean.jsonl": str(tmp_dir / "session.clean.jsonl")})
            self.assertEqual((code, out, err), (0, expected, ""))
            written = (tmp_dir / "session.clean.jsonl").read_text(encoding="utf-8")
            self.assertEqual(written, sample("scrub-output"))

    def test_argument_error_sample(self) -> None:
        line = re.search(r"```text\n(llm-pii-airgap: error: unrecognized arguments[^\n]*)\n```", README).group(1)
        _, _, err = run_cli(["check", "-t", "Alex", "Example"])
        self.assertIn(line, err)

    def test_scrubbed_transcript_check_reports_only_the_uuids(self) -> None:
        # The transcript recipe says check flags the records' own uuid values and nothing else.
        uuid = "123e4567-e89b-12d3-a456-426614174000"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            source = tmp_dir / "session.jsonl"
            source.write_text(json.dumps({"type": "user", "uuid": uuid, "message": {"content": "DB_PASSWORD=FAKE"}}) + "\n",
                              encoding="utf-8")
            run_cli(["scrub", "-i", str(source), "-o", str(tmp_dir / "clean.jsonl")])
            code, out, _ = run_cli(["check", "-p", str(EXAMPLE_PROFILE), "-i", str(tmp_dir / "clean.jsonl")])
            self.assertEqual((code, json.loads(out)["secret_pattern_counts"]), (1, {"<UUID>": 1}))


class TestReadmeTables(unittest.TestCase):
    def test_rule_table_matches_the_rules_in_order(self) -> None:
        rows = re.findall(r"^\| (\d+) \| `(<[A-Z_]+>)` \|", section("What it looks for"), re.M)
        self.assertEqual([label for _, label in rows], [label for label, _ in REDACT_RULES])
        self.assertEqual([int(n) for n, _ in rows], list(range(1, len(REDACT_RULES) + 1)))

    def test_diagram_rule_count(self) -> None:
        self.assertIn(f'"{len(REDACT_RULES)} rules, in order"', README)

    def test_every_profile_message_is_listed(self) -> None:
        for key, message in MESSAGES.items():
            with self.subTest(message=key):
                self.assertIn(f"`{message}`", README)

    def test_profile_table_lists_every_field_and_placeholder(self) -> None:
        profile = IdentityProfile.from_json_file(EXAMPLE_PROFILE)
        table = section("Configure: the profile")
        for placeholder in profile.placeholder_map():
            if not placeholder.startswith("[CUSTOM_"):
                self.assertIn(f"`{placeholder}`", table)
        for key in ("full_name", "email", "phone", "street_address", "postal_code", "custom_fields"):
            self.assertIn(f"| `{key}` |", table)

    def test_tested_table_names_real_tests(self) -> None:
        names = re.findall(r"`(test_\w+(?:\.\w+)*)`", section("Limits"))
        self.assertTrue(names)
        for name in names:
            with self.subTest(test=name):
                module_name, *attrs = name.split(".")
                obj = __import__(module_name)
                for attr in attrs:
                    obj = getattr(obj, attr)

    def test_every_misses_corpus_test_is_in_the_tested_table(self) -> None:
        listed = section("Limits")
        for class_name in ("TestTokeniserLimits", "TestScrubberLimits"):
            cls = getattr(test_misses_corpus, class_name)
            for attr in dir(cls):
                if attr.startswith("test_"):
                    with self.subTest(test=attr):
                        self.assertIn(f"test_misses_corpus.{class_name}.{attr}", listed)

    def test_development_table_lists_every_test_file(self) -> None:
        table = section("Development")
        for path in sorted((ROOT / "tests").glob("test_*.py")):
            with self.subTest(file=path.name):
                self.assertIn(f"`{path.name}`", table)


class TestNoNetwork(unittest.TestCase):
    def test_the_package_imports_nothing_that_talks_to_a_network(self) -> None:
        # Backs the README's "no network calls": no networking or process modules are imported.
        banned = {"socket", "ssl", "http", "urllib", "ftplib", "smtplib", "requests", "subprocess", "asyncio"}
        for path in sorted((ROOT / "src" / "llm_pii_airgap").glob("*.py")):
            imported = set(re.findall(r"^\s*(?:import|from)\s+([A-Za-z_]\w*)", path.read_text(encoding="utf-8"), re.M))
            with self.subTest(file=path.name):
                self.assertEqual(imported & banned, set())


class TestExampleProfileAndVersions(unittest.TestCase):
    def test_example_profile_loads_and_uses_reserved_values(self) -> None:
        profile = IdentityProfile.from_json_file(EXAMPLE_PROFILE)
        PIIAirgap(profile)
        self.assertTrue(profile.email.endswith("@example.invalid"))
        self.assertTrue(profile.phone.startswith("+1 202 555 01"))
        self.assertIn(EXAMPLE_PROFILE.read_text(encoding="utf-8").strip(), README)

    def test_version_numbers_match(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        self.assertEqual(project["version"], llm_pii_airgap.__version__)
        self.assertIn(f"@v{llm_pii_airgap.__version__}\"", README)
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(f"## {llm_pii_airgap.__version__} ", changelog)

    def test_supported_pythons_match(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        self.assertEqual(project["requires-python"], ">=3.11")
        classifiers = [c.rsplit(" ", 1)[-1] for c in project["classifiers"] if re.search(r"Python :: 3\.\d+$", c)]
        self.assertEqual(classifiers, ["3.11", "3.12", "3.13", "3.14"])
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn('python-version: ["3.11", "3.12", "3.13", "3.14"]', ci)
        self.assertIn("Python 3.11 or newer", README)
        self.assertRegex(README, r"CI runs the tests on Linux, macOS\s+and Windows with Python 3\.11 to 3\.14\.")

    def test_gitignore_covers_local_profiles(self) -> None:
        lines = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn("*.local.json", lines)
        self.assertIn("profile.json", lines)


if __name__ == "__main__":
    unittest.main()
