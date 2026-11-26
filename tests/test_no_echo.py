"""The tool never prints a protected value: not in its output, its errors, or a traceback.

Every command and error path runs in a fresh interpreter, as a user would run it, with input
full of profile values and fake secrets. Its stdout and stderr must contain none of them.
"""

from __future__ import annotations

import json
import tempfile
import unicodedata
import unittest
from pathlib import Path

from support import FAKE_SECRET, SAMPLE_PROFILE_DATA, j, run_cli_subprocess, write_json

FAKE_TOKEN = j("gh", "p_", "FAKE" * 9)
PROFILE_VALUES = [
    SAMPLE_PROFILE_DATA["full_name"],
    SAMPLE_PROFILE_DATA["email"],
    SAMPLE_PROFILE_DATA["phone"],
    SAMPLE_PROFILE_DATA["street_address"],
    SAMPLE_PROFILE_DATA["custom_fields"]["employee_id"],
]
# Words of the values too, so a partial echo ("Example") is caught as well as a whole one.
VALUES = [*PROFILE_VALUES, FAKE_SECRET, FAKE_TOKEN, "Maple", "9042", "0143"]
TEXT = " ".join([*PROFILE_VALUES, f"DB_PASSWORD={FAKE_SECRET}", f"token {FAKE_TOKEN}"])


class TestNoEcho(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.profile = write_json(self.tmp / "profile.json", SAMPLE_PROFILE_DATA)

    def file(self, name: str, content: str | bytes) -> str:
        path = self.tmp / name
        if isinstance(content, str):
            content = content.encode("utf-8")
        path.write_bytes(content)
        return str(path)

    def assert_silent(self, argv: list[str], *, stdin: bytes | None = None, code: int | None = None) -> None:
        with self.subTest(argv=[a if len(a) < 40 else a[:37] + "..." for a in argv]):
            proc = run_cli_subprocess(argv, stdin=stdin)
            output = proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")
            for value in VALUES:
                self.assertNotIn(value, output)
            self.assertNotIn("Traceback", output)
            if code is not None:
                self.assertEqual(proc.returncode, code, output)

    def test_normal_runs(self) -> None:
        p = str(self.profile)
        transcript = self.file("t.jsonl", json.dumps({"type": "user", "uuid": "1", "message": {"content": TEXT}}) + "\n")
        prompt = self.file("prompt.txt", TEXT)
        self.assert_silent(["check", "-p", p, "-t", TEXT], code=1)
        self.assert_silent(["check", "-p", p, "-i", prompt], code=1)
        self.assert_silent(["check", "-p", p, "-i", "-"], stdin=TEXT.encode("utf-8"), code=1)
        self.assert_silent(["check", "-i", prompt], code=1)
        self.assert_silent(["scrub", "-i", transcript, "-o", str(self.tmp / "out.jsonl")], code=0)
        self.assert_silent(["sanitize", "-p", p, "-i", prompt, "-o", str(self.tmp / "safe.txt")], code=0)
        self.assert_silent(["rehydrate", "-p", p, "-t", "[FULL_NAME]", "--allow-all", "-o", str(self.tmp / "r.txt")], code=0)

    def test_sanitize_refusals(self) -> None:
        p = str(self.profile)
        escaped = self.file("escaped.json", json.dumps({"to": TEXT.replace(" ", "\n")}))
        nfd = self.file("nfd.txt", unicodedata.normalize("NFD", "Ale\N{LATIN SMALL LETTER X} Exampl\N{LATIN SMALL LETTER E WITH ACUTE}"))
        accented = write_json(self.tmp / "accented.json", {"full_name": "Alex Exampl\N{LATIN SMALL LETTER E WITH ACUTE}"})
        self.assert_silent(["sanitize", "-p", p, "-i", escaped], code=2)
        self.assert_silent(["sanitize", "-p", str(accented), "-i", nfd], code=2)
        # JSON inside a JSON string, with the accent escaped: --json cannot unpack it, so it refuses.
        inner = json.dumps({"to": "Alex Exampl\N{LATIN SMALL LETTER E WITH ACUTE} " + FAKE_SECRET})
        nested = self.file("nested.json", json.dumps({"inner": inner}))
        self.assert_silent(["sanitize", "-p", str(accented), "--json", "-i", nested, "-o", str(self.tmp / "o.json")],
                           code=2)

    def test_bad_input(self) -> None:
        p = str(self.profile)
        self.assert_silent(["sanitize", "-p", p, "--json", "-t", '{"to": "' + TEXT + '"'], code=2)
        deep = self.file("deep.json", "[" * 50_000 + json.dumps(TEXT) + "]" * 50_000)
        self.assert_silent(["sanitize", "-p", p, "--json", "-i", deep], code=2)
        self.assert_silent(["rehydrate", "-p", p, "--json", "-i", deep, "--allow-all"], code=2)
        self.assert_silent(["check", "-p", p, "-i", self.file("legacy2.txt", (TEXT + " caf\xe9").encode("cp1252"))], code=2)
        self.assert_silent(["check", "-p", p, "-i", self.file("u16.txt", TEXT.encode("utf-16"))], code=2)
        self.assert_silent(["check", "-p", p, "-i", self.file("u16le.txt", TEXT.encode("utf-16-le"))], code=2)
        self.assert_silent(["sanitize", "-p", p, "-i", "-"], stdin=(TEXT + " caf\xe9").encode("cp1252"), code=2)
        bad_records = "\n".join([
            json.dumps({"type": "user", "message": {"content": [{"type": "text", "text": 5}]}}),
            "[" * 50_000 + json.dumps(TEXT) + "]" * 50_000,
            "{" + TEXT,
            json.dumps({"type": "user", "message": {"content": TEXT}}),
        ])
        self.assert_silent(["scrub", "-i", self.file("bad.jsonl", bad_records), "-o", str(self.tmp / "o.jsonl")], code=0)
        self.assert_silent(["scrub", "-i", self.file("u16.jsonl", TEXT.encode("utf-16")), "-o", str(self.tmp / "o_u16.jsonl")], code=2)
        self.assert_silent(["scrub", "-i", self.file("cp.jsonl", (TEXT + " caf\xe9").encode("cp1252")), "-o", str(self.tmp / "o_cp.jsonl")], code=2)

    def test_missing_files_and_flags(self) -> None:
        p = str(self.profile)
        self.assert_silent(["check", "-p", p, "-i", str(self.tmp / "missing.txt")], code=2)
        self.assert_silent(["check", "-p", str(self.tmp / "missing.json"), "-t", TEXT], code=2)
        self.assert_silent(["rehydrate", "-p", p, "-t", TEXT], code=2)
        self.assert_silent(["rehydrate", "-p", p, "-t", TEXT, "--allow-from", str(self.tmp / "missing.txt")], code=2)
        self.assert_silent(["scrub", "-i", str(self.tmp / "missing.jsonl"), "-o", str(self.tmp / "o.jsonl")], code=2)

    def test_argument_errors_never_repeat_what_was_typed(self) -> None:
        p = str(self.profile)
        name = SAMPLE_PROFILE_DATA["full_name"]
        self.assert_silent(["check", "-t", *name.split()], code=2)  # unquoted text: a stray word
        self.assert_silent(["check", "-t", "x", FAKE_SECRET], code=2)
        self.assert_silent([name], code=2)  # an unknown command
        self.assert_silent(["sanitize", "-p", p, "-t", "x", f"--json={FAKE_SECRET}"], code=2)
        self.assert_silent(["rehydrate", "-p", p, "-t", "x", f"--allow={FAKE_SECRET}"], code=2)
        self.assert_silent(["check", f"--{FAKE_SECRET}"], code=2)

    def test_bad_profiles(self) -> None:
        name = SAMPLE_PROFILE_DATA["full_name"]
        for label, content in (
            ("unknown key", json.dumps({"fullname": name})),
            ("non-string value", json.dumps({"full_name": [name]})),
            ("non-string custom value", json.dumps({"custom_fields": {"id": [FAKE_SECRET]}})),
            ("custom fields not an object", json.dumps({"custom_fields": [FAKE_SECRET]})),
            ("colliding custom fields", json.dumps({"custom_fields": {"a b": FAKE_SECRET, "a-b": name}})),
            ("duplicate key", '{"full_name": "' + name + '", "full_name": "' + FAKE_SECRET + '"}'),
            ("root is a list", json.dumps([name, FAKE_SECRET])),
            ("invalid JSON", '{"full_name": "' + name),
            ("too short", json.dumps({"full_name": name, "custom_fields": {"x": "AE"}})),
            ("empty", "{}"),
            ("utf-16", json.dumps({"full_name": name}).encode("utf-16")),
        ):
            with self.subTest(profile=label):
                profile = self.file("bad.json", content)
                self.assert_silent(["check", "-p", profile, "-t", TEXT], code=2)
                self.assert_silent(["sanitize", "-p", profile, "-t", TEXT], code=2)


if __name__ == "__main__":
    unittest.main()
