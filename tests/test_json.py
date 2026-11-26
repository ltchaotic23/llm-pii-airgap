"""JSON input: keys, numbers, JSON Lines, escapes and JSON nested inside strings."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from support import (
    ACCENTED_NAME as _ACCENTED_NAME,
    SAMPLE_PROFILE_DATA,
    PIIAirgap,
    run_cli as _run_cli,
    sample_profile as _sample_profile,
    write_json as _write_json,
)


class TestJsonShapes(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.profile = _write_json(Path(tmp.name) / "p.json", SAMPLE_PROFILE_DATA)

    def sanitize_json(self, text: str) -> tuple[int, str]:
        code, out, _ = _run_cli(["sanitize", "-p", str(self.profile), "--json", "-t", text])
        return code, out

    def test_array_root_and_scalars(self) -> None:
        code, out = self.sanitize_json('["Alex Example", 12345, 12345.5, true, null, {"k": []}]')
        self.assertEqual((code, json.loads(out)), (0, ["[FULL_NAME]", "[POSTAL_CODE]", "[POSTAL_CODE].5", True, None, {"k": []}]))

    def test_a_bare_json_string(self) -> None:
        self.assertEqual(self.sanitize_json('"Alex Example"'), (0, '"[FULL_NAME]"\n'))

    def test_unicode_keys_and_values_are_written_without_escapes(self) -> None:
        code, out = self.sanitize_json(json.dumps({"caf\N{LATIN SMALL LETTER E WITH ACUTE}": "Alex Example"}))
        self.assertEqual((code, out), (0, '{\n  "caf\N{LATIN SMALL LETTER E WITH ACUTE}": "[FULL_NAME]"\n}\n'))

    def test_json_lines_skip_blank_lines(self) -> None:
        code, out = self.sanitize_json('{"a": "Alex Example"}\n\n{"b": 1}\n')
        self.assertEqual((code, out), (0, '{"a": "[FULL_NAME]"}\n{"b": 1}\n'))

    def test_one_bad_json_line_fails_the_whole_input(self) -> None:
        code, out = self.sanitize_json('{"a": "Alex Example"}\n{"b": \n')
        self.assertEqual((code, out), (2, ""))

    def test_nested_json_written_without_escapes_is_sanitised_as_text(self) -> None:
        inner = json.dumps({"to": "Alex Example"})
        code, out = self.sanitize_json(json.dumps({"inner": inner}))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(json.loads(out)["inner"]), {"to": "[FULL_NAME]"})

    def test_an_unpaired_surrogate_escape_cannot_be_written(self) -> None:
        backslash = chr(92)
        tmp_dir = Path(self.profile).parent
        target = tmp_dir / "o.json"
        code, out, err = _run_cli(["sanitize", "-p", str(self.profile), "--json", "-o",
                                   str(target), "-t", '{"x": "' + backslash + 'ud800"}'])
        self.assertEqual((code, out), (2, ""))
        self.assertIn("cannot be written as UTF-8", err)
        self.assertFalse(target.exists())

        existing = tmp_dir / "existing.json"
        existing.write_text("DO_NOT_OVERWRITE", encoding="utf-8")
        for argv in (
            ["sanitize", "-p", str(self.profile), "--json", "-o", str(existing), "-t", '{"x": "' + backslash + 'ud800"}'],
            ["rehydrate", "-p", str(self.profile), "--json", "--allow-all", "-o", str(existing),
             "-t", '{"x": "' + backslash + 'ud800"}'],
        ):
            with self.subTest(cmd=argv[0]):
                code, out, err = _run_cli(argv)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("cannot be written as UTF-8", err)
                self.assertEqual(existing.read_text(encoding="utf-8"), "DO_NOT_OVERWRITE")

        bad_jl = tmp_dir / "bad_surrogate.jsonl"
        bad_jl.write_text(
            '{"type": "user", "uuid": "1", "message": {"content": "first row"}}\n'
            '{"type": "user", "uuid": "2", "message": {"content": "bad ' + backslash + 'ud800 row"}}\n',
            encoding="utf-8",
        )
        code, out, err = _run_cli(["scrub", "-i", str(bad_jl), "-o", str(existing)])
        self.assertEqual((code, out), (2, ""))
        self.assertIn("cannot be written as UTF-8", err)
        self.assertEqual(existing.read_text(encoding="utf-8"), "DO_NOT_OVERWRITE")

    def test_nested_json_escape_levels_one_to_four(self) -> None:
        tmp_dir = Path(self.profile).parent
        p_jose = _write_json(tmp_dir / "jose.json", {"full_name": "Jos\N{LATIN SMALL LETTER E WITH ACUTE} Example"})
        payload = json.dumps({"to": "Jos\N{LATIN SMALL LETTER E WITH ACUTE} Example"})
        for level in range(1, 5):
            payload = json.dumps({f"level_{level}": payload})
            with self.subTest(level=level):
                code, out, _ = _run_cli(["check", "-p", str(p_jose), "-t", payload])
                self.assertEqual((code, json.loads(out)["raw_profile_fields_detected"]), (1, ["[FULL_NAME]"]))
                target = tmp_dir / f"nested_{level}.json"
                code, _, err = _run_cli(["sanitize", "-p", str(p_jose), "--json", "-t", payload, "-o", str(target)])
                self.assertEqual(code, 2)
                self.assertIn("nested inside a string", err)
                self.assertFalse(target.exists())

    def test_check_decodes_escaped_surrogate_pairs(self) -> None:
        backslash = chr(92)
        emoji = "\N{GRINNING FACE}"
        profile = _write_json(Path(self.profile).parent / "emoji.json", {"custom_fields": {"handle": f"alex{emoji}example"}})
        escaped = '{"to": "alex' + backslash + "ud83d" + backslash + 'ude00example"}'
        code, out, _ = _run_cli(["check", "-p", str(profile), "-t", escaped])
        self.assertEqual((code, json.loads(out)["raw_profile_fields_detected"]), (1, ["[CUSTOM_HANDLE]"]))

    def test_keys_that_become_equal_are_refused(self) -> None:
        code, out = self.sanitize_json('{"Alex Example": 1, "[FULL_NAME]": 2}')
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
        restored = airgap.rehydrate(sanitized, allow=airgap.profile.placeholder_map().keys())
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
