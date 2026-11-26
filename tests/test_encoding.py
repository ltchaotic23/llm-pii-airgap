"""Input encodings: piped UTF-8, byte order marks, UTF-16, legacy code pages and line endings."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import (
    ACCENTED_NAME as _ACCENTED_NAME,
    SAMPLE_PROFILE_DATA,
    run_cli as _run_cli,
    run_cli_subprocess,
    write_json as _write_json,
)

BOM = b"\xef\xbb\xbf"


class FileEncodingTestCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.profile = _write_json(self.tmp / "p.json", SAMPLE_PROFILE_DATA)

    def bytes_file(self, name: str, data: bytes) -> Path:
        path = self.tmp / name
        path.write_bytes(data)
        return path


class TestByteOrderMark(FileEncodingTestCase):
    """Notepad and Windows PowerShell 5.1 save UTF-8 with a byte order mark."""

    def test_profile_with_bom_loads(self) -> None:
        profile = self.bytes_file("bom.json", BOM + json.dumps(SAMPLE_PROFILE_DATA).encode("utf-8"))
        code, out, err = _run_cli(["sanitize", "-p", str(profile), "-t", "Hi Alex Example"])
        self.assertEqual((code, out, err), (0, "Hi [FULL_NAME]\n", ""))

    def test_text_input_with_bom(self) -> None:
        source = self.bytes_file("in.txt", BOM + b"Alex Example wrote this")
        target = self.tmp / "out.txt"
        code, _, err = _run_cli(["sanitize", "-p", str(self.profile), "-i", str(source), "-o", str(target)])
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(target.read_bytes(), b"[FULL_NAME] wrote this")

    def test_json_input_with_bom(self) -> None:
        source = self.bytes_file("in.json", BOM + b'{"to": "Alex Example"}')
        code, out, _ = _run_cli(["sanitize", "-p", str(self.profile), "--json", "-i", str(source)])
        self.assertEqual((code, json.loads(out)), (0, {"to": "[FULL_NAME]"}))
        code, out, _ = _run_cli(["check", "-p", str(self.profile), "-i", str(source)])
        self.assertEqual((code, json.loads(out)["raw_profile_fields_detected"]), (1, ["[FULL_NAME]"]))

    def test_allow_from_and_transcript_with_bom(self) -> None:
        sent = self.bytes_file("sent.txt", BOM + b"[FULL_NAME]")
        code, out, _ = _run_cli(["rehydrate", "-p", str(self.profile), "-t", "[FULL_NAME]", "--allow-from", str(sent)])
        self.assertEqual((code, out), (0, "Alex Example\n"))
        record = json.dumps({"type": "user", "uuid": "1", "message": {"content": "hello"}}).encode("utf-8")
        source = self.bytes_file("in.jsonl", BOM + record + b"\n")
        code, out, _ = _run_cli(["scrub", "-i", str(source), "-o", str(self.tmp / "out.jsonl")])
        self.assertEqual((code, json.loads(out)["rows_kept"], json.loads(out)["invalid_json"]), (0, 1, 0))


class TestUtf16(FileEncodingTestCase):
    """UTF-16 is refused: read as UTF-8, its letters are split by NUL bytes and never match."""

    def test_utf16_with_bom_is_refused(self) -> None:
        source = self.bytes_file("in.txt", "Alex Example".encode("utf-16"))
        for command in (["check"], ["sanitize"]):
            with self.subTest(command=command[0]):
                code, out, err = _run_cli([*command, "-p", str(self.profile), "-i", str(source)])
                self.assertEqual((code, out), (2, ""))
                self.assertIn("UTF-8", err)
        jsonl_src = self.bytes_file("in.jsonl", '{"type": "user", "message": {"content": "hi"}}\n'.encode("utf-16"))
        target = self.tmp / "out.jsonl"
        code, out, err = _run_cli(["scrub", "-i", str(jsonl_src), "-o", str(target)])
        self.assertEqual((code, out), (2, ""))
        self.assertIn("UTF-8", err)
        self.assertFalse(target.exists())

    def test_utf16_without_bom_is_refused_not_passed_as_clean(self) -> None:
        source = self.bytes_file("in.txt", "Alex Example".encode("utf-16-le"))
        for command in (["check"], ["sanitize"]):
            with self.subTest(command=command[0]):
                code, out, err = _run_cli([*command, "-p", str(self.profile), "-i", str(source)])
                self.assertEqual((code, out), (2, ""))
                self.assertIn("UTF-16", err)
        jsonl_src = self.bytes_file("in_le.jsonl", '{"type": "user", "message": {"content": "hi"}}\n'.encode("utf-16-le"))
        target = self.tmp / "out_le.jsonl"
        code, out, err = _run_cli(["scrub", "-i", str(jsonl_src), "-o", str(target)])
        self.assertEqual((code, out), (2, ""))
        self.assertIn("UTF-16", err)
        self.assertFalse(target.exists())

    def test_utf16_piped_without_bom_is_refused(self) -> None:
        proc = run_cli_subprocess(["check", "-p", str(self.profile), "-i", "-"], stdin="Alex Example".encode("utf-16-le"))
        self.assertEqual((proc.returncode, proc.stdout), (2, b""))


class TestLegacyCodePage(FileEncodingTestCase):
    def test_legacy_file_is_refused(self) -> None:
        source = self.bytes_file("in.txt", f"Write to {_ACCENTED_NAME}".encode("cp1252"))
        profile = _write_json(self.tmp / "accented.json", {"full_name": _ACCENTED_NAME})
        for command in ("check", "sanitize"):
            with self.subTest(command=command):
                code, out, err = _run_cli([command, "-p", str(profile), "-i", str(source)])
                self.assertEqual((code, out), (2, ""))
                self.assertIn("not valid UTF-8", err)

    def test_scrub_refuses_legacy_encoding(self) -> None:
        record = json.dumps({"type": "user", "uuid": "1", "message": {"content": "caf\xe9 at 203.0.113.9"}},
                            ensure_ascii=False)
        source = self.bytes_file("in.jsonl", record.encode("cp1252") + b"\n")
        target = self.tmp / "out.jsonl"
        code, out, err = _run_cli(["scrub", "-i", str(source), "-o", str(target)])
        self.assertEqual((code, out), (2, ""))
        self.assertIn("not valid UTF-8", err)
        self.assertFalse(target.exists())


class TestLineEndingsAndSizes(FileEncodingTestCase):
    def test_crlf_input(self) -> None:
        source = self.bytes_file("in.txt", b"Dear Alex\r\nExample,\r\nyour code is 12345.\r\n")
        target = self.tmp / "out.txt"
        code, _, _ = _run_cli(["sanitize", "-p", str(self.profile), "-i", str(source), "-o", str(target)])
        self.assertEqual(code, 0)
        written = target.read_text(encoding="utf-8")
        self.assertEqual(written.splitlines(), ["Dear [FULL_NAME],", "your code is [POSTAL_CODE]."])
        code, out, _ = _run_cli(["check", "-p", str(self.profile), "-i", str(source)])
        self.assertEqual(json.loads(out)["raw_profile_fields_detected"], ["[FULL_NAME]", "[POSTAL_CODE]"])

    def test_empty_file(self) -> None:
        source = self.bytes_file("empty.txt", b"")
        target = self.tmp / "out.txt"
        code, _, _ = _run_cli(["sanitize", "-p", str(self.profile), "-i", str(source), "-o", str(target)])
        self.assertEqual((code, target.read_bytes()), (0, b""))
        code, out, _ = _run_cli(["check", "-p", str(self.profile), "-i", str(source)])
        self.assertEqual((code, json.loads(out)["clean"]), (0, True))
        code, out, _ = _run_cli(["scrub", "-i", str(source), "-o", str(target)])
        self.assertEqual((code, json.loads(out)["lines_read"]), (0, 0))

    def test_very_long_line(self) -> None:
        source = self.bytes_file("long.txt", b"x " * 1_000_000 + b"Alex Example")
        code, out, _ = _run_cli(["check", "-p", str(self.profile), "-i", str(source)])
        self.assertEqual((code, json.loads(out)["raw_profile_fields_detected"]), (1, ["[FULL_NAME]"]))


class TestOutputEncoding(FileEncodingTestCase):
    def test_stdout_is_utf8_even_on_a_legacy_console(self) -> None:
        # A redirected stdout on Windows defaults to a legacy code page that cannot hold every name.
        profile = _write_json(self.tmp / "cjk.json", {"full_name": "\N{CJK UNIFIED IDEOGRAPH-738B}\N{CJK UNIFIED IDEOGRAPH-5C0F}\N{CJK UNIFIED IDEOGRAPH-660E}"})
        proc = run_cli_subprocess(["rehydrate", "-p", str(profile), "-t", "Hi [FULL_NAME]", "--allow-all"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.decode("utf-8").rstrip("\r\n"), "Hi \N{CJK UNIFIED IDEOGRAPH-738B}\N{CJK UNIFIED IDEOGRAPH-5C0F}\N{CJK UNIFIED IDEOGRAPH-660E}")



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

        with mock.patch.object(sys, "stdin", self._legacy_stdin(b"Hello [FULL_NAME]")):
            code, out, _ = _run_cli(["rehydrate", "-p", str(self.profile), "-i", "-", "--allow-all"])
        self.assertEqual((code, out), (0, f"Hello {_ACCENTED_NAME}\n"))

    def test_stdin_that_is_not_utf8_is_an_error_not_a_guess(self) -> None:
        piped = f"Write to {_ACCENTED_NAME} please".encode("cp1252")
        with mock.patch.object(sys, "stdin", self._legacy_stdin(piped)):
            code, out, _ = _run_cli(["sanitize", "-p", str(self.profile), "-i", "-"])
        self.assertEqual((code, out), (2, ""))


if __name__ == "__main__":
    unittest.main()
