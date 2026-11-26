"""Every command, flag and exit code of the command-line tool."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from support import FAKE_SECRET, SAMPLE_PROFILE_DATA, cli_main, run_cli, write_json

from llm_pii_airgap import __version__


class TestCommands(unittest.TestCase):
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
                cli_main(
                    ["rehydrate", "-p", str(profile_path), "-i", str(sanitized_file),
                     "--allow-from", str(sanitized_file), "-o", str(rehydrated_file)]
                ),
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


class CliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.profile = write_json(self.tmp / "profile.json", SAMPLE_PROFILE_DATA)

    def file(self, name: str, text: str) -> Path:
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        return path


class TestTopLevel(CliTestCase):
    def test_version(self) -> None:
        code, out, err = run_cli(["--version"])
        self.assertEqual((code, out, err), (0, f"llm-pii-airgap {__version__}\n", ""))

    def test_help_lists_every_command(self) -> None:
        code, out, _ = run_cli(["--help"])
        self.assertEqual(code, 0)
        for command in ("scrub", "sanitize", "rehydrate", "check"):
            self.assertIn(command, out)

    def test_missing_or_unknown_command_exits_2(self) -> None:
        for argv in ([], ["scan"], ["sanitize"], ["check"], ["scrub", "-i", "x.jsonl"]):
            with self.subTest(argv=argv):
                code, out, err = run_cli(argv)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertIn("error:", err)


class TestScrubCommand(CliTestCase):
    def write_transcript(self, records: list[dict]) -> Path:
        return self.file("in.jsonl", "".join(json.dumps(r) + "\n" for r in records))

    def test_prints_counts_only_and_creates_the_output_folder(self) -> None:
        source = self.write_transcript(
            [{"type": "user", "uuid": "1", "message": {"content": f"use DB_PASSWORD={FAKE_SECRET} on 203.0.113.9"}}]
        )
        target = self.tmp / "new" / "folder" / "out.jsonl"
        code, out, err = run_cli(["scrub", "-i", str(source), "-o", str(target)])
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(
            json.loads(out),
            {
                "lines_read": 1,
                "rows_kept": 1,
                "duplicates_skipped": 0,
                "invalid_json": 0,
                "non_user_skipped": 0,
                "redactions": {"<IP>": 1, "<SECRET>": 1},
            },
        )
        self.assertNotIn(FAKE_SECRET, out)
        row = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(row, {"uuid": "1", "timestamp": None, "text": "use DB_PASSWORD=<SECRET> on <IP>"})

    def test_keep_tool_results_keeps_the_text_but_never_the_tool_output(self) -> None:
        record = {
            "type": "user",
            "uuid": "1",
            "toolUseResult": {"stdout": "tool output"},
            "message": {"content": [
                {"type": "tool_result", "content": "tool output"},
                {"type": "text", "text": "and my note"},
            ]},
        }
        source = self.write_transcript([record])
        target = self.tmp / "out.jsonl"
        code, out, _ = run_cli(["scrub", "-i", str(source), "-o", str(target)])
        self.assertEqual((code, json.loads(out)["rows_kept"]), (0, 0))

        code, out, _ = run_cli(["scrub", "-i", str(source), "-o", str(target), "--keep-tool-results"])
        self.assertEqual((code, json.loads(out)["rows_kept"]), (0, 1))
        written = target.read_text(encoding="utf-8")
        self.assertEqual(json.loads(written)["text"], "and my note")
        self.assertNotIn("tool output", written)

    def test_missing_input_exits_2_and_writes_nothing(self) -> None:
        target = self.tmp / "out.jsonl"
        code, out, err = run_cli(["scrub", "-i", str(self.tmp / "missing.jsonl"), "-o", str(target)])
        self.assertEqual((code, out), (2, ""))
        self.assertTrue(err.startswith("error: "))
        self.assertFalse(target.exists())


class TestSanitizeCommand(CliTestCase):
    def test_inline_text_goes_to_stdout(self) -> None:
        code, out, err = run_cli(["sanitize", "-p", str(self.profile), "-t", "Hi Alex Example"])
        self.assertEqual((code, out, err), (0, "Hi [FULL_NAME]\n", ""))

    def test_file_in_file_out_prints_nothing(self) -> None:
        source = self.file("in.txt", "Hi Alex Example")
        target = self.tmp / "out.txt"
        code, out, err = run_cli(["sanitize", "-p", str(self.profile), "-i", str(source), "-o", str(target)])
        self.assertEqual((code, out, err), (0, "", ""))
        self.assertEqual(target.read_text(encoding="utf-8"), "Hi [FULL_NAME]")

    def test_json_document_and_json_lines(self) -> None:
        code, out, _ = run_cli(["sanitize", "-p", str(self.profile), "--json", "-t", '{"to": "Alex Example"}'])
        self.assertEqual((code, out), (0, '{\n  "to": "[FULL_NAME]"\n}\n'))
        lines = '{"to": "Alex Example"}\n{"n": 12345}\n'
        code, out, _ = run_cli(["sanitize", "-p", str(self.profile), "--json", "-t", lines])
        self.assertEqual((code, out), (0, '{"to": "[FULL_NAME]"}\n{"n": "[POSTAL_CODE]"}\n'))

    def test_invalid_json_exits_2(self) -> None:
        code, out, err = run_cli(["sanitize", "-p", str(self.profile), "--json", "-t", '{"to": "Alex Example"'])
        self.assertEqual((code, out), (2, ""))
        self.assertTrue(err.startswith("error: "))

    def test_text_and_input_are_exclusive_and_one_is_required(self) -> None:
        source = self.file("in.txt", "x")
        for argv in (["-t", "x", "-i", str(source)], []):
            with self.subTest(argv=argv):
                code, out, _ = run_cli(["sanitize", "-p", str(self.profile), *argv])
                self.assertEqual((code, out), (2, ""))

    def test_missing_profile_exits_2(self) -> None:
        code, out, err = run_cli(["sanitize", "-p", str(self.tmp / "missing.json"), "-t", "x"])
        self.assertEqual((code, out), (2, ""))
        self.assertTrue(err.startswith("error: "))
        code, _, _ = run_cli(["sanitize", "-t", "x"])
        self.assertEqual(code, 2)

    def test_direct_leftover_refusal_message_does_not_blame_escapes(self) -> None:
        profile = write_json(
            self.tmp / "tag_profile.json",
            {"full_name": "Alex Example", "custom_fields": {"tag": "FULL_NAME"}},
        )
        code, out, err = run_cli(["sanitize", "-p", str(profile), "-t", "Alex Example"])
        self.assertEqual((code, out), (2, ""))
        self.assertNotIn("hidden behind escapes", err)
        self.assertIn("still present", err)


class TestRehydrateCommand(CliTestCase):
    reply = "Dear [FULL_NAME], we will ship to [ADDRESS]."

    def test_an_allow_list_choice_is_required(self) -> None:
        code, out, err = run_cli(["rehydrate", "-p", str(self.profile), "-t", self.reply])
        self.assertEqual((code, out), (2, ""))
        self.assertIn("--allow-from", err)
        self.assertIn("--allow-all", err)

    def test_allow_from_and_allow_all_are_exclusive(self) -> None:
        sent = self.file("sent.txt", "Greet [FULL_NAME]")
        code, out, _ = run_cli(
            ["rehydrate", "-p", str(self.profile), "-t", self.reply, "--allow-from", str(sent), "--allow-all"]
        )
        self.assertEqual((code, out), (2, ""))

    def test_allow_from_restores_only_what_was_sent(self) -> None:
        sent = self.file("sent.txt", "Greet [FULL_NAME]")
        code, out, _ = run_cli(["rehydrate", "-p", str(self.profile), "-t", self.reply, "--allow-from", str(sent)])
        self.assertEqual((code, out), (0, "Dear Alex Example, we will ship to [ADDRESS].\n"))

    def test_allow_all_restores_everything(self) -> None:
        code, out, _ = run_cli(["rehydrate", "-p", str(self.profile), "-t", self.reply, "--allow-all"])
        self.assertEqual((code, out), (0, "Dear Alex Example, we will ship to 100 Maple Avenue, Springfield.\n"))

    def test_json_mode(self) -> None:
        sent = self.file("sent.txt", '{"to": "[FULL_NAME]"}')
        code, out, _ = run_cli(
            ["rehydrate", "-p", str(self.profile), "--json", "-t", '{"[FULL_NAME]": "[ADDRESS]"}',
             "--allow-from", str(sent)]
        )
        self.assertEqual((code, json.loads(out)), (0, {"Alex Example": "[ADDRESS]"}))

    def test_missing_allow_from_file_exits_2(self) -> None:
        code, out, err = run_cli(
            ["rehydrate", "-p", str(self.profile), "-t", self.reply, "--allow-from", str(self.tmp / "missing.txt")]
        )
        self.assertEqual((code, out), (2, ""))
        self.assertTrue(err.startswith("error: "))

    def test_stdin_input(self) -> None:
        from support import run_cli_subprocess
        proc = run_cli_subprocess(
            ["rehydrate", "-p", str(self.profile), "-i", "-", "--allow-all"],
            stdin=b"Dear [FULL_NAME]",
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.decode("utf-8").rstrip("\r\n"), "Dear Alex Example")


class TestCheckCommand(CliTestCase):
    def test_clean_text_exits_0(self) -> None:
        code, out, err = run_cli(["check", "-p", str(self.profile), "-t", "Hi [FULL_NAME]"])
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(
            json.loads(out), {"clean": True, "secret_pattern_counts": {}, "raw_profile_fields_detected": []}
        )

    def test_findings_exit_1_with_counts_and_field_names_only(self) -> None:
        text = f"Alex Example, DB_PASSWORD={FAKE_SECRET}, 203.0.113.9 and 198.51.100.7"
        code, out, _ = run_cli(["check", "-p", str(self.profile), "-t", text])
        self.assertEqual(code, 1)
        self.assertEqual(
            json.loads(out),
            {
                "clean": False,
                "secret_pattern_counts": {"<IP>": 2, "<SECRET>": 1},
                "raw_profile_fields_detected": ["[FULL_NAME]"],
            },
        )
        for value in ("Alex Example", FAKE_SECRET, "203.0.113.9"):
            self.assertNotIn(value, out)

    def test_profile_is_optional(self) -> None:
        code, out, _ = run_cli(["check", "-t", "Alex Example"])
        self.assertEqual((code, json.loads(out)["clean"]), (0, True))

    def test_missing_input_or_bad_profile_exits_2(self) -> None:
        bad = write_json(self.tmp / "bad.json", {"fullname": "Alex Example"})
        for argv in (["-i", str(self.tmp / "missing.txt")], ["-p", str(bad), "-t", "x"]):
            with self.subTest(argv=argv):
                code, out, err = run_cli(["check", *argv])
                self.assertEqual((code, out), (2, ""))
                self.assertTrue(err.startswith("error: "))


if __name__ == "__main__":
    unittest.main()
