"""Shared helpers and sample data for the tests.

Every value here is made up. Names are plainly fictional, email addresses use reserved test
domains (example.invalid), phone numbers come from the fictional +1 202 555 0100 to 0199
range, and IP addresses come from the documentation ranges (192.0.2.x, 198.51.100.x,
203.0.113.x). Fake secrets contain FAKE where the format allows it and are assembled at run
time from fragments, so this repository never holds a whole token-shaped string.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from llm_pii_airgap import (  # noqa: E402
    REDACT_RULES,
    IdentityProfile,
    PIIAirgap,
    redact_secrets,
    scrub_jsonl_stream,
    strip_harness_tags,
)
from llm_pii_airgap.cli import main as cli_main  # noqa: E402


def j(*parts: str) -> str:
    """Join fragments into one fake value."""
    return "".join(parts)


FAKE_SECRET = j("hunter2", "secret")
ACCENTED_NAME = "Jos\N{LATIN SMALL LETTER E WITH ACUTE} Mu\N{LATIN SMALL LETTER N WITH TILDE}oz"

SAMPLE_PROFILE_DATA = {
    "full_name": "Alex Example",
    "email": "alex.example@example.invalid",
    "phone": "+1 202 555 0143",
    "street_address": "100 Maple Avenue, Springfield",
    "postal_code": "12345",
    "custom_fields": {"employee_id": "EMP-9042"},
}


def sample_profile() -> IdentityProfile:
    return IdentityProfile(**SAMPLE_PROFILE_DATA)


def run_cli(argv: list[str]) -> tuple[int, str, str]:
    """Run the CLI in-process and return (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli_main(argv)
        except SystemExit as exc:  # argparse errors, --help and --version
            code = exc.code if isinstance(exc.code, int) else 2
    return code, out.getvalue(), err.getvalue()


def run_cli_subprocess(argv: list[str], *, stdin: bytes | None = None) -> subprocess.CompletedProcess:
    """Run the CLI in a fresh interpreter, as a user would, and capture its raw output.

    PYTHONIOENCODING is removed so the child uses the platform's default encodings.
    """
    env = {k: v for k, v in os.environ.items() if k != "PYTHONIOENCODING"}
    env["PYTHONPATH"] = str(SRC)
    return subprocess.run(
        [sys.executable, "-m", "llm_pii_airgap.cli", *argv],
        input=stdin,
        capture_output=True,
        env=env,
        timeout=120,
    )


def write_json(path: Path, data: object, *, ascii_escapes: bool = False) -> Path:
    path.write_text(json.dumps(data, ensure_ascii=ascii_escapes), encoding="utf-8")
    return path


__all__ = [
    "ACCENTED_NAME",
    "FAKE_SECRET",
    "REDACT_RULES",
    "ROOT",
    "SAMPLE_PROFILE_DATA",
    "IdentityProfile",
    "PIIAirgap",
    "cli_main",
    "j",
    "redact_secrets",
    "run_cli",
    "run_cli_subprocess",
    "sample_profile",
    "scrub_jsonl_stream",
    "strip_harness_tags",
    "write_json",
]
