"""CLI entrypoint for llm-pii-airgap."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .scrubber import redact_secrets, scrub_jsonl_stream
from .tokenizer import IdentityProfile, PIIAirgap


def _read_text_arg(text: str | None, input_path: str | None) -> str:
    if text is not None:
        return text
    if input_path == "-":
        return sys.stdin.read()
    if input_path is not None:
        return Path(input_path).read_text(encoding="utf-8")
    raise ValueError("Provide either --text or --input.")


def _write_text_output(content: str, output_path: str | None) -> None:
    if output_path:
        Path(output_path).write_text(content, encoding="utf-8")
    else:
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")


def _cmd_scrub(args: argparse.Namespace) -> int:
    in_path = Path(args.input)
    out_path = Path(args.output)
    with in_path.open("r", encoding="utf-8", errors="replace") as src:
        rows, summary = scrub_jsonl_stream(src, drop_tool_results=not args.keep_tool_results)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="\n") as dst:
        for row in rows:
            dst.write(json.dumps(row, ensure_ascii=False) + "\n")

    sys.stdout.write(json.dumps(summary, indent=2) + "\n")
    return 0


def _cmd_sanitize(args: argparse.Namespace) -> int:
    profile = IdentityProfile.from_json_file(args.profile)
    airgap = PIIAirgap(profile)
    raw = _read_text_arg(args.text, args.input)
    if args.json:
        payload = json.loads(raw)
        result = json.dumps(airgap.sanitize_payload(payload), indent=2, ensure_ascii=False)
    else:
        result = airgap.sanitize_prompt(raw)
    _write_text_output(result, args.output)
    return 0


def _cmd_rehydrate(args: argparse.Namespace) -> int:
    profile = IdentityProfile.from_json_file(args.profile)
    airgap = PIIAirgap(profile)
    raw = _read_text_arg(args.text, args.input)
    if args.json:
        payload = json.loads(raw)
        result = json.dumps(airgap.rehydrate(payload), indent=2, ensure_ascii=False)
    else:
        result = str(airgap.rehydrate(raw))
    _write_text_output(result, args.output)
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    raw = _read_text_arg(args.text, args.input)
    _, secret_counts = redact_secrets(raw)
    pii_hits: list[str] = []
    if args.profile:
        airgap = PIIAirgap(IdentityProfile.from_json_file(args.profile))
        pii_hits = airgap.contains_raw_pii(raw)

    clean = (not secret_counts) and (not pii_hits)
    report = {
        "clean": clean,
        "secret_pattern_counts": secret_counts,
        "raw_profile_fields_detected": pii_hits,
    }
    sys.stdout.write(json.dumps(report, indent=2) + "\n")
    return 0 if clean else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llm-pii-airgap",
        description="Client-side PII tokeniser and JSONL agent transcript secret scrubber.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scrub = sub.add_parser("scrub", help="Filter and redact secrets/PII from a JSONL transcript.")
    p_scrub.add_argument("-i", "--input", required=True, help="Path to source .jsonl file.")
    p_scrub.add_argument("-o", "--output", required=True, help="Path to write scrubbed .jsonl output.")
    p_scrub.add_argument(
        "--keep-tool-results",
        action="store_true",
        help="Retain user records carrying tool_result payloads.",
    )
    p_scrub.set_defaults(func=_cmd_scrub)

    for name, help_text, handler in (
        ("sanitize", "Replace raw profile PII with placeholders before sending to an LLM.", _cmd_sanitize),
        ("rehydrate", "Restore placeholders in LLM output back to local profile values.", _cmd_rehydrate),
    ):
        p_tok = sub.add_parser(name, help=help_text)
        p_tok.add_argument("-p", "--profile", required=True, help="Path to local JSON identity profile.")
        group = p_tok.add_mutually_exclusive_group(required=True)
        group.add_argument("-t", "--text", help="Inline text to transform.")
        group.add_argument("-i", "--input", help="Input file path (or '-' for stdin).")
        p_tok.add_argument("-o", "--output", help="Optional output file path.")
        p_tok.add_argument("--json", action="store_true", help="Parse input as JSON and transform recursively.")
        p_tok.set_defaults(func=handler)

    p_check = sub.add_parser("check", help="Exit 1 if secret patterns or raw profile PII are found.")
    group = p_check.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--text", help="Inline text to scan.")
    group.add_argument("-i", "--input", help="Input file path (or '-' for stdin).")
    p_check.add_argument("-p", "--profile", help="Optional identity profile JSON to check for raw PII.")
    p_check.set_defaults(func=_cmd_check)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
