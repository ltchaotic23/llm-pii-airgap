"""CLI entrypoint for llm-pii-airgap."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Sequence

from .scrubber import redact_secrets, scrub_jsonl_stream
from .tokenizer import IdentityProfile, PIIAirgap


def _read_text_arg(text: str | None, input_path: str | None) -> str:
    if text is not None:
        return text
    if input_path == "-":
        # A Windows pipe defaults to a legacy code page. Decoding UTF-8 input with it garbles
        # accented letters so they no longer match the profile. Stdin is therefore always read
        # as strict UTF-8, and anything else is an error instead of a silent mismatch.
        reconfigure = getattr(sys.stdin, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="strict")
        return sys.stdin.read()
    if input_path is not None:
        return Path(input_path).read_text(encoding="utf-8")
    raise ValueError("Provide either --text or --input.")


def _load_json_documents(raw: str) -> tuple[list[Any], bool]:
    """Parse text as one JSON document or, failing that, as JSON Lines.

    Returns the documents and whether the input was JSON Lines.
    """
    try:
        return [json.loads(raw)], False
    except ValueError as whole_error:
        lines = [line for line in raw.splitlines() if line.strip()]
        if len(lines) < 2:
            raise
        try:
            return [json.loads(line) for line in lines], True
        except ValueError:
            raise whole_error from None


def _dump_json_documents(documents: list[Any], is_json_lines: bool) -> str:
    if is_json_lines:
        return "".join(json.dumps(doc, ensure_ascii=False) + "\n" for doc in documents)
    return json.dumps(documents[0], indent=2, ensure_ascii=False)


_JSON_ESCAPE = re.compile(r'\\(?:u([0-9a-fA-F]{4})|(["\\/bfnrt]))')
_SIMPLE_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
_SURROGATE_PAIR = re.compile("[\ud800-\udbff][\udc00-\udfff]")
_MAX_ESCAPE_DEPTH = 4  # JSON nested inside JSON strings is escaped once per level


def _decode_escape(match: re.Match[str]) -> str:
    if match.group(1):
        return chr(int(match.group(1), 16))
    return _SIMPLE_ESCAPES[match.group(2)]


def _join_surrogates(match: re.Match[str]) -> str:
    high, low = match.group(0)
    return chr(0x10000 + ((ord(high) - 0xD800) << 10) + (ord(low) - 0xDC00))


def _text_views(raw: str) -> list[str]:
    """Return the text as written, plus what it says once JSON-style escapes are decoded.

    JSON can hide a value from a plain-text scan: "Jos\\u00e9" for an accented name, or
    "\\n" in the middle of an address. Leak checks therefore also scan the unescaped text.
    Working on escapes rather than parsing means it holds for JSON, JSON Lines, JSON nested
    in strings, and text that is no longer valid JSON.
    """
    views = [raw]
    for _ in range(_MAX_ESCAPE_DEPTH):
        decoded = _SURROGATE_PAIR.sub(_join_surrogates, _JSON_ESCAPE.sub(_decode_escape, views[-1]))
        if decoded == views[-1]:
            break
        views.append(decoded)
    return views


def _profile_fields_in(airgap: PIIAirgap, raw: str) -> list[str]:
    """Placeholder names whose raw values appear in the text, as written or once unescaped."""
    found: set[str] = set()
    for view in _text_views(raw):
        found.update(airgap.contains_raw_pii(view))
    return [token for token in airgap.profile.placeholder_map() if token in found]


def _redaction_counts_in(raw: str) -> dict[str, int]:
    """How many times each redaction pattern fires: per pattern, the most found in any view of the text.

    Only pattern names and counts leave this function, never the matched text.
    """
    counts: dict[str, int] = {}
    for view in _text_views(raw):
        for placeholder, hits in redact_secrets(view)[1].items():
            counts[placeholder] = max(counts.get(placeholder, 0), hits)
    return counts


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
        documents, is_json_lines = _load_json_documents(raw)
        result = _dump_json_documents([airgap.sanitize_payload(doc) for doc in documents], is_json_lines)
    else:
        result = airgap.sanitize_prompt(raw)

    # Check the result before it leaves: plain-text mode cannot see inside JSON escapes.
    leftover = _profile_fields_in(airgap, result)
    if leftover:
        hint = (
            "They sit in JSON text nested inside a string value, which --json does not unpack."
            if args.json
            else "If the input is JSON or JSON Lines, re-run with --json; otherwise unescape the text first."
        )
        raise ValueError(
            f"Refusing to write output: profile values for {', '.join(leftover)} are still present "
            f"after sanitising, hidden behind escapes such as \\n or \\u00e9. {hint}"
        )
    _write_text_output(result, args.output)
    return 0


def _cmd_rehydrate(args: argparse.Namespace) -> int:
    profile = IdentityProfile.from_json_file(args.profile)
    airgap = PIIAirgap(profile)
    raw = _read_text_arg(args.text, args.input)
    allow: set[str] | None = None
    if args.allow_from:
        # Restore only placeholders that were present in the prompt actually sent.
        allow = airgap.placeholders_in(Path(args.allow_from).read_text(encoding="utf-8"))
    if args.json:
        documents, is_json_lines = _load_json_documents(raw)
        result = _dump_json_documents([airgap.rehydrate(doc, allow=allow) for doc in documents], is_json_lines)
    else:
        result = str(airgap.rehydrate(raw, allow=allow))
    _write_text_output(result, args.output)
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    raw = _read_text_arg(args.text, args.input)
    pattern_counts = _redaction_counts_in(raw)
    pii_hits: list[str] = []
    if args.profile:
        airgap = PIIAirgap(IdentityProfile.from_json_file(args.profile))
        pii_hits = _profile_fields_in(airgap, raw)

    clean = (not pattern_counts) and (not pii_hits)
    report = {
        "clean": clean,
        "secret_pattern_counts": pattern_counts,
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
        p_tok.add_argument(
            "--json",
            action="store_true",
            help="Parse input as JSON (or JSON Lines) and transform keys and values recursively.",
        )
        if name == "rehydrate":
            p_tok.add_argument(
                "--allow-from",
                metavar="SANITIZED_PROMPT",
                help="Only restore placeholders that appear in this sanitized prompt file.",
            )
        p_tok.set_defaults(func=handler)

    p_check = sub.add_parser(
        "check",
        help="Exit 1 if secret patterns or raw profile PII are found (JSON and JSON Lines are also decoded).",
    )
    group = p_check.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--text", help="Inline text to scan.")
    group.add_argument("-i", "--input", help="Input file path (or '-' for stdin).")
    p_check.add_argument("-p", "--profile", help="Optional identity profile JSON to check for raw PII.")
    p_check.set_defaults(func=_cmd_check)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (ValueError, OSError) as exc:
        # Exit 2 keeps "could not run" distinct from check's exit 1 ("leaks found").
        # Messages name fields and files only, never the values being protected.
        sys.stderr.write(f"error: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
