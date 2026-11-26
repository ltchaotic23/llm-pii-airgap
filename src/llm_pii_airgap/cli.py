"""CLI entrypoint for llm-pii-airgap."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import unicodedata
from collections.abc import Collection, Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .scrubber import redact_secrets, scrub_jsonl_stream
from .tokenizer import IdentityProfile, PIIAirgap, _char_ranges


def _read_text_arg(text: str | None, input_path: str | None) -> str:
    if text is not None:
        return _checked_text(text)
    if input_path == "-":
        # A Windows pipe defaults to a legacy code page. Decoding UTF-8 input with it garbles
        # accented letters so they no longer match the profile. Stdin is therefore always read
        # as strict UTF-8, and anything else is an error instead of a silent mismatch.
        reconfigure = getattr(sys.stdin, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="strict")
        return _checked_text(sys.stdin.read().removeprefix("\N{BYTE ORDER MARK}"))
    if input_path is not None:
        return _read_file(input_path)
    raise ValueError("Provide either --text or --input.")


def _read_file(path: str) -> str:
    return _checked_text(Path(path).read_text(encoding="utf-8-sig"))  # -sig: accept a byte order mark


def _checked_text(text: str) -> str:
    # UTF-16 text without a byte order mark is valid UTF-8 with a NUL after every ASCII letter,
    # so no profile value or secret pattern would match it. Refuse it instead of passing it as clean.
    if "\0" in text:
        raise ValueError(
            "The input contains NUL characters, so it is probably UTF-16 or a binary file. "
            "Save it as UTF-8 and try again."
        )
    return text


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
_MAX_ESCAPE_DEPTH = 5  # plain JSON plus four nested JSON-in-JSON string levels


def _decode_escape(match: re.Match[str]) -> str:
    if match.group(1):
        return chr(int(match.group(1), 16))
    return _SIMPLE_ESCAPES[match.group(2)]


def _join_surrogates(match: re.Match[str]) -> str:
    high, low = match.group(0)
    return chr(0x10000 + ((ord(high) - 0xD800) << 10) + (ord(low) - 0xDC00))


# Invisible format characters (Cf: zero-width spaces/joiners, direction marks, tag characters,
# BOM) plus variation selectors and blank fillers that can sit inside a value invisibly.
_INVISIBLE = re.compile(
    "["
    + _char_ranges(
        [cp for cp in range(sys.maxunicode + 1) if unicodedata.category(chr(cp)) == "Cf"]
        + [
            0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, *range(0x180B, 0x1810),
            0x3164, *range(0xFE00, 0xFE10), 0xFFA0, *range(0xE0100, 0xE01F0),
        ]
    )
    + "]"
)


def _text_views(raw: str, *, normalise: bool = True) -> list[str]:
    """Return the text as written, plus what it says once JSON-style escapes are decoded.

    JSON can hide a value from a plain-text scan: "Jos\\u00e9" for an accented name, or
    "\\n" in the middle of an address. Leak checks therefore also scan the unescaped text.
    Working on escapes rather than parsing means it holds for JSON, JSON Lines, JSON nested
    in strings, and text that is no longer valid JSON.

    With ``normalise``, each view is also scanned with invisible characters removed and NFKC
    normalisation applied, so a decomposed accent, a zero-width space inside a name or
    full-width digits in a phone number are still found.
    """
    views = [raw]
    for _ in range(_MAX_ESCAPE_DEPTH):
        decoded = _SURROGATE_PAIR.sub(_join_surrogates, _JSON_ESCAPE.sub(_decode_escape, views[-1]))
        if decoded == views[-1]:
            break
        views.append(decoded)
    if normalise:
        for view in list(views):
            normalised = unicodedata.normalize("NFKC", _INVISIBLE.sub("", view))
            if normalised not in views:
                views.append(normalised)
    return views


def _profile_fields_in(airgap: PIIAirgap, raw: str, *, normalise: bool = True) -> list[str]:
    """Placeholder names whose raw values appear in the text, as written or once unescaped."""
    found: set[str] = set()
    for view in _text_views(raw, normalise=normalise):
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


def _atomic_write_text(
    path: Path,
    content: str,
    *,
    newline: str | None = None,
    make_parents: bool = False,
) -> None:
    content.encode("utf-8")  # fail before creating folders or touching any target file
    if make_parents:
        path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline=newline,
            dir=path.parent,
            prefix=".llm-pii-airgap-",
            suffix=".tmp",
            delete=False,
        ) as handle:
            tmp_path = Path(handle.name)
            handle.write(content)
        os.replace(tmp_path, path)
    except BaseException:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)
        raise


def _write_text_output(content: str, output_path: str | None) -> None:
    if output_path:
        _atomic_write_text(Path(output_path), content)
    else:
        content.encode("utf-8")
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")


def _cmd_scrub(args: argparse.Namespace) -> int:
    in_path = Path(args.input)
    out_path = Path(args.output)
    with in_path.open("r", encoding="utf-8-sig", errors="strict") as src:
        rows, summary = scrub_jsonl_stream(
            (_checked_text(line) for line in src),
            drop_tool_results=not args.keep_tool_results,
        )

    content = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
    _atomic_write_text(out_path, content, newline="\n", make_parents=True)

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

    # Check the result before it leaves: plain-text mode cannot see inside JSON escapes, and
    # neither mode replaces a value written with look-alike Unicode.
    direct = airgap.contains_raw_pii(result)
    if direct:
        raise ValueError(
            f"Refusing to write output: profile values for {', '.join(direct)} are still present "
            "in the sanitised output (for example inside an inserted placeholder)."
        )
    leftover = _profile_fields_in(airgap, result)
    if leftover and not _profile_fields_in(airgap, result, normalise=False):
        raise ValueError(
            f"Refusing to write output: profile values for {', '.join(leftover)} are still present "
            "after sanitising, written with Unicode variants such as a decomposed accent, a zero-width "
            "character or full-width digits. Normalise the text (NFKC) and remove invisible characters, "
            "then try again."
        )
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
    if args.allow_all:
        allow: Collection[str] = profile.placeholder_map().keys()
    else:
        # Restore only placeholders that were present in the prompt actually sent.
        allow = airgap.placeholders_in(_read_file(args.allow_from))
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


# argparse quotes what was typed in a few of its errors. A word of unquoted -t text that lands
# as a stray argument could be a name or a secret, so those parts of the message are replaced.
_ECHOING_ERRORS = (
    (re.compile(r"unrecognized arguments: .*", re.S), "unrecognized arguments (not shown; put text with spaces in quotes)"),
    (re.compile(r"invalid choice: .*?(?=\(choose from [^()]*\)$)|invalid choice: .*", re.S), "invalid choice "),
    (re.compile(r"ignored explicit argument .*", re.S), "this option takes no value"),
    (re.compile(r"ambiguous option: .*? could match", re.S), "ambiguous option, could match"),
)


class _QuietParser(argparse.ArgumentParser):
    def error(self, message: str):  # type: ignore[override]
        for pattern, replacement in _ECHOING_ERRORS:
            message = pattern.sub(replacement, message)
        super().error(message.strip())


def build_parser() -> argparse.ArgumentParser:
    parser = _QuietParser(
        prog="llm-pii-airgap",
        description="Client-side PII tokeniser and JSONL agent transcript secret scrubber.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scrub = sub.add_parser("scrub", help="Filter and redact secrets/PII from a JSONL transcript.")
    p_scrub.add_argument("-i", "--input", required=True, help="Path to source .jsonl file.")
    p_scrub.add_argument("-o", "--output", required=True, help="Path to write scrubbed .jsonl output.")
    p_scrub.add_argument(
        "--keep-tool-results",
        action="store_true",
        help="Keep the text of user records that also carry tool results (the tool output itself is never kept).",
    )
    p_scrub.set_defaults(func=_cmd_scrub)

    for name, help_text, handler in (
        ("sanitize", "Replace raw profile PII with placeholders before sending to an LLM.", _cmd_sanitize),
        ("rehydrate", "Restore placeholders in LLM output back to local profile values.", _cmd_rehydrate),
    ):
        p_tok = sub.add_parser(name, help=help_text)
        p_tok.add_argument("-p", "--profile", required=True, help="Path to local JSON identity profile.")
        group = p_tok.add_mutually_exclusive_group(required=True)
        group.add_argument("-t", "--text", help="Inline text to transform (it stays in your shell history).")
        group.add_argument("-i", "--input", help="Input file path (or '-' for stdin).")
        p_tok.add_argument("-o", "--output", help="Optional output file path.")
        p_tok.add_argument(
            "--json",
            action="store_true",
            help="Parse input as JSON (or JSON Lines) and transform keys and values recursively.",
        )
        if name == "rehydrate":
            # A model reply is untrusted, so the caller must say what may be restored.
            allow = p_tok.add_mutually_exclusive_group(required=True)
            allow.add_argument(
                "--allow-from",
                metavar="SANITIZED_PROMPT",
                help="Only restore placeholders that appear in this file: the prompt that was sent.",
            )
            allow.add_argument(
                "--allow-all",
                action="store_true",
                help="Restore every placeholder in the profile, even ones the prompt never contained.",
            )
        p_tok.set_defaults(func=handler)

    p_check = sub.add_parser(
        "check",
        help="Exit 1 if secret patterns or raw profile PII are found (JSON and JSON Lines are also decoded).",
    )
    group = p_check.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--text", help="Inline text to scan (it stays in your shell history).")
    group.add_argument("-i", "--input", help="Input file path (or '-' for stdin).")
    p_check.add_argument("-p", "--profile", help="Optional identity profile JSON to check for raw PII.")
    p_check.set_defaults(func=_cmd_check)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Output is UTF-8 like the input: a legacy console code page cannot hold every name.
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(encoding="utf-8")
    try:
        return int(args.func(args))
    # Exit 2 keeps "could not run" distinct from check's exit 1 ("leaks found").
    # Messages name fields and files only, never the values being protected, so the text of
    # Unicode errors (which quotes the offending character) is never shown.
    except UnicodeDecodeError as exc:
        return _fail(f"the input is not valid UTF-8 (first bad byte at position {exc.start}). "
                     "Save it as UTF-8 and try again.")
    except UnicodeEncodeError:
        return _fail("the output contains text that cannot be written as UTF-8, such as an unpaired "
                     "surrogate escape.")
    except RecursionError:
        return _fail("the input is nested too deeply to process.")
    except (ValueError, OSError) as exc:
        return _fail(str(exc))


def _fail(message: str) -> int:
    sys.stderr.write(f"error: {message}\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
