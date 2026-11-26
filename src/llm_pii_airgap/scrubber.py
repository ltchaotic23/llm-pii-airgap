"""Ordered regex secret/PII scrubber and JSONL agent transcript sanitizer."""

from __future__ import annotations

import collections
import json
import re
from collections.abc import Iterable
from typing import Any

DEFAULT_DROP_PREFIXES: tuple[str, ...] = (
    "<task-notification",
    "<local-command",
    "<command-",
    "<scheduled-task",
    "<side-sessions-event",
    "<ci-monitor-event",
    "[Request interrupted",
    "[Workflow harness",
    "[handback",
    "Caveat:",
)

# A harness block runs from "<tag ...>" to the first "</tag ...>" after it. All closers are
# indexed in one pass so stripping stays linear even with thousands of distinct tag names.
_BLOCK_TAGS = (
    r"system-reminder|side-sessions-event|scheduled-task|task-notification|ci-monitor-event"
    r"|local-command|pasted_content[\w-]*|ide_[a-z_]+|attachment"
)
_BLOCK_START = re.compile(rf"<({_BLOCK_TAGS})(?![\w-])")
_BLOCK_END = re.compile(rf"</({_BLOCK_TAGS})(?![\w-])")
_INLINE_START = re.compile(r"(?<!!)\[(?:Image #\d|Pasted text #)")

# --- <SECRET>: a secret-looking name followed by its value -------------------------------
# The keyword may sit inside a longer name (DB_PASSWORD, accessToken, client_secret, a quoted
# JSON key), so there is deliberately no word boundary in front of it.
_AUTH_WORD = r"(?i:authorization)"
_CORE_SECRET_WORD = (
    r"(?:(?i:password|passwd|passphrase|pwd|secret|credentials?"
    r"|(?:api|access|private|auth|signing|encryption)[_-]?key)"
    r"|(?i:token)(?!(?:[_-]?type(?![A-Za-z0-9])|Type(?![a-z])))"
    r"|(?<![A-Za-z])(?i:pass)(?![A-Za-z])(?![_-]?(?i:rate)(?![A-Za-z0-9]))"
    r"|_KEY)"  # env style: STRIPE_KEY, SSH_KEY
)
_SECRET_WORD_ALL = rf"(?:{_CORE_SECRET_WORD}|{_AUTH_WORD})"
# ...but not inside a longer ordinary word or a plural: tokens, tokenizer, secretary, MAX_TOKENS.
_NOT_LONGER_WORD = r"(?:(?<=[A-Z])(?![A-Za-z])|(?<![A-Z])(?![a-z]))"
_SECRET_NAME = _CORE_SECRET_WORD + _NOT_LONGER_WORD + r"[A-Za-z0-9_.-]{0,120}"
_AUTH_NAME = _AUTH_WORD + _NOT_LONGER_WORD + r"[A-Za-z0-9_.-]{0,120}"
# Leave values that are already a placeholder (<API_KEY>, <YOUR_TOKEN>) or plainly not a secret.
_NOT_A_SECRET = (
    r"(?!\\?[\"']?<[A-Z][A-Z0-9_]*>)"
    r"(?![A-Za-z][A-Za-z0-9._-]{0,31}[ \t]+\\?[\"']?<[A-Z][A-Z0-9_]*>)"
    r"(?!(?i:true|false|null|none)(?=$|[\s,}\]);#]))"
)
_STR_PREFIX = r"(?:(?i:[rbfu]|rb|br|fr|rf))?"
_QUOTED_SECRET = (
    rf"(?:{_STR_PREFIX}\"\"\"(?:[^\"\\]|\\.|\"(?!\"\"))*\"\"\""  # """triple double quoted, may span lines"""
    rf"|{_STR_PREFIX}'''(?:[^'\\]|\\.|'(?!''))*'''"  # '''triple single quoted, may span lines'''
    rf"|{_STR_PREFIX}(?!\"\"\")\"(?:[^\"\\]|\\.|\"\")*\""  # "double quoted, may span lines"
    rf"|{_STR_PREFIX}(?!''')'(?:[^'\\]|\\.|'')*'"  # 'single quoted, handles '' escapes'
    r"|`(?!``)(?:[^`\\]|\\.|``)*`"  # `backtick quoted`
    r"|\\\"(?:[^\"\\\n]|\\\\|\\(?!\"))*\\\""  # \"quoted inside an escaped JSON string\"
    # Backstop for unclosed quotes or prefixed quotes: redact to end of line rather than leaking.
    rf"|{_STR_PREFIX}[\"'`][^\r\n]*"
    r"|\\\"[^\r\n]*)"
)
# A value must never swallow the next key. It may sit on a later line than its name, but
# not when that line is itself "name:" or "name=": that is a nested block, and taking its
# key as the value would leave the real secret behind it untouched.
_KEY_LIKE = r"[\"']?[A-Za-z_][\w.-]{0,120}[\"']?[ \t]*(?:=(?![=]|$)|:(?=\s|$))"
_YAML_BLOCK_SCALAR = (
    rf"[|>](?:[+-]?\d+|\d+[+-]?|[+-])?[ \t]*(?:#[^\r\n]*)?"
    rf"(?:\r?\n(?:[ \t]*\r?\n)*+[ \t]+(?!{_KEY_LIKE})\S[^\r\n]*)+"
)
_SECRET_VALUE = (
    rf"(?:{_YAML_BLOCK_SCALAR}"
    rf"|{_QUOTED_SECRET}"
    # Backstop for unclosed block-scalar headers or extra delimiters: redact to end of line.
    r"|[|>][+-]?\d*[ \t]*[^\r\n]+"
    r"|[=>]+[ \t]*[^\r\n]+"
    # bare word, with an optional auth scheme in front; never an opening { or [, whose
    # contents are matched on their own ("token": {"access_token": ...}). A word ending in a
    # backslash continues on the next line (shell and .env line continuation), so the rest of
    # a split value is replaced too. Possessive, so the search stays linear.
    r"|(?![{\[])\S++(?:(?<=\\)\r?\n[ \t]*+\S++)*+)"
)
# "- " is a YAML list marker: step over it, and never treat the marker itself as the value.
_VALUE_GAP = rf"[ \t]*(?:\r?\n[ \t]*(?:-[ \t]+|(?!-[ \t]))(?!{_KEY_LIKE}))?+"
_CHAINED_LHS = (
    rf"(?:[ \t]*[A-Za-z_][\w.]{{0,80}}[ \t]+(?:=>|:=|=(?!=))[ \t]*"
    rf"|[ \t]*[A-Za-z_]{{0,40}}?{_SECRET_NAME}[ \t]*(?:=>|:=|=(?!=))[ \t]*){{0,4}}+"
)
_ENV_GET_CALL = r"(?:os\.(?:getenv|environ\.get)\(\s*[\"'][^\"'\r\n]{1,120}[\"']\s*,\s*)"
# Each alternative captures the text to keep (name and separator); only the value is replaced.
_SECRET_RULE = (
    # Authorization header with any scheme word (Bearer, Basic, Token, ApiKey, ...)
    rf"({_AUTH_NAME}\\?[\"']?\]?[ \t]*(?:=>|:=|={{1,3}}|:){_VALUE_GAP}(?:[A-Za-z][A-Za-z0-9._-]{{0,31}}[ \t]+)?+)"
    rf"(?![=>]+\s*<[A-Z][A-Z0-9_]*>){_NOT_A_SECRET}"
    rf"(?:{_YAML_BLOCK_SCALAR}|{_QUOTED_SECRET}|[|>][+-]?\d*[ \t]*[^\r\n]+|(?![{{\[])[^\s\"']+)"
    # os.getenv("SECRET_NAME", "default") / os.environ.get("SECRET_NAME", "default")
    rf"|((?:os\.(?:getenv|environ\.get))\(\s*[\"'][A-Za-z0-9_.-]{{0,60}}?(?:{_SECRET_NAME}|{_AUTH_NAME})[\"']\s*,\s*){_NOT_A_SECRET}{_SECRET_VALUE}"
    # name = value, name: value, "name": "value", NAME=value, obj["name"] = value
    rf"|({_SECRET_NAME}\\?[\"']?\]?[ \t]*(?:=>|:=|={{1,3}}|:){_CHAINED_LHS}{_VALUE_GAP}{_ENV_GET_CALL}?+)"
    rf"(?![=>]+\s*<[A-Z][A-Z0-9_]*>){_NOT_A_SECRET}{_SECRET_VALUE}"
    # Bearer <token> outside a header
    rf"|((?i:\bbearer)[ \t]+){_NOT_A_SECRET}(?=[\w.~+/-]{{0,200}}\d)[\w.~+/-]{{16,}}=*"
    # --password value, --api-key "two words"
    rf"|(--[A-Za-z0-9-]{{0,80}}?{_SECRET_WORD_ALL}{_NOT_LONGER_WORD}[A-Za-z0-9._-]{{0,80}}[ \t]+)"
    rf"{_NOT_A_SECRET}(?!-){_SECRET_VALUE}"
)

# Several rules start only at the beginning of a run of the characters they match, never inside
# it, and keep any leading punctuation in a group. Starting inside the run would rescan the rest
# of the run from every position, which takes quadratic time on crafted input such as "a.a.a.".
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_TOKEN_CHARS = r"A-Za-z0-9_\-+/"
_RAW_REDACT_RULES: tuple[tuple[str, str], ...] = (
    # Specificity order matters: structured keys and URIs must run before generic patterns.
    # On its own this pattern rescans to the end of the text from every header that has no END
    # line after it; redact_secrets() therefore only searches up to the last END line.
    ("<PRIVATE_KEY>", r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----"),
    ("<DISCORD_TOKEN>", r"\b[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,40}(?![\w-])"),
    (
        "<API_KEY>",
        r"\b(?:(?:sk-[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{35}|xox[abpr]-[A-Za-z0-9-]{10,})(?![\w-])"
        r"|(?:gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16})\b)",
    ),
    # A URL scheme is at most 32 characters, which keeps the search linear.
    ("<URL_WITH_CREDS>", r"\b[A-Za-z][A-Za-z0-9+.-]{0,31}://[^\s/:@]+:[^\s/@]+@\S+"),
    ("<PROXY_URI>", r"\b(?:vless|vmess|trojan|ss|hysteria2?|hy2)://\S+"),
    ("<UUID>", r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    ("<EMAIL>", r"(?<![\w.+-])([.+-]*+)\b[\w.+-]+@(?!v?\d[\d.]*\b)[\w-]+\.(?=[\w.-]*[A-Za-z])[\w.-]+\b"),
    ("<IP>", rf"(?<!\d)(?<!\d\.){_OCTET}(?:\.{_OCTET}){{3}}(?!\d)(?!\.\d)"),
    ("<PHONE>", r"(?<!\w)\+(?!(?:19|20)\d\d-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b)\d[\d \-()]{8,}\d\b"),
    ("<SECRET>", _SECRET_RULE),
    (
        "<LONG_TOKEN>",
        rf"(?<![{_TOKEN_CHARS}])([+/-]*+)\b(?=[{_TOKEN_CHARS}]*\d)(?=[{_TOKEN_CHARS}]*[A-Za-z])[{_TOKEN_CHARS}]{{40,}}={{0,2}}",
    ),
)

REDACT_RULES: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (placeholder, re.compile(pattern, re.S))
    for placeholder, pattern in _RAW_REDACT_RULES
)


class _NextChar:
    """Position of the next occurrence of one character, cached while searches move forward."""

    def __init__(self, text: str, char: str) -> None:
        self.text, self.char = text, char
        self.queried_from = -1
        self.found = -2

    def at_or_after(self, start: int) -> int:
        if start < self.queried_from or (self.found != -1 and self.found < start):
            self.found = self.text.find(self.char, start)
            self.queried_from = start
        return self.found


def _strip_blocks(text: str) -> str:
    first = _BLOCK_START.search(text)
    if first is None:
        return text
    closers: dict[str, collections.deque[tuple[int, int]]] = collections.defaultdict(collections.deque)
    end_gt = _NextChar(text, ">")
    for match in _BLOCK_END.finditer(text, first.start()):
        gt = end_gt.at_or_after(match.end())
        if gt == -1:
            break
        closers[match.group(1)].append((match.start(), gt))

    pieces: list[str] = []
    keep_from = 0
    open_gt = _NextChar(text, ">")
    opener: re.Match[str] | None = first
    while opener is not None:
        open_end = open_gt.at_or_after(opener.end())
        if open_end == -1:
            break  # no opener can be complete from here on
        if text[open_end - 1] == "/":
            pieces.append(text[keep_from:opener.start()])
            keep_from = open_end + 1
            opener = _BLOCK_START.search(text, keep_from)
            continue
        queue = closers.get(opener.group(1))
        while queue and queue[0][0] <= open_end:
            queue.popleft()
        if not queue:
            opener = _BLOCK_START.search(text, opener.end())
            continue
        _, close_end = queue.popleft()
        pieces.append(text[keep_from:opener.start()])
        keep_from = close_end + 1
        opener = _BLOCK_START.search(text, keep_from)
    pieces.append(text[keep_from:])
    return "".join(pieces)


def _strip_inline(text: str) -> str:
    pieces: list[str] = []
    keep_from = pos = 0
    next_bracket = _NextChar(text, "]")
    while (marker := _INLINE_START.search(text, pos)) is not None:
        close = next_bracket.at_or_after(marker.end())
        if close == -1:
            break
        if close + 1 < len(text) and text[close + 1] == "(":
            pos = marker.end()
            continue
        pieces.append(text[keep_from:marker.start()])
        keep_from = pos = close + 1
    pieces.append(text[keep_from:])
    return "".join(pieces)


def strip_harness_tags(text: str) -> str:
    """Remove agent harness XML blocks and inline attachment markers from text."""
    if not text:
        return ""
    return _strip_inline(_strip_blocks(text)).strip()


def redact_secrets(text: str) -> tuple[str, dict[str, int]]:
    """Scrub secret and PII patterns in specificity order; return text and counts.

    A rule may capture a leading part of its match (a key name and separator); that
    part is kept and only the rest is replaced, so ``DB_PASSWORD=x`` becomes
    ``DB_PASSWORD=<SECRET>``.
    """
    counts: dict[str, int] = {}
    if not text:
        return text, counts

    scrubbed = text
    for placeholder, pattern in REDACT_RULES:
        scrubbed, hits = _apply_rule(placeholder, pattern, scrubbed)
        if hits:
            counts[placeholder] = hits
    return scrubbed, counts


_KEY_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY-----")


def _apply_rule(placeholder: str, pattern: re.Pattern[str], text: str) -> tuple[str, int]:
    """Replace one rule's matches, keeping any captured leading part of each match."""
    end = len(text)
    if placeholder == "<PRIVATE_KEY>":
        # No key block can end after the last END line, and a header after it would make the
        # lazy pattern rescan to the end of the text, so the search stops at that line.
        end = max((found.end() for found in _KEY_END.finditer(text)), default=0)
    head, hits = pattern.subn(
        lambda match: "".join(part for part in match.groups() if part) + placeholder,
        text[:end],
    )
    return head + text[end:], hits


def extract_user_text(
    record: dict[str, Any],
    *,
    drop_tool_results: bool = True,
    drop_prefixes: tuple[str, ...] = DEFAULT_DROP_PREFIXES,
) -> str | None:
    """Extract clean human-authored prompt text from a JSONL session event."""
    if not isinstance(record, dict):
        return None
    if record.get("type") != "user" or record.get("isSidechain") or record.get("agentId"):
        return None
    if record.get("isMeta") or record.get("isCompactSummary") or record.get("isVisibleInTranscriptOnly"):
        return None
    if drop_tool_results and "toolUseResult" in record:
        return None

    message = record.get("message")
    content = message.get("content") if isinstance(message, dict) else record.get("content")
    if isinstance(content, str):
        parts = [content]
    elif isinstance(content, list):
        if drop_tool_results and any(isinstance(p, dict) and p.get("type") == "tool_result" for p in content):
            return None
        # A text part whose "text" is not a string is skipped rather than stopping the whole file.
        parts = [
            p["text"]
            for p in content
            if isinstance(p, dict) and p.get("type") == "text" and isinstance(p.get("text"), str)
        ]
    else:
        return None

    joined = "\n".join(part for part in parts if part).strip()
    if not joined or joined.startswith(drop_prefixes):
        return None
    cleaned = strip_harness_tags(joined)
    if not cleaned or cleaned.startswith(drop_prefixes):
        return None
    return cleaned


def scrub_jsonl_stream(
    lines: Iterable[str],
    *,
    drop_tool_results: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Filter, deduplicate, and redact a stream of JSONL agent transcript lines."""
    seen_uuids: set[str] = set()
    rows: list[dict[str, Any]] = []
    redactions: collections.Counter[str] = collections.Counter()
    # Every counter is reported, zero or not, so the summary always has the same shape.
    stats: dict[str, int] = dict.fromkeys(
        ("lines_read", "rows_kept", "duplicates_skipped", "invalid_json", "non_user_skipped"), 0
    )

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        stats["lines_read"] += 1
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, ValueError, RecursionError):  # ValueError: >4300-digit int
            stats["invalid_json"] += 1
            continue

        uid = record.get("uuid") if isinstance(record, dict) else None
        if uid is not None:
            uid_key = str(uid)
            if uid_key in seen_uuids:
                stats["duplicates_skipped"] += 1
                continue
            seen_uuids.add(uid_key)

        text = extract_user_text(record, drop_tool_results=drop_tool_results)
        if text is None:
            stats["non_user_skipped"] += 1
            continue

        scrubbed, counts = redact_secrets(text)
        redactions.update(counts)
        rows.append(
            {
                "uuid": uid,
                "timestamp": record.get("timestamp"),
                "text": scrubbed,
            }
        )
        stats["rows_kept"] += 1

    summary: dict[str, Any] = stats.copy()
    summary["redactions"] = dict(redactions)
    return rows, summary
