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

_STRIP_BLOCKS = re.compile(
    r"<(system-reminder|side-sessions-event|scheduled-task|task-notification|ci-monitor-event"
    r"|local-command|pasted_content[\w-]*|ide_[a-z_]+|attachment)(?![\w-])[^>]*>.*?</\1(?![\w-])[^>]*>",
    re.S,
)
_STRIP_INLINE = re.compile(r"\[Image #?\d*[^\]]*\]|\[Pasted text[^\]]*\]")

# --- <SECRET>: a secret-looking name followed by its value -------------------------------
# The keyword may sit inside a longer name (DB_PASSWORD, accessToken, client_secret, a quoted
# JSON key), so there is deliberately no word boundary in front of it.
_SECRET_WORD = (
    r"(?:(?i:password|passwd|passphrase|pwd|secret|token|credentials?|authorization"
    r"|(?:api|access|private|auth|signing|encryption)[_-]?key)"
    r"|(?<![A-Za-z])(?i:pass)(?![A-Za-z])"  # DB_PASS, but not PASSED or bypass
    r"|_KEY)"  # env style: STRIPE_KEY, SSH_KEY
)
# ...but not inside a longer ordinary word or a plural: tokens, tokenizer, secretary, MAX_TOKENS.
_NOT_LONGER_WORD = r"(?![a-z]|S(?![A-Za-z0-9]))"
_SECRET_NAME = _SECRET_WORD + _NOT_LONGER_WORD + r"[A-Za-z0-9_-]{0,40}"
# Leave values that are already a placeholder (<API_KEY>, <YOUR_TOKEN>) or plainly not a secret.
_NOT_A_SECRET = r"(?!\\?[\"']?<[A-Z][A-Z0-9_]*>)(?!(?i:true|false|null|none)(?![A-Za-z0-9_]))"
_SECRET_VALUE = (
    r"(?:\"(?:[^\"\\\n]|\\.)*\""  # "double quoted, may contain spaces"
    r"|'(?:[^'\\\n]|\\.)*'"  # 'single quoted'
    r"|\\\"[^\"\n]*\\\""  # \"quoted inside an escaped JSON string\"
    # bare word, with an optional auth scheme in front; never an opening { or [, whose
    # contents are matched on their own ("token": {"access_token": ...})
    r"|(?![{\[])(?:(?i:bearer|basic)[ \t]+)?\S+)"
)
# A value must never swallow the next key. It may sit on a later line than its name, but
# not when that line is itself "name:" or "name=": that is a nested block, and taking its
# key as the value would leave the real secret behind it untouched.
_KEY_LIKE = r"[\"']?[A-Za-z_][\w.-]{0,80}[\"']?[ \t]*(?:=(?![=\s]|$)|:(?=\s|$))"
# "- " is a YAML list marker: step over it, and never treat the marker itself as the value.
_VALUE_GAP = rf"[ \t]*(?:\r?\n\s*(?:-[ \t]+|(?!-[ \t]))(?!{_KEY_LIKE}))?"
# Each alternative captures the text to keep (name and separator); only the value is replaced.
_SECRET_RULE = (
    # name = value, name: value, "name": "value", NAME=value, obj["name"] = value
    # (the guard after the separator stops "== <SECRET>" being matched again on a second pass)
    rf"({_SECRET_NAME}\\?[\"']?\]?\s*(?:=>|:=|={{1,3}}|:){_VALUE_GAP})"
    rf"(?![=>]+\s*<[A-Z][A-Z0-9_]*>){_NOT_A_SECRET}{_SECRET_VALUE}"
    # Bearer <token> outside a header
    rf"|((?i:\bbearer)[ \t]+){_NOT_A_SECRET}(?=[\w.~+/-]{{0,200}}\d)[\w.~+/-]{{16,}}=*"
    # --password value, --api-key value
    rf"|(--[A-Za-z0-9-]{{0,40}}?{_SECRET_WORD}{_NOT_LONGER_WORD}[A-Za-z0-9-]{{0,40}}[ \t]+){_NOT_A_SECRET}(?!-)\S+"
)

_RAW_REDACT_RULES: tuple[tuple[str, str], ...] = (
    # Specificity order matters: structured keys and URIs must run before generic patterns.
    ("<PRIVATE_KEY>", r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----"),
    ("<DISCORD_TOKEN>", r"\b[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,40}\b"),
    ("<API_KEY>", r"\b(?:sk-[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9]{30,}|xox[abpr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b"),
    ("<URL_WITH_CREDS>", r"\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@\S+"),
    ("<PROXY_URI>", r"\b(?:vless|vmess|trojan|ss|hysteria2?|hy2)://\S+"),
    ("<UUID>", r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    ("<EMAIL>", r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    ("<IP>", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    ("<PHONE>", r"(?<!\w)\+\d[\d \-]{8,}\d\b"),
    ("<SECRET>", _SECRET_RULE),
    ("<LONG_TOKEN>", r"\b(?=[A-Za-z0-9_\-+/]*\d)(?=[A-Za-z0-9_\-+/]*[A-Za-z])[A-Za-z0-9_\-+/]{40,}={0,2}"),
)

REDACT_RULES: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (placeholder, re.compile(pattern, re.S))
    for placeholder, pattern in _RAW_REDACT_RULES
)


def strip_harness_tags(text: str) -> str:
    """Remove agent harness XML blocks and inline attachment markers from text."""
    if not text:
        return ""
    stripped = _STRIP_BLOCKS.sub("", text)
    stripped = _STRIP_INLINE.sub("", stripped)
    return stripped.strip()


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
        scrubbed, hits = pattern.subn(
            lambda match, tag=placeholder: "".join(part for part in match.groups() if part) + tag,
            scrubbed,
        )
        if hits:
            counts[placeholder] = hits
    return scrubbed, counts


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
        parts = [
            p.get("text", "")
            for p in content
            if isinstance(p, dict) and p.get("type") == "text"
        ]
    else:
        return None

    joined = "\n".join(part for part in parts if part).strip()
    if not joined or joined.startswith(drop_prefixes):
        return None
    cleaned = strip_harness_tags(joined)
    return cleaned or None


def scrub_jsonl_stream(
    lines: Iterable[str],
    *,
    drop_tool_results: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Filter, deduplicate, and redact a stream of JSONL agent transcript lines."""
    seen_uuids: set[str] = set()
    rows: list[dict[str, Any]] = []
    redactions: collections.Counter[str] = collections.Counter()
    stats: collections.Counter[str] = collections.Counter()

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        stats["lines_read"] += 1
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
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

    summary: dict[str, Any] = dict(stats)
    summary["redactions"] = dict(redactions)
    return rows, summary
