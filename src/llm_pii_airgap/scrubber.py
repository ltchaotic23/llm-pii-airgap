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
    ("<SECRET>", r"(?i)\b(?:password|passwd|pwd|token|secret|api[_-]?key)\b\s*[:=]\s*(?!<(?:PRIVATE_KEY|DISCORD_TOKEN|API_KEY|URL_WITH_CREDS|PROXY_URI|UUID|EMAIL|IP|PHONE|SECRET|LONG_TOKEN)>)\S+"),
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
    """Scrub secret and PII patterns in specificity order; return text and counts."""
    counts: dict[str, int] = {}
    if not text:
        return text, counts

    scrubbed = text
    for placeholder, pattern in REDACT_RULES:
        scrubbed, hits = pattern.subn(placeholder, scrubbed)
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
            if uid in seen_uuids:
                stats["duplicates_skipped"] += 1
                continue
            seen_uuids.add(str(uid))

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
