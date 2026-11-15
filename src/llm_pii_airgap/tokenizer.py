"""Bidirectional client-side PII tokeniser for outbound LLM prompts and responses."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _normalize_custom_key(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
    return f"[CUSTOM_{cleaned or 'FIELD'}]"


@dataclass(frozen=True)
class IdentityProfile:
    """Local identity attributes withheld from external LLM API calls."""

    full_name: str = ""
    email: str = ""
    phone: str = ""
    street_address: str = ""
    postal_code: str = ""
    custom_fields: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_json_file(cls, path: str | os.PathLike[str]) -> IdentityProfile:
        """Load an IdentityProfile from a local JSON object."""
        raw = Path(path).read_text(encoding="utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Identity profile JSON must contain an object at the root.")

        known = {"full_name", "email", "phone", "street_address", "postal_code"}
        kwargs: dict[str, Any] = {}
        for key in known:
            val = data.get(key, "")
            kwargs[key] = str(val).strip() if val is not None else ""

        raw_custom = data.get("custom_fields") or {}
        if not isinstance(raw_custom, dict):
            raise ValueError("'custom_fields' in identity profile JSON must be an object.")
        kwargs["custom_fields"] = {
            str(k).strip(): str(v).strip()
            for k, v in raw_custom.items()
            if str(k).strip() and v is not None and str(v).strip()
        }
        return cls(**kwargs)

    def placeholder_map(self) -> dict[str, str]:
        """Return ordered placeholder -> raw value pairs for all populated fields."""
        mapping: dict[str, str] = {}
        base_fields = (
            ("[FULL_NAME]", self.full_name),
            ("[EMAIL]", self.email),
            ("[PHONE]", self.phone),
            ("[ADDRESS]", self.street_address),
            ("[POSTAL_CODE]", self.postal_code),
        )
        for token, value in base_fields:
            cleaned = value.strip()
            if cleaned:
                mapping[token] = cleaned

        for key, value in self.custom_fields.items():
            cleaned = value.strip()
            if cleaned:
                mapping[_normalize_custom_key(key)] = cleaned
        return mapping


class PIIAirgap:
    """Deterministic outbound PII redactor and local response re-hydrator."""

    def __init__(self, profile: IdentityProfile) -> None:
        self.profile = profile
        self._placeholders = profile.placeholder_map()

        # Sort raw values longest-first so full addresses/emails match before substrings.
        sorted_items = sorted(
            self._placeholders.items(),
            key=lambda item: len(item[1]),
            reverse=True,
        )
        self._ordered_items: list[tuple[str, str]] = sorted_items
        self._raw_lookup: dict[str, str] = {}
        for token, raw_val in sorted_items:
            self._raw_lookup.setdefault(raw_val.casefold(), token)

        if sorted_items:
            raw_alt = "|".join(re.escape(raw_val) for _, raw_val in sorted_items)
            self._raw_rx: re.Pattern[str] | None = re.compile(raw_alt, re.IGNORECASE)
        else:
            self._raw_rx = None

        if self._placeholders:
            tok_alt = "|".join(re.escape(tok) for tok in self._placeholders)
            self._token_rx: re.Pattern[str] | None = re.compile(tok_alt)
        else:
            self._token_rx = None

    def sanitize_prompt(self, text: str) -> str:
        """Replace raw profile PII inside text with canonical placeholders."""
        if not text or self._raw_rx is None:
            return text
        return self._raw_rx.sub(
            lambda match: self._raw_lookup[match.group(0).casefold()],
            text,
        )

    def sanitize_payload(self, payload: Any) -> Any:
        """Recursively sanitize strings inside nested lists and dicts."""
        if isinstance(payload, str):
            return self.sanitize_prompt(payload)
        if isinstance(payload, list):
            return [self.sanitize_payload(item) for item in payload]
        if isinstance(payload, dict):
            return {k: self.sanitize_payload(v) for k, v in payload.items()}
        return payload

    def rehydrate(self, payload: Any) -> Any:
        """Recursively replace placeholders in LLM output with local profile values."""
        if isinstance(payload, str):
            if not payload or self._token_rx is None:
                return payload
            return self._token_rx.sub(
                lambda match: self._placeholders[match.group(0)],
                payload,
            )
        if isinstance(payload, list):
            return [self.rehydrate(item) for item in payload]
        if isinstance(payload, dict):
            return {k: self.rehydrate(v) for k, v in payload.items()}
        return payload

    def contains_raw_pii(self, text: str) -> list[str]:
        """Return placeholder names whose raw values appear in text."""
        if not text:
            return []
        folded = text.casefold()
        hits: list[str] = []
        for token, raw_val in self._placeholders.items():
            if raw_val.casefold() in folded:
                hits.append(token)
        return hits
