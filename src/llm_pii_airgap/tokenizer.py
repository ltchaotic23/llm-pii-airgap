"""Bidirectional client-side PII tokeniser for outbound LLM prompts and responses."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Collection
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


_BASE_FIELDS = ("full_name", "email", "phone", "street_address", "postal_code")


def _normalize_custom_key(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
    return f"[CUSTOM_{cleaned or 'FIELD'}]"


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """JSON object hook: a repeated key would silently discard the earlier value."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate key '{key}' in identity profile JSON.")
        result[key] = value
    return result


@dataclass(frozen=True)
class IdentityProfile:
    """Local identity attributes withheld from external LLM API calls."""

    full_name: str = ""
    email: str = ""
    phone: str = ""
    street_address: str = ""
    postal_code: str = ""
    custom_fields: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Refuse anything that would be dropped or could never match: a silent skip is a silent leak.
        for name in _BASE_FIELDS:
            if not isinstance(getattr(self, name), str):
                raise ValueError(f"Profile field '{name}' must be a string.")
        if not isinstance(self.custom_fields, dict):
            raise ValueError("'custom_fields' must be an object mapping names to strings.")
        for key, value in self.custom_fields.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValueError(f"Custom field {key!r} must map a string name to a string value.")
        self.placeholder_map()  # raises if two custom field names share a placeholder

    @classmethod
    def from_json_file(cls, path: str | os.PathLike[str]) -> IdentityProfile:
        """Load an IdentityProfile from a local JSON object.

        Unknown keys, duplicate keys and non-string values raise ``ValueError``: a
        misspelt field name must never load as an empty profile.
        """
        raw = Path(path).read_text(encoding="utf-8")
        data = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        if not isinstance(data, dict):
            raise ValueError("Identity profile JSON must contain an object at the root.")

        unknown = sorted(set(data) - {*_BASE_FIELDS, "custom_fields"})
        if unknown:
            raise ValueError(
                f"Unknown profile field(s): {', '.join(unknown)}. "
                f"Known fields are {', '.join(_BASE_FIELDS)}; put anything else under 'custom_fields'."
            )

        kwargs: dict[str, Any] = {}
        for key in _BASE_FIELDS:
            val = data.get(key)
            kwargs[key] = "" if val is None else val

        raw_custom = data.get("custom_fields")
        if raw_custom is None:
            raw_custom = {}
        if isinstance(raw_custom, dict):
            raw_custom = {k: v for k, v in raw_custom.items() if v is not None}
        kwargs["custom_fields"] = raw_custom
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

        sources: dict[str, str] = {}
        for key, value in self.custom_fields.items():
            cleaned = value.strip()
            if not cleaned:
                continue
            token = _normalize_custom_key(key)
            if token in mapping:
                # Overwriting would leave the earlier value unprotected.
                raise ValueError(
                    f"Custom fields '{sources[token]}' and '{key}' both map to placeholder {token}; rename one."
                )
            mapping[token] = cleaned
            sources[token] = key
        return mapping


MIN_VALUE_LENGTH = 3
_PHONE_SEPARATORS = r"[\s\-().]*"


def _value_pattern(raw_val: str) -> str:
    """Regex for one raw value: whole-token only, tolerant of whitespace reflow."""
    parts = [r"\s+" if chunk.isspace() else re.escape(chunk) for chunk in re.split(r"(\s+)", raw_val) if chunk]
    body = "".join(parts)
    # Only anchor edges that are word characters, so "Ann" never matches inside "Annual".
    lead = r"(?<!\w)" if raw_val[0].isalnum() or raw_val[0] == "_" else ""
    trail = r"(?!\w)" if raw_val[-1].isalnum() or raw_val[-1] == "_" else ""
    return f"{lead}{body}{trail}"


def _phone_pattern(raw_val: str) -> str:
    """Regex for a phone number that ignores spacing, dashes, dots and brackets."""
    digits = re.sub(r"\D", "", raw_val)
    plus = r"\+?" if raw_val.lstrip().startswith("+") else ""
    return rf"(?<![\w+]){plus}{_PHONE_SEPARATORS.join(digits)}(?!\w)"


class PIIAirgap:
    """Deterministic outbound PII redactor and local response re-hydrator."""

    def __init__(self, profile: IdentityProfile) -> None:
        self.profile = profile
        self._placeholders = profile.placeholder_map()

        if not self._placeholders:
            # An airgap with nothing to match would pass every input through unchanged.
            raise ValueError("Identity profile has no values to protect.")

        for token, raw_val in self._placeholders.items():
            if len(raw_val) < MIN_VALUE_LENGTH:
                # Refuse rather than skip: a silently ignored field is a silent leak.
                raise ValueError(
                    f"Profile value for {token} is shorter than {MIN_VALUE_LENGTH} characters "
                    "and cannot be matched without corrupting unrelated text."
                )

        # Sort raw values longest-first so full addresses/emails match before substrings.
        sorted_items = sorted(
            self._placeholders.items(),
            key=lambda item: len(item[1]),
            reverse=True,
        )
        self._group_tokens: dict[str, str] = {}
        alternatives: list[str] = []
        for index, (token, raw_val) in enumerate(sorted_items):
            group = f"g{index}"
            self._group_tokens[group] = token
            is_phone = token == "[PHONE]" and sum(ch.isdigit() for ch in raw_val) >= 7
            pattern = _phone_pattern(raw_val) if is_phone else _value_pattern(raw_val)
            alternatives.append(f"(?P<{group}>{pattern})")

        self._raw_rx: re.Pattern[str] = re.compile("|".join(alternatives), re.IGNORECASE)
        self._token_rx: re.Pattern[str] = re.compile("|".join(re.escape(tok) for tok in self._placeholders))

    def sanitize_prompt(self, text: str) -> str:
        """Replace raw profile PII inside text with canonical placeholders."""
        if not text:
            return text
        return self._raw_rx.sub(
            lambda match: self._group_tokens[str(match.lastgroup)],
            text,
        )

    def placeholders_in(self, text: str) -> set[str]:
        """Return the known placeholders present in text (use as a rehydrate allow-list)."""
        if not text:
            return set()
        return set(self._token_rx.findall(text))

    def sanitize_payload(self, payload: Any) -> Any:
        """Recursively sanitize a JSON-like payload: strings, numbers and dict keys.

        A number that equals a profile value (a phone stored as an integer) becomes
        its placeholder string. Types that cannot be inspected raise ``TypeError``
        rather than passing through unchecked.
        """
        if isinstance(payload, str):
            return self.sanitize_prompt(payload)
        if payload is None or isinstance(payload, bool):
            return payload
        if isinstance(payload, (int, float)):
            text = str(payload)
            cleaned = self.sanitize_prompt(text)
            return payload if cleaned == text else cleaned
        if isinstance(payload, list):
            return [self.sanitize_payload(item) for item in payload]
        if isinstance(payload, tuple):
            return tuple(self.sanitize_payload(item) for item in payload)
        if isinstance(payload, dict):
            result: dict[Any, Any] = {}
            for key, value in payload.items():
                new_key = self.sanitize_payload(key)
                if new_key in result:
                    raise ValueError("Two payload keys are identical after sanitising; rename one of them.")
                result[new_key] = self.sanitize_payload(value)
            return result
        raise TypeError(f"Cannot sanitize a value of type {type(payload).__name__}.")

    def rehydrate(self, payload: Any, *, allow: Collection[str] | None = None) -> Any:
        """Recursively replace placeholders in LLM output with local profile values.

        A model response is untrusted: it can contain placeholders the prompt never
        had (for example via prompt injection asking for "[ADDRESS]"). Pass ``allow``
        (typically ``placeholders_in(sanitized_prompt)``) to restore only those
        placeholders and leave any others as inert text.
        """
        if isinstance(payload, str):
            if not payload:
                return payload
            return self._token_rx.sub(
                lambda match: (
                    self._placeholders[match.group(0)]
                    if allow is None or match.group(0) in allow
                    else match.group(0)
                ),
                payload,
            )
        if isinstance(payload, list):
            return [self.rehydrate(item, allow=allow) for item in payload]
        if isinstance(payload, tuple):
            return tuple(self.rehydrate(item, allow=allow) for item in payload)
        if isinstance(payload, dict):
            return {
                (self.rehydrate(k, allow=allow) if isinstance(k, str) else k): self.rehydrate(v, allow=allow)
                for k, v in payload.items()
            }
        return payload

    def contains_raw_pii(self, text: str) -> list[str]:
        """Return placeholder names whose raw values appear in text."""
        if not text:
            return []
        found = {self._group_tokens[str(match.lastgroup)] for match in self._raw_rx.finditer(text)}
        return [token for token in self._placeholders if token in found]
