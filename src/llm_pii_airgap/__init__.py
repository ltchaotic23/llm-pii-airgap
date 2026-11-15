"""Client-side PII airgap tokeniser and JSONL agent transcript secret scrubber."""

from .scrubber import (
    DEFAULT_DROP_PREFIXES,
    REDACT_RULES,
    redact_secrets,
    scrub_jsonl_stream,
    strip_harness_tags,
)
from .tokenizer import IdentityProfile, PIIAirgap

__all__ = [
    "DEFAULT_DROP_PREFIXES",
    "IdentityProfile",
    "PIIAirgap",
    "REDACT_RULES",
    "redact_secrets",
    "scrub_jsonl_stream",
    "strip_harness_tags",
]
__version__ = "0.1.0"
