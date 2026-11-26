"""Client-side PII airgap tokeniser and JSONL agent transcript secret scrubber."""

__version__ = "0.2.0"

from .scrubber import (  # noqa: E402
    DEFAULT_DROP_PREFIXES,
    REDACT_RULES,
    redact_secrets,
    scrub_jsonl_stream,
    strip_harness_tags,
)
from .tokenizer import IdentityProfile, PIIAirgap  # noqa: E402

__all__ = [
    "DEFAULT_DROP_PREFIXES",
    "IdentityProfile",
    "PIIAirgap",
    "REDACT_RULES",
    "redact_secrets",
    "scrub_jsonl_stream",
    "strip_harness_tags",
]
