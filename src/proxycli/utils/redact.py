from __future__ import annotations

import re
from collections.abc import Iterable

SENSITIVE_KEYS = frozenset(
    {"password", "passwd", "token", "secret", "proxy_authorization", "cloudflare_token"}
)
_ASSIGNED = re.compile(r"(?i)(password|passwd|token|secret)(\s*[:=]\s*)(\S+)")


def redact_text(text: str, secrets: Iterable[str] | None = None) -> str:
    redacted = text
    for secret in secrets or []:
        if secret and len(secret) >= 4 and secret in redacted:
            redacted = redacted.replace(secret, "***")
    return _ASSIGNED.sub(r"\1\2***", redacted)


def contains_secret(text: str, secrets: Iterable[str]) -> bool:
    return any(secret and len(secret) >= 4 and secret in text for secret in secrets)
