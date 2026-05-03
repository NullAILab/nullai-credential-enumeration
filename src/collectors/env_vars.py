"""Environment variable credential scanner.

[EDUCATIONAL — authorised testing on systems you own only]

Scans the current process environment for variables that likely contain
credentials.  Uses two strategies:
  1. Pattern matching against known variable name conventions
     (API_KEY, SECRET, TOKEN, PASSWORD, etc.)
  2. Shannon entropy analysis on the value — high-entropy values suggest
     secrets even if the variable name is opaque.

Values are ALWAYS redacted in the findings (only variable names are
reported in plaintext).
"""

from __future__ import annotations

import math
import os
import re
from typing import Optional

from models import Category, Finding, Severity


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

_SECRET_NAME_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"(^|_)(api[_-]?key|apikey)(_|$)",
        r"(^|_)(secret[_-]?key|secret)(_|$)",
        r"(^|_)(access[_-]?token|auth[_-]?token|bearer[_-]?token)(_|$)",
        r"(^|_)(password|passwd|pwd)(_|$)",
        r"(^|_)(private[_-]?key|privkey)(_|$)",
        r"(^|_)(aws[_-]?secret|aws[_-]?access)",
        r"(^|_)(stripe[_-]?key|stripe[_-]?secret)",
        r"(^|_)(github[_-]?token|gh[_-]?token)",
        r"(^|_)(slack[_-]?token|slack[_-]?webhook)",
        r"(^|_)(database[_-]?url|db[_-]?url|db[_-]?password)",
        r"(^|_)(smtp[_-]?password|email[_-]?password)",
        r"(^|_)(encryption[_-]?key|jwt[_-]?secret)",
        r"(^|_)(credentials?|creds?)(_|$)",
    ]
]

_ALLOW_LIST_NAMES = {
    "GPG_AGENT_INFO", "SSH_AGENT_PID", "SSH_AUTH_SOCK",
    "TERM", "PATH", "HOME", "USER", "SHELL",
}

_ENTROPY_THRESHOLD = 3.5   # bits/char — consistent with secrets scanner P29
_MIN_VALUE_LENGTH  = 16


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in freq.values())


def _is_likely_secret_name(name: str) -> bool:
    if name in _ALLOW_LIST_NAMES:
        return False
    return any(p.search(name) for p in _SECRET_NAME_PATTERNS)


def _is_high_entropy_value(value: str) -> bool:
    if len(value) < _MIN_VALUE_LENGTH:
        return False
    return _shannon_entropy(value) >= _ENTROPY_THRESHOLD


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def collect_env_findings(
    env: Optional[dict[str, str]] = None,
) -> list[Finding]:
    """Scan environment variables for credential-like values."""
    env = env if env is not None else dict(os.environ)
    findings: list[Finding] = []

    for name, value in env.items():
        matched_by_name = _is_likely_secret_name(name)
        matched_by_entropy = _is_high_entropy_value(value)

        if not matched_by_name and not matched_by_entropy:
            continue

        if matched_by_name:
            reason = "variable name matches credential pattern"
            severity = Severity.CRITICAL
        else:
            reason = f"high-entropy value (entropy={_shannon_entropy(value):.2f} bits/char)"
            severity = Severity.MEDIUM

        findings.append(Finding(
            category=Category.ENV_VAR,
            severity=severity,
            source=f"env:{name}",
            label=f"Environment variable: {name}",
            detail=f"{reason}, value length={len(value)} (value redacted)",
            plaintext=True,
            redacted=True,
            extra={
                "var_name": name,
                "value_length": len(value),
                "entropy": round(_shannon_entropy(value), 3),
                "matched_by_name": matched_by_name,
                "matched_by_entropy": matched_by_entropy,
            },
        ))

    return findings
