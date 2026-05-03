"""Report generator and optional XOR-based output obfuscation.

[EDUCATIONAL — authorised testing on systems you own only]

The "encryption" here is XOR with a PBKDF2-derived key — it is a
DEMONSTRATION, NOT production encryption.  Use a proper KMS or GPG for
real-world exfiltration-safe output.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Optional

from models import CredentialReport, Severity


# ---------------------------------------------------------------------------
# Text renderer
# ---------------------------------------------------------------------------

_SEV_COLOURS = {
    Severity.CRITICAL: "\033[91m",   # bright red
    Severity.HIGH:     "\033[93m",   # yellow
    Severity.MEDIUM:   "\033[33m",   # orange-ish
    Severity.LOW:      "\033[32m",   # green
    Severity.INFO:     "\033[36m",   # cyan
}
_RESET = "\033[0m"


def render_text(report: CredentialReport, colour: bool = True) -> str:
    lines: list[str] = []

    def c(sev: Severity, text: str) -> str:
        if colour:
            return f"{_SEV_COLOURS.get(sev, '')}{text}{_RESET}"
        return text

    lines.append("=" * 64)
    lines.append(" CREDENTIAL ENUMERATION REPORT")
    lines.append(f" Host:     {report.hostname}")
    lines.append(f" User:     {report.username}")
    lines.append(f" Platform: {report.os_platform}")
    lines.append(f" Risk:     {c(Severity(report.risk_level) if report.risk_level != 'CLEAN' else Severity.INFO, report.risk_level)}")
    lines.append(f" Findings: {len(report.findings)}")
    lines.append("=" * 64)

    for cat, cat_findings in sorted(report.by_category.items()):
        lines.append(f"\n[{cat.upper()}]")
        for f in cat_findings:
            sev_str = c(f.severity, f"[{f.severity.value}]")
            lines.append(f"  {sev_str} {f.label}")
            lines.append(f"      Source : {f.source}")
            lines.append(f"      Detail : {f.detail}")
            if f.plaintext:
                tag = c(Severity.CRITICAL, "PLAINTEXT")
                lines.append(f"      ⚠  {tag} — value accessible without decryption")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON renderer
# ---------------------------------------------------------------------------

def render_json(report: CredentialReport, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent)


# ---------------------------------------------------------------------------
# XOR obfuscation (demo — not production crypto)
# ---------------------------------------------------------------------------

def _derive_key(passphrase: str, salt: bytes, length: int = 64) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, iterations=100_000, dklen=length)


def obfuscate(data: str, passphrase: str) -> str:
    """XOR-obfuscate `data` with a PBKDF2-derived key.  NOT secure encryption."""
    salt = os.urandom(16)
    data_bytes = data.encode()
    key = _derive_key(passphrase, salt, len(data_bytes))
    xored = bytes(a ^ b for a, b in zip(data_bytes, key))
    blob = salt + xored
    return base64.b64encode(blob).decode()


def deobfuscate(blob_b64: str, passphrase: str) -> str:
    """Reverse of obfuscate().  Returns decoded string; invalid bytes replaced."""
    blob = base64.b64decode(blob_b64.encode())
    salt = blob[:16]
    xored = blob[16:]
    key = _derive_key(passphrase, salt, len(xored))
    plain = bytes(a ^ b for a, b in zip(xored, key))
    return plain.decode(errors="replace")
