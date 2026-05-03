"""SSH private key finder.

[EDUCATIONAL — authorised testing on systems you own only]

Scans ~/.ssh/ (and an optional extra path list) for private key files.
Reports the key type and whether it is passphrase-protected.
Does NOT extract or copy key material.
"""

from __future__ import annotations

import stat
from pathlib import Path
from typing import Optional

from models import Category, Finding, Severity


_PRIVATE_KEY_HEADERS = [
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
]

_ENCRYPTED_MARKERS = [
    "ENCRYPTED",
    "Proc-Type: 4,ENCRYPTED",
]


def _is_world_readable(path: Path) -> bool:
    try:
        mode = path.stat().st_mode
        return bool(mode & stat.S_IROTH)
    except OSError:
        return False


def _detect_key_type(first_line: str) -> str:
    mappings = {
        "RSA": "RSA",
        "EC": "EC (ECDSA)",
        "DSA": "DSA",
        "OPENSSH": "OpenSSH (modern format)",
        "PGP": "PGP",
    }
    for key, label in mappings.items():
        if key in first_line:
            return label
    return "Unknown"


def _is_passphrase_protected(content: str) -> bool:
    return any(m in content for m in _ENCRYPTED_MARKERS)


def _scan_file(path: Path) -> Optional[Finding]:
    try:
        content = path.read_text(errors="replace")
    except OSError:
        return None

    first_line = content.splitlines()[0] if content.strip() else ""
    if not any(header in content for header in _PRIVATE_KEY_HEADERS):
        return None

    key_type = _detect_key_type(first_line)
    protected = _is_passphrase_protected(content)
    world_readable = _is_world_readable(path)

    severity = Severity.LOW if protected else Severity.CRITICAL
    detail_parts = [f"Type: {key_type}"]
    if protected:
        detail_parts.append("passphrase-protected")
    else:
        detail_parts.append("NO PASSPHRASE — key is unprotected")
    if world_readable:
        detail_parts.append("world-readable permissions (insecure)")

    return Finding(
        category=Category.SSH,
        severity=severity,
        source=str(path),
        label=f"SSH private key: {path.name}",
        detail=", ".join(detail_parts),
        plaintext=not protected,
        extra={
            "key_type": key_type,
            "passphrase_protected": protected,
            "world_readable": world_readable,
        },
    )


def collect_ssh_findings(
    home: Optional[Path] = None,
    extra_paths: Optional[list[Path]] = None,
) -> list[Finding]:
    """Scan for SSH private keys under ~/.ssh/ and any extra paths."""
    home = home or Path.home()
    search_dirs = [home / ".ssh"]
    if extra_paths:
        search_dirs.extend(extra_paths)

    findings: list[Finding] = []
    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
        for path in search_dir.iterdir():
            if path.is_file():
                finding = _scan_file(path)
                if finding:
                    findings.append(finding)
    return findings
