"""Plaintext credential file collector.

[EDUCATIONAL — authorised testing on systems you own only]

Parses common plaintext credential files:
  - ~/.netrc             — FTP/HTTP credentials
  - ~/.git-credentials   — Git HTTPS credentials (plaintext URL with creds)
  - ~/.aws/credentials   — AWS access keys
  - ~/.pgpass            — PostgreSQL passwords
  - ~/.docker/config.json — Docker registry auth tokens

All files parsed are on the known-plaintext list: if they exist they are
readable in clear text (no decryption required).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from models import Category, Finding, Severity


# ---------------------------------------------------------------------------
# .netrc parser
# ---------------------------------------------------------------------------

def _parse_netrc(path: Path) -> list[Finding]:
    """Parse ~/.netrc for machine/login/password entries."""
    try:
        content = path.read_text(errors="replace")
    except OSError:
        return []

    findings: list[Finding] = []
    # Tokenise: machine, login, password, account keywords
    tokens = content.split()
    i = 0
    current: dict[str, str] = {}

    while i < len(tokens):
        tok = tokens[i].lower()
        if tok == "machine" and i + 1 < len(tokens):
            if current:
                _append_netrc_finding(current, path, findings)
            current = {"machine": tokens[i + 1]}
            i += 2
        elif tok in ("login", "password", "account") and i + 1 < len(tokens):
            current[tok] = tokens[i + 1]
            i += 2
        else:
            i += 1

    if current:
        _append_netrc_finding(current, path, findings)

    return findings


def _append_netrc_finding(entry: dict, path: Path, findings: list[Finding]):
    machine = entry.get("machine", "unknown")
    login = entry.get("login", "")
    has_password = "password" in entry
    password = entry.get("password", "")

    detail = f"host={machine} user={login}"
    if has_password:
        detail += f" password={'*' * len(password)} (redacted)"

    findings.append(Finding(
        category=Category.CONFIG_FILE,
        severity=Severity.CRITICAL if has_password else Severity.MEDIUM,
        source=str(path),
        label=f".netrc entry: {machine}",
        detail=detail,
        plaintext=True,
        redacted=True,
        extra={"host": machine, "login": login, "has_password": has_password},
    ))


# ---------------------------------------------------------------------------
# .git-credentials parser
# ---------------------------------------------------------------------------

_GIT_CRED_RE = re.compile(
    r"https?://(?P<user>[^:@\n]+):(?P<pass>[^@\n]+)@(?P<host>[^\n/]+)"
)


def _parse_git_credentials(path: Path) -> list[Finding]:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return []

    findings: list[Finding] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        m = _GIT_CRED_RE.search(line)
        if m:
            findings.append(Finding(
                category=Category.CONFIG_FILE,
                severity=Severity.CRITICAL,
                source=str(path),
                label=f".git-credentials: {m.group('host')}",
                detail=f"user={m.group('user')} password=*** (redacted)",
                plaintext=True,
                redacted=True,
                extra={"host": m.group("host"), "user": m.group("user")},
            ))
        else:
            # Partial match (token-style, no embedded password)
            findings.append(Finding(
                category=Category.CONFIG_FILE,
                severity=Severity.MEDIUM,
                source=str(path),
                label=".git-credentials entry",
                detail=f"Credential URL: {line[:60]}",
                plaintext=True,
                redacted=False,
            ))
    return findings


# ---------------------------------------------------------------------------
# ~/.aws/credentials parser
# ---------------------------------------------------------------------------

def _parse_aws_credentials(path: Path) -> list[Finding]:
    try:
        content = path.read_text(errors="replace")
    except OSError:
        return []

    findings: list[Finding] = []
    profile = "default"
    access_key = ""

    for line in content.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            profile = line[1:-1]
            access_key = ""
        elif line.startswith("aws_access_key_id"):
            access_key = line.split("=", 1)[-1].strip()
        elif line.startswith("aws_secret_access_key") and access_key:
            findings.append(Finding(
                category=Category.CONFIG_FILE,
                severity=Severity.CRITICAL,
                source=str(path),
                label=f"AWS credentials: [{profile}]",
                detail=f"access_key={access_key} secret=*** (redacted)",
                plaintext=True,
                redacted=True,
                extra={"profile": profile, "access_key_id": access_key},
            ))
            access_key = ""

    return findings


# ---------------------------------------------------------------------------
# ~/.pgpass parser
# ---------------------------------------------------------------------------

def _parse_pgpass(path: Path) -> list[Finding]:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return []

    findings: list[Finding] = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 5:
            host, port, db, user = parts[0], parts[1], parts[2], parts[3]
            findings.append(Finding(
                category=Category.CONFIG_FILE,
                severity=Severity.CRITICAL,
                source=str(path),
                label=f".pgpass: {user}@{host}/{db}",
                detail=f"host={host} port={port} db={db} user={user} password=*** (redacted)",
                plaintext=True,
                redacted=True,
                extra={"host": host, "port": port, "db": db, "user": user},
            ))
    return findings


# ---------------------------------------------------------------------------
# ~/.docker/config.json parser
# ---------------------------------------------------------------------------

def _parse_docker_config(path: Path) -> list[Finding]:
    try:
        data = json.loads(path.read_text(errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []

    findings: list[Finding] = []
    auths = data.get("auths", {})
    for registry, info in auths.items():
        if "auth" in info:
            findings.append(Finding(
                category=Category.CONFIG_FILE,
                severity=Severity.HIGH,
                source=str(path),
                label=f"Docker auth: {registry}",
                detail=f"Base64-encoded credentials for {registry}",
                plaintext=False,  # base64 encoded but trivially decodable
                redacted=False,
                extra={"registry": registry},
            ))
    return findings


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

_COLLECTORS = [
    (".netrc",                        _parse_netrc),
    (".git-credentials",              _parse_git_credentials),
    (str(Path(".aws") / "credentials"), _parse_aws_credentials),
    (".pgpass",                       _parse_pgpass),
    (str(Path(".docker") / "config.json"), _parse_docker_config),
]


def collect_config_findings(home: Optional[Path] = None) -> list[Finding]:
    """Scan common credential config files and return a list of Findings."""
    home = home or Path.home()
    findings: list[Finding] = []
    for rel_path, parser in _COLLECTORS:
        full_path = home / rel_path
        if full_path.exists():
            findings.extend(parser(full_path))
    return findings
