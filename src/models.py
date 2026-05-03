"""Data models for credential findings.

All findings represent DISCOVERED locations or plaintext credentials that
an authorised tester has found on a system they own.  This tool is strictly
for educational use and authorised security assessments.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"   # Plaintext credential, immediately actionable
    HIGH     = "HIGH"       # Encrypted credential store (requires further work)
    MEDIUM   = "MEDIUM"     # Possible credential, needs review
    LOW      = "LOW"        # Metadata / path disclosure only
    INFO     = "INFO"       # Informational


class Category(str, Enum):
    BROWSER     = "browser"
    SSH         = "ssh"
    CONFIG_FILE = "config_file"
    ENV_VAR     = "env_var"


@dataclass
class Finding:
    """A single discovered credential or credential-adjacent artefact."""

    category: Category
    severity: Severity
    source: str            # file path, env var name, or description
    label: str             # human-readable label (e.g. "Chrome Login Data")
    detail: str            # what was found (value or description)
    plaintext: bool = False
    redacted: bool = False
    extra: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict:
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "source": self.source,
            "label": self.label,
            "detail": self.detail,
            "plaintext": self.plaintext,
            "redacted": self.redacted,
            "extra": self.extra,
        }


@dataclass
class CredentialReport:
    """Aggregated findings from all collectors."""

    hostname: str
    username: str
    os_platform: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def critical(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def by_category(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.category.value, []).append(f)
        return result

    @property
    def risk_level(self) -> str:
        if self.critical:
            return "CRITICAL"
        if self.high:
            return "HIGH"
        if any(f.severity == Severity.MEDIUM for f in self.findings):
            return "MEDIUM"
        if self.findings:
            return "LOW"
        return "CLEAN"

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "username": self.username,
            "os_platform": self.os_platform,
            "risk_level": self.risk_level,
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }
