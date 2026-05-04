"""Tests for the credential enumeration tool — all offline, no real credentials."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from collectors.config_files import (
    collect_config_findings,
    _parse_aws_credentials,
    _parse_git_credentials,
    _parse_netrc,
    _parse_pgpass,
    _parse_docker_config,
)
from collectors.env_vars import collect_env_findings, _shannon_entropy, _is_likely_secret_name
from collectors.ssh_keys import collect_ssh_findings, _scan_file
from models import Category, CredentialReport, Finding, Severity
from reporter import deobfuscate, obfuscate, render_json, render_text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class TestFinding:
    def test_to_dict_keys(self):
        f = Finding(
            category=Category.SSH,
            severity=Severity.CRITICAL,
            source="/home/user/.ssh/id_rsa",
            label="SSH private key",
            detail="unprotected RSA key",
            plaintext=True,
        )
        d = f.to_dict()
        assert d["category"] == "ssh"
        assert d["severity"] == "CRITICAL"
        assert d["plaintext"] is True

    def test_redacted_default_false(self):
        f = Finding(Category.ENV_VAR, Severity.HIGH, "env:X", "X", "desc")
        assert f.redacted is False


class TestCredentialReport:
    def _report(self, *findings):
        r = CredentialReport("host", "user", "Linux")
        r.findings.extend(findings)
        return r

    def test_critical_property(self):
        r = self._report(
            Finding(Category.ENV_VAR, Severity.CRITICAL, "e", "l", "d"),
            Finding(Category.SSH,     Severity.LOW,      "s", "l", "d"),
        )
        assert len(r.critical) == 1

    def test_high_property(self):
        r = self._report(
            Finding(Category.BROWSER, Severity.HIGH, "b", "l", "d"),
        )
        assert len(r.high) == 1

    def test_by_category(self):
        r = self._report(
            Finding(Category.SSH,     Severity.CRITICAL, "s", "l", "d"),
            Finding(Category.SSH,     Severity.LOW,      "s", "l", "d"),
            Finding(Category.ENV_VAR, Severity.MEDIUM,   "e", "l", "d"),
        )
        bc = r.by_category
        assert len(bc["ssh"]) == 2
        assert len(bc["env_var"]) == 1

    def test_risk_level_critical(self):
        r = self._report(Finding(Category.ENV_VAR, Severity.CRITICAL, "e", "l", "d"))
        assert r.risk_level == "CRITICAL"

    def test_risk_level_clean(self):
        r = self._report()
        assert r.risk_level == "CLEAN"

    def test_to_dict_structure(self):
        r = self._report(Finding(Category.SSH, Severity.HIGH, "s", "l", "d"))
        d = r.to_dict()
        assert d["hostname"] == "host"
        assert d["risk_level"] == "HIGH"
        assert d["total_findings"] == 1
        assert len(d["findings"]) == 1


# ---------------------------------------------------------------------------
# Config file collectors
# ---------------------------------------------------------------------------

class TestNetrcParser:
    def test_parses_machine_login_password(self, tmp_path):
        p = tmp_path / ".netrc"
        write(p, "machine ftp.example.com login alice password s3cr3t")
        findings = _parse_netrc(p)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.CRITICAL
        assert "ftp.example.com" in f.label
        assert f.plaintext is True
        assert f.extra["login"] == "alice"
        assert f.extra["has_password"] is True

    def test_parses_multiple_machines(self, tmp_path):
        p = tmp_path / ".netrc"
        write(p, (
            "machine host1.com login bob password abc\n"
            "machine host2.com login carol password xyz\n"
        ))
        findings = _parse_netrc(p)
        assert len(findings) == 2

    def test_entry_without_password_is_medium(self, tmp_path):
        p = tmp_path / ".netrc"
        write(p, "machine host.com login alice")
        findings = _parse_netrc(p)
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].extra["has_password"] is False

    def test_empty_file_returns_no_findings(self, tmp_path):
        p = tmp_path / ".netrc"
        write(p, "")
        assert _parse_netrc(p) == []

    def test_nonexistent_file_returns_empty(self, tmp_path):
        assert _parse_netrc(tmp_path / "no_such_file") == []


class TestGitCredentialsParser:
    def test_url_with_embedded_password(self, tmp_path):
        p = tmp_path / ".git-credentials"
        write(p, "https://alice:mytoken@github.com\n")
        findings = _parse_git_credentials(p)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.CRITICAL
        assert f.extra["host"] == "github.com"
        assert f.extra["user"] == "alice"
        assert "***" in f.detail

    def test_partial_url_is_medium(self, tmp_path):
        p = tmp_path / ".git-credentials"
        write(p, "https://github.com\n")
        findings = _parse_git_credentials(p)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_multiple_lines(self, tmp_path):
        p = tmp_path / ".git-credentials"
        write(p, "https://user:pass@a.com\nhttps://user:pass@b.com\n")
        assert len(_parse_git_credentials(p)) == 2

    def test_empty_lines_ignored(self, tmp_path):
        p = tmp_path / ".git-credentials"
        write(p, "\n\n")
        assert _parse_git_credentials(p) == []


class TestAwsCredentialsParser:
    def test_parses_access_and_secret(self, tmp_path):
        p = tmp_path / "credentials"
        write(p, (
            "[default]\n"
            "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        ))
        findings = _parse_aws_credentials(p)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.CRITICAL
        assert "AKIAIOSFODNN7EXAMPLE" in f.detail
        assert "***" in f.detail
        assert f.extra["profile"] == "default"

    def test_multiple_profiles(self, tmp_path):
        p = tmp_path / "credentials"
        write(p, (
            "[default]\naws_access_key_id = KEY1\naws_secret_access_key = SECRET1\n"
            "[prod]\naws_access_key_id = KEY2\naws_secret_access_key = SECRET2\n"
        ))
        findings = _parse_aws_credentials(p)
        assert len(findings) == 2

    def test_missing_secret_no_finding(self, tmp_path):
        p = tmp_path / "credentials"
        write(p, "[default]\naws_access_key_id = ONLY_ACCESS_KEY\n")
        assert _parse_aws_credentials(p) == []


class TestPgpassParser:
    def test_parses_single_entry(self, tmp_path):
        p = tmp_path / ".pgpass"
        write(p, "localhost:5432:mydb:postgres:mysecretpassword\n")
        findings = _parse_pgpass(p)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.CRITICAL
        assert f.extra["host"] == "localhost"
        assert f.extra["user"] == "postgres"
        assert "***" in f.detail

    def test_ignores_comments(self, tmp_path):
        p = tmp_path / ".pgpass"
        write(p, "# This is a comment\nlocalhost:5432:db:user:pass\n")
        findings = _parse_pgpass(p)
        assert len(findings) == 1

    def test_wildcard_entries(self, tmp_path):
        p = tmp_path / ".pgpass"
        write(p, "*:*:*:admin:password123\n")
        findings = _parse_pgpass(p)
        assert len(findings) == 1
        assert findings[0].extra["host"] == "*"


class TestDockerConfigParser:
    def test_parses_auth_entry(self, tmp_path):
        p = tmp_path / "config.json"
        data = {"auths": {"https://index.docker.io/v1/": {"auth": "dXNlcjpwYXNz"}}}
        write(p, json.dumps(data))
        findings = _parse_docker_config(p)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.HIGH
        assert "index.docker.io" in f.label

    def test_no_auths_returns_empty(self, tmp_path):
        p = tmp_path / "config.json"
        write(p, json.dumps({"credsStore": "desktop"}))
        assert _parse_docker_config(p) == []

    def test_invalid_json_returns_empty(self, tmp_path):
        p = tmp_path / "config.json"
        write(p, "not json")
        assert _parse_docker_config(p) == []


class TestCollectConfigFindings:
    def test_finds_multiple_file_types(self, tmp_path):
        write(tmp_path / ".netrc", "machine x.com login bob password abc")
        aws_dir = tmp_path / ".aws"
        aws_dir.mkdir()
        write(aws_dir / "credentials",
              "[default]\naws_access_key_id = KEY\naws_secret_access_key = SECRET\n")

        findings = collect_config_findings(home=tmp_path)
        cats = {f.category for f in findings}
        assert Category.CONFIG_FILE in cats
        assert len(findings) >= 2

    def test_empty_home_returns_empty(self, tmp_path):
        assert collect_config_findings(home=tmp_path) == []


# ---------------------------------------------------------------------------
# Environment variable scanner
# ---------------------------------------------------------------------------

class TestShannonEntropy:
    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char(self):
        assert _shannon_entropy("aaaa") == 0.0

    def test_high_entropy(self):
        # Long random-looking string should have high entropy
        val = "A9z2K8mXqP1nBr7vLwYt4cGhJsUdEoFi"
        assert _shannon_entropy(val) > 3.0

    def test_low_entropy_repeated(self):
        assert _shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0


class TestIsLikelySecretName:
    def test_api_key_matches(self):
        assert _is_likely_secret_name("API_KEY")
        assert _is_likely_secret_name("MY_API_KEY")
        assert _is_likely_secret_name("STRIPE_API_KEY")

    def test_password_matches(self):
        assert _is_likely_secret_name("DB_PASSWORD")
        assert _is_likely_secret_name("PASSWORD")
        assert _is_likely_secret_name("SMTP_PASSWD")

    def test_token_matches(self):
        assert _is_likely_secret_name("ACCESS_TOKEN")
        assert _is_likely_secret_name("GITHUB_TOKEN")

    def test_safe_names_no_match(self):
        assert not _is_likely_secret_name("HOME")
        assert not _is_likely_secret_name("PATH")
        assert not _is_likely_secret_name("TERM")

    def test_random_name_no_match(self):
        assert not _is_likely_secret_name("DISPLAY")
        assert not _is_likely_secret_name("LANG")


class TestCollectEnvFindings:
    def test_detects_secret_by_name(self):
        env = {"API_KEY": "some_value_here_12345678", "HOME": "/home/user"}
        findings = collect_env_findings(env=env)
        labels = [f.label for f in findings]
        assert any("API_KEY" in l for l in labels)

    def test_detects_high_entropy_value(self):
        # High-entropy value even with innocuous name
        env = {"MY_CONFIG": "A9z2K8mXqP1nBr7vLwYt4cGhJsUdEoFi"}
        findings = collect_env_findings(env=env)
        assert any(f.category == Category.ENV_VAR for f in findings)

    def test_no_false_positives_on_safe_env(self):
        safe_env = {"HOME": "/home/user", "TERM": "xterm-256color", "LANG": "en_US.UTF-8"}
        findings = collect_env_findings(env=safe_env)
        assert findings == []

    def test_values_are_redacted(self):
        env = {"SECRET_KEY": "mysecretvalue12345678"}
        findings = collect_env_findings(env=env)
        for f in findings:
            assert "mysecretvalue" not in f.detail

    def test_empty_env_returns_empty(self):
        assert collect_env_findings(env={}) == []


# ---------------------------------------------------------------------------
# SSH key finder
# ---------------------------------------------------------------------------

RSA_KEY = """\
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29A0rGvBYAiHoJ
BHk3fOY7bvMF
-----END RSA KEY-----
"""

OPENSSH_ENCRYPTED = """\
-----BEGIN OPENSSH PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,ABCDEF1234567890

b3BlbnNzaC1rZXktdjEAAAAA
-----END OPENSSH PRIVATE KEY-----
"""


class TestSshKeyFinder:
    def test_finds_unprotected_rsa_key(self, tmp_path):
        key_file = tmp_path / "id_rsa"
        write(key_file, RSA_KEY)
        finding = _scan_file(key_file)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert "RSA" in finding.detail
        assert finding.plaintext is True

    def test_finds_passphrase_protected_key(self, tmp_path):
        key_file = tmp_path / "id_openssh"
        write(key_file, OPENSSH_ENCRYPTED)
        finding = _scan_file(key_file)
        assert finding is not None
        assert finding.severity == Severity.LOW
        assert "passphrase-protected" in finding.detail
        assert finding.plaintext is False

    def test_non_key_file_returns_none(self, tmp_path):
        f = tmp_path / "config"
        write(f, "Host github.com\n  User git\n")
        assert _scan_file(f) is None

    def test_collect_scans_ssh_dir(self, tmp_path):
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        write(ssh_dir / "id_rsa", RSA_KEY)
        write(ssh_dir / "config", "Host github.com\n  User git\n")
        findings = collect_ssh_findings(home=tmp_path)
        assert len(findings) == 1
        assert "id_rsa" in findings[0].source

    def test_missing_ssh_dir_returns_empty(self, tmp_path):
        assert collect_ssh_findings(home=tmp_path) == []


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------

class TestReporter:
    def _sample_report(self) -> CredentialReport:
        r = CredentialReport("myhost", "alice", "Linux x86_64")
        r.findings.append(Finding(
            category=Category.CONFIG_FILE,
            severity=Severity.CRITICAL,
            source="/home/alice/.netrc",
            label=".netrc entry: ftp.example.com",
            detail="host=ftp.example.com user=alice password=*** (redacted)",
            plaintext=True,
            redacted=True,
        ))
        return r

    def test_render_text_contains_hostname(self):
        report = self._sample_report()
        text = render_text(report, colour=False)
        assert "myhost" in text

    def test_render_text_contains_severity(self):
        report = self._sample_report()
        text = render_text(report, colour=False)
        assert "CRITICAL" in text

    def test_render_text_contains_label(self):
        report = self._sample_report()
        text = render_text(report, colour=False)
        assert ".netrc entry" in text

    def test_render_json_is_valid(self):
        report = self._sample_report()
        data = json.loads(render_json(report))
        assert data["hostname"] == "myhost"
        assert data["risk_level"] == "CRITICAL"
        assert len(data["findings"]) == 1

    def test_obfuscate_deobfuscate_roundtrip(self):
        original = '{"secret": "test_value_12345"}'
        key = "test-passphrase-2026"
        blob = obfuscate(original, key)
        assert blob != original
        recovered = deobfuscate(blob, key)
        assert recovered == original

    def test_wrong_key_produces_garbage(self):
        original = "Hello, World! This is a test string."
        blob = obfuscate(original, "correct-key")
        # Wrong key XORs with a different key stream — output is garbled
        wrong = deobfuscate(blob, "wrong-key")
        assert wrong != original
        # Note: byte-level XOR with wrong key may produce multi-byte UTF-8
        # sequences, so character count isn't guaranteed to match — only
        # confirm the content is different (garbage).

    def test_obfuscate_is_base64(self):
        import base64
        blob = obfuscate("test data for encoding", "passphrase")
        # Should not raise
        base64.b64decode(blob)

    def test_render_text_risk_level(self):
        r = CredentialReport("h", "u", "Linux")
        text = render_text(r, colour=False)
        assert "CLEAN" in text
