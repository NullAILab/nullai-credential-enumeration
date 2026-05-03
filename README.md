# Credential Enumeration

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Tests](https://img.shields.io/badge/tests-47%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT%20%2B%20Responsible%20Use-blue)

After initial access, attackers spend an average of 24 days inside a network before detection — most of that time harvesting credentials that enable lateral movement. Browser saved passwords, SSH private keys, AWS credential files, `.netrc` entries, and high-entropy environment variables are all fair game. This tool replicates that post-exploitation enumeration phase: it discovers credential artefacts across a system, scores their severity, and produces a redacted report — all values are masked, only metadata (path, hostname, owner) is shown. Designed for authorised red-team assessments and internal audit tooling.

## Features

- **Browser credentials** — detects Chrome/Edge `Login Data` SQLite and Firefox `logins.json` across Windows, macOS, and Linux profile paths; reports entry counts without reading plaintext
- **SSH key scanner** — finds private keys in `~/.ssh/`, identifies key type, flags unprotected keys (no passphrase), checks file permissions
- **Config file parser** — five parsers: `.netrc` (tokenised), `.git-credentials` (URL-regex), `~/.aws/credentials` (INI), `.pgpass` (colon-delimited), `.docker/config.json` (JSON)
- **Environment variable scanner** — two-pass scan: name matched against 14 credential-pattern regexes, then value entropy scored (Shannon ≥ 3.5 bits/char + length ≥ 16)
- **Report renderer** — plain-text table or JSON; all secrets redacted; severity rated CRITICAL / HIGH / MEDIUM / LOW
- **XOR obfuscation demo** — save findings to an XOR+PBKDF2 obfuscated file and decrypt later (demonstration — not production encryption)
- **47 tests** — all offline using `tmp_path` fixtures

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.10+ |
| Storage | stdlib `sqlite3` (browser detection only) |
| Entropy | Shannon bit-per-char formula |
| CLI | stdlib `argparse` |
| Testing | `pytest` + `tmp_path` fixtures |

## Project Structure

```
32-credential-enumeration/
├── src/
│   ├── collectors/
│   │   ├── browser.py        ← Chrome/Edge/Firefox profile detection
│   │   ├── ssh_keys.py       ← SSH private key finder + permission checker
│   │   ├── config_files.py   ← .netrc, .git-credentials, AWS, pgpass, Docker
│   │   └── env_vars.py       ← Environment variable pattern + entropy scanner
│   ├── models.py             ← Finding, CredentialReport, Severity, Category
│   ├── reporter.py           ← Text/JSON rendering + XOR obfuscation demo
│   └── cli.py                ← argparse CLI (--all, --browser, --ssh, --config, --env)
├── tests/
│   └── test_credential_enum.py  ← 47 tests, all offline
└── requirements.txt
```

## Usage

```bash
pip install -r requirements.txt

# Scan everything on your own system
python src/cli.py --all

# Individual collectors
python src/cli.py --browser
python src/cli.py --ssh
python src/cli.py --config
python src/cli.py --env

# JSON output
python src/cli.py --all --json

# Save with XOR obfuscation (demo only)
python src/cli.py --all --output findings.enc --key "my-passphrase"
python src/cli.py --decrypt findings.enc --key "my-passphrase"
```

**Example output:**

```
 [CRITICAL] AWS credentials file found
            path  : /home/user/.aws/credentials
            profile: default (key_id: AK***)

 [HIGH    ] Unprotected SSH private key
            file  : /home/user/.ssh/id_rsa
            type  : RSA  |  passphrase: NO  |  perms: 0644

 [MEDIUM  ] High-entropy environment variable
            name  : DB_PASSWORD  |  entropy: 4.12 bits/char
```

## Running Tests

```bash
python -m pytest tests/ -v
```

All 47 tests run offline — `tmp_path` fixtures create isolated directories with synthetic credential artefacts; no real secrets accessed.

## Detection Logic

**Browser:** Resolves Chrome/Edge/Firefox profile paths per OS, checks existence of `Login Data` or `logins.json`, counts SQLite rows when readable without decryption.

**SSH:** Reads each file in `~/.ssh/`, matches PEM headers (`-----BEGIN * PRIVATE KEY-----`), checks for `Proc-Type: 4,ENCRYPTED` to detect passphrase protection, validates file permissions.

**Config files:** `.netrc` → tokenised line parser. `.git-credentials` → URL regex extraction. `~/.aws/credentials` → INI parser. `.pgpass` → colon-delimited field parser. `.docker/config.json` → JSON registry credential check.

**Env vars:** Two-pass scan — name matched against 14 regexes (`*_KEY`, `*_SECRET`, `*_TOKEN`, `*_PASSWORD`, etc.), then value measured for Shannon entropy with a length gate.

## References

- [OWASP Credential Stuffing Prevention](https://owasp.org/www-community/attacks/Credential_stuffing)
- [MITRE ATT&CK T1552 — Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- [AWS Credentials File Format](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

## License

MIT License + Responsible Use Guidelines. See [LICENSE](LICENSE) for full terms.
