"""Command-line interface for the credential enumerator.

[EDUCATIONAL — authorised testing on systems you own only]

Usage:
  python cli.py [--all] [--browser] [--ssh] [--config] [--env]
                [--json] [--output FILE] [--key PASSPHRASE]
                [--decrypt FILE --key PASSPHRASE]
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import socket
import sys
from pathlib import Path

# Allow running from src/ directly
sys.path.insert(0, str(Path(__file__).parent))

from collectors.browser import collect_browser_findings
from collectors.config_files import collect_config_findings
from collectors.env_vars import collect_env_findings
from collectors.ssh_keys import collect_ssh_findings
from models import CredentialReport
from reporter import deobfuscate, obfuscate, render_json, render_text


def build_report(
    do_browser: bool,
    do_ssh: bool,
    do_config: bool,
    do_env: bool,
) -> CredentialReport:
    report = CredentialReport(
        hostname=socket.gethostname(),
        username=getpass.getuser(),
        os_platform=platform.platform(),
    )

    if do_browser:
        report.findings.extend(collect_browser_findings())
    if do_ssh:
        report.findings.extend(collect_ssh_findings())
    if do_config:
        report.findings.extend(collect_config_findings())
    if do_env:
        report.findings.extend(collect_env_findings())

    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="cred-enum",
        description=(
            "Credential enumerator — EDUCATIONAL / AUTHORISED TESTING ONLY.\n"
            "Run only on systems you own."
        ),
    )

    parser.add_argument("--all",     action="store_true", help="Enable all collectors")
    parser.add_argument("--browser", action="store_true", help="Browser credential stores")
    parser.add_argument("--ssh",     action="store_true", help="SSH private keys")
    parser.add_argument("--config",  action="store_true", help="Config file credentials")
    parser.add_argument("--env",     action="store_true", help="Environment variable secrets")
    parser.add_argument("--json",    action="store_true", help="Output as JSON")
    parser.add_argument("--output",  metavar="FILE",      help="Write output to file")
    parser.add_argument("--key",     metavar="PASSPHRASE",help="Obfuscate/deobfuscate with this key")
    parser.add_argument("--decrypt", metavar="FILE",      help="Deobfuscate a saved blob")

    args = parser.parse_args()

    # --- Decrypt mode ---
    if args.decrypt:
        if not args.key:
            print("Error: --decrypt requires --key", file=sys.stderr)
            return 1
        try:
            blob = Path(args.decrypt).read_text()
            print(deobfuscate(blob, args.key))
            return 0
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    # --- Collect ---
    do_all = args.all or not any([args.browser, args.ssh, args.config, args.env])
    report = build_report(
        do_browser=do_all or args.browser,
        do_ssh=do_all or args.ssh,
        do_config=do_all or args.config,
        do_env=do_all or args.env,
    )

    # --- Render ---
    if args.json:
        text = render_json(report)
    else:
        text = render_text(report, colour=not args.output)

    if args.key:
        text = obfuscate(text, args.key)

    if args.output:
        Path(args.output).write_text(text)
        print(f"Output written to {args.output}")
    else:
        print(text)

    # Exit 1 if any findings, 0 if clean
    return 0 if not report.findings else 1


if __name__ == "__main__":
    sys.exit(main())
