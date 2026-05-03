"""Browser credential store detector.

[EDUCATIONAL — authorised testing on systems you own only]

Locates browser credential databases (Chrome, Firefox, Edge) and reports
their presence.  Does NOT decrypt DPAPI-protected passwords — a live system
would require OS keychain integration beyond this demo's scope.

What this reports:
- Path to the Login Data SQLite file (Chrome/Edge)
- Path to logins.json (Firefox)
- Number of rows / entries if the file is readable SQLite
"""

from __future__ import annotations

import os
import platform
import sqlite3
from pathlib import Path
from typing import Optional

from models import Category, Finding, Severity


# ---------------------------------------------------------------------------
# Profile path resolution
# ---------------------------------------------------------------------------

def _chrome_profile_dirs(home: Optional[Path] = None) -> list[Path]:
    """Return candidate Chrome / Chromium profile directories for the OS."""
    home = home or Path.home()
    system = platform.system()

    if system == "Windows":
        local_app = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        candidates = [
            local_app / "Google" / "Chrome" / "User Data" / "Default",
            local_app / "Microsoft" / "Edge" / "User Data" / "Default",
            local_app / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default",
        ]
    elif system == "Darwin":
        candidates = [
            home / "Library" / "Application Support" / "Google" / "Chrome" / "Default",
            home / "Library" / "Application Support" / "Microsoft Edge" / "Default",
        ]
    else:  # Linux
        candidates = [
            home / ".config" / "google-chrome" / "Default",
            home / ".config" / "chromium" / "Default",
            home / ".config" / "microsoft-edge" / "Default",
            home / "snap" / "chromium" / "common" / "chromium" / "Default",
        ]
    return candidates


def _firefox_profile_dirs(home: Optional[Path] = None) -> list[Path]:
    """Return candidate Firefox profile directories for the OS."""
    home = home or Path.home()
    system = platform.system()

    if system == "Windows":
        roaming = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        profiles_ini = roaming / "Mozilla" / "Firefox" / "profiles.ini"
    elif system == "Darwin":
        profiles_ini = (
            home / "Library" / "Application Support" / "Firefox" / "profiles.ini"
        )
    else:
        profiles_ini = home / ".mozilla" / "firefox" / "profiles.ini"

    if not profiles_ini.exists():
        return []

    dirs: list[Path] = []
    try:
        content = profiles_ini.read_text(errors="replace")
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("Path="):
                rel = line[5:].strip()
                parent = profiles_ini.parent
                dirs.append(parent / rel)
    except OSError:
        pass
    return dirs


# ---------------------------------------------------------------------------
# Row counting helper
# ---------------------------------------------------------------------------

def _count_login_rows(db_path: Path) -> Optional[int]:
    """Return the number of rows in the Chrome `logins` table, or None."""
    try:
        # Open read-only using URI
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)
        cursor = con.execute("SELECT COUNT(*) FROM logins")
        count = cursor.fetchone()[0]
        con.close()
        return count
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def collect_browser_findings(home: Optional[Path] = None) -> list[Finding]:
    """Locate browser credential stores and return a list of Findings."""
    findings: list[Finding] = []
    home = home or Path.home()

    # --- Chrome / Edge / Brave ---
    for profile_dir in _chrome_profile_dirs(home):
        login_db = profile_dir / "Login Data"
        if login_db.exists():
            row_count = _count_login_rows(login_db)
            detail = (
                f"{row_count} encrypted login(s) stored"
                if row_count is not None
                else "Login Data file found (could not read)"
            )
            findings.append(Finding(
                category=Category.BROWSER,
                severity=Severity.HIGH,
                source=str(login_db),
                label=f"{profile_dir.parts[-3] if len(profile_dir.parts) >= 3 else 'Browser'} Login Data",
                detail=detail,
                plaintext=False,
                extra={"row_count": row_count},
            ))

    # --- Firefox ---
    for profile_dir in _firefox_profile_dirs(home):
        logins_json = profile_dir / "logins.json"
        if logins_json.exists():
            findings.append(Finding(
                category=Category.BROWSER,
                severity=Severity.HIGH,
                source=str(logins_json),
                label="Firefox logins.json",
                detail="Mozilla-encrypted login store found",
                plaintext=False,
            ))

    return findings
