# -*- coding: utf-8 -*-
"""
Fredo — Community Edition
7-day trial gate.

The Community Edition is free to use for 7 days from the moment it is first
launched on a machine. This module records the first-run time and refuses to
run once the window has elapsed.

This is an honest time-limit, not copy protection. The marker file is signed
with an HMAC so it can't be silently edited to extend the window, but anyone
can of course delete it to start a fresh 7 days — that's fine. The point is to
keep the free build a try-before-you-buy, not to lock anyone out.

Environment overrides (useful for testing / CI):
    FREDO_TRIAL_DAYS   integer, replaces the 7-day window
    FREDO_TRIAL_RESET  if set to "1", deletes the marker and starts over
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Window length. Override with FREDO_TRIAL_DAYS for testing only.
TRIAL_DAYS = int(os.environ.get("FREDO_TRIAL_DAYS", "7"))

# Not a secret in any real sense (it ships in the source) — it only raises the
# bar above "edit the JSON by hand".
_SIGNING_KEY = b"fredo-community-edition-trial-v1"

_MARKER_DIR = Path.home() / ".fredo"
_MARKER_FILE = _MARKER_DIR / "trial.json"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _sign(payload: str) -> str:
    return hmac.new(_SIGNING_KEY, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def _read_marker() -> datetime | None:
    """Return the recorded first-run time, or None if missing/tampered."""
    try:
        raw = json.loads(_MARKER_FILE.read_text(encoding="utf-8"))
        started = raw["started"]
        if _sign(started) != raw.get("sig"):
            # Signature mismatch — someone edited the file. Treat as tampered:
            # refuse rather than trust an attacker-chosen date.
            return "tampered"  # type: ignore[return-value]
        return datetime.fromisoformat(started)
    except FileNotFoundError:
        return None
    except Exception:
        return "tampered"  # type: ignore[return-value]


def _write_marker(started: datetime) -> None:
    _MARKER_DIR.mkdir(parents=True, exist_ok=True)
    payload = started.isoformat()
    _MARKER_FILE.write_text(
        json.dumps({"started": payload, "sig": _sign(payload)}, indent=2),
        encoding="utf-8",
    )


class TrialStatus:
    def __init__(self, ok: bool, days_left: float, started: datetime | None,
                 expires: datetime | None, tampered: bool = False):
        self.ok = ok
        self.days_left = days_left
        self.started = started
        self.expires = expires
        self.tampered = tampered

    @property
    def message(self) -> str:
        if self.tampered:
            return ("Trial marker is invalid or was modified. "
                    "Delete ~/.fredo/trial.json to start a fresh 7-day trial, "
                    "or upgrade at https://github.com/your-org/fredo for the full edition.")
        if not self.ok:
            return ("Your 7-day Fredo Community Edition trial has expired. "
                    "Thanks for trying it! Upgrade to the full edition for unlimited use.")
        if self.days_left <= 1:
            hrs = max(0, int(self.days_left * 24))
            return f"Fredo Community Edition — trial: ~{hrs} hour(s) remaining."
        # Round up so a fresh 7-day trial reads "7 days", not "6".
        import math
        whole = math.ceil(self.days_left)
        return f"Fredo Community Edition — trial: {whole} day(s) remaining."


def check_trial() -> TrialStatus:
    """Evaluate the trial window, recording first-run on the first call."""
    if os.environ.get("FREDO_TRIAL_RESET") == "1":
        try:
            _MARKER_FILE.unlink()
        except FileNotFoundError:
            pass

    started = _read_marker()

    if started == "tampered":
        return TrialStatus(ok=False, days_left=0, started=None, expires=None, tampered=True)

    if started is None:
        started = _utcnow()
        _write_marker(started)

    expires = started + timedelta(days=TRIAL_DAYS)
    remaining = (expires - _utcnow()).total_seconds() / 86400.0
    return TrialStatus(ok=remaining > 0, days_left=remaining, started=started, expires=expires)


def enforce_trial(quiet: bool = False) -> TrialStatus:
    """Check the trial and exit the process if it has expired.

    Returns the status when still valid so callers can show 'N days left'.
    """
    status = check_trial()
    if not status.ok:
        if not quiet:
            print("=" * 60)
            print("  FREDO — COMMUNITY EDITION")
            print("=" * 60)
            print(f"  {status.message}")
            print("=" * 60)
        sys.exit(2)
    return status
