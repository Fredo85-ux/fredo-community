# fredo-community
A free, dark-themed desktop **security scanner**. Point it at a host, get an instant **0–100 risk score**, and every scan is **saved to a local history** you can re-open and export. Includes a built-in **PID Finder** for tracking down and killing the process behind a port.
> **Free for 7 days.** The Community Edition runs free for 7 days from the first
> time you launch it. After that it asks you to upgrade. See
> [Trial](#7-day-trial).

![Fredo desktop app](docs/preview.png)

---

## Features

- **Network scan with risk scoring** — scan a target, see open ports graded by
  severity (Telnet, RDP, SMB, exposed databases, Redis, Docker API, …) and
  rolled into a single 0–100 score with a `LOW / MODERATE / ELEVATED / CRITICAL`
  band.
- **Saved history** — every scan is written to a local SQLite database
  (`~/.fredo/history.db`). Browse past scans, re-open the full analysis, and
  export any of them to a self-contained HTML report.
- **PID Finder** — find which process owns a TCP/UDP port, list every listening
  socket, and terminate a process — all from inside the app.
- **Two scan engines** — a zero-dependency built-in port scanner (default), or
  **nmap** for service/version detection if it's installed.

---

## Install & run

Requires Python 3.10+.

```bash
git clone [https://github.com/Fredo85-ux/fredo-community]
cd fredo-community
pip install -r requirements.txt

# Launch the desktop app
python app.py
```

That's it — the **Scan**, **History**, and **PID Finder** tabs are in the
sidebar. Enter a target (defaults to `127.0.0.1`), pick a scan profile, and hit
**RUN SCAN**.

> Tip: the **Full scan** profile uses [nmap](https://nmap.org/download.html) for
> service/version detection. If nmap isn't on your PATH, Fredo automatically
> falls back to the built-in engine.

---

## Command-line (optional)

The same engine is available headless — no GUI dependencies needed:

```bash
python fredo.py scan 127.0.0.1 --html   # scan + risk score + HTML report
python fredo.py pid 8080                 # who owns port 8080?
python fredo.py listeners                # every listening socket + PID
python fredo.py status                   # trial status
```

---

## How scoring works

Each open port is matched against a curated risk map (service, severity, and
remediation advice) and weighted into a **0–100 threat score**:

| Band | Score | Meaning |
|---|---|---|
| 🟢 LOW | 0–14 | Minimal exposure |
| 🟡 MODERATE | 15–39 | Worth reviewing |
| 🟠 ELEVATED | 40–69 | Notable risk |
| 🔴 CRITICAL | 70–100 | Dangerous services exposed |

---

## 7-day trial

The first time you launch, Fredo records the moment in `~/.fredo/trial.json`
(signed so it can't be silently edited forward). After 7 days the app shows an
upgrade prompt instead of opening.

- The marker is per-machine and is **not** committed (it's in `.gitignore`).
- For testing you can override the window with `FREDO_TRIAL_DAYS=1` or reset it
  with `FREDO_TRIAL_RESET=1`.

This is an honest time limit, not copy protection — deleting the marker starts a
fresh 7 days. If you find Fredo useful, please contact me!

---

## ⚠️ Authorized use only

Port scanning and process termination are powerful. **Only run this against
machines you own or are explicitly authorized to test.** Unauthorized scanning
may be illegal where you live. See [LICENSE](LICENSE).

---

## What's stored where

| Path | Contents |
|---|---|
| `~/.fredo/history.db` | Saved scan history (SQLite) |
| `~/.fredo/trial.json` | Signed trial marker |
| `./fredo_scan_*.html` | Exported HTML reports |

The full edition adds continuous endpoint monitoring, CIS benchmark scoring,
security *drift* detection, a fleet dashboard, compliance reporting, and
local-first AI analysis. This Community Edition is a free taste of that toolkit.
Licensed under the [Community Edition License](LICENSE).
