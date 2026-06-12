# -*- coding: utf-8 -*-
"""
Fredo — Community Edition
Port scanner core.

Two engines:

  1. Built-in TCP connect scanner (pure standard library, zero dependencies,
     cross-platform). This is the default so the free edition works the moment
     you clone it — no nmap install required.

  2. nmap (optional). If nmap is on PATH it is used for service/version
     detection, which the built-in engine can't do. Pass engine="nmap".

Every scan is run through a curated risk analyzer that flags well-known
dangerous services and produces a 0–100 threat score.
"""
from __future__ import annotations

import concurrent.futures
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone

_NO_WINDOW = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

# Top ~50 TCP ports worth checking in a fast default sweep.
TOP_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 514, 587, 631, 636, 873, 990, 993, 995, 1025, 1080, 1433, 1521,
    1723, 2049, 2375, 3000, 3306, 3389, 4444, 5000, 5432, 5601, 5900, 5985,
    6379, 7001, 8000, 8008, 8080, 8443, 8888, 9000, 9200, 11211, 27017,
]

# service name, severity, advice — same intelligence the full Fredo product uses.
RISK_MAP: dict[int, tuple[str, str, str]] = {
    21:    ("FTP",        "HIGH",     "Plaintext file transfer — use SFTP instead."),
    22:    ("SSH",        "MEDIUM",   "Ensure key-based auth and no root login."),
    23:    ("Telnet",     "CRITICAL", "Unencrypted remote shell. Disable immediately."),
    25:    ("SMTP",       "MEDIUM",   "Check for open relay misconfiguration."),
    53:    ("DNS",        "LOW",      "Restrict recursion; watch for amplification abuse."),
    80:    ("HTTP",       "LOW",      "Plaintext web — redirect to HTTPS."),
    110:   ("POP3",       "MEDIUM",   "Plaintext mail retrieval — prefer POP3S/IMAPS."),
    135:   ("MSRPC",      "HIGH",     "Windows RPC exposed — should not face the internet."),
    139:   ("NetBIOS",    "HIGH",     "Legacy SMB/NetBIOS — block at the perimeter."),
    143:   ("IMAP",       "MEDIUM",   "Plaintext mail — prefer IMAPS (993)."),
    161:   ("SNMP",       "HIGH",     "Often uses default 'public' community string."),
    389:   ("LDAP",       "MEDIUM",   "Directory exposed — require LDAPS and auth."),
    443:   ("HTTPS",      "INFO",     "Check TLS version and certificate expiry."),
    445:   ("SMB",        "CRITICAL", "WannaCry/EternalBlue vector. Restrict access."),
    465:   ("SMTPS",      "INFO",     "Encrypted mail submission — verify TLS config."),
    1433:  ("MSSQL",      "HIGH",     "Database exposed — restrict to localhost/VPN."),
    1521:  ("Oracle",     "HIGH",     "Database exposed — restrict to localhost/VPN."),
    1723:  ("PPTP",       "HIGH",     "Obsolete VPN with known crypto flaws. Replace."),
    2049:  ("NFS",        "HIGH",     "Network file share exposed — lock down exports."),
    2375:  ("Docker API", "CRITICAL", "Unauthenticated Docker socket = full host takeover."),
    3306:  ("MySQL",      "HIGH",     "Database exposed — restrict to localhost/VPN."),
    3389:  ("RDP",        "CRITICAL", "Ransomware gold mine. Use a VPN instead."),
    4444:  ("Metasploit", "CRITICAL", "Common reverse-shell/C2 port — investigate now."),
    5432:  ("PostgreSQL", "HIGH",     "Database exposed — restrict to localhost/VPN."),
    5601:  ("Kibana",     "MEDIUM",   "Dashboards exposed — put behind auth proxy."),
    5900:  ("VNC",        "CRITICAL", "Remote desktop without VPN — block it."),
    5985:  ("WinRM",      "HIGH",     "Remote PowerShell — restrict to mgmt network."),
    6379:  ("Redis",      "CRITICAL", "Usually no auth by default. Expose = owned."),
    7001:  ("WebLogic",   "HIGH",     "Frequent RCE target — patch and restrict."),
    8080:  ("HTTP-Alt",   "MEDIUM",   "Dev/proxy server exposed? Review immediately."),
    8443:  ("HTTPS-Alt",  "LOW",      "Check what's running behind this port."),
    9200:  ("Elasticsearch","CRITICAL","Often unauthenticated — full data exposure."),
    11211: ("Memcached",  "CRITICAL", "Unauth + UDP amplification vector. Block it."),
    27017: ("MongoDB",    "CRITICAL", "Unauthenticated MongoDB = free database."),
}

SEVERITY_WEIGHT = {
    445: 30, 23: 30, 6379: 28, 5900: 25, 3389: 25, 27017: 25, 2375: 30,
    9200: 28, 11211: 25, 4444: 30, 22: 20, 21: 15, 135: 18, 139: 18,
    1433: 18, 3306: 18, 5432: 18, 1521: 18, 5985: 18, 80: 8, 443: 5,
}

SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}


@dataclass
class ScanResult:
    target: str
    engine: str
    timestamp: str
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)  # port -> service/version text
    raw_output: str = ""
    error: str = ""
    threat_score: int = 0
    analysis: str = ""


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


# ── Built-in connect scanner ───────────────────────────────────────────────────

def _probe(host: str, port: int, timeout: float) -> int | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                return port
    except OSError:
        return None
    return None


def builtin_scan(target: str, ports: list[int] | None = None,
                 timeout: float = 0.6, workers: int = 100) -> ScanResult:
    """Pure-stdlib threaded TCP connect scan. Works everywhere, no install."""
    ports = ports or TOP_PORTS
    try:
        host = socket.gethostbyname(target)
    except OSError as e:
        return ScanResult(target=target, engine="builtin", timestamp=_utcnow_iso(),
                          error=f"Could not resolve '{target}': {e}")

    open_ports: list[int] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_probe, host, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            p = fut.result()
            if p is not None:
                open_ports.append(p)

    open_ports.sort()
    result = ScanResult(
        target=target, engine="builtin", timestamp=_utcnow_iso(),
        open_ports=open_ports,
        services={p: RISK_MAP.get(p, ("unknown", "", ""))[0] for p in open_ports},
    )
    _finalize(result)
    return result


# ── Optional nmap engine ───────────────────────────────────────────────────────

def nmap_available() -> bool:
    return _nmap_path() is not None


def _nmap_path() -> str | None:
    path = shutil.which("nmap")
    if path:
        return path
    for p in (r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"):
        import os
        if os.path.exists(p):
            return p
    return None


def nmap_scan(target: str, top_ports: int = 1000, timeout: int = 300) -> ScanResult:
    """Service/version detection via nmap. Falls back to builtin if nmap absent."""
    path = _nmap_path()
    if not path:
        res = builtin_scan(target)
        res.error = "nmap not found — used built-in scanner instead. Install nmap for service detection."
        return res

    cmd = [path, "-sT", "-sV", "--top-ports", str(top_ports), "--open",
           "--max-retries", "2", "--host-timeout", "120s", target]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, creationflags=_NO_WINDOW)
    except Exception as e:
        return ScanResult(target=target, engine="nmap", timestamp=_utcnow_iso(),
                          error=str(e))

    services: dict[int, str] = {}
    open_ports: list[int] = []
    for m in re.finditer(r"^(\d+)/tcp\s+open\s+(.+)$", proc.stdout, re.MULTILINE):
        port = int(m.group(1))
        open_ports.append(port)
        services[port] = m.group(2).strip()

    open_ports.sort()
    result = ScanResult(
        target=target, engine="nmap", timestamp=_utcnow_iso(),
        open_ports=open_ports, services=services,
        raw_output=proc.stdout, error=proc.stderr.strip(),
    )
    _finalize(result)
    return result


# ── Risk analysis ──────────────────────────────────────────────────────────────

def analyze(open_ports: list[int]) -> str:
    if not open_ports:
        return "No open ports detected on the scanned set. Surface looks quiet."
    lines = [f"{len(open_ports)} open port(s) found:\n"]
    for p in sorted(open_ports):
        info = RISK_MAP.get(p)
        if info:
            svc, severity, note = info
            icon = SEVERITY_ICON.get(severity, "⚪")
            lines.append(f"{icon} Port {p} ({svc}) [{severity}]")
            lines.append(f"     {note}")
        else:
            lines.append(f"⚪ Port {p} — unknown service, investigate manually")
        lines.append("")
    return "\n".join(lines).rstrip()


def threat_score(open_ports: list[int], analysis_text: str) -> int:
    score = sum(SEVERITY_WEIGHT.get(p, 3) for p in open_ports)
    upper = analysis_text.upper()
    if "CRITICAL" in upper:
        score += 15
    elif "HIGH" in upper:
        score += 8
    return min(score, 100)


def _finalize(result: ScanResult) -> None:
    result.analysis = analyze(result.open_ports)
    result.threat_score = threat_score(result.open_ports, result.analysis)


def score_label(score: int) -> tuple[str, str]:
    """Return (label, hex_color) for a threat score (3-band, CLI/report use)."""
    if score >= 50:
        return "HIGH RISK", "#FF3B3B"
    if score >= 20:
        return "MODERATE", "#E0A500"
    return "LOW RISK", "#1FC77D"


def risk_band(score: int) -> tuple[str, str]:
    """Return (label, hex_color) for a threat score (4-band, dashboard gauge)."""
    if score >= 70:
        return "CRITICAL", "#FF3B3B"
    if score >= 40:
        return "ELEVATED", "#E0A500"
    if score >= 15:
        return "MODERATE", "#C9A227"
    return "LOW", "#1FC77D"
