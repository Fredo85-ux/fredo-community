# -*- coding: utf-8 -*-
"""
Fredo — Community Edition
PID / port-owner finder.

Identify which process owns a local port, list every listening socket, and
(optionally) terminate a process by PID. Pure standard library.

  • Windows : uses PowerShell (Get-NetTCPConnection / Get-Process / Stop-Process)
  • Linux/macOS : uses lsof + ps + kill

Each public function returns plain dicts/lists so it can drive either the CLI
or the GUI without change.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys

IS_WINDOWS = sys.platform == "win32"
_NO_WINDOW = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0


# ── Windows backend (PowerShell) ────────────────────────────────────────────────

def _run_ps(cmd: str) -> str:
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
         "-Command", cmd],
        capture_output=True, text=True, startupinfo=si, creationflags=_NO_WINDOW,
    )
    return proc.stdout.strip()


def _ps_json(cmd: str):
    out = _run_ps(cmd)
    if not out:
        return []
    try:
        data = json.loads(out)
        return [data] if isinstance(data, dict) else data
    except json.JSONDecodeError:
        return []


def _win_find_port(port: int, proto: str) -> list[dict]:
    if proto.upper() == "TCP":
        cmd = (f"Get-NetTCPConnection -LocalPort {port} -ErrorAction SilentlyContinue "
               f"| Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess "
               f"| ConvertTo-Json -Compress")
    else:
        cmd = (f"Get-NetUDPEndpoint -LocalPort {port} -ErrorAction SilentlyContinue "
               f"| Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress")
    rows = _ps_json(cmd)
    return [{
        "pid": int(r.get("OwningProcess", 0) or 0),
        "local": f"{r.get('LocalAddress','?')}:{r.get('LocalPort','?')}",
        "remote": f"{r.get('RemoteAddress','')}:{r.get('RemotePort','')}".strip(":"),
        "state": str(r.get("State", "")),
        "proto": proto.upper(),
    } for r in rows if r.get("OwningProcess")]


def _win_proc_info(pid: int) -> dict:
    cmd = (
        f"$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; if ($p) {{"
        f"  $pub = try {{ $p.MainModule.FileVersionInfo.CompanyName }} catch {{ '-' }};"
        f"  [PSCustomObject]@{{ Name=$p.ProcessName; CPU=[math]::Round($p.CPU,1);"
        f"  MemMB=[math]::Round($p.WorkingSet/1MB,1); Publisher=if($pub){{$pub}}else{{'-'}} }}"
        f"  | ConvertTo-Json -Compress }}"
    )
    out = _run_ps(cmd)
    try:
        d = json.loads(out) if out else {}
    except json.JSONDecodeError:
        d = {}
    return {"pid": pid, "name": d.get("Name", "?"), "cpu": d.get("CPU", "?"),
            "mem": d.get("MemMB", "?"), "publisher": (d.get("Publisher") or "-").strip()}


def _win_listeners() -> list[dict]:
    cmd = ("Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue "
           "| Select-Object LocalAddress,LocalPort,OwningProcess "
           "| Sort-Object LocalPort | ConvertTo-Json -Compress")
    rows = _ps_json(cmd)
    out = []
    for r in rows:
        out.append({
            "proto": "TCP",
            "port": int(r.get("LocalPort", 0) or 0),
            "address": str(r.get("LocalAddress", "?")),
            "pid": int(r.get("OwningProcess", 0) or 0),
        })
    return out


def _win_kill(pid: int) -> tuple[bool, str]:
    out = _run_ps(f"try {{ Stop-Process -Id {pid} -Force -ErrorAction Stop; 'OK' }} "
                  f"catch {{ $_.Exception.Message }}")
    if out.strip() == "OK":
        return True, f"PID {pid} terminated."
    return False, out.strip() or f"Failed to terminate PID {pid}."


# ── POSIX backend (lsof / ps / kill) ────────────────────────────────────────────

def _run(args: list[str]) -> str:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return ""


def _posix_find_port(port: int, proto: str) -> list[dict]:
    out = _run(["lsof", "-nP", f"-i{proto.lower()}:{port}"])
    rows = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 9:
            rows.append({
                "pid": int(parts[1]),
                "local": parts[8],
                "remote": "",
                "state": parts[9].strip("()") if len(parts) > 9 else "",
                "proto": proto.upper(),
            })
    return rows


def _posix_proc_info(pid: int) -> dict:
    out = _run(["ps", "-p", str(pid), "-o", "comm=,pcpu=,rss="])
    name, cpu, mem = "?", "?", "?"
    parts = out.split()
    if len(parts) >= 3:
        name, cpu = parts[0], parts[1]
        try:
            mem = round(int(parts[2]) / 1024, 1)  # rss KB -> MB
        except ValueError:
            mem = parts[2]
    return {"pid": pid, "name": name, "cpu": cpu, "mem": mem, "publisher": "-"}


def _posix_listeners() -> list[dict]:
    out = _run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
    rows = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 9:
            addr = parts[8]
            port = addr.rsplit(":", 1)[-1]
            try:
                port_i = int(port)
            except ValueError:
                continue
            rows.append({"proto": "TCP", "port": port_i, "address": addr, "pid": int(parts[1])})
    return rows


def _posix_kill(pid: int) -> tuple[bool, str]:
    try:
        os.kill(pid, signal.SIGTERM)
        return True, f"PID {pid} terminated (SIGTERM)."
    except ProcessLookupError:
        return False, f"No such process: {pid}."
    except PermissionError:
        return False, f"Permission denied terminating PID {pid} (try sudo)."
    except Exception as e:
        return False, str(e)


# ── Public API (dispatches by platform) ─────────────────────────────────────────

def find_port_owner(port: int, proto: str = "TCP") -> list[dict]:
    return _win_find_port(port, proto) if IS_WINDOWS else _posix_find_port(port, proto)


def process_info(pid: int) -> dict:
    return _win_proc_info(pid) if IS_WINDOWS else _posix_proc_info(pid)


def list_listeners() -> list[dict]:
    return _win_listeners() if IS_WINDOWS else _posix_listeners()


def kill_process(pid: int) -> tuple[bool, str]:
    return _win_kill(pid) if IS_WINDOWS else _posix_kill(pid)
