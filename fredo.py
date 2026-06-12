#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fredo — Community Edition (Free)
Command-line entry point.

    python fredo.py scan <target> [--full] [--ports 22,80,443] [--html]
    python fredo.py pid  <port>   [--udp] [--kill]
    python fredo.py listeners
    python fredo.py gui            # launch the graphical PID Finder
    python fredo.py status         # show trial status

Free for 7 days from first launch. See README.md.
"""
from __future__ import annotations

import argparse
import sys

# Windows consoles default to a legacy code page; force UTF-8 so the banner and
# severity icons render instead of mojibake. Harmless on POSIX.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except Exception:
        pass

from fredo import __version__, scanner, pidtools, report
from fredo.trial import enforce_trial, check_trial

BANNER = r"""
  _____              _
 |  ___|_ __ ___  __| | ___
 | |_ | '__/ _ \/ _` |/ _ \
 |  _|| | |  __/ (_| | (_) |    CYBER ANALYST
 |_|  |_|  \___|\__,_|\___/     Community Edition
                                v%s · Free 7-day trial
""" % __version__


def _print_trial_line() -> None:
    status = check_trial()
    print(f"  {status.message}\n")


# ── scan ────────────────────────────────────────────────────────────────────────

def cmd_scan(args: argparse.Namespace) -> int:
    ports = None
    if args.ports:
        try:
            ports = [int(p) for p in args.ports.split(",") if p.strip()]
        except ValueError:
            print("[ERROR] --ports must be a comma-separated list of port numbers.")
            return 1

    print(f"> Scanning {args.target} …")
    if args.full:
        if not scanner.nmap_available():
            print("  nmap not found — falling back to built-in scanner "
                  "(install nmap for service/version detection).")
        result = scanner.nmap_scan(args.target)
    else:
        result = scanner.builtin_scan(args.target, ports=ports)

    if result.error and not result.open_ports:
        print(f"[ERROR] {result.error}")
        return 1

    print("-" * 60)
    print(f"  Target : {result.target}")
    print(f"  Engine : {result.engine}")
    print(f"  Time   : {result.timestamp} UTC")
    print("-" * 60)
    print(result.analysis)
    print("-" * 60)
    label, _ = scanner.score_label(result.threat_score)
    print(f"  THREAT SCORE: {result.threat_score}/100  [{label}]")
    print("-" * 60)
    if result.error:
        print(f"  note: {result.error}")

    if args.html:
        path = report.export_html(result)
        print(f"  HTML report written to: {path}")
    return 0


# ── pid ─────────────────────────────────────────────────────────────────────────

def cmd_pid(args: argparse.Namespace) -> int:
    proto = "UDP" if args.udp else "TCP"
    print(f"> Looking up owner of port {args.port}/{proto} …")
    rows = pidtools.find_port_owner(args.port, proto)
    if not rows:
        print(f"  No process is bound to port {args.port}/{proto}.")
        return 0

    seen: set[int] = set()
    for r in rows:
        print(f"  {r['proto']}  {r['local']:<24} {r.get('state',''):<12} PID {r['pid']}")
        seen.add(r["pid"])

    print("-" * 60)
    for pid in sorted(seen):
        info = pidtools.process_info(pid)
        print(f"  PID {pid} | {info['name']} | CPU {info['cpu']} | "
              f"RAM {info['mem']} MB | {info['publisher']}")
        print(f"    kill: {'Stop-Process -Id %d -Force' % pid if pidtools.IS_WINDOWS else 'kill %d' % pid}")

    if args.kill:
        for pid in sorted(seen):
            ok, msg = pidtools.kill_process(pid)
            print(f"  [{'OK' if ok else 'ERR'}] {msg}")
    return 0


# ── listeners ────────────────────────────────────────────────────────────────────

def cmd_listeners(_args: argparse.Namespace) -> int:
    rows = pidtools.list_listeners()
    if not rows:
        print("  No listening sockets found.")
        return 0
    print(f"  {'Proto':<6} {'Port':<8} {'Address':<26} {'PID':<8} Process")
    print("  " + "-" * 70)
    for r in sorted(rows, key=lambda x: x["port"]):
        info = pidtools.process_info(r["pid"])
        print(f"  {r['proto']:<6} {r['port']:<8} {r['address']:<26} {r['pid']:<8} {info['name']}")
    print(f"\n  {len(rows)} listener(s).")
    return 0


# ── gui ──────────────────────────────────────────────────────────────────────────

def cmd_gui(_args: argparse.Namespace) -> int:
    try:
        from app import main as gui_main
    except ImportError as e:
        print(f"[ERROR] GUI requires customtkinter and Pillow: pip install -r requirements.txt\n  ({e})")
        return 1
    gui_main()
    return 0


# ── status ────────────────────────────────────────────────────────────────────────

def cmd_status(_args: argparse.Namespace) -> int:
    status = check_trial()
    print(f"  Edition : Fredo — Community (Free)")
    print(f"  Version : {__version__}")
    if status.started:
        print(f"  Started : {status.started.isoformat()}")
        print(f"  Expires : {status.expires.isoformat()}")
    print(f"  Status  : {status.message}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fredo",
        description="Fredo — Community Edition (Free). Port scanner + PID finder.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Scan a host for open ports + risk analysis")
    s.add_argument("target", help="Hostname or IP to scan (e.g. 127.0.0.1)")
    s.add_argument("--full", action="store_true", help="Use nmap for service/version detection")
    s.add_argument("--ports", help="Comma-separated ports to check (built-in engine)")
    s.add_argument("--html", action="store_true", help="Write an HTML report")
    s.set_defaults(func=cmd_scan)

    pid = sub.add_parser("pid", help="Find the process that owns a local port")
    pid.add_argument("port", type=int, help="Local port number (1-65535)")
    pid.add_argument("--udp", action="store_true", help="Look up a UDP port instead of TCP")
    pid.add_argument("--kill", action="store_true", help="Terminate the owning process")
    pid.set_defaults(func=cmd_pid)

    ls = sub.add_parser("listeners", help="List all listening sockets and their PIDs")
    ls.set_defaults(func=cmd_listeners)

    g = sub.add_parser("gui", help="Launch the desktop app (scan + history + PID finder)")
    g.set_defaults(func=cmd_gui)

    st = sub.add_parser("status", help="Show trial status")
    st.set_defaults(func=cmd_status)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # `status` is always allowed so users can see why they're locked out.
    if args.command != "status":
        enforce_trial()

    print(BANNER)
    if args.command != "status":
        _print_trial_line()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
