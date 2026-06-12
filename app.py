# -*- coding: utf-8 -*-
"""
Fredo — Community Edition
Desktop security scanner.

A free, dark-themed GUI that scans a target for open ports, scores the risk
0–100, remembers every scan in a local history, and includes a PID finder for
tracking down and killing the process behind a port.

    pip install -r requirements.txt
    python app.py

Free for 7 days from first launch (see README).
"""
from __future__ import annotations

import threading

try:
    import customtkinter as ctk
    import tkinter as tk
    from tkinter import messagebox
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "The desktop app needs customtkinter + Pillow. "
        "Run: pip install -r requirements.txt"
    ) from e

from fredo import __version__, scanner, pidtools, history, report
from fredo.trial import check_trial

# ── Theme — brand-guide palette ─────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

BG       = "#111111"   # obsidian base
PANEL    = "#0a1812"   # raised dark-forest panel
PANEL2   = "#0d2018"   # nested surface
FOREST   = "#0B3D2E"   # deep forest
ACCENT   = "#00BFA6"   # quetzal teal — links / active
ACCENT_DK= "#0f5a50"
GOLD     = "#C9A227"   # phoenix gold — window trim / values
EMERALD  = "#046A38"   # brand green — trim ring / structure
TEXT     = "#F5F5F0"
DIM      = "#6B7F76"
BORDER   = "#1C3B30"
RISK_HIGH= "#FF3B3B"
RISK_MED = "#E0A500"
SECURE   = "#1FC77D"

UI   = "Segoe UI"
MONO = "Consolas"

TRIM_GOLD, TRIM_GREEN = 3, 2

PROFILE_QUICK = "Quick · built-in (~50 ports)"
PROFILE_FULL  = "Full · nmap service scan"


class FredoApp:
    def __init__(self, root: ctk.CTk, trial_msg: str):
        self.root = root
        self.root.title("Fredo — Community Edition")
        self.root.geometry("1040x680")
        self.root.minsize(880, 580)

        # Gold outer trim + brand-green inner ring around the window.
        self.root.configure(fg_color=GOLD)
        ring = ctk.CTkFrame(self.root, fg_color=EMERALD, corner_radius=0)
        ring.pack(fill="both", expand=True, padx=TRIM_GOLD, pady=TRIM_GOLD)
        body = ctk.CTkFrame(ring, fg_color=BG, corner_radius=0)
        body.pack(fill="both", expand=True, padx=TRIM_GREEN, pady=TRIM_GREEN)

        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        self._build_sidebar(body, trial_msg)

        self.content = ctk.CTkFrame(body, fg_color=BG, corner_radius=0)
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

        # State shared by the PID view.
        self._pid: int | None = None
        self._pid_view_mode = "idle"

        self.views: dict[str, ctk.CTkFrame] = {}
        self._build_scan_view()
        self._build_history_view()
        self._build_pid_view()
        self.show("scan")
        self._refresh_history()

    # ── Sidebar ─────────────────────────────────────────────────────────────────
    def _build_sidebar(self, parent, trial_msg: str):
        bar = ctk.CTkFrame(parent, fg_color=PANEL, width=190, corner_radius=0)
        bar.grid(row=0, column=0, sticky="nsw")
        bar.grid_propagate(False)

        ctk.CTkLabel(bar, text="FREDO", font=(UI, 20, "bold"),
                     text_color=GOLD).pack(anchor="w", padx=18, pady=(20, 0))
        ctk.CTkLabel(bar, text="Community Edition", font=(UI, 11),
                     text_color=ACCENT).pack(anchor="w", padx=18, pady=(0, 18))

        self._nav_btns: dict[str, ctk.CTkButton] = {}
        for key, label in (("scan", "  Scan"), ("history", "  History"),
                           ("pid", "  PID Finder")):
            b = ctk.CTkButton(
                bar, text=label, anchor="w", height=40, corner_radius=6,
                font=(UI, 13, "bold"), fg_color="transparent", text_color=TEXT,
                hover_color=FOREST, command=lambda k=key: self.show(k))
            b.pack(fill="x", padx=10, pady=3)
            self._nav_btns[key] = b

        # Footer: trial status + authorized-use note.
        foot = ctk.CTkFrame(bar, fg_color="transparent")
        foot.pack(side="bottom", fill="x", padx=14, pady=14)
        ctk.CTkLabel(foot, text=trial_msg, font=(UI, 10), text_color=GOLD,
                     wraplength=160, justify="left").pack(anchor="w")
        ctk.CTkLabel(foot, text=f"v{__version__} · authorized use only",
                     font=(UI, 9), text_color=DIM, wraplength=160,
                     justify="left").pack(anchor="w", pady=(6, 0))

    def show(self, key: str):
        for view in self.views.values():
            view.grid_forget()
        self.views[key].grid(row=0, column=0, sticky="nsew")
        for k, b in self._nav_btns.items():
            b.configure(fg_color=FOREST if k == key else "transparent")

    # ── Scan view ───────────────────────────────────────────────────────────────
    def _build_scan_view(self):
        v = ctk.CTkFrame(self.content, fg_color=BG, corner_radius=0)
        v.grid_columnconfigure(0, weight=1)
        v.grid_rowconfigure(2, weight=1)
        self.views["scan"] = v

        ctk.CTkLabel(v, text="Network Scan", font=(UI, 22, "bold"),
                     text_color=TEXT).grid(row=0, column=0, sticky="w", padx=18, pady=(16, 4))

        # Controls — pack-based with RUN SCAN pinned right so it never clips.
        ctrl = ctk.CTkFrame(v, fg_color=PANEL, corner_radius=8)
        ctrl.grid(row=1, column=0, sticky="ew", padx=18, pady=6)

        self.scan_btn = ctk.CTkButton(ctrl, text="RUN SCAN", width=120, height=34,
                                      font=(UI, 12, "bold"), fg_color=EMERALD,
                                      hover_color=SECURE, text_color="#06241a",
                                      command=self._start_scan)
        self.scan_btn.pack(side="right", padx=14, pady=12)

        ctk.CTkLabel(ctrl, text="TARGET", font=(UI, 10, "bold"),
                     text_color=ACCENT).pack(side="left", padx=(14, 6), pady=12)
        self.target_entry = ctk.CTkEntry(ctrl, width=180, font=(MONO, 12),
                                         fg_color=PANEL2, border_color=ACCENT_DK,
                                         placeholder_text="127.0.0.1 / host / IP")
        self.target_entry.insert(0, "127.0.0.1")
        self.target_entry.pack(side="left", pady=12)
        self.target_entry.bind("<Return>", lambda _: self._start_scan())

        self.profile_var = ctk.StringVar(value=PROFILE_QUICK)
        ctk.CTkOptionMenu(ctrl, values=[PROFILE_QUICK, PROFILE_FULL],
                          variable=self.profile_var, width=210, font=(UI, 11),
                          fg_color=PANEL2, button_color=BORDER,
                          button_hover_color=FOREST).pack(side="left", padx=12, pady=12)

        ctk.CTkLabel(ctrl, text="PORTS", font=(UI, 10, "bold"),
                     text_color=ACCENT).pack(side="left", padx=(8, 6), pady=12)
        self.ports_entry = ctk.CTkEntry(ctrl, width=120, font=(MONO, 11),
                                        fg_color=PANEL2, border_color=ACCENT_DK,
                                        placeholder_text="22,80,443 (opt)")
        self.ports_entry.pack(side="left", pady=12)

        # Body: risk card (left) + output (right)
        bodyf = ctk.CTkFrame(v, fg_color=BG, corner_radius=0)
        bodyf.grid(row=2, column=0, sticky="nsew", padx=18, pady=(6, 16))
        bodyf.grid_rowconfigure(0, weight=1)
        bodyf.grid_columnconfigure(1, weight=1)

        card = ctk.CTkFrame(bodyf, fg_color=PANEL, corner_radius=10, width=240)
        card.grid(row=0, column=0, sticky="ns", padx=(0, 12))
        card.grid_propagate(False)
        ctk.CTkLabel(card, text="RISK SCORE", font=(UI, 11, "bold"),
                     text_color=DIM).pack(pady=(24, 4))
        self.score_lbl = ctk.CTkLabel(card, text="—", font=(UI, 52, "bold"),
                                      text_color=DIM)
        self.score_lbl.pack(pady=(4, 0))
        ctk.CTkLabel(card, text="out of 100", font=(UI, 10), text_color=DIM).pack()
        self.band_lbl = ctk.CTkLabel(card, text="NO SCAN YET", font=(UI, 15, "bold"),
                                     text_color=DIM)
        self.band_lbl.pack(pady=(14, 4))
        self.gauge = ctk.CTkProgressBar(card, width=180, progress_color=DIM,
                                        fg_color=PANEL2)
        self.gauge.set(0)
        self.gauge.pack(pady=6)
        self.detail_lbl = ctk.CTkLabel(card, text="Run a scan to begin.",
                                       font=(UI, 11), text_color=DIM, wraplength=200)
        self.detail_lbl.pack(pady=(14, 10), padx=14)
        self.status_lbl = ctk.CTkLabel(card, text="IDLE", font=(MONO, 11, "bold"),
                                       text_color=SECURE)
        self.status_lbl.pack(side="bottom", pady=14)

        outwrap = ctk.CTkFrame(bodyf, fg_color=PANEL, corner_radius=10)
        outwrap.grid(row=0, column=1, sticky="nsew")
        ctk.CTkLabel(outwrap, text="ANALYSIS", font=(UI, 11, "bold"),
                     text_color=ACCENT).pack(anchor="w", padx=14, pady=(10, 2))
        self.scan_out = ctk.CTkTextbox(outwrap, fg_color=PANEL2, text_color=TEXT,
                                       font=(MONO, 12), wrap="word", corner_radius=6)
        self.scan_out.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.scan_out.insert("end",
            "Enter a target and click RUN SCAN.\n\n"
            "• Quick scan needs nothing installed.\n"
            "• Full scan uses nmap (if on PATH) for service/version detail.\n\n"
            "Every scan is scored 0–100 and saved to History.")
        self.scan_out.configure(state="disabled")

    def _start_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Fredo", "Enter a target to scan.")
            return
        ports = None
        raw = self.ports_entry.get().strip()
        if raw:
            try:
                ports = [int(p) for p in raw.split(",") if p.strip()]
            except ValueError:
                messagebox.showwarning("Fredo", "Ports must be comma-separated numbers.")
                return
        profile = self.profile_var.get()
        self.scan_btn.configure(state="disabled", text="SCANNING…")
        self.status_lbl.configure(text="SCANNING", text_color=GOLD)
        self.gauge.configure(mode="indeterminate"); self.gauge.start()
        self._set_out(f"> Scanning {target} …\n")
        threading.Thread(target=self._do_scan, args=(target, profile, ports),
                         daemon=True).start()

    def _do_scan(self, target, profile, ports):
        if profile == PROFILE_FULL and not ports:
            result = scanner.nmap_scan(target)
        else:
            result = scanner.builtin_scan(target, ports=ports)
        self.root.after(0, self._scan_done, result)

    def _scan_done(self, result):
        self.gauge.stop(); self.gauge.configure(mode="determinate")
        self.scan_btn.configure(state="normal", text="RUN SCAN")
        if result.error and not result.open_ports:
            self.status_lbl.configure(text="ERROR", text_color=RISK_HIGH)
            self._set_out(f"[ERROR] {result.error}\n")
            return
        self._render_result(result)
        try:
            history.save_scan(result)
            self._refresh_history()
        except Exception as e:
            self._append_out(f"\n[history] could not save: {e}\n")
        self.status_lbl.configure(text="DONE", text_color=SECURE)

    def _render_result(self, result):
        band, color = scanner.risk_band(result.threat_score)
        self.score_lbl.configure(text=str(result.threat_score), text_color=color)
        self.band_lbl.configure(text=band, text_color=color)
        self.gauge.configure(progress_color=color)
        self.gauge.set(result.threat_score / 100)
        self.detail_lbl.configure(
            text=f"{result.target} · {len(result.open_ports)} open port(s) · {result.engine}",
            text_color=DIM)
        lines = [f"Target : {result.target}",
                 f"Engine : {result.engine}    Time: {result.timestamp} UTC",
                 "─" * 56, result.analysis]
        if result.services and result.engine == "nmap":
            lines += ["", "Services:"]
            for p in result.open_ports:
                lines.append(f"  {p:<7} {result.services.get(p, '')}")
        self._set_out("\n".join(lines) + "\n")

    def _set_out(self, text):
        self.scan_out.configure(state="normal")
        self.scan_out.delete("1.0", "end")
        self.scan_out.insert("end", text)
        self.scan_out.configure(state="disabled")

    def _append_out(self, text):
        self.scan_out.configure(state="normal")
        self.scan_out.insert("end", text)
        self.scan_out.see("end")
        self.scan_out.configure(state="disabled")

    # ── History view ────────────────────────────────────────────────────────────
    def _build_history_view(self):
        v = ctk.CTkFrame(self.content, fg_color=BG, corner_radius=0)
        v.grid_columnconfigure(1, weight=1)
        v.grid_rowconfigure(1, weight=1)
        self.views["history"] = v

        head = ctk.CTkFrame(v, fg_color=BG, corner_radius=0)
        head.grid(row=0, column=0, columnspan=2, sticky="ew", padx=18, pady=(16, 4))
        ctk.CTkLabel(head, text="Scan History", font=(UI, 22, "bold"),
                     text_color=TEXT).pack(side="left")
        ctk.CTkButton(head, text="Clear all", width=90, height=30, font=(UI, 11),
                      fg_color=PANEL, hover_color="#2a0d14", border_color=RISK_HIGH,
                      border_width=1, text_color=TEXT, command=self._clear_history
                      ).pack(side="right")
        ctk.CTkButton(head, text="Refresh", width=90, height=30, font=(UI, 11),
                      fg_color=PANEL, hover_color=FOREST, border_color=ACCENT_DK,
                      border_width=1, text_color=TEXT, command=self._refresh_history
                      ).pack(side="right", padx=8)
        self.stats_lbl = ctk.CTkLabel(head, text="", font=(UI, 11), text_color=DIM)
        self.stats_lbl.pack(side="right", padx=12)

        self.hist_list = ctk.CTkScrollableFrame(v, fg_color=PANEL, width=360,
                                                corner_radius=10)
        self.hist_list.grid(row=1, column=0, sticky="ns", padx=(18, 8), pady=(4, 16))

        detail = ctk.CTkFrame(v, fg_color=PANEL, corner_radius=10)
        detail.grid(row=1, column=1, sticky="nsew", padx=(8, 18), pady=(4, 16))
        bar = ctk.CTkFrame(detail, fg_color="transparent")
        bar.pack(fill="x", padx=12, pady=(10, 0))
        ctk.CTkLabel(bar, text="DETAIL", font=(UI, 11, "bold"),
                     text_color=ACCENT).pack(side="left")
        self.export_btn = ctk.CTkButton(bar, text="Export HTML", width=110, height=28,
                                        font=(UI, 11), fg_color=FOREST, hover_color=EMERALD,
                                        text_color=TEXT, state="disabled",
                                        command=self._export_current)
        self.export_btn.pack(side="right")
        self.hist_detail = ctk.CTkTextbox(detail, fg_color=PANEL2, text_color=TEXT,
                                          font=(MONO, 12), wrap="word", corner_radius=6)
        self.hist_detail.pack(fill="both", expand=True, padx=10, pady=10)
        self.hist_detail.insert("end", "Select a scan on the left to view its detail.")
        self.hist_detail.configure(state="disabled")
        self._current_scan_id: int | None = None

    def _refresh_history(self):
        for w in self.hist_list.winfo_children():
            w.destroy()
        rows = history.get_recent_scans(200)
        st = history.get_stats()
        last = st.get("last_scan")
        self.stats_lbl.configure(
            text=f"{st['scan_count']} scans · avg {st['avg_score']}/100"
                 + (f" · last {last['target']}" if last else ""))
        if not rows:
            ctk.CTkLabel(self.hist_list, text="No scans yet.", font=(UI, 12),
                         text_color=DIM).pack(pady=20)
            return
        for r in rows:
            band, color = scanner.risk_band(r["threat_score"])
            ts = (r["timestamp"][:16]).replace("T", " ")
            txt = (f"#{r['id']}  {r['target']}\n"
                   f"   {r['threat_score']}/100 {band} · {len(r['open_ports'])}p · {ts}")
            ctk.CTkButton(self.hist_list, text=txt, anchor="w", height=46,
                          font=(MONO, 11), fg_color=PANEL2, hover_color=FOREST,
                          text_color=color, corner_radius=6,
                          command=lambda i=r["id"]: self._show_detail(i)
                          ).pack(fill="x", padx=6, pady=3)

    def _show_detail(self, scan_id: int):
        rec = history.get_scan(scan_id)
        if not rec:
            return
        self._current_scan_id = scan_id
        self.export_btn.configure(state="normal")
        band, _ = scanner.risk_band(rec["threat_score"])
        ports = rec["open_ports"]
        lines = [
            f"Scan #{rec['id']}",
            f"Target    : {rec['target']}",
            f"Engine    : {rec['engine']}",
            f"Time (UTC): {rec['timestamp']}",
            f"Risk      : {rec['threat_score']}/100  {band}",
            f"Open ports: {', '.join(map(str, ports)) or 'none'}",
            "─" * 56,
            rec.get("analysis", ""),
        ]
        if rec.get("raw_output"):
            lines += ["", "── raw output " + "─" * 42, rec["raw_output"]]
        self.hist_detail.configure(state="normal")
        self.hist_detail.delete("1.0", "end")
        self.hist_detail.insert("end", "\n".join(lines))
        self.hist_detail.configure(state="disabled")

    def _export_current(self):
        if self._current_scan_id is None:
            return
        rec = history.get_scan(self._current_scan_id)
        if not rec:
            return
        # Rehydrate a ScanResult so we can reuse the HTML exporter.
        res = scanner.ScanResult(
            target=rec["target"], engine=rec["engine"], timestamp=rec["timestamp"],
            open_ports=rec["open_ports"],
            services={int(k): v for k, v in rec.get("services", {}).items()},
            raw_output=rec.get("raw_output", ""), threat_score=rec["threat_score"],
            analysis=rec.get("analysis", ""))
        path = report.export_html(res)
        messagebox.showinfo("Fredo", f"Report written to:\n{path}")

    def _clear_history(self):
        if messagebox.askyesno("Fredo", "Delete all saved scans? This cannot be undone."):
            history.clear_history()
            self._current_scan_id = None
            self.export_btn.configure(state="disabled")
            self.hist_detail.configure(state="normal")
            self.hist_detail.delete("1.0", "end")
            self.hist_detail.insert("end", "Select a scan on the left to view its detail.")
            self.hist_detail.configure(state="disabled")
            self._refresh_history()

    # ── PID finder view ─────────────────────────────────────────────────────────
    def _build_pid_view(self):
        v = ctk.CTkFrame(self.content, fg_color=BG, corner_radius=0)
        v.grid_columnconfigure(0, weight=1)
        v.grid_rowconfigure(2, weight=1)
        self.views["pid"] = v

        ctk.CTkLabel(v, text="PID Finder", font=(UI, 22, "bold"),
                     text_color=TEXT).grid(row=0, column=0, sticky="w", padx=18, pady=(16, 4))

        ctrl = ctk.CTkFrame(v, fg_color=PANEL, corner_radius=8)
        ctrl.grid(row=1, column=0, sticky="ew", padx=18, pady=6)
        ctk.CTkLabel(ctrl, text="PORT", font=(UI, 10, "bold"),
                     text_color=ACCENT).pack(side="left", padx=(14, 6), pady=12)
        self.pid_port = ctk.CTkEntry(ctrl, width=90, font=(MONO, 12), fg_color=PANEL2,
                                     border_color=ACCENT_DK, placeholder_text="8080")
        self.pid_port.pack(side="left", pady=12)
        self.pid_port.bind("<Return>", lambda _: self._pid_find())
        self.pid_proto = ctk.StringVar(value="TCP")
        for pr in ("TCP", "UDP"):
            ctk.CTkRadioButton(ctrl, text=pr, variable=self.pid_proto, value=pr,
                               font=(UI, 11), text_color=TEXT, fg_color=EMERALD,
                               hover_color=SECURE, border_color=EMERALD
                               ).pack(side="left", padx=8, pady=12)
        ctk.CTkButton(ctrl, text="FIND", width=80, height=32, font=(UI, 12, "bold"),
                      fg_color=EMERALD, hover_color=SECURE, text_color="#06241a",
                      command=self._pid_find).pack(side="left", padx=(12, 6), pady=12)
        ctk.CTkButton(ctrl, text="ALL LISTENERS", width=130, height=32, font=(UI, 11, "bold"),
                      fg_color=FOREST, hover_color=EMERALD, text_color=TEXT,
                      command=self._pid_listeners).pack(side="left", padx=6, pady=12)
        self.pid_kill_btn = ctk.CTkButton(ctrl, text="TERMINATE", width=110, height=32,
                                          font=(UI, 12, "bold"), fg_color="#2a0d14",
                                          hover_color="#3a121c", border_color=RISK_HIGH,
                                          border_width=2, text_color=TEXT, state="disabled",
                                          command=self._pid_kill)
        self.pid_kill_btn.pack(side="right", padx=14, pady=12)

        outwrap = ctk.CTkFrame(v, fg_color=PANEL, corner_radius=10)
        outwrap.grid(row=2, column=0, sticky="nsew", padx=18, pady=(6, 6))
        self.pid_out = ctk.CTkTextbox(outwrap, fg_color=PANEL2, text_color=ACCENT,
                                      font=(MONO, 12), wrap="none", corner_radius=6)
        self.pid_out.pack(fill="both", expand=True, padx=10, pady=10)
        # Custom name (NOT "sel" — that clashes with Tk's built-in selection tag,
        # which the widget rewrites on every click and would wipe our highlight).
        self.pid_out._textbox.tag_configure("rowsel", background=ACCENT_DK,
                                            foreground="#ffffff")
        self.pid_out._textbox.bind("<Button-1>", self._pid_click, add="+")
        self._pid_banner()

        self.pid_cmd = ctk.CTkLabel(v, text="KILL CMD:  —", font=(MONO, 11),
                                    text_color=RISK_MED, anchor="w")
        self.pid_cmd.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 14))

    def _pid_banner(self):
        self._pid_set("Enter a port and click FIND, or list all listeners.\n"
                      "Click a result row to select its PID, then TERMINATE.\n")

    def _pid_set(self, text):
        self.pid_out.configure(state="normal")
        self.pid_out.delete("1.0", "end")
        self.pid_out.insert("end", text)
        self.pid_out.configure(state="disabled")

    def _pid_append(self, text):
        self.pid_out.configure(state="normal")
        self.pid_out.insert("end", text)
        self.pid_out.see("end")
        self.pid_out.configure(state="disabled")

    def _pid_find(self):
        raw = self.pid_port.get().strip()
        if not raw.isdigit() or not (1 <= int(raw) <= 65535):
            self._pid_set("[ERROR] Enter a valid port (1–65535).\n"); return
        port, proto = int(raw), self.pid_proto.get()
        self._pid_view_mode = "port"
        self._pid_set(f"> Looking up owner of port {port}/{proto} …\n")
        threading.Thread(target=self._pid_do_find, args=(port, proto), daemon=True).start()

    def _pid_do_find(self, port, proto):
        rows = pidtools.find_port_owner(port, proto)
        self.root.after(0, self._pid_show_find, port, proto, rows)

    def _pid_show_find(self, port, proto, rows):
        if not rows:
            self._pid_append(f"  No {proto} process found on port {port}.\n"); return
        self._pid_append(f"\n  {'Local':<24} {'State':<12} PID\n  " + "─" * 44 + "\n")
        for r in rows:
            self._pid_append(f"  {r['local']:<24} {r.get('state',''):<12} {r['pid']}\n")
        self._pid_append("  ↑ click a row to select its PID\n")
        self._pid_select(rows[0]["pid"])

    def _pid_listeners(self):
        self._pid_view_mode = "listeners"
        self._pid_set("> Listing all TCP listeners …\n")
        threading.Thread(target=self._pid_do_listeners, daemon=True).start()

    def _pid_do_listeners(self):
        rows = pidtools.list_listeners()
        self.root.after(0, self._pid_show_listeners, rows)

    def _pid_show_listeners(self, rows):
        if not rows:
            self._pid_append("  No listeners found.\n"); return
        self._pid_append(f"\n  {'Proto':<6} {'Port':<8} {'Address':<26} {'PID':<8} Process\n")
        self._pid_append("  ↑ click a row to select its PID\n  " + "─" * 60 + "\n")
        for r in sorted(rows, key=lambda x: x["port"]):
            info = pidtools.process_info(r["pid"])
            self._pid_append(f"  {r['proto']:<6} {r['port']:<8} {r['address']:<26} "
                             f"{r['pid']:<8} {info['name']}\n")
        self._pid_append(f"\n  {len(rows)} listener(s).\n")

    def _pid_click(self, event):
        tw = self.pid_out._textbox
        ln = int(tw.index(f"@{event.x},{event.y}").split(".")[0])
        fields = tw.get(f"{ln}.0", f"{ln}.end").split()

        def num(s):
            try:
                val = int(s); return val if 1 <= val <= 4_194_304 else None
            except ValueError:
                return None
        pid = None
        if self._pid_view_mode == "listeners" and len(fields) > 3:
            pid = num(fields[3])
        elif self._pid_view_mode == "port" and fields:
            pid = num(fields[-1])
        if pid is None:
            return
        tw.configure(state="normal")
        tw.tag_remove("rowsel", "1.0", "end")
        tw.tag_add("rowsel", f"{ln}.0", f"{ln}.end+1c")
        tw.tag_raise("rowsel")  # draw above the default selection tag
        tw.configure(state="disabled")
        self._pid_select(pid)

    def _pid_select(self, pid):
        self._pid = pid
        self.pid_cmd.configure(text="KILL CMD:  " + (
            f"Stop-Process -Id {pid} -Force" if pidtools.IS_WINDOWS else f"kill {pid}"))
        self.pid_kill_btn.configure(state="normal")

    def _pid_kill(self):
        if self._pid is None:
            return
        pid = self._pid
        info = pidtools.process_info(pid)
        if not messagebox.askyesno("Fredo — Confirm Termination",
                                   f"Terminate PID {pid} ({info['name']})?\n\n"
                                   "This cannot be undone.", icon="warning"):
            self._pid_append("\n  [!] Termination cancelled.\n"); return
        ok, msg = pidtools.kill_process(pid)
        self._pid_append(f"\n  [{'OK' if ok else 'ERROR'}] {msg}\n")
        if ok:
            self._pid = None
            self.pid_kill_btn.configure(state="disabled")
            self.pid_cmd.configure(text="KILL CMD:  —")


def main():
    history.init_db()
    status = check_trial()

    root = ctk.CTk()
    if not status.ok:
        root.withdraw()
        messagebox.showerror(
            "Fredo — Trial expired",
            "Your 7-day Fredo Community Edition trial has expired.\n\n"
            "Thanks for trying it! Upgrade to the full edition for unlimited use.")
        root.destroy()
        return

    FredoApp(root, status.message)
    root.mainloop()


if __name__ == "__main__":
    main()
