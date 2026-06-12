# -*- coding: utf-8 -*-
"""
Fredo — Community Edition (Free)

A free, 7-day trial build of the Fredo security toolkit, containing two of the
flagship features:

  • Port Scanner  — find open ports and get a risk-scored analysis.
  • PID Finder    — find and terminate the process that owns a local port.

The full Fredo platform adds continuous endpoint monitoring, CIS benchmark
scoring, security drift detection, fleet dashboards, and AI analysis.
"""

__version__ = "1.0.0"
__edition__ = "Community"

from . import trial, scanner, pidtools, report, history  # noqa: F401
