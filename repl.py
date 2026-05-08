#!/usr/bin/env python3
"""
DeltaV Event Log Analyzer - Portable REPL
Standalone Windows-compatible shell for browsing event log exports.
No external dependencies beyond Python 3.10+ stdlib.

Usage:
    python repl.py                              # interactive REPL
    python repl.py /load path/to/log.txt        # auto-load
    python repl.py /load path/ /summary         # load and run command
"""

import sys
import json
import csv
import os
import re
import time
import textwrap
from datetime import datetime
from pathlib import Path


# === ANSI helpers using chr(27) to avoid escape-sequence-in-source issues ===
ESC = chr(27)
_RED = ESC + "[31m"
_GREEN = ESC + "[32m"
_YELLOW = ESC + "[33m"
_CYAN = ESC + "[36m"
_BOLD = ESC + "[1m"
_DIM = ESC + "[2m"
_RESET = ESC + "[0m"


def cprint(text: str, color: str = ""):
    """Print with optional color prefix and auto-reset."""
    if color:
        print(f"{color}{text}{_RESET}")
    else:
        print(text)


def _u_box(w):
    """Unicode box-drawing top line. Falls back to === on narrow terminals."""
    try:
        cols = os.get_terminal_size().columns
    except (ValueError, OSError):
        cols = 80
    w = min(w, cols - 2)
    try:
        return "\u2500" * w
    except UnicodeEncodeError:
        return "=" * w


def section(title: str):
    """Print a section header with colored box."""
    try:
        cols = os.get_terminal_size().columns
    except (ValueError, OSError):
        cols = 80
    w = min(len(title) + 12, cols)
    print()
    cprint(f"\n{_CYAN}{_BOLD}{_u_box(w)}{_RESET}", "")
    cprint(f"{_CYAN}{_BOLD}{title}{_RESET}", "")
    cprint(f"{_CYAN}{_u_box(w)}{_RESET}", "")


def sub(label: str, val, limit=10):
    """Print a subsection with optional list truncation."""
    prefix = "  "
    if isinstance(val, list):
        for item in val[:limit]:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                cprint(f"{prefix}{_GREEN}{item[1]:>6}{_RESET}  {item[0]}", "")
            elif isinstance(item, dict):
                for k, v in item.items():
                    print(f"{prefix}{k}: {v}")
            else:
                print(f"{prefix}{item}")
        if len(val) > limit:
            cprint(f"{prefix}{_YELLOW}... and {len(val) - 10} more{_RESET}", "")
    elif isinstance(val, dict):
        for k, v in list(val.items())[:limit]:
            print(f"{prefix}{_DIM}{k}:{_RESET} {v}")
        if len(val) > limit:
            cprint(f"{prefix}{_YELLOW}... and {len(val) - limit} more{_RESET}", "")
    else:
        print(f"{prefix}{val}")


# ============================================================
# Event Log Parser
# ============================================================

class EventLog:
    """Parsed DeltaV event log data with analysis methods."""

    def __init__(self, path: str = None):
        self.events = []
        self.path = path
        self._summary_cache = {}
        if path:
            self.load(path)

    def load(self, path: str):
        """Parse a DeltaV event log export file (tab-delimited TSV)."""
        self.path = Path(path).resolve()
        self.events = []
        self._summary_cache = {}
        raw = Path(path).read_text(encoding="utf-8", errors="replace")
        lines = raw.splitlines()

        headers = None
        header_skip = 0  # how many leading columns to trim (line number prefix)

        for line in lines:
            if not line.strip():
                continue
            # Skip non-data lines (metadata headers)
            stripped = line.strip()
            if (stripped.startswith("DeltaV") or stripped.startswith("File") or
                stripped.startswith("User") or stripped.startswith("Print") or
                stripped.startswith("Event Log") or stripped.startswith("=") or
                stripped.startswith("-")):
                continue

            # Split by tab
            parts = line.split("\t")

            # Detect header row: first column is empty or contains "Date"
            if not headers:
                for p in parts:
                    p_stripped = p.strip().rstrip("*")
                    if p_stripped in ("Date/Time", "Date/Time*", "DateTime", "Date Time"):
                        headers = [h.strip().rstrip("*") for h in parts]
                        # If first column is empty or a label like "No.", it's a line number
                        first = parts[0].strip().lower()
                        if not first or first in ("no.", "no", "#", "row"):
                            header_skip = 1
                            # Drop the first header too (it's just a line-number label)
                            headers = headers[1:]
                        break
                continue

            # Data row — skip the line-number column if present
            data_parts = parts[header_skip:] if header_skip else parts
            if len(data_parts) < len(headers):
                continue

            event = {}
            for i, h in enumerate(headers):
                if i < len(data_parts):
                    event[h] = data_parts[i].strip()
                else:
                    event[h] = ""

            # Parse datetime with optional milliseconds and AM/PM
            dt_str = event.get("Date/Time", event.get("DateTime", event.get("Date Time", "")))
            if dt_str:
                # Try formats in order of specificity
                for fmt in ("%m/%d/%Y %I:%M:%S.%f %p",
                            "%m/%d/%Y %I:%M:%S %p",
                            "%m/%d/%Y %H:%M:%S.%f",
                            "%m/%d/%Y %H:%M:%S",
                            "%m/%d/%Y %H:%M",
                            "%m/%d/%y %I:%M:%S %p"):
                    try:
                        event["_dt"] = datetime.strptime(dt_str.strip(), fmt)
                        break
                    except ValueError:
                        continue
                else:
                    event["_dt"] = None
            else:
                event["_dt"] = None

            self.events.append(event)

        # Sort chronologically (oldest first) so all derived views default oldest-first
        self.events.sort(key=lambda x: x["_dt"] if x.get("_dt") else __import__("datetime").datetime.min)

    @property
    def total(self) -> int:
        return len(self.events)

    def basic_summary(self) -> dict:
        """Quick overview stats."""
        nodes = {}
        levels = {}
        modules = {}
        descs = {}

        for ev in self.events:
            n = ev.get("Node Name", ev.get("Node", "?"))
            nodes[n] = nodes.get(n, 0) + 1

            lv = ev.get("Level", ev.get("Alarm Level", ""))
            if lv:
                levels[lv] = levels.get(lv, 0) + 1

            m = ev.get("Module Name", ev.get("Module", ""))
            if m:
                modules[m] = modules.get(m, 0) + 1

            d = ev.get("Description", ev.get("Alarm Description", ev.get("Desc2", ev.get("Desc1", ""))))
            if d:
                descs[d] = descs.get(d, 0) + 1

        return {
            "total_events": len(self.events),
            "by_node": sorted(nodes.items(), key=lambda x: -x[1]),
            "by_level": sorted(levels.items(), key=lambda x: -x[1]),
            "by_module": sorted(modules.items(), key=lambda x: -x[1]),
            "by_description": sorted(descs.items(), key=lambda x: -x[1]),
        }

    def alarm_summary(self) -> dict:
        """Summary focused on alarm conditions."""
        alarms = [ev for ev in self.events
                  if "ALARM" in str(ev.get("Event Type", "")).upper()
                  or ev.get("Level", "").strip()
                  or "ALARM" in str(ev.get("Description", "")).upper()]

        # Fallback: if nothing flagged as alarm, treat all events with levels as alarms
        if not alarms:
            alarms = [ev for ev in self.events if ev.get("Level", "").strip()]

        nodes = {}
        levels = {}
        descs = {}

        for ev in alarms:
            n = ev.get("Node Name", ev.get("Node", "?"))
            nodes[n] = nodes.get(n, 0) + 1

            lv = ev.get("Level", ev.get("Alarm Level", ""))
            if lv:
                levels[lv] = levels.get(lv, 0) + 1

            d = ev.get("Description", ev.get("Alarm Description", ev.get("Desc2", ev.get("Desc1", ""))))
            if d:
                descs[d] = descs.get(d, 0) + 1

        return {
            "total": len(alarms),
            "by_level": sorted(levels.items(), key=lambda x: -x[1]),
            "by_node": sorted(nodes.items(), key=lambda x: -x[1]),
            "by_description": sorted(descs.items(), key=lambda x: -x[1]),
        }

    @staticmethod
    def _desc(ev: dict) -> str:
        """Get description field from event dict, trying all possible column names."""
        return str(ev.get("Description", ev.get("Desc2", ev.get("Desc1", ev.get("Alarm Description", "")))))

    def filter_events(self, **kwargs) -> list:
        """Filter events by field values. Keys are column names, values are strings or callables."""
        results = self.events
        for key, val in kwargs.items():
            if callable(val):
                results = [ev for ev in results if val(ev.get(key, ""))]
            else:
                results = [ev for ev in results if str(val).lower() in str(ev.get(key, "")).lower()]
        return results

    def acn_events(self) -> dict:
        """Find ACN (Alarm Condition Notification) events."""
        acn = [ev for ev in self.events
               if "ACN" in str(ev.get("Event Type", "")).upper()
               or "ALARM" in str(ev.get("Event Type", "")).upper()]
        return {
            "total": len(acn),
            "sample": acn[:50],
        }

    def bad_io(self) -> dict:
        """Find BAD I/O or field comm failures."""
        bad = [ev for ev in self.events
               if "BAD" in str(ev.get("Value", "")).upper()
               or "COMM" in self._desc(ev).upper()
               or "FAIL" in self._desc(ev).upper()
               or "LOST" in self._desc(ev).upper()]
        still_bad = [ev for ev in bad
                     if "BAD" in str(ev.get("Event Type", "")).upper()[-4:]
                     or "BAD" in self._desc(ev).upper()]
        return {
            "total": len(bad),
            "still_bad": len(still_bad),
            "sample": bad[:50],
        }

    def standby_events(self) -> dict:
        """Find standby/secondary events."""
        standby = [ev for ev in self.events
                   if "STANDBY" in self._desc(ev).upper()
                   or "FAILOVER" in self._desc(ev).upper()
                   or "SECONDARY" in self._desc(ev).upper()]
        return {
            "total": len(standby),
            "sample": standby[:50],
        }

    def interlock_events(self) -> dict:
        """Find interlock/trip events."""
        il = [ev for ev in self.events
              if "INTERLOCK" in self._desc(ev).upper()
              or "TRIP" in self._desc(ev).upper()
              or "PERMIT" in self._desc(ev).upper()]
        return {
            "total": len(il),
            "sample": il[:50],
        }

    def event_limited(self) -> dict:
        """Find EVENT_LIMITED / buffer overflow conditions."""
        lim = [ev for ev in self.events
               if "LIMIT" in self._desc(ev).upper()
               or "OVERFLOW" in self._desc(ev).upper()]
        nodes = {}
        for ev in lim:
            n = ev.get("Node Name", ev.get("Node", "?"))
            nodes[n] = nodes.get(n, 0) + 1
        return {
            "total": len(lim),
            "by_node": sorted(nodes.items(), key=lambda x: -x[1]),
            "sample": lim[:30],
        }

    def hardware_alarms(self) -> dict:
        """Find hardware alarm events."""
        hw = [ev for ev in self.events
              if "HW" in str(ev.get("Event Type", "")).upper()
              or "HARDWARE" in self._desc(ev).upper()
              or "CHASSIS" in self._desc(ev).upper()]
        nodes = {}
        for ev in hw:
            n = ev.get("Node Name", ev.get("Node", "?"))
            nodes[n] = nodes.get(n, 0) + 1
        return {
            "total": len(hw),
            "by_node": sorted(nodes.items(), key=lambda x: -x[1]),
            "sample": hw[:30],
        }

    def process_events(self) -> dict:
        """Find process / module events."""
        proc = [ev for ev in self.events
                if "PROCESS" in str(ev.get("Event Type", "")).upper()
                or "MODULE" in str(ev.get("Event Type", "")).upper()]
        combos = {}
        for ev in proc:
            key = f"{ev.get('Node Name', ev.get('Node', '?'))} / {ev.get('Module Name', ev.get('Module', '?'))} / {EventLog._desc(ev)}"
            combos[key] = combos.get(key, 0) + 1
        return {
            "total": len(proc),
            "by_combo": sorted(combos.items(), key=lambda x: -x[1])[:30],
        }

    def export_json(self, path: str):
        """Export events as JSON."""
        export = []
        for ev in self.events:
            clean = {k: v for k, v in ev.items() if not k.startswith("_")}
            clean["_parsed_at"] = datetime.now().isoformat()
            export.append(clean)
        Path(path).write_text(json.dumps(export, indent=2), encoding="utf-8")

    def timeline(self) -> list:
        """Return events sorted chronologically."""
        valid = [ev for ev in self.events if ev.get("_dt")]
        valid.sort(key=lambda x: x["_dt"])
        return valid

    def search(self, text: str) -> list:
        """Search all event text for a string (case-insensitive)."""
        text_lower = text.lower()
        results = []
        for ev in self.events:
            for v in ev.values():
                if isinstance(v, str) and text_lower in v.lower():
                    results.append(ev)
                    break
        return results


# ============================================================
# Priority ordering & display helpers
# ============================================================

# Numeric prefix = priority weight (higher = more urgent)
_PRIORITY_ORDER = {
    "15-CRITICAL": 0,
    "14-SIS_CRITICAL": 1,
    "13-DCS_CRITICAL": 2,
    "12-PROMPT": 3,
    "11-WARNING": 4,
    "10-SIS_WARNING": 5,
    "09-DCS_WARNING": 6,
    "08-ADVISORY": 7,
    "07-SIS_ADVISORY": 8,
    "06-DCS_ADVISORY": 9,
    "04-ALERT": 10,
    "4-INFO": 11,
    "1-DISABLED": 12,
    "PROCESS": 13,
}


def _priority_key(item):
    """Sort by DeltaV priority (highest first). Unknown levels go last."""
    name, _ = item
    return _PRIORITY_ORDER.get(name, 99)


def show_priority(data: dict):
    """Show alarm/event priority breakdown, highest priority first."""
    levels = data.get("by_level", [])
    if not levels:
        return
    critical = sum(c for n, c in levels if "CRITICAL" in n.upper())
    warning = sum(c for n, c in levels if "WARNING" in n.upper())

    section("PRIORITY BREAKDOWN")
    if critical:
        cprint(f"{_RED}{_BOLD}CRITICAL: {critical} events{_RESET}", "")
    if warning:
        cprint(f"{_YELLOW}{_BOLD}WARNING:  {warning} events{_RESET}", "")

    # Show detailed breakdown sorted by severity
    detailed = sorted([(n, c) for n, c in levels if n.strip()], key=_priority_key)
    for name, count in detailed:
        if "CRITICAL" in name.upper():
            cprint(f"    {_RED}{name:25s} {count:>5}{_RESET}", "")
        elif "WARNING" in name.upper():
            cprint(f"    {_YELLOW}{name:25s} {count:>5}{_RESET}", "")
        elif "INFO" in name.upper():
            cprint(f"    {_CYAN}{name:25s} {count:>5}{_RESET}", "")
        else:
            cprint(f"    {_DIM}{name:25s} {count:>5}{_RESET}", "")
    blank_count = sum(c for n, c in levels if not n.strip())
    if blank_count:
        print(f"    {_DIM}(blank): {blank_count}{_RESET}")


def show_node_events(events: list[dict], node_name: str):
    """Show events for a specific node, focused on actionable items."""
    matching = [ev for ev in events
                if node_name.lower() in str(ev.get("Node Name", ev.get("Node", ""))).lower()]

    if not matching:
        cprint(f"  No events found for node: {node_name}", _YELLOW)
        return

    section(f"EVENTS FOR: {node_name} ({len(matching)} total)")

    # Break down by level
    levels = {}
    for ev in matching:
        lv = ev.get("Level", ev.get("Alarm Level", ""))
        if lv:
            levels[lv] = levels.get(lv, 0) + 1

    if levels:
        cprint("  By Priority:", _DIM)
        for lv, cnt in sorted(levels.items(), key=lambda x: -x[1]):
            if "CRITICAL" in lv.upper():
                color = _RED
            elif "WARNING" in lv.upper():
                color = _YELLOW
            else:
                color = _DIM
            cprint(f"    {color}{lv:25s} {cnt:>5}{_RESET}", "")

    # Show critical events first
    criticals = [ev for ev in matching if "CRITICAL" in str(ev.get("Level", "")).upper()]
    if criticals:
        section("CRITICAL EVENTS")
        for ev in criticals[:20]:
            dt = ev.get("Date/Time", ev.get("DateTime", ev.get("Date Time", "")))
            desc = EventLog._desc(ev)[:60]
            mod = ev.get("Module Name", ev.get("Module", ""))
            val = ev.get("Value", "")
            cprint(f"  {_RED}{dt}{_RESET}  {mod}  {desc}  {val}", "")

    # Show all events chronologically (oldest first)
    timeline = sorted(
        [ev for ev in matching if ev.get("_dt")],
        key=lambda x: x["_dt"]
    )
    if timeline:
        total_events = len(timeline)
        max_show = min(total_events, 200)
        section(f"ALL EVENTS (first {max_show} of {total_events})")
        for ev in timeline[:max_show]:
            dt = ev.get("Date/Time", ev.get("DateTime", ev.get("Date Time", "")))
            desc = EventLog._desc(ev)[:60]
            lv = ev.get("Level", ev.get("Alarm Level", ""))
            mod = ev.get("Module Name", ev.get("Module", ""))
            if mod:
                print(f"  {dt:30s}  {lv:20s}  {mod:20s}  {desc}")
            else:
                print(f"  {dt:30s}  {lv:20s}  {desc}")


# ============================================================
# REPL
# ============================================================

class DeltaVREPL:
    """Interactive shell for browsing DeltaV event logs."""

    def __init__(self, path: str = None):
        self.log = EventLog()
        self.history = []
        self.loaded_path = None
        if path:
            self._load(path)

    def _error(self, msg: str):
        cprint(f"{_RED}ERROR: {msg}{_RESET}", "")

    def _load(self, path: str):
        expanded = os.path.expanduser(path)
        if not os.path.exists(expanded):
            self._error(f"File not found: {expanded}")
            return
        try:
            self.log.load(expanded)
            self.loaded_path = expanded
            self._show_overview()
        except Exception as e:
            self._error(f"Failed to load: {e}")

    def _show_overview(self):
        data = self.log.basic_summary()
        section("OVERVIEW")
        cprint(f"  Total Events: {_BOLD}{data['total_events']:,}{_RESET}", "")
        print(f"  File: {self.loaded_path}")
        if data["total_events"] > 0:
            start = self.log.events[0].get("Date/Time", self.log.events[0].get("DateTime", "?"))
            end = self.log.events[-1].get("Date/Time", self.log.events[-1].get("DateTime", "?"))
            print(f"  Range: {start}  ->  {end}")

            # Full level breakdown
            levels = data.get("by_level", [])
            show_priority(data)

    def _show_acn(self):
        data = self.log.acn_events()
        section("ALARM CONDITION NOTIFICATIONS")
        cprint(f"  Total: {_BOLD}{data['total']:,}{_RESET}", "")
        for r in data["sample"][:20]:
            print(f"  {r.get('Date/Time', r.get('DateTime', '')):30s}  {r.get('Node Name', r.get('Node', '?')):25s}  "
                  f"{EventLog._desc(r)[:60]}")

    def _show_bad(self):
        data = self.log.bad_io()
        section("BAD I/O EVENTS")
        cprint(f"  Total: {_BOLD}{data['total']:,}{_RESET}", "")
        for r in data["sample"][:20]:
            flag = f"{_RED}STILL BAD{_RESET}" if "BAD" in r.get("Event Type", "")[-4:].upper() else f"{_GREEN}CLEARED{_RESET}"
            print(f"  {flag}  {r.get('Date/Time', r.get('DateTime', '')):30s}  {r.get('Node Name', r.get('Node', '?')):25s}  "
                  f"{EventLog._desc(r)[:60]}")

    def _show_standby(self):
        data = self.log.standby_events()
        section("STANDBY / FAILOVER EVENTS")
        cprint(f"  Total: {_BOLD}{data['total']:,}{_RESET}", "")
        for r in data["sample"][:20]:
            print(f"  {r.get('Date/Time', r.get('DateTime', '')):30s}  {r.get('Node Name', r.get('Node', '?')):25s}  "
                  f"{EventLog._desc(r)[:60]}")

    def _show_interlocks(self):
        data = self.log.interlock_events()
        section("INTERLOCK / TRIP EVENTS")
        cprint(f"  Total: {_BOLD}{data['total']:,}{_RESET}", "")
        for r in data["sample"][:20]:
            print(f"  {r.get('Date/Time', r.get('DateTime', '')):30s}  {r.get('Node Name', r.get('Node', '?')):25s}  "
                  f"{EventLog._desc(r)[:60]}")

    def _show_limited(self):
        data = self.log.event_limited()
        section("EVENT_LIMITED (BUFFER OVERFLOW)")
        cprint(f"  Total: {_RED}{data['total']}{_RESET}", "")
        sub("By Node:", data["by_node"])
        for r in data["sample"]:
            print(f"  {r.get('Date/Time', r.get('DateTime', '')):30s}  {r.get('Node', '?'):25s}  {r.get('Module', '?'):25s}")

    def _show_hardware(self):
        data = self.log.hardware_alarms()
        section("HARDWARE ALARMS")
        cprint(f"  Total: {data['total']}", "")
        sub("By Node:", data["by_node"])

    def _show_process(self):
        data = self.log.process_events()
        section("PROCESS EVENTS")
        cprint(f"  Total: {data['total']}", "")
        sub("By Node/Module/Desc:", data["by_combo"])

    def _show_alarms(self):
        data = self.log.alarm_summary()
        section("ALARM ANALYSIS")
        cprint(f"  Total alarms: {_BOLD}{data['total']:,}{_RESET}", "")

        if data.get("by_level"):
            section("By Priority")
            flagged = [l for l in data["by_level"] if "CRITICAL" in l[0].upper() or "WARNING" in l[0].upper()]
            for name, count in flagged:
                clr = _RED if "CRITICAL" in name.upper() else _YELLOW
                cprint(f"  {clr}{name:25s} {count:>5}{_RESET}", "")
            section("By Description")
        else:
            section("By Description")
        sub("", data["by_description"][:15])
        section("By Node")
        sub("", data["by_node"][:10])

    def _show_top(self, n: int = 20):
        data = self.log.basic_summary()
        section(f"TOP {n} DESCRIPTIONS")
        sub("", data["by_description"][:n])

    def _show_node(self, name: str):
        show_node_events(self.log.events, name)

    def _show_summary(self):
        data = self.log.basic_summary()
        section("FULL SUMMARY")
        cprint(f"  Total Events: {_BOLD}{data['total_events']:,}{_RESET}", "")
        print(f"  File: {self.loaded_path}")

        if data.get("by_level"):
            show_priority(data)

        section("Top Nodes")
        sub("", data["by_node"][:10])

        section("Top Modules")
        sub("", data["by_module"][:10])

        section("Top Descriptions")
        sub("", data["by_description"][:20])

    def _export(self, path: str):
        try:
            self.log.export_json(path)
            expanded = os.path.abspath(os.path.expanduser(path))
            cprint(f"Exported to: {expanded}", _GREEN)
        except Exception as e:
            self._error(f"Export failed: {e}")

    def _search(self, text: str):
        results = self.log.search(text)
        cprint(f"  {len(results)} events matching search: {text}", _YELLOW)
        for ev in results[:30]:
            dt = ev.get("Date/Time", ev.get("DateTime", ev.get("Date Time", "")))
            node = ev.get("Node Name", ev.get("Node", ""))
            desc = ev.get("Desc2", ev.get("Description", ev.get("Alarm Description", "")))[:80]
            print(f"  {dt:30s}  {node:25s}  {desc}")
        if len(results) > 30:
            cprint(f"  ... and {len(results) - 30} more", _YELLOW)

    def _filter_by(self, col: str, val: str):
        """Filter events where a column matches a value."""
        results = self.log.filter_events(**{col: val})
        cprint(f"  {len(results)} events matching {col}={val}", _YELLOW)
        for ev in results[:30]:
            dt = ev.get("Date/Time", ev.get("DateTime", ev.get("Date Time", "")))
            node = ev.get("Node Name", ev.get("Node", ""))
            desc = ev.get("Desc2", ev.get("Description", ev.get("Alarm Description", "")))[:80]
            print(f"  {dt:30s}  {node:25s}  {desc}")
        if len(results) > 30:
            cprint(f"  ... and {len(results) - 30} more", _YELLOW)

    def _describe_schema(self):
        if not self.log.events:
            self._error("No data loaded")
            return
        keys = set()
        for ev in self.log.events:
            keys.update(ev.keys())
        section("AVAILABLE COLUMNS")
        for k in sorted(keys):
            if k.startswith("_"):
                continue
            values = set()
            for ev in self.log.events[:100]:
                v = ev.get(k, "")
                if v and v.strip():
                    values.add(v.strip())
            cprint(f"  {_CYAN}{k}{_RESET}", "")
            if values:
                print(f"    e.g. {', '.join(list(values)[:5])}")
        print(f"\n  Total columns: {len([k for k in keys if not k.startswith('_')])}")

    def _sample_raw(self, n: int = 5):
        if not self.log.events:
            self._error("No data loaded")
            return
        section(f"RAW SAMPLE ({n} events)")
        for ev in self.log.events[:n]:
            clean = {k: v for k, v in ev.items() if not k.startswith("_")}
            print(json.dumps(clean, indent=2))
            print()

    def run_command(self, cmd: str):
        """Parse and execute a command string."""
        self.history.append(cmd)
        parts = cmd.strip().split(None, 1)
        if not parts:
            return

        verb = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if verb in ("/load", "/l"):
            self._load(arg)
        elif verb in ("/summary", "/s"):
            self._show_summary()
        elif verb in ("/alarms", "/a"):
            self._show_alarms()
        elif verb in ("/acn",):
            self._show_acn()
        elif verb in ("/bad", "/b"):
            self._show_bad()
        elif verb in ("/standby", "/st"):
            self._show_standby()
        elif verb in ("/il", "/interlock"):
            self._show_interlocks()
        elif verb in ("/limited", "/event-limited"):
            self._show_limited()
        elif verb in ("/hardware", "/hw"):
            self._show_hardware()
        elif verb in ("/process", "/proc"):
            self._show_process()
        elif verb in ("/top", "/t"):
            try:
                n = int(arg) if arg else 20
            except ValueError:
                n = 20
            self._show_top(n)
        elif verb in ("/node", "/n"):
            if arg:
                self._show_node(arg)
            else:
                self._error("Usage: /node <name>")
        elif verb in ("/export", "/e"):
            if arg:
                self._export(arg)
            else:
                self._error("Usage: /export <path>")
        elif verb in ("/search", "/find"):
            if arg:
                self._search(arg)
            else:
                self._error("Usage: /search <text>")
        elif verb in ("/filter", "/f"):
            parts2 = arg.split(None, 1)
            if len(parts2) >= 2:
                self._filter_by(parts2[0], parts2[1])
            else:
                self._error("Usage: /filter <column> <value>")
        elif verb in ("/schema", "/columns"):
            self._describe_schema()
        elif verb in ("/sample", "/raw"):
            n = 5
            if arg:
                try:
                    n = int(arg.split()[0])
                except ValueError:
                    pass
            self._sample_raw(n)
        elif verb in ("/help", "/h", "/?"):
            self._show_help()
        else:
            self._error(f"Unknown command: {verb}")

    def _show_help(self):
        section("DELTAV REPL COMMANDS")
        cmds = [
            ("/load <path>", "Load an event log file"),
            ("/summary", "Show overview summary"),
            ("/alarms", "Show alarm analysis"),
            ("/acn", "Show alarm condition notifications"),
            ("/bad", "Show BAD I/O events"),
            ("/standby", "Show standby/failover events"),
            ("/interlock", "Show interlock/trip events"),
            ("/limited", "Show EVENT_LIMITED (buffer overflow)"),
            ("/hardware", "Show hardware alarms"),
            ("/process", "Show process events"),
            ("/top <n>", "Show top N descriptions"),
            ("/node <name>", "Focus on events for a node"),
            ("/filter <col> <val>", "Filter events by column value"),
            ("/search <text>", "Search all event text"),
            ("/schema", "Show available columns"),
            ("/sample <n>", "Show N raw events"),
            ("/export <path>", "Export events as JSON"),
            ("/help", "Show this help"),
            ("/quit", "Exit"),
        ]
        for cmd, desc in cmds:
            cprint(f"  {_CYAN}{cmd:25s}{_RESET}  {desc}", "")
        print()

    def run(self):
        """Start the interactive REPL."""
        section("DELTAV EVENT LOG ANALYZER")
        cprint("Type /help for commands or /load <path> to begin", _DIM)

        while True:
            try:
                line = input(f"{_CYAN}Dv>{_RESET} ").strip()
                if not line:
                    continue
                if line.lower() in ("/quit", "/q", "/exit", "exit", "quit"):
                    cprint("Bye.", _CYAN)
                    break
                if line.startswith("/"):
                    self.run_command(line)
                else:
                    self._error("Commands start with /")
            except (EOFError, KeyboardInterrupt):
                print()
                cprint("Bye.", _CYAN)
                break
            except Exception as e:
                self._error(f"Unexpected error: {e}")


# ============================================================
# CLI entry
# ============================================================

def main():
    """Handle CLI args and launch REPL."""
    args = sys.argv[1:]

    # Handle --load / path shorthand
    if args and not args[0].startswith("/"):
        args = ["/load", args[0]] + args[1:]

    repl = DeltaVREPL()

    if args:
        # Process commands in order
        i = 0
        while i < len(args):
            cmd = args[i]
            if cmd.startswith("/") and cmd in ("/load", "/l"):
                if i + 1 < len(args):
                    repl.run_command(f"{cmd} {args[i+1]}")
                    i += 2
                else:
                    repl._error(f"{cmd} requires a path")
                    i += 1
            elif cmd.startswith("/"):
                repl.run_command(cmd)
                i += 1
            else:
                i += 1

    # Always enter interactive REPL after processing CLI args
    repl.run()


if __name__ == "__main__":
    main()
