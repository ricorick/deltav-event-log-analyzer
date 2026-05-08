"""
deltav-analyzer: Core analysis engine for DeltaV event log TSV exports.

Phases:
  Layer 1 - Statistical aggregation (event types, categories, states, nodes)
  Layer 2 - Pattern detection (ACN pairs, BAD INTEGRITY resolution, standby recovery,
            interlock cycling, alarm storms, EVENT_LIMITED, HART failures)

Usage:
    from analyzer import DeltaVEventLog
    log = DeltaVEventLog("/path/to/events.txt")
    s = log.summary()
    nodes = log.node_summary()
    acn = log.acn_switches()
"""

import csv
import json
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


class DeltaVEventLog:
    """Parse and analyze a DeltaV event log TSV export."""

    def __init__(self, path: str):
        self.path = Path(path)
        self.rows: list[dict] = []
        self._load()

    # ── Loading ──────────────────────────────────────────────────────

    def _load(self):
        """Parse TSV file. Handles line-number prefix, Windows line endings.
        Sorts events chronologically after loading."""
        with open(self.path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()

        # Split into lines, handling both \r\n and \n
        lines = text.replace("\r\n", "\n").split("\n")
        lines = [l for l in lines if l.strip()]

        if not lines:
            raise ValueError("Empty file")

        # Parse header
        header_parts = lines[0].split("\t")
        raw_names = [c.strip().lower().rstrip("*") for c in header_parts]

        # Detect if file has a line-number prefix column:
        # Header starts with empty cell (from leading tab) or column name.
        # Data rows start with a line number (digits only).
        # Check first data row to determine.
        sample = lines[1].split("\t")
        has_line_numbers = len(sample) > 13 and _is_line_number(sample[0])

        col_map = {
            "date/time": 0,
            "event type": 1,
            "category": 2,
            "area": 3,
            "node": 4,
            "unit": 5,
            "module": 6,
            "module description": 7,
            "parameter": 8,
            "state": 9,
            "level": 10,
            "desc1": 11,
            "desc2": 12,
        }

        # Map column names to positions in raw header
        col_index = {}
        for i, name in enumerate(raw_names):
            if name in col_map:
                col_index[col_map[name]] = i

        if not col_index:
            # Fallback: assume standard 13-column order
            col_index = {k: k for k in range(13)}

        # Parse data rows
        for line in lines[1:]:
            parts = line.split("\t")
            row = {}
            for std_idx, raw_idx in col_index.items():
                raw_pos = raw_idx  # No offset needed — header empty col aligns with line number col
                row[_COL_NAMES[std_idx]] = parts[raw_pos] if raw_pos < len(parts) else ""
            # Ensure all keys exist
            for name in _COL_NAMES.values():
                row.setdefault(name, "")
            # Parse datetime for sorting later
            row["_dt"] = _parse_dt(row["datetime"])
            self.rows.append(row)

        # Sort chronologically (put None-datetime rows at end)
        self.rows.sort(key=lambda r: r["_dt"] or datetime.max)

    def _sorted(self, rows: list) -> list:
        """Return rows sorted chronologically by parsed datetime."""
        return sorted(rows, key=lambda r: r.get("_dt") or datetime.max)

    # ── Stats ─────────────────────────────────────────────────────────

    def _counter(self, key: str) -> Counter:
        return Counter(r[key] for r in self.rows)

    def total_events(self) -> int:
        return len(self.rows)

    def time_range(self) -> tuple[str, str]:
        dts = [r["_dt"] for r in self.rows if r["_dt"]]
        if not dts:
            return ("", "")
        return (min(dts).strftime("%m/%d/%Y %I:%M:%S %p"), max(dts).strftime("%m/%d/%Y %I:%M:%S %p"))

    def event_type_summary(self) -> list[tuple[str, int]]:
        return self._counter("event_type").most_common()

    def category_summary(self) -> list[tuple[str, int]]:
        return self._counter("category").most_common()

    def state_summary(self) -> list[tuple[str, int]]:
        return self._counter("state").most_common()

    def level_summary(self) -> list[tuple[str, int]]:
        return self._counter("level").most_common()

    def node_summary(self) -> list[tuple[str, int]]:
        return self._counter("node").most_common()

    def alarm_summary(self) -> dict:
        alarms = [r for r in self.rows if r["event_type"] == "ALARM"]
        return {
            "total": len(alarms),
            "by_description": Counter(r["desc2"] for r in alarms).most_common(),
            "by_node": Counter(r["node"] for r in alarms).most_common(),
            "by_param_state": Counter(
                (r["parameter"], r["state"]) for r in alarms if r["parameter"] or r["state"]
            ).most_common(20),
            "by_state": Counter(r["state"] for r in alarms).most_common(),
            "by_level": Counter(r["level"] for r in alarms).most_common(),
        }

    def top_patterns(self, n: int = 20) -> list[tuple]:
        return Counter(
            (r["node"], r["parameter"], r["state"], r["desc2"]) for r in self.rows
        ).most_common(n)

    # ── Pattern Detection ─────────────────────────────────────────────

    def acn_switches(self) -> dict:
        """Detect ACN COMM network switches and find switch pairs."""
        acn = [r for r in self.rows if "ACN COMM" in r["parameter"]]
        pairs = []
        prev = None
        for r in acn:
            if prev and _same_node(r, prev):
                pairs.append((prev, r))
            prev = r

        # Count switches by node
        by_node: dict[str, int] = defaultdict(int)
        for r in acn:
            by_node[r["node"]] += 1

        # Timeline (first 20 for brief, full count)
        return {
            "total": len(acn),
            "by_node": sorted(by_node.items(), key=lambda x: -x[1]),
            "pairs_detected": len(pairs),
            "sample_pairs": pairs[:5] if pairs else [],
        }

    def bad_integrity(self) -> dict:
        """BAD INTEGRITY events, grouped by parameter, with resolution tracking."""
        bad = [r for r in self.rows if "BAD INTEGRITY" in r["state"].upper()
               or r["state"] == "BAD INTEGRITY"]
        by_param: dict[str, list] = defaultdict(list)
        for r in bad:
            param = r["parameter"] or r["node"] or "UNKNOWN"
            by_param[param].append(r)

        resolved = {}
        for param, events in by_param.items():
            last_bad = events[-1]
            last_dt = last_bad["datetime"]
            # Check if any OK event follows for same parameter
            ok_later = [
                r for r in self.rows
                if r["datetime"] > last_dt
                and r["parameter"] == param
                and r["state"].upper() in ("OK", "ACTIVE", "NORMAL")
            ]
            resolved[param] = {
                "count": len(events),
                "first": events[0]["datetime"],
                "last": last_dt,
                "still_bad": len(ok_later) == 0,
            }

        return {
            "total": len(bad),
            "by_parameter": sorted(
                resolved.items(), key=lambda x: -x[1]["count"]
            ),
        }

    def standby_events(self) -> dict:
        """Standby/redundancy events with recovery time calculation."""
        stby = [
            r for r in self.rows
            if "standby" in r["desc2"].lower() or "redundancy" in r["desc2"].lower()
        ]

        # Find Available/Unavailable pairs
        unavailable = [r for r in stby if "unavailable" in r["desc2"].lower()]
        available = [r for r in stby if "available" in r["desc2"].lower()]

        recovery_times = []
        for u in unavailable:
            u_dt = _parse_dt(u["datetime"])
            if not u_dt:
                continue
            # Find next Available for same node
            for a in available:
                a_dt = _parse_dt(a["datetime"])
                if a_dt and a_dt > u_dt and a["node"] == u["node"]:
                    secs = (a_dt - u_dt).total_seconds()
                    recovery_times.append({
                        "node": u["node"],
                        "unavailable_at": u["datetime"],
                        "available_at": a["datetime"],
                        "duration_seconds": secs,
                        "duration_minutes": round(secs / 60, 1),
                    })
                    break

        # Count events by node
        by_node: dict[str, int] = defaultdict(int)
        for r in stby:
            by_node[r["node"]] += 1

        if recovery_times:
            durations = [r["duration_seconds"] for r in recovery_times]
            avg_min = sum(durations) / len(durations) / 60
            max_hours = max(durations) / 3600
        else:
            avg_min = 0
            max_hours = 0

        return {
            "total": len(stby),
            "unavailable_count": len(unavailable),
            "available_count": len(available),
            "by_node": sorted(by_node.items(), key=lambda x: -x[1]),
            "recovery_pairs": len(recovery_times),
            "avg_recovery_minutes": round(avg_min, 1),
            "max_recovery_hours": round(max_hours, 2),
            "sample_recoveries": recovery_times[:5],
        }

    def interlock_cycling(self) -> dict:
        """Detect interlock tracking conditions cycling on the same module."""
        interlock = [
            r for r in self.rows
            if "INTERLOCK" in r["parameter"].upper()
            or r.get("category", "").upper() == "INTERLOCK"
        ]

        by_module: dict[str, list] = defaultdict(list)
        for r in interlock:
            mod = r["module"] or r["node"] or "UNKNOWN"
            by_module[mod].append(r)

        cycling = {}
        for mod, events in by_module.items():
            # Count ACTIVE vs cleared transitions
            states = Counter(r["state"] for r in events)
            tracking_active = any("TRACKING" in s.upper() and "ACTIVE" in s.upper() for s in states)
            cycling[mod] = {
                "count": len(events),
                "states": dict(states.most_common(5)),
                "tracking_active": tracking_active,
                "first": events[0]["datetime"],
                "last": events[-1]["datetime"],
            }

        return {
            "total": len(interlock),
            "by_module": sorted(
                cycling.items(), key=lambda x: -x[1]["count"]
            ),
        }

    def hart_events(self) -> list:
        """HART-related events."""
        return [
            r for r in self.rows
            if "HART" in r["desc2"].upper()
        ]

    def io_failures(self) -> dict:
        """I/O transfer failures (Outputs/Inputs Transfer Failure)."""
        io = [
            r for r in self.rows
            if "Transfer Failure" in r["desc2"]
        ]
        by_module: dict[str, int] = defaultdict(int)
        for r in io:
            by_module[r["module"] or r["node"]] += 1
        return {
            "total": len(io),
            "by_module": sorted(by_module.items(), key=lambda x: -x[1]),
        }

    def event_limited(self) -> dict:
        """EVENT_LIMITED state events — buffer overflow indicators."""
        el = [
            r for r in self.rows
            if "EVENT_LIMITED" in r["state"].upper()
            or "LIMITED" in r["state"].upper()
        ]
        by_node: dict[str, int] = defaultdict(int)
        for r in el:
            by_node[r["node"]] += 1
        return {
            "total": len(el),
            "by_node": sorted(by_node.items(), key=lambda x: -x[1]),
            "sample": el[:5],
        }

    def process_events(self) -> dict:
        """Process category events grouped by node/module/desc."""
        proc = [r for r in self.rows if r["category"] == "PROCESS"]
        return {
            "total": len(proc),
            "by_combo": Counter(
                (r["node"], r["module"], r["desc2"]) for r in proc
            ).most_common(15),
        }

    def hardware_alarms(self) -> dict:
        """Hardware category events."""
        hw = [r for r in self.rows if r["category"] == "HARDWARE"]
        return {
            "total": len(hw),
            "by_node": Counter(r["node"] for r in hw).most_common(),
            "by_desc": Counter(r["desc2"] for r in hw).most_common(10),
        }

    def security_events(self) -> dict:
        """LOGON_FAILED_ATTEMPT and security-related events."""
        sec = [r for r in self.rows if r["event_type"] == "LOGON_FAILED_ATTEMPT"
               or r["event_type"] == "LOGON_FAILURE"]
        return {
            "total": len(sec),
            "by_node": Counter(r["node"] for r in sec).most_common(),
        }

    # ── Full Analysis ─────────────────────────────────────────────────

    def comprehensive_analysis(self) -> dict:
        """Run all analyses and return as a single dict."""
        return {
            "file": str(self.path),
            "total_events": self.total_events(),
            "time_range": self.time_range(),
            "event_types": self.event_type_summary(),
            "categories": self.category_summary(),
            "states": self.state_summary(),
            "levels": self.level_summary(),
            "nodes": self.node_summary(),
            "alarms": self.alarm_summary(),
            "acn_switches": self.acn_switches(),
            "bad_integrity": self.bad_integrity(),
            "standby": self.standby_events(),
            "interlocks": self.interlock_cycling(),
            "hart": len(self.hart_events()),
            "io_failures": self.io_failures(),
            "event_limited": self.event_limited(),
            "process": self.process_events(),
            "hardware": self.hardware_alarms(),
            "security": self.security_events(),
            "top_patterns": self.top_patterns(20),
        }

    def to_json(self, indent: int = 2) -> str:
        """Export comprehensive analysis as JSON."""
        return json.dumps(self.comprehensive_analysis(), indent=indent, default=str)

    def to_dict(self) -> dict:
        """Return comprehensive analysis as dict (for LLM consumption)."""
        return self.comprehensive_analysis()

    # ── Filtering ─────────────────────────────────────────────────────

    def events_for_node(self, node_name: str) -> list[dict]:
        """All events for a specific node."""
        return [
            r for r in self.rows
            if node_name.upper() in r["node"].upper()
        ]

    def events_matching(self, **kwargs) -> list[dict]:
        """Filter events by key=value pairs. Case-insensitive substring match."""
        results = self.rows
        for key, val in kwargs.items():
            results = [
                r for r in results
                if val.upper() in r.get(key, "").upper()
            ]
        return results


# ── Internal helpers ──────────────────────────────────────────────────

_COL_NAMES = {
    0: "datetime",
    1: "event_type",
    2: "category",
    3: "area",
    4: "node",
    5: "unit",
    6: "module",
    7: "module_desc",
    8: "parameter",
    9: "state",
    10: "level",
    11: "desc1",
    12: "desc2",
}


def _same_node(a: dict, b: dict) -> bool:
    return a["node"] == b["node"]


def _is_line_number(s: str) -> bool:
    return s.strip().isdigit()


def _parse_dt(dt_str: str) -> Optional[datetime]:
    """Try common DeltaV timestamp formats."""
    formats = [
        "%m/%d/%Y %I:%M:%S.%f %p",
        "%m/%d/%Y %I:%M:%S %p",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(dt_str.strip(), fmt)
        except ValueError:
            continue
    return None
