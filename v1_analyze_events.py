#!/usr/bin/env python3
"""
DeltaV Event Log Analyzer v1
Flat script. Run with a file path. Prints everything. No interactive mode.
Usage:
    python v1_analyze_events.py <path_to_events.txt>
"""
import sys
from collections import defaultdict, Counter
from pathlib import Path
from datetime import datetime

# ANSI helpers
ESC = chr(27)
_RED = ESC + "[31m"
_GREEN = ESC + "[32m"
_YELLOW = ESC + "[33m"
_CYAN = ESC + "[36m"
_BOLD = ESC + "[1m"
_DIM = ESC + "[2m"
_RESET = ESC + "[0m"


def parse_log(path: str) -> list:
    """Parse a DeltaV event log TSV file. Returns list of dicts."""
    raw = Path(path).read_text(encoding="utf-8", errors="replace")
    lines = raw.splitlines()

    headers = None
    header_skip = 0
    rows = []

    for line in lines:
        if not line.strip():
            continue
        stripped = line.strip()
        # Skip metadata headers
        if (stripped.startswith("DeltaV") or stripped.startswith("File") or
            stripped.startswith("User") or stripped.startswith("Print") or
            stripped.startswith("Event Log") or stripped.startswith("=") or
            stripped.startswith("-")):
            continue

        parts = line.split("\t")

        # Detect header
        if not headers:
            for p in parts:
                p_stripped = p.strip().rstrip("*")
                if p_stripped in ("Date/Time", "Date/Time*", "DateTime", "Date Time"):
                    headers = [h.strip().rstrip("*") for h in parts]
                    first = parts[0].strip().lower()
                    if not first or first in ("no.", "no", "#", "row"):
                        header_skip = 1
                        headers = headers[1:]
                    break
            continue

        # Data row
        data_parts = parts[header_skip:] if header_skip else parts
        if len(data_parts) < len(headers):
            continue

        event = {}
        for i, h in enumerate(headers):
            if i < len(data_parts):
                event[h] = data_parts[i].strip()
            else:
                event[h] = ""

        # Parse datetime
        dt_str = event.get("Date/Time", event.get("DateTime", event.get("Date Time", "")))
        if dt_str:
            for fmt in ("%m/%d/%Y %I:%M:%S.%f %p", "%m/%d/%Y %I:%M:%S %p",
                        "%m/%d/%Y %H:%M:%S.%f", "%m/%d/%Y %H:%M:%S",
                        "%m/%d/%Y %H:%M", "%m/%d/%y %I:%M:%S %p"):
                try:
                    event["_dt"] = datetime.strptime(dt_str.strip(), fmt)
                    break
                except ValueError:
                    continue
            else:
                event["_dt"] = None
        else:
            event["_dt"] = None

        rows.append(event)

    # Sort chronologically
    rows.sort(key=lambda r: r["_dt"] if r.get("_dt") else datetime.min)
    return rows


def desc(ev: dict) -> str:
    return str(ev.get("Description", ev.get("Desc2", ev.get("Desc1", ev.get("Alarm Description", "")))))


def section(title: str):
    print(f"\n{_CYAN}{_BOLD}{'=' * min(len(title) + 8, 80)}{_RESET}")
    print(f"{_CYAN}{_BOLD}  {title}{_RESET}")
    print(f"{_CYAN}{'=' * min(len(title) + 8, 80)}{_RESET}")


def hdr(label: str):
    print(f"\n{_BOLD}{label}{_RESET}")


# ── Main ────────────────────────────────────────────────────────────────

if len(sys.argv) < 2:
    print("Usage: python v1_analyze_events.py <path_to_events.txt>")
    sys.exit(1)

filepath = sys.argv[1]
if not Path(filepath).exists():
    print(f"File not found: {filepath}")
    sys.exit(1)

print(f"\n{_BOLD}DeltaV Event Log Analyzer v1{_RESET}")
print(f"File: {filepath}")

events = parse_log(filepath)
print(f"\n{_BOLD}Total events:{_RESET} {len(events):,}")

# Time range
times = [e.get("Date/Time", e.get("DateTime", "")) for e in events if e.get("_dt")]
if times:
    print(f"{_BOLD}Time range:{_RESET} {min(times)}  ->  {max(times)}")


# ── EVENT TYPE SUMMARY ─────────────────────────────────────────────────

section("EVENT TYPE SUMMARY")
for etype, count in Counter(e.get("Event Type", e.get("EventType", "")) for e in events).most_common():
    print(f"  {count:>6}  {etype}")


# ── CATEGORY SUMMARY ──────────────────────────────────────────────────

section("CATEGORY SUMMARY")
for cat, count in Counter(e.get("Category", "") for e in events if e.get("Category", "")).most_common():
    print(f"  {count:>6}  {cat}")


# ── STATE SUMMARY ─────────────────────────────────────────────────────

section("STATE SUMMARY")
for s, count in Counter(e.get("State", "") for e in events if e.get("State", "")).most_common():
    print(f"  {count:>6}  {s}")


# ── LEVEL / PRIORITY ──────────────────────────────────────────────────

section("PRIORITY BREAKDOWN")
levels = Counter(e.get("Level", e.get("Alarm Level", "")) for e in events if e.get("Level", ""))
for lv, count in sorted(levels.items(), key=lambda x: -x[1]):
    if "CRITICAL" in lv.upper():
        print(f"  {_RED}{lv:30s} {count:>5}{_RESET}")
    elif "WARNING" in lv.upper():
        print(f"  {_YELLOW}{lv:30s} {count:>5}{_RESET}")
    else:
        print(f"  {lv:30s} {count:>5}")


# ── NODE SUMMARY ──────────────────────────────────────────────────────

section("NODES WITH MOST EVENTS")
nodes = Counter(e.get("Node Name", e.get("Node", "?")) for e in events)
for node, count in nodes.most_common():
    print(f"  {count:>6}  {node}")


# ── ALARM ANALYSIS ────────────────────────────────────────────────────

section("ALARM ANALYSIS")
alarms = [e for e in events if e.get("Level", "").strip() or "ALARM" in str(e.get("Event Type", "")).upper()]
print(f"  Total alarms: {len(alarms):,}")

if alarms:
    hdr("By Description")
    for d, cnt in Counter(desc(e) for e in alarms).most_common():
        print(f"  {cnt:>6}x  {d[:90]}")

    hdr("By Node")
    for n, cnt in Counter(e.get("Node Name", e.get("Node", "?")) for e in alarms).most_common():
        color = _RED if "CRITICAL" in n.upper() else ""
        print(f"  {color}{cnt:>6}  {n}{_RESET}")

    hdr("By State (Active vs Cleared)")
    for s, cnt in Counter(e.get("State", "") for e in alarms if e.get("State", "")).most_common():
        print(f"  {cnt:>6}  {s}")


# ── STANDBY / REDUNDANCY ──────────────────────────────────────────────

section("STANDBY / REDUNDANCY")
stby = [e for e in events if "STANDBY" in desc(e).upper()
        or "FAILOVER" in desc(e).upper()
        or "UNAVAILABLE" in desc(e).upper()
        or "AVAILABLE" in desc(e).upper()
        or "SECONDARY" in desc(e).upper()
        or "redundancy" in desc(e).lower()]
print(f"  Total standby events: {len(stby)}")

if stby:
    print()
    # Sort by time
    stby_sorted = sorted([e for e in stby if e.get("_dt")], key=lambda x: x["_dt"])

    # Calculate recovery times: pair Unavailable -> Available per node
    by_node = defaultdict(list)
    for e in stby_sorted:
        node = e.get("Node Name", e.get("Node", "?"))
        by_node[node].append(e)

    for node, evts in by_node.items():
        print(f"  {_BOLD}{node}{_RESET} ({len(evts)} events):")
        for e in evts:
            dt = e.get("Date/Time", e.get("DateTime", ""))
            d = desc(e)[:90]
            print(f"    {dt}  {d}")

        # Try to find recovery pairs
        i = 0
        while i < len(evts):
            d = desc(evts[i]).upper()
            if "UNAVAILABLE" in d or "FAILOVER" in d:
                down_dt = evts[i].get("_dt")
                for j in range(i + 1, len(evts)):
                    next_d = desc(evts[j]).upper()
                    if "AVAILABLE" in next_d:
                        up_dt = evts[j].get("_dt")
                        if down_dt and up_dt:
                            secs = (up_dt - down_dt).total_seconds()
                            mins = secs / 60
                            color = _RED if secs > 300 else _YELLOW if secs > 60 else _GREEN
                            print(f"    {color}>> Recovery: {secs:.0f}s ({mins:.1f} min){_RESET}")
                        i = j
                        break
                else:
                    # No recovery found for this failure
                    print(f"    {_RED}>> NO RECOVERY EVENT FOUND (still down?){_RESET}")
            i += 1

    # Summary stats
    recoveries = []
    by_node_rec = defaultdict(list)
    for node, evts in by_node.items():
        i = 0
        while i < len(evts):
            d = desc(evts[i]).upper()
            if "UNAVAILABLE" in d or "FAILOVER" in d:
                down_dt = evts[i].get("_dt")
                for j in range(i + 1, len(evts)):
                    next_d = desc(evts[j]).upper()
                    if "AVAILABLE" in next_d:
                        up_dt = evts[j].get("_dt")
                        if down_dt and up_dt:
                            secs = (up_dt - down_dt).total_seconds()
                            rec = {"down": down_dt, "up": up_dt, "duration_secs": int(secs), "duration_min": round(secs / 60, 1)}
                            recoveries.append(rec)
                            by_node_rec[node].append(rec)
                        i = j
                        break
            i += 1

    if recoveries:
        print()
        hdr("Recovery Summary")
        for node, recs in by_node_rec.items():
            avg_min = sum(r["duration_min"] for r in recs) / len(recs)
            max_sec = max(r["duration_secs"] for r in recs)
            total_min = sum(r["duration_min"] for r in recs)
            print(f"  {node}: {len(recs)} outage(s), avg {avg_min:.1f} min, total {total_min:.1f} min, max {max_sec:.0f}s")
            for r in recs:
                color = _RED if r["duration_secs"] > 300 else _YELLOW if r["duration_secs"] > 60 else _GREEN
                print(f"    {color}{r['down'].strftime('%m/%d %I:%M:%S %p'):25s} -> {r['up'].strftime('%m/%d %I:%M:%S %p'):25s}  ({r['duration_min']:.1f} min){_RESET}")


# ── BAD / FAILURE EVENTS ──────────────────────────────────────────────

section("BAD / FAILURE EVENTS")
bad = [e for e in events if "BAD" in str(e.get("State", "")).upper() or "FAIL" in str(e.get("State", "")).upper()]
print(f"  Total: {len(bad)}")
for e in bad:
    dt = e.get("Date/Time", e.get("DateTime", ""))
    node = e.get("Node Name", e.get("Node", "?"))
    state = e.get("State", "")
    param = e.get("Parameter", e.get("Param", ""))
    d = desc(e)[:80]
    print(f"  {dt}  {node}  State={state}  Param={param}  {d}")


# ── ACN COMM SWITCHES ─────────────────────────────────────────────────

section("ACN COMM NETWORK SWITCHES")
acn = [e for e in events if "ACN COMM" in str(e.get("Parameter", e.get("Param", ""))).upper()]
print(f"  Total: {len(acn)}")
for e in acn:
    dt = e.get("Date/Time", e.get("DateTime", ""))
    node = e.get("Node Name", e.get("Node", "?"))
    state = e.get("State", "")
    d = desc(e)[:80]
    print(f"  {dt}  {node}  {state}  {d}")


# ── PROCESS EVENTS ────────────────────────────────────────────────────

section("PROCESS EVENTS")
proc = [e for e in events if e.get("Category", "") == "PROCESS"]
print(f"  Total: {len(proc)}")
for (node, mod, d), cnt in Counter(
    (e.get("Node Name", e.get("Node", "?")),
     e.get("Module Name", e.get("Module", "")),
     desc(e))
    for e in proc
).most_common():
    print(f"  {cnt:>4}x  {node}  |  {mod}  |  {d[:80]}")


# ── EVENT_LIMITED (BUFFER OVERFLOW) ───────────────────────────────────

section("EVENT_LIMITED (BUFFER OVERFLOW)")
el = [e for e in events if "LIMIT" in str(e.get("State", "")).upper() or "OVERFLOW" in desc(e).upper()]
if el:
    print(f"  Total: {len(el)}")
    for node, cnt in Counter(e.get("Node Name", e.get("Node", "?")) for e in el).most_common():
        print(f"  {cnt:>4}  {node}")
    for e in el:
        dt = e.get("Date/Time", e.get("DateTime", ""))
        node = e.get("Node Name", e.get("Node", "?"))
        mod = e.get("Module Name", e.get("Module", ""))
        state = e.get("State", "")
        print(f"    {dt}  {node}  {mod}  {state}")
else:
    print("  None found")


# ── OUTPUTS TRANSFER FAILURE ──────────────────────────────────────────

section("OUTPUTS TRANSFER FAILURE")
otf = [e for e in events if "Transfer Failure" in desc(e)]
if otf:
    print(f"  Total: {len(otf)}")
    for e in otf:
        dt = e.get("Date/Time", e.get("DateTime", ""))
        node = e.get("Node Name", e.get("Node", "?"))
        mod = e.get("Module Name", e.get("Module", ""))
        state = e.get("State", "")
        print(f"  {dt}  {node}  {mod}  State={state}")
else:
    print("  None found")


# ── HART EVENTS ────────────────────────────────────────────────────────

section("HART EVENTS")
hart = [e for e in events if "HART" in desc(e).upper()]
if hart:
    print(f"  Total: {len(hart)}")
    for e in hart:
        dt = e.get("Date/Time", e.get("DateTime", ""))
        node = e.get("Node Name", e.get("Node", "?"))
        d = desc(e)[:80]
        print(f"  {dt}  {node}  {d}")
else:
    print("  None found")


# ── TOP EVENT PATTERNS ────────────────────────────────────────────────

section("TOP 20 EVENT PATTERNS")
for (node, param, state, d), cnt in Counter(
    (e.get("Node Name", e.get("Node", "?")),
     e.get("Parameter", e.get("Param", "")),
     e.get("State", ""),
     desc(e)[:60])
    for e in events
).most_common(20):
    print(f"  {cnt:>5}x  {node}  |  Param={param}  |  State={state}  |  {d}")


# ── ALL EVENTS BY NODE ────────────────────────────────────────────────

section("ALL EVENTS BY NODE")
for node in sorted(nodes.keys()):
    node_events = [e for e in events if e.get("Node Name", e.get("Node", "?")) == node]
    print(f"\n{_BOLD}{node}{_RESET} ({len(node_events)} events):")
    for e in node_events:
        dt = e.get("Date/Time", e.get("DateTime", ""))
        lv = e.get("Level", e.get("Alarm Level", ""))
        st = e.get("State", "")
        d = desc(e)[:80]
        if lv:
            print(f"  {dt}  [{lv}]  {d}")
        else:
            print(f"  {dt}  {st:20s}  {d}")


print(f"\n{_GREEN}{_BOLD}Done. {len(events)} events analyzed.{_RESET}\n")
