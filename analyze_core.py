#!/usr/bin/env python3
"""
DELTA V EVENT LOG ANALYZER - CORE ENGINE (CANONICAL)

This is the single source of truth for parsing DeltaV event logs.

Run with no args: drops to a command prompt (/load, /help, /quit).
Run with file arg: analyzes and prints immediately, then exits.

Usage:
    python analyze_core.py                # interactive
    python analyze_core.py <path>         # one-shot

────────────────────────────────────────────

CANONICAL RULES (CRITICAL):

- This file is the ONLY authoritative parser for event interpretation
- Do NOT duplicate parsing logic in other files
- Do NOT override or reinterpret its output elsewhere
- All downstream tools must consume its output as-is
- Output schema must remain stable across all future changes
- Changes must be minimal and intentional (no silent refactors)

────────────────────────────────────────────
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
        if (stripped.startswith("DeltaV") or stripped.startswith("File") or
            stripped.startswith("User") or stripped.startswith("Print") or
            stripped.startswith("Event Log") or stripped.startswith("=") or
            stripped.startswith("-")):
            continue

        parts = line.split("\t")
        if not headers:
            for p in parts:
                p_stripped = p.strip().rstrip("*")
                if p_stripped in ("Date/Time", "Date/Time*", "DateTime", "Date Time"):
                    headers = [h.strip().rstrip("*") for h in parts]
                    first = parts[0].strip().lower()
                    if first in ("no.", "no", "#", "row"):
                        header_skip = 1
                        headers = headers[1:]
                    break
            continue

        data_parts = parts[header_skip:] if header_skip else parts
        if len(data_parts) < len(headers):
            continue

        event = {}
        for i, h in enumerate(headers):
            if i < len(data_parts):
                event[h] = data_parts[i].strip()
            else:
                event[h] = ""

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

    rows.sort(key=lambda r: r["_dt"] if r.get("_dt") else datetime.min)
    return rows


def node(e: dict) -> str:
    return e.get("Node Name", e.get("Node", "?"))


def mod(e: dict) -> str:
    return e.get("Module Name", e.get("Module", ""))


def desc(e: dict) -> str:
    return str(e.get("Description", e.get("Desc2", e.get("Desc1", e.get("Alarm Description", "")))))


def _section(title: str):
    print(f"\n{_CYAN}{_BOLD}{title}{_RESET}")


# ── ANALYSIS ENGINE (v4 — compressed) ─────────────────────────────────


def analyze(events: list, filename: str = ""):
    """Compressed analysis — one-line summary, highlights, then compact sections."""
    if not events:
        print("No events loaded.")
        return

    # ── HEADER LINE ──
    times = [e.get("Date/Time", e.get("DateTime", "")) for e in events if e.get("_dt")]
    time_str = f"  |  {min(times)}  ->  {max(times)}" if times else ""
    node_cnt = len(set(node(e) for e in events))
    print(f"\n{_BOLD}{filename}{_RESET}")
    print(f"{len(events):,} events  |  {node_cnt} node(s){time_str}")
    print()

    # ── HIGHLIGHTS (one line per non-zero category) ──
    alarms = [e for e in events if e.get("Level", "").strip() or "ALARM" in str(e.get("Event Type", "")).upper()]
    stby   = [e for e in events if "STANDBY" in desc(e).upper() or "FAILOVER" in desc(e).upper()
              or "UNAVAILABLE" in desc(e).upper() or "AVAILABLE" in desc(e).upper()
              or "SECONDARY" in desc(e).upper() or "redundancy" in desc(e).lower()]
    bad    = [e for e in events if "BAD" in str(e.get("State", "")).upper() or "FAIL" in str(e.get("State", "")).upper()]
    acn    = [e for e in events if "ACN COMM" in str(e.get("Parameter", e.get("Param", ""))).upper()]
    el     = [e for e in events if "LIMIT" in str(e.get("State", "")).upper()]
    otf    = [e for e in events if "Transfer Failure" in desc(e)]
    hart   = [e for e in events if "HART" in desc(e).upper()]
    proc   = [e for e in events if e.get("Category", "") == "PROCESS"]
    crit   = [e for e in events if "CRITICAL" in str(e.get("Level", "")).upper()]

    highlights = []
    if node_cnt > 1:
        top_nodes = Counter(node(e) for e in events).most_common(3)
        highlights.append(f"Top nodes: {'  '.join(f'{n} ({c})' for n, c in top_nodes)}")
    if alarms:
        highlights.append(f"Alarms: {len(alarms)} ({len(crit)} critical)")
    if stby:
        stby_nodes = set(node(e) for e in stby)
        highlights.append(f"Standby/Redundancy: {len(stby)} events on {len(stby_nodes)} node(s)")
    if bad:
        highlights.append(f"BAD/FAIL State: {len(bad)}")
    if acn:
        acn_nodes = set(node(e) for e in acn)
        highlights.append(f"ACN COMM switches: {len(acn)} on {len(acn_nodes)} node(s)")
    if el:
        highlights.append(f"EVENT_LIMITED (buffer overflow): {len(el)}")
    if otf:
        highlights.append(f"Outputs Transfer Failure: {len(otf)}")
    if hart:
        highlights.append(f"HART events: {len(hart)}")
    if proc:
        highlights.append(f"Process events: {len(proc)}")

    if highlights:
        print(f"  {_BOLD}Highlights{_RESET}")
        for h in highlights:
            print(f"    {h}")
        print()

    # ── PRIORITY (compact) ──
    prio_counts = Counter(e.get("Level", "") for e in events if e.get("Level", ""))
    if prio_counts:
        _section("PRIORITY")
        for lv in sorted(prio_counts, key=lambda x: -prio_counts[x]):
            c = prio_counts[lv]
            if "CRITICAL" in lv.upper():
                print(f"  {_RED}{lv:28s} {c:>5}{_RESET}")
            elif "WARNING" in lv.upper():
                print(f"  {_YELLOW}{lv:28s} {c:>5}{_RESET}")
            else:
                print(f"  {lv:28s} {c:>5}")

    # ── STANDBY / REDUNDANCY (recovery summary only, no raw dump) ──
    if stby:
        _section("STANDBY / REDUNDANCY")
        stby_sorted = sorted([e for e in stby if e.get("_dt")], key=lambda x: x["_dt"])
        by_node = defaultdict(list)
        for e in stby_sorted:
            by_node[node(e)].append(e)

        print(f"  {len(stby)} events, {len(by_node)} node(s) with standby activity")
        print(f"  {_DIM}Events (oldest first):{_RESET}")
        first_n_shown = set()
        for n, evts in by_node.items():
            print(f"    {n}: {len(evts)} events")
            # Collapse repeating patterns — show first occurrence of each distinct desc
            seen_patterns = set()
            for e in evts:
                d = desc(e)
                if d not in seen_patterns:
                    seen_patterns.add(d)
                    dt = e.get("Date/Time", e.get("DateTime", ""))
                    print(f"      {dt}  {d[:120]}")
                    if len(seen_patterns) >= 3:
                        print(f"      {_DIM}... (repeating patterns){_RESET}")
                        break

        # Recovery summary
        by_node_rec = defaultdict(list)
        for n, evts in by_node.items():
            i = 0
            while i < len(evts):
                d = desc(evts[i]).upper()
                if "UNAVAILABLE" in d or "FAILOVER" in d or ("STANDBY" in d and "NOT" in d):
                    down_dt = evts[i].get("_dt")
                    for j in range(i + 1, len(evts)):
                        next_d = desc(evts[j]).upper()
                        if "AVAILABLE" in next_d or "PRIMARY" in next_d:
                            up_dt = evts[j].get("_dt")
                            if down_dt and up_dt:
                                secs = (up_dt - down_dt).total_seconds()
                                rec = {"node": n, "down": down_dt, "up": up_dt,
                                       "duration_secs": int(secs), "duration_min": round(secs / 60, 1)}
                                by_node_rec[n].append(rec)
                            i = j
                            break
                i += 1

        if by_node_rec:
            print()
            print(f"  {_BOLD}Recovery Summary{_RESET}")
            for n, recs in by_node_rec.items():
                avg_min = sum(r["duration_min"] for r in recs) / len(recs)
                max_sec = max(r["duration_secs"] for r in recs)
                total_min = sum(r["duration_min"] for r in recs)
                print(f"    {n}: {len(recs)} outage(s), avg {avg_min:.1f} min, total {total_min:.1f} min, max {max_sec:.0f}s")

    # ── ALARMS ──
    if alarms:
        _section("ALARMS")
        _hdr = lambda label: print(f"  {_BOLD}{label}{_RESET}")
        _hdr("By Description (top 10)")
        for d, cnt in Counter(desc(e) for e in alarms).most_common(10):
            print(f"    {cnt:>5}x  {d[:120]}")

        inact = [e for e in alarms if "INACT" in str(e.get("State", "")).upper()]
        if inact:
            _hdr("By State")
            print(f"    {len(inact)} inactive/cleared  |  {len(alarms) - len(inact)} active")

    # ── BAD / FAILURE ──
    if bad:
        _section("BAD / FAILURE")
        by_param = Counter(e.get("Parameter", e.get("Param", "")) for e in bad).most_common()
        for param, cnt in by_param[:10]:
            print(f"    {cnt:>4}x  {param}")
        if len(by_param) > 10:
            print(f"    {_DIM}... and {len(by_param) - 10} more parameters{_RESET}")

    # ── ACN COMM ──
    if acn:
        _section("ACN COMM NETWORK SWITCHES")
        by_pattern = Counter((node(e), e.get("State", ""), desc(e)[:80]) for e in acn).most_common()
        print(f"    {len(acn)} total events")
        for (n, s, d), cnt in by_pattern[:5]:
            print(f"    {cnt:>4}x  {n}  State={s}  {d}")

    # ── EVENT_LIMITED ──
    if el:
        _section("EVENT_LIMITED (BUFFER OVERFLOW)")
        by_mod = Counter((node(e), mod(e)) for e in el)
        print(f"    {len(el)} total, {len(by_mod)} module(s) affected")
        mod_counts = Counter(by_mod.values())
        nodes_involved = set(n for n, _ in by_mod)
        if len(mod_counts) == 1 and len(nodes_involved) == 1:
            all_cnt = next(iter(mod_counts.keys()))
            first_node = next(iter(nodes_involved))
            print(f"    All {len(by_mod)} modules on {first_node} — {all_cnt} each")
        else:
            for (n, m), cnt in sorted(by_mod.items(), key=lambda x: -x[1]):
                print(f"    {cnt:>4}x  {m:30s} on {n}")

    # ── OUTPUTS TRANSFER FAILURE ──
    if otf:
        _section("OUTPUTS TRANSFER FAILURE")
        by_mod = Counter((node(e), mod(e)) for e in otf)
        print(f"    {len(otf)} total, {len(by_mod)} module(s)")
        mod_counts = Counter(by_mod.values())
        nodes_involved = set(n for n, _ in by_mod)
        if len(mod_counts) == 1 and len(nodes_involved) == 1:
            all_cnt = next(iter(mod_counts.keys()))
            first_node = next(iter(nodes_involved))
            print(f"    All {len(by_mod)} modules on {first_node} — {all_cnt} each")
        else:
            for (n, m), cnt in sorted(by_mod.items(), key=lambda x: -x[1]):
                print(f"    {cnt:>4}x  {m:30s} on {n}")

    # ── HART ──
    if hart:
        _section("HART EVENTS")
        by_desc = Counter(desc(e)[:80] for e in hart).most_common()
        for d, cnt in by_desc[:5]:
            print(f"    {cnt:>4}x  {d}")
        if len(by_desc) > 5:
            print(f"    {_DIM}... and {len(by_desc) - 5} more patterns{_RESET}")

    # ── PROCESS EVENTS ──
    if proc:
        _section("PROCESS EVENTS")
        for (n, m, d), cnt in Counter(
            (node(e), mod(e), desc(e)) for e in proc
        ).most_common(10):
            print(f"    {cnt:>4}x  {n}  |  {m}  |  {d[:100]}")

    # ── TOP 10 PATTERNS (always) ──
    _section("TOP 10 EVENT PATTERNS")
    for (n, param, state, d), cnt in Counter(
        (node(e),
         e.get("Parameter", e.get("Param", "")),
         e.get("State", ""),
         desc(e)[:80])
        for e in events
    ).most_common(10):
        print(f"    {cnt:>5}x  {n}  |  Param={param}  |  State={state}  |  {d}")

    print(f"\n{_GREEN}{_BOLD}Done. {len(events)} events analyzed.{_RESET}")


# ── COMMAND LOOP (same as v3) ────────────────────────────────────────

def _repl():
    """Interactive command prompt."""
    loaded = None  # (filename, events)
    print(f"\n{_BOLD}DeltaV Event Log Analyzer v4{_RESET}")
    print("Type /load <file> to load and analyze an event log.")
    print("Type /help for commands.")
    print("Type /quit to exit.\n")

    while True:
        try:
            line = input("\u0394v> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue

        if line.startswith("/"):
            cmd = line.split()
            base = cmd[0].lower()

            if base == "/quit" or base == "/exit":
                print("Goodbye.")
                break

            elif base == "/help":
                print(f"\n{_CYAN}{_BOLD}Commands{_RESET}")
                print("  /load <filepath>   Load and analyze an event log file")
                print("  /reload            Re-analyze the last loaded file")
                print("  /help              Show this help")
                print("  /quit, /exit       Exit")
                print()

            elif base == "/load":
                if len(cmd) < 2:
                    print("  Usage: /load <filepath>")
                    continue
                fpath = " ".join(cmd[1:])
                fp = Path(fpath).expanduser()
                if not fp.exists():
                    print(f"  File not found: {fp}")
                    continue
                try:
                    events = parse_log(str(fp))
                except Exception as ex:
                    print(f"  Error parsing file: {ex}")
                    continue
                loaded = (str(fp), events)
                analyze(events, str(fp))

            elif base == "/reload":
                if loaded is None:
                    print("  No file loaded yet. Use /load <filepath>")
                    continue
                fpath, _ = loaded
                try:
                    events = parse_log(fpath)
                except Exception as ex:
                    print(f"  Error re-parsing file: {ex}")
                    continue
                loaded = (fpath, events)
                analyze(events, fpath)

            else:
                print(f"  Unknown command: {base}. Type /help for commands.")

        else:
            if loaded is None:
                print("  No data loaded. Use /load <filepath> first.")
                continue
            _, events = loaded
            q = line.lower()
            matches = [e for e in events if q in str(e).lower()]
            if not matches:
                print(f"  No matches for: {line}")
                continue
            print(f"  {_BOLD}{len(matches):,} matches{_RESET} for \"{line}\":")
            for e in matches[:50]:
                dt = e.get("Date/Time", e.get("DateTime", ""))
                n = node(e)
                d = desc(e)[:120]
                print(f"  {dt}  {n}  {d}")
            if len(matches) > 50:
                print(f"  {_DIM}... and {len(matches) - 50} more{_RESET}")


def main():
    if len(sys.argv) >= 2:
        filepath = sys.argv[1]
        if not Path(filepath).exists():
            print(f"File not found: {filepath}")
            sys.exit(1)
        print(f"\n{_BOLD}DeltaV Event Log Analyzer v4{_RESET}")
        events = parse_log(filepath)
        analyze(events, filepath)
    else:
        _repl()


if __name__ == "__main__":
    main()
