#!/usr/bin/env python3
"""
Summarize DeltaV event log analysis using local Ollama + structured JSON.
Parses the event file, builds a structured data payload, sends to granite4.1:3b.
The model reads structured data rather than formatted text, so it can weigh
all sections fairly instead of latching onto whatever comes first.

Usage:
    python summarize_analysis.py /path/to/event_log.txt
"""

import sys
import json
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime, timedelta

OLLAMA_URL = "http://172.29.64.1:11434/api/generate"
MODEL = "analysis:base"


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

        rows.append(event)

    rows.sort(key=lambda r: r.get("_dt") or datetime.min)
    return rows


def node(e: dict) -> str:
    return e.get("Node Name", e.get("Node", "?"))


def mod(e: dict) -> str:
    return e.get("Module Name", e.get("Module", ""))


def desc(e: dict) -> str:
    return str(e.get("Description", e.get("Desc2", e.get("Desc1", e.get("Alarm Description", "")))))


def _node_refs(events: list) -> dict:
    """Detect which nodes reference OTHER nodes in event descriptions.
    Returns downstream_deps: {node: [other_nodes_it_references]}"""
    deps = defaultdict(set)
    for e in events:
        n = node(e)
        d = desc(e)
        # Check if description references another known node
        for other in set(node(e2) for e2 in events):
            if other != n and other in d:
                deps[n].add(other)
    return {n: sorted(r) for n, r in sorted(deps.items())}


def _unrecovered_outages(stby_events: list) -> list:
    """Find standby failure events at the end of each node's timeline
    that never got a matching recovery event."""
    stby_sorted = sorted([e for e in stby_events if e.get("_dt")], key=lambda x: x["_dt"])
    by_node = defaultdict(list)
    for e in stby_sorted:
        by_node[node(e)].append(e)

    unrecovered = []
    for n, evts in by_node.items():
        i = 0
        while i < len(evts):
            d = desc(evts[i]).upper()
            if "UNAVAILABLE" in d or "FAILOVER" in d or ("STANDBY" in d and "NOT" in d):
                down_dt = evts[i].get("_dt")
                found_recovery = False
                for j in range(i + 1, len(evts)):
                    next_d = desc(evts[j]).upper()
                    if "AVAILABLE" in next_d or "PRIMARY" in next_d:
                        found_recovery = True
                        i = j
                        break
                if not found_recovery:
                    unrecovered.append({
                        "node": n,
                        "down_time": str(down_dt),
                        "description": desc(evts[i])[:100],
                    })
            i += 1
    return unrecovered


def build_json_summary(events: list, filename: str) -> dict:
    """Build a structured JSON payload for the LLM."""
    total = len(events)
    node_set = set(node(e) for e in events)

    # Timespan
    times = sorted([e["_dt"] for e in events if e.get("_dt")])
    timespan = {"start": str(times[0]), "end": str(times[-1])} if len(times) >= 2 else {}

    # Priority breakdown
    prio = dict(Counter(e.get("Level", "") for e in events if e.get("Level", "")))

    # Categorized events
    alarms   = [e for e in events if e.get("Level", "").strip() or "ALARM" in str(e.get("Event Type", "")).upper()]
    stby     = [e for e in events if "STANDBY" in desc(e).upper() or "FAILOVER" in desc(e).upper()
                or "UNAVAILABLE" in desc(e).upper() or "AVAILABLE" in desc(e).upper()
                or "SECONDARY" in desc(e).upper() or "redundancy" in desc(e).lower()]
    bad      = [e for e in events if "BAD" in str(e.get("State", "")).upper() or "FAIL" in str(e.get("State", "")).upper()]
    acn      = [e for e in events if "ACN COMM" in str(e.get("Parameter", e.get("Param", ""))).upper()]
    el       = [e for e in events if "LIMIT" in str(e.get("State", "")).upper()]
    otf      = [e for e in events if "Transfer Failure" in desc(e)]
    hart     = [e for e in events if "HART" in desc(e).upper()]
    proc     = [e for e in events if e.get("Category", "") == "PROCESS"]
    crit     = [e for e in events if "CRITICAL" in str(e.get("Level", "")).upper()]

    # Top nodes
    top_nodes = [{"node": n, "events": c} for n, c in Counter(node(e) for e in events).most_common(10)]

    # --- Causal analysis ---
    # Which nodes reference other nodes in failure descriptions
    refs = _node_refs(events)

    # Connection failures: which nodes are the TARGET of device connection failures
    conn_fail_targets = Counter()
    for e in events:
        d = desc(e)
        if "Connection Failure" in d or "Connection Opened" in d:
            for tok in d.split():
                if tok in node_set and tok != node(e):
                    conn_fail_targets[tok] += 1

    # Node role: categorize what each node primarily does in the event stream
    node_event_types = {}
    for n in sorted(node_set):
        n_events = [e for e in events if node(e) == n]
        n_alarms = sum(1 for e in n_events if "CRITICAL" in str(e.get("Level", "")).upper())
        n_conn_fail = sum(1 for e in n_events if "Connection Failure" in desc(e) or "Connection Opened" in desc(e))
        n_stby = sum(1 for e in n_events if "STANDBY" in desc(e).upper() or "FAILOVER" in desc(e).upper()
                      or "UNAVAILABLE" in desc(e).upper())
        n_io_fail = sum(1 for e in n_events if "I/O Input Failure" in desc(e) or "I/O Output Failure" in desc(e)
                        or "Transfer Failure" in desc(e) or "Module Failure" in desc(e))
        n_self_referenced = sum(1 for r_tgt, cnt in conn_fail_targets.items() if r_tgt == n)
        n_dep_references = sum(1 for src, tgts in refs.items() if n in tgts)

        roles = []
        if n_stby > 10:
            roles.append("standby_failures")
        if n_io_fail > 10:
            roles.append("io_failures")
        if n_conn_fail > 10:
            roles.append("connection_failures_downstream")
        if n_dep_references > 2 and n_self_referenced == 0:
            roles.append("downstream_consumer")
        if n_self_referenced > 10:
            roles.append("connection_failure_target")
        if not roles:
            roles.append("other")
        node_event_types[n] = {
            "total_events": len(n_events),
            "critical_alarms": n_alarms,
            "standby_events": n_stby,
            "io_failure_events": n_io_fail,
            "connection_failure_events": n_conn_fail,
            "referenced_as_failure_target": n_self_referenced,
            "roles": roles,
        }

    # --- Standby recovery summary ---
    standby_info = None
    if stby:
        stby_sorted = sorted([e for e in stby if e.get("_dt")], key=lambda x: x["_dt"])
        by_node = defaultdict(list)
        for e in stby_sorted:
            by_node[node(e)].append(e)

        recovery = []
        unrecovered = []
        for n, evts in by_node.items():
            i = 0
            while i < len(evts):
                d = desc(evts[i]).upper()
                if "UNAVAILABLE" in d or "FAILOVER" in d or ("STANDBY" in d and "NOT" in d):
                    down_dt = evts[i].get("_dt")
                    found_recovery = False
                    for j in range(i + 1, len(evts)):
                        next_d = desc(evts[j]).upper()
                        if "AVAILABLE" in next_d or "PRIMARY" in next_d:
                            up_dt = evts[j].get("_dt")
                            if down_dt and up_dt:
                                secs = (up_dt - down_dt).total_seconds()
                                recovery.append({
                                    "node": n, "downtime_secs": int(secs),
                                    "downtime_min": round(secs / 60, 1),
                                    "down_time": str(down_dt), "up_time": str(up_dt),
                                })
                            found_recovery = True
                            i = j
                            break
                    if not found_recovery:
                        unrecovered.append({
                            "node": n,
                            "down_time": str(down_dt),
                            "description": desc(evts[i])[:100],
                        })
                    i += 1
                else:
                    i += 1

        if recovery:
            avg_min = sum(r["downtime_min"] for r in recovery) / len(recovery)
            total_min = sum(r["downtime_min"] for r in recovery)
            standby_info = {
                "total_events": len(stby),
                "nodes_affected": len(by_node),
                "nodes_with_standby_activity": sorted(by_node.keys()),
                "recovery_summary": {
                    "total_paired_outages": len(recovery),
                    "avg_downtime_min": round(avg_min, 1),
                    "total_downtime_min": round(total_min, 1),
                    "max_downtime_secs": max(r["downtime_secs"] for r in recovery),
                },
                "unrecovered_outages": unrecovered,
                "outages": recovery,
            }
        else:
            standby_info = {
                "total_events": len(stby),
                "nodes_affected": len(by_node),
                "nodes_with_standby_activity": sorted(by_node.keys()),
                "recovery_summary": "No clear recovery pairs found",
                "unrecovered_outages": unrecovered,
                "outages": [],
            }

    # Top alarm descriptions
    top_alarms = [{"description": d, "count": c}
                  for d, c in Counter(desc(e) for e in alarms).most_common(10)] if alarms else []

    # BAD/FAIL by parameter
    bad_by_param = [{"parameter": p, "count": c}
                    for p, c in Counter(e.get("Parameter", e.get("Param", "")) for e in bad).most_common(10)] if bad else []

    # ACN/device connection patterns
    acn_patterns = [{"node": n, "state": s, "desc": d[:80], "count": c}
                    for (n, s, d), c in Counter(
                        (node(e), e.get("State", ""), desc(e)[:80]) for e in acn
                    ).most_common(5)] if acn else []

    # EVENT_LIMITED by module
    el_by_mod = [{"node": n, "module": m, "count": c}
                 for (n, m), c in Counter((node(e), mod(e)) for e in el).most_common(10)] if el else []

    # OTF by module
    otf_by_mod = [{"node": n, "module": m, "count": c}
                  for (n, m), c in Counter((node(e), mod(e)) for e in otf).most_common(10)] if otf else []

    # HART
    hart_by_desc = [{"description": d, "count": c}
                    for d, c in Counter(desc(e)[:80] for e in hart).most_common(5)] if hart else []

    # Process
    proc_by_node = [{"node": n, "module": m, "description": d, "count": c}
                    for (n, m, d), c in Counter(
                        (node(e), mod(e), desc(e)) for e in proc
                    ).most_common(10)] if proc else []

    # Top overall patterns
    top_patterns = [{"node": n, "parameter": p, "state": s, "description": d[:80], "count": c}
                    for (n, p, s, d), c in Counter(
                        (node(e), e.get("Parameter", e.get("Param", "")),
                         e.get("State", ""), desc(e)[:80])
                        for e in events
                    ).most_common(10)]

    return {
        "file": filename,
        "total_events": total,
        "total_nodes": len(node_set),
        "timespan": timespan,
        "node_list": sorted(node_set),
        "top_nodes": top_nodes,
        "node_event_types": node_event_types,
        "downstream_references": refs,
        "connection_failure_targets": dict(conn_fail_targets.most_common(10)),
        "priority": prio,
        "analysis_hints": {
            "has_unrecovered_outages": len(stby) > 0 and bool(standby_info and standby_info.get("unrecovered_outages")),
            "has_connection_failure_targets": bool(conn_fail_targets),
            "has_paired_outages": bool(standby_info and standby_info.get("outages")),
            "likely_normal_operations": bool(
                not (stby and standby_info and standby_info.get("unrecovered_outages"))
                and not conn_fail_targets
            ),
        },
        "critical_alarms": len(crit),
        "sections": {
            "alarms": {
                "count": len(alarms),
                "top_descriptions": top_alarms,
            },
            "standby_redundancy": standby_info,
            "bad_failure": {
                "count": len(bad),
                "top_parameters": bad_by_param,
            },
            "device_connection_events": {
                "count": len(acn),
                "patterns": acn_patterns,
            },
            "event_limited": {
                "count": len(el),
                "by_module": el_by_mod,
            },
            "outputs_transfer_failure": {
                "count": len(otf),
                "by_module": otf_by_mod,
            },
            "hart": {
                "count": len(hart),
                "top_descriptions": hart_by_desc,
            },
            "process_events": {
                "count": len(proc),
                "by_module": proc_by_node,
            },
        },
        "top_event_patterns": top_patterns,
    }


def generate_normal_ops_summary(js: dict) -> str:
    """Generate a summary for files with no root cause (normal operations)."""
    nodes = js.get("total_nodes", 0)
    total = js.get("total_events", 0)
    span = js.get("timespan", {})
    top = js.get("top_nodes", [])[:3]
    prio = js.get("priority", {})
    stby = js.get("sections", {}).get("standby_redundancy", {})

    top_desc = ", ".join(f"{n['node']} ({n['events']} events)" for n in top)
    top_prio = ", ".join(f"{k}: {v}" for k, v in sorted(prio.items(), key=lambda x: -x[1])[:3])

    lines = []
    lines.append("### Root Cause")
    lines.append("No root cause identified. The data shows no unrecovered outages and no connection failure targets.")
    lines.append("")

    lines.append("### Scope")
    lines.append(f"- **{nodes} nodes** generated **{total} events** across the time window.")
    lines.append(f"- Highest activity: {top_desc}")
    if top_prio:
        lines.append(f"- Priority breakdown: {top_prio}")
    if stby:
        lines.append(f"- {stby.get('total_events', 0)} standby/redundancy events (all recovered).")
    lines.append("")

    lines.append("### Risk")
    if total < 500:
        lines.append("Low. Normal operational event volume with no unrecovered failures.")
    elif total < 2000:
        lines.append("Low to moderate. Elevated event volume but no unrecovered failures — likely reflects a planned activity (shutdown, startup, batch transition).")
    else:
        lines.append("Low. High event volume without unrecovered failures suggests a controlled process (shutdown, startup) rather than equipment failure.")
    lines.append("")

    lines.append("### Recommendation")
    lines.append("No action required — normal operating pattern. Review event timestamps to confirm if this was a planned shutdown/startup.")

    return "\n".join(lines)


def summarize(json_data: dict) -> str:
    hints = json_data.get("analysis_hints", {})

    # Short-circuit: if likely normal operations, generate summary without model
    if hints.get("likely_normal_operations", False):
        return generate_normal_ops_summary(json_data)
    payload = json.dumps({
        "model": MODEL,
        "prompt": f"""Here is the structured event log data in JSON:

{json.dumps(json_data, indent=2)}

ANALYZE CAUSALLY, NOT JUST BY VOLUME. START with the `analysis_hints` field — it tells you the ground truth about root causes. Work through these steps:

0. **READ ANALYSIS_HINTS FIRST**: Check `analysis_hints.likely_normal_operations`. If TRUE, there are NO unrecovered outages and NO connection failures — the data reflects normal operations (startup, shutdown, maintenance). Do NOT invent a root cause. Describe what the event data actually shows.

1. **IDENTIFY THE SOURCE NODE** (only if `analysis_hints.has_unrecovered_outages` is TRUE): Look at `standby_redundancy.unrecovered_outages` for nodes with failures that NEVER recovered. Then check `connection_failure_targets` for nodes targeted by connection failures.

2. **NO ROOT CAUSE = NORMAL STATE**: If there are NO unrecovered outages AND connection_failure_targets is empty, the event stream likely reflects normal operations (startup, shutdown, scheduled maintenance). Say so clearly instead of forcing a root cause.

3. **DOWNSTREAM EFFECTS ARE NOT ROOT CAUSES**: Nodes with I/O Input Failure, Transfer Failure, or Module Failure that also appear in `downstream_references` are downstream victims. Their event volume is a consequence, not a cause.

4. **PERMANENT FAILURES OVERRIDE INTERMITTENT**: A node with unrecovered outages (never came back) is more significant than one with many events that all recovered.

5. **CHECK STANDBY/REDUNDANCY**: Look at `standby_redundancy.outages` for the actual failure timeline. Multiple short-duration outages followed by longer ones suggests a flapping failure.

Now produce a concise summary with these exact sections:

1. **Root Cause**: Name the specific root node(s) and failure description using exact node names from the data. Distinguish root cause from downstream effects. If no root cause exists, state that the data shows no unrecovered failures and describe the actual event pattern observed (e.g. controlled shutdown, startup sequencing, normal operations).

2. **Scope**: How many nodes show the primary failure pattern vs how many are downstream victims. If no failure pattern exists, describe the node activity distribution.

3. **Risk**: Immediate operational risk given unrecovered status and event severity. If no risk (normal operations), say so.

4. **Recommendation**: Specific next steps. If the root cause is a WIOC with wireless radio coverage issues, say that. If it's an ACN path failure, say that. If no action is needed, say "No action required — normal operating pattern.\"""",
        "stream": False,
        "options": {
            "temperature": 0.4,
            "num_predict": 1024,
        },
    }).encode()

    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read())
            return result.get("response", "").strip()
    except Exception as e:
        return f"[Ollama error] {e}"


def main():
    if len(sys.argv) < 2:
        print("Usage: python summarize_analysis.py <event_log_file>")
        sys.exit(1)

    path = sys.argv[1]
    if not Path(path).exists():
        print(f"File not found: {path}")
        sys.exit(1)

    print("Parsing events...", file=sys.stderr)
    events = parse_log(path)
    print(f"Parsed {len(events):,} events.", file=sys.stderr)

    print("Building structured JSON...", file=sys.stderr)
    json_data = build_json_summary(events, path)

    print("Sending to Ollama (analysis:base)...", file=sys.stderr)
    summary = summarize(json_data)

    print("\n" + "=" * 60)
    print(summary)
    print("=" * 60)


if __name__ == "__main__":
    main()
