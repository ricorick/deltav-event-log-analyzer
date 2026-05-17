#!/usr/bin/env python3
"""
ops_analyzer.py — Operational health assessment for DeltaV event logs.

Assumes normal operations unless evidence proves otherwise.
Parses event data, computes health score (0-100), identifies patterns,
and flags anomalies for review. Uses local Ollama (analysis:7b) for
natural-language narrative.

Usage:
    python ops_analyzer.py /path/to/event_log.txt

Output:
    HEALTH SCORE: XX/100
    SUMMARY: ...
    PATTERNS: ...
    ANOMALIES: ...
    RECOMMENDATION: ...

Depends on analyze_core.py (same directory) for parsing.
Kept separate from summarize_analysis.py — different focus, different output.
"""

import sys
import json
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime

# Import parsing core from canonical analyzer (has __main__ guard — safe to import)
from analyze_core import parse_log, node, mod, desc

OLLAMA_URL = "http://172.29.64.1:11434/api/generate"
MODEL = "analysis:14b"


# ── ANALYSIS ───────────────────────────────────────────────────────────


def hourly_volume(events: list) -> dict:
    """Group events by hour of day. Returns {hour: count} and peak info."""
    hourly = Counter()
    for e in events:
        dt = e.get("_dt")
        if dt:
            hourly[dt.hour] += 1
    if not hourly:
        return {}
    peak_hour = max(hourly, key=hourly.get)
    avg = sum(hourly.values()) / max(len(hourly), 1)
    return {
        "distribution": {str(h).zfill(2): hourly[h] for h in sorted(hourly)},
        "peak_hour": f"{peak_hour:02d}:00",
        "peak_count": hourly[peak_hour],
        "hours_active": len(hourly),
        "avg_per_hour": round(avg, 1),
    }


def event_type_distribution(events: list) -> dict:
    """Categorize events into operational types for human-readable output."""
    dist = Counter()
    for e in events:
        cat = e.get("Category", "").strip()
        d = desc(e).upper()
        st = str(e.get("State", "")).upper()

        if "STANDBY" in d or "FAILOVER" in d or "AVAILABLE" in d or "UNAVAILABLE" in d:
            dist["Standby/Redundancy"] += 1
        elif "BAD INTEGRITY" in st or ("FAIL" in st and "TRANSFER" not in d):
            dist["Bad/Failure"] += 1
        elif "TRANSFER FAILURE" in d:
            dist["Output Transfer Failure"] += 1
        elif "HART" in d:
            dist["HART"] += 1
        elif "LIMIT" in st:
            dist["Event Limited (Buffer)"] += 1
        elif "CONNECTION" in d or "ACN COMM" in str(e.get("Parameter", "")).upper():
            dist["Connection/Network"] += 1
        elif cat == "PROCESS" or "TRACKING" in d:
            dist["Process/Tracking"] += 1
        elif cat == "INTERLOCK" or "INTERLOCK" in d:
            dist["Interlock"] += 1
        elif cat == "SECURITY" or "LOGON" in d:
            dist["Security"] += 1
        elif e.get("Event Type", "").strip():
            dist[e["Event Type"].strip()] += 1
        else:
            dist["Other"] += 1
    return {k: v for k, v in dist.most_common()}


def compute_health_score(
    total_events: int,
    unrecovered_outages: list,
    acn_count: int,
    bad_counts_per_node: dict,
    bad_fail_pct: float,
    otf_count: int,
    el_count: int,
) -> tuple:
    """Compute 0-100 health score with calibrated formula.

    Baseline = 85. Deductions for unrecovered outages, ACN storms,
    BAD/FAIL density, I/O transfer failures, and event buffer issues.
    Returns (score, list_of_reason_strings).
    """
    score = 85
    reasons = []
    total = total_events

    # ── Unrecovered outages (January had ~252) ──
    outage_count = len(unrecovered_outages)
    if outage_count > 0:
        if outage_count <= 100:
            score -= 5
        elif outage_count <= 250:
            score -= 10
        else:
            score -= 20
        reasons.append(f"Unrecovered outage(s): {outage_count}")

    # ── ACN COMM percentage (January was 32.6%) ──
    acn_pct = (acn_count / total * 100) if total else 0
    if acn_pct > 35:
        if acn_pct <= 50:
            score -= 10
            reasons.append(f"ACN COMM {acn_pct:.1f}% — elevated")
        else:
            score -= 25
            reasons.append(f"ACN COMM {acn_pct:.1f}% — severe")

    # ── BAD INTEGRITY on worst node (January had 14,469 on 52WIOCDCS02A) ──
    bad_single_node_max = max(bad_counts_per_node.values()) if bad_counts_per_node else 0
    if bad_single_node_max > 15000:
        if bad_single_node_max <= 30000:
            score -= 10
        else:
            score -= 20
        reasons.append(f"Worst-node BAD/FAIL: {bad_single_node_max} events")

    # ── BAD/FAIL percentage (January was ~7.5%) ──
    if bad_fail_pct > 10:
        if bad_fail_pct <= 20:
            score -= 10
        else:
            score -= 25
        reasons.append(f"BAD/FAIL {bad_fail_pct:.1f}%")

    # ── I/O Transfer Failures (January had 90) ──
    if otf_count > 100:
        if otf_count <= 500:
            score -= 5
        else:
            score -= 15
        reasons.append(f"Output Transfer Failures: {otf_count}")

    # ── EVENT_LIMITED (January had 21) ──
    if el_count > 50:
        if el_count <= 200:
            score -= 5
        else:
            score -= 10
        reasons.append(f"EVENT_LIMITED: {el_count}")

    return max(0, min(100, score)), reasons


# ── JSON PAYLOAD ───────────────────────────────────────────────────────


def build_ops_json(events: list, filename: str) -> dict:
    """Build a structured JSON payload focused on operational health."""
    total = len(events)
    nodes_raw = list(set(node(e) for e in events))

    # Timespan
    times = sorted([e["_dt"] for e in events if e.get("_dt")])
    timespan = (
        {"start": str(times[0]), "end": str(times[-1])}
        if len(times) >= 2
        else {}
    )

    # Priority and category breakdowns
    prio = dict(Counter(
        e.get("Level", "") for e in events if e.get("Level", "")
    ))
    cats = dict(Counter(
        e.get("Category", "") for e in events if e.get("Category", "")
    ))

    # Operational view
    op_types = event_type_distribution(events)
    hourly = hourly_volume(events)
    top_nodes = [
        {"node": n, "events": c}
        for n, c in Counter(node(e) for e in events).most_common(10)
    ]

    # ── Category-specific event lists ──
    stby = [
        e for e in events
        if "STANDBY" in desc(e).upper()
        or "FAILOVER" in desc(e).upper()
        or "UNAVAILABLE" in desc(e).upper()
        or "AVAILABLE" in desc(e).upper()
        or "SECONDARY" in desc(e).upper()
    ]
    bad = [
        e for e in events
        if "BAD" in str(e.get("State", "")).upper()
        or "FAIL" in str(e.get("State", "")).upper()
    ]
    acn = [
        e for e in events
        if "ACN COMM" in str(e.get("Parameter", e.get("Param", ""))).upper()
    ]
    el_list = [
        e for e in events
        if "LIMIT" in str(e.get("State", "")).upper()
    ]
    otf_list = [
        e for e in events
        if "Transfer Failure" in desc(e)
    ]
    hart_list = [
        e for e in events
        if "HART" in desc(e).upper()
    ]
    crit = [
        e for e in events
        if "CRITICAL" in str(e.get("Level", "")).upper()
    ]
    io_fail = [
        e for e in events
        if "I/O Input Failure" in desc(e)
        or "I/O Output Failure" in desc(e)
        or "Module Failure" in desc(e)
    ]

    # ── Standby unrecovered check ──
    unrecovered = []
    if stby:
        stby_sorted = sorted(
            [e for e in stby if e.get("_dt")], key=lambda x: x["_dt"]
        )
        by_node = defaultdict(list)
        for e in stby_sorted:
            by_node[node(e)].append(e)
        for n, evts in by_node.items():
            i = 0
            while i < len(evts):
                d = desc(evts[i]).upper()
                if "UNAVAILABLE" in d or "FAILOVER" in d:
                    down_dt = evts[i].get("_dt")
                    found = False
                    for j in range(i + 1, len(evts)):
                        nd = desc(evts[j]).upper()
                        if "AVAILABLE" in nd or "PRIMARY" in nd:
                            found = True
                            i = j
                            break
                    if not found:
                        unrecovered.append({
                            "node": n,
                            "down_time": str(down_dt),
                            "description": desc(evts[i])[:100],
                        })
                i += 1

    # ── Connection failure targets ──
    node_set = set(nodes_raw)
    conn_fail_targets = Counter()
    for e in events:
        d = desc(e)
        if "Connection Failure" in d or "Connection Opened" in d:
            for tok in d.split():
                if tok in node_set and tok != node(e):
                    conn_fail_targets[tok] += 1

    # ── I/O failure clusters ──
    io_by_node = Counter(node(e) for e in io_fail).most_common()
    io_fail_clusters = [n for n, c in io_by_node if c > 10]
    bad_fail_pct = round(len(bad) / total * 100, 1) if total else 0
    critical_pct = round(len(crit) / total * 100, 1) if total else 0

    # ── BAD/FAIL by parameter ──
    bad_by_param = [
        {
            "param": p,
            "count": c,
        }
        for p, c in Counter(
            e.get("Parameter", e.get("Param", "")) for e in bad
        ).most_common(10)
    ] if bad else []

    # ── BAD/FAIL counts per node ──
    bad_counts_per_node = Counter()
    for e in bad:
        bad_counts_per_node[node(e)] += 1

    analysis = {
        "unrecovered_outages": unrecovered,
        "conn_fail_targets": dict(conn_fail_targets.most_common(10)),
        "bad_fail_pct": bad_fail_pct,
        "critical_pct": critical_pct,
        "io_fail_clusters": io_fail_clusters,
        "acn_count": len(acn),
        "otf_count": len(otf_list),
        "el_count": len(el_list),
        "bad_counts_per_node": dict(bad_counts_per_node),
    }

    health_score, deductions = compute_health_score(
        total_events=total,
        unrecovered_outages=unrecovered,
        acn_count=len(acn),
        bad_counts_per_node=dict(bad_counts_per_node),
        bad_fail_pct=bad_fail_pct,
        otf_count=len(otf_list),
        el_count=len(el_list),
    )

    return {
        "file": filename,
        "total_events": total,
        "total_nodes": len(nodes_raw),
        "timespan": timespan,
        "avg_events_per_node": round(total / max(len(nodes_raw), 1), 1),
        "priority": prio,
        "categories": cats,
        "event_types": op_types,
        "hourly_volume": hourly,
        "top_nodes": top_nodes,
        "standby_events": {
            "count": len(stby),
            "unrecovered_outages": unrecovered,
        },
        "bad_failure": {
            "count": len(bad),
            "pct_of_total": bad_fail_pct,
            "top_parameters": bad_by_param,
        },
        "acn_comm": {
            "count": len(acn),
            "significance": (
                "high" if len(acn) > 50
                else "moderate" if len(acn) > 10
                else "low"
            ),
        },
        "event_limited": {"count": len(el_list)},
        "output_transfer_failure": {"count": len(otf_list)},
        "hart": {"count": len(hart_list)},
        "critical_alarms": len(crit),
        "io_failure_clusters": io_fail_clusters,
        "health_score": {
            "value": health_score,
            "deductions": deductions,
        },
    }


# ── LLM SUMMARIZATION ──────────────────────────────────────────────────


def summarize(ops_data: dict) -> str:
    """Send ops data to Ollama; return natural-language summary."""
    hs = ops_data["health_score"]
    hs_line = f"HEALTH SCORE: {hs['value']}/100"

    payload = json.dumps({
        "model": MODEL,
        "prompt": (
            "You are an operational health assessor for a DeltaV DCS plant. "
            "Your job: look at the pre-computed health score and the structured "
            "event data, then write a clear, concise operational summary.\n\n"
            "Here is the structured event log data in JSON:\n\n"
            f"{json.dumps(ops_data, indent=2)}\n\n"
            "RULES:\n"
            f"1. The health score is {hs['value']}/100 — it is already computed "
            "from hard deductions. Do not recompute or argue with it. "
            "Reference it in context.\n"
            "2. DEFAULT ASSUMPTION is normal operations. Only flag something as "
            "an anomaly if the data clearly supports it (unrecovered outages, "
            "high BAD/FAIL %, massive event volumes, etc.).\n"
            "3. Be specific with exact node names and counts from the data. "
            "Do not extrapolate beyond what the data says.\n"
            "4. SUMMARY should describe the overall operational picture: "
            "normal shift, planned event (startup/shutdown), or degraded state.\n"
            "5. PATTERNS should cover: peak activity time, busiest nodes, "
            "dominant event categories. This is observational, not diagnostic.\n"
            "6. ANOMALIES should only list things that clearly drove the health "
            "score down. Use the deduction reasons as your guide. "
            "If score >= 70, say \"None detected.\"\n"
            f"7. RECOMMENDATION: if health score >= 70, say "
            "\"None required — normal operations.\" "
            "If < 70, suggest specific investigation steps based on the data. "
            "Do not give generic advice.\n\n"
            "Output format — one section per line:\n\n"
            f"{hs_line}\n"
            "SUMMARY: <2-3 sentences>\n"
            "PATTERNS: <2-3 sentences>\n"
            "ANOMALIES: <specifics or None detected>\n"
            "RECOMMENDATION: <specific or None required>\n"
        ),
        "stream": True,
    }).encode()

    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        response_text = ""
        with urllib.request.urlopen(req, timeout=600) as resp:
            for line in resp:
                if not line.strip():
                    continue
                chunk = json.loads(line.decode())
                token = chunk.get("response", "")
                print(token, end="", flush=True)
                response_text += token
        print()  # newline after stream ends
        return response_text.strip()
    except Exception as e:
        print()  # newline after any partial stream
        return f"[Ollama error] {e}"


# ── MAIN ───────────────────────────────────────────────────────────────


def main():
    if len(sys.argv) < 2:
        print("Usage: python ops_analyzer.py <event_log_file>")
        sys.exit(1)

    path = sys.argv[1]
    if not Path(path).exists():
        print(f"File not found: {path}")
        sys.exit(1)

    print("Parsing events...", file=sys.stderr)
    events = parse_log(path)
    print(f"Parsed {len(events):,} events.", file=sys.stderr)

    print("Analyzing operational health...", file=sys.stderr)
    ops_data = build_ops_json(events, path)

    hs = ops_data["health_score"]
    print(f"Health score: {hs['value']}/100", file=sys.stderr)
    if hs["deductions"]:
        for d in hs["deductions"]:
            print(f"  -> {d}", file=sys.stderr)

    print(f"Sending to Ollama ({MODEL})...", file=sys.stderr)
    print("\n" + "=" * 60, flush=True)
    summary = summarize(ops_data)
    print("=" * 60)


if __name__ == "__main__":
    main()
