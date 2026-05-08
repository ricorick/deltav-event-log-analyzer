import json, sys
sys.path.insert(0, '.')
from analyzer import DeltaVEventLog

log = DeltaVEventLog('/mnt/c/Users/rickc/Hermes_Safe_Zone/event_logs/Events202656121944.txt')
raw = json.loads(log.to_json())

# Build a concise summary - trim verbose lists, keep signal
out = {
    "file": raw["file"],
    "total_events": raw["total_events"],
    "time_range": raw["time_range"],
    "event_types": dict(raw["event_types"]),
    "acn_switches": {
        "total": raw["acn_switches"]["total"],
        "top_nodes": [n for n, c in raw["acn_switches"]["by_node"][:5]]
    },
    "bad_integrity": {
        "total": raw["bad_integrity"]["total"],
        "details": raw["bad_integrity"]["by_parameter"][:10]
    },
    "standby": {
        "total_pairs": raw["standby"]["recovery_pairs"],
        "unavailable": raw["standby"]["unavailable_count"],
        "available": raw["standby"]["available_count"],
        "avg_recovery_min": raw["standby"]["avg_recovery_minutes"],
        "max_recovery_hrs": raw["standby"]["max_recovery_hours"]
    },
    "interlocks": {
        "total": raw["interlocks"]["total"],
        "top_modules": raw["interlocks"]["by_module"][:5]
    },
    "io_failures": raw["io_failures"]["total"],
    "event_limited": raw["event_limited"]["total"],
    "security": raw["security"]["total"],
    "top_patterns": raw["top_patterns"][:10]
}

condensed = json.dumps(out, indent=0)
print(condensed)
print(f"\n---LEN:{len(condensed)}", file=sys.stderr)
