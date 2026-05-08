"""Windows-side test: verify analyzer loads and processes data."""
import sys, os, json

# Detect script directory for relative path resolution
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

from analyzer import DeltaVEventLog

# Map relative C: drive path
log_path = r"C:\Users\rickc\Hermes_Safe_Zone\event_logs\Events202656121944.txt"

if not os.path.exists(log_path):
    # Try with Hermes_Safe_Zone directly
    alt = os.path.join(script_dir, "..", "event_logs", "Events202656121944.txt")
    if os.path.exists(alt):
        log_path = os.path.abspath(alt)
    else:
        print(f"File not found at {log_path} or {alt}")
        sys.exit(1)

print(f"Loading: {log_path}")
log = DeltaVEventLog(log_path)
print(f"Python: {sys.version}")

d = log.comprehensive_analysis()
print(f"Events: {d['total_events']}")
print(f"Range: {d['time_range']}")
print(f"Event types: {dict(d['event_types'])}")
print(f"ACN switches: {d['acn_switches']['total']}")
print(f"Standby pairs: {d['standby']['recovery_pairs']}")
print(f"Interlock cycles: {d['interlocks']['total']}")
print()
print("ALL WIN TESTS PASSED")
