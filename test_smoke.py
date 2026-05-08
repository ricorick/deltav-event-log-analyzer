"""Smoke test matching actual DeltaVEventLog API."""
import sys
sys.path.insert(0, '/mnt/c/Users/rickc/Hermes_Safe_Zone/deltav-analyzer')
from analyzer import DeltaVEventLog

path = '/mnt/c/Users/rickc/Hermes_Safe_Zone/event_logs/Events202656121944.txt'
log = DeltaVEventLog(path)

t = log.total_events()
tr = log.time_range()
types = dict(log.event_type_summary())
cats = dict(log.category_summary())

# Core stats
assert t == 4621
assert "05/02/2026" in tr[0]
assert "05/06/2026" in tr[1]
assert types["EVENT"] == 3491
assert types["ALARM"] == 472
assert types["CHANGE"] == 524
assert types["STATUS"] == 95

# Categories
assert "SYSTEM" in cats
assert "PROCESS" in cats
assert "USER" in cats
assert "HARDWARE" in cats
assert "INTERLOCK" in cats

# Pattern detection
acn = log.acn_switches()
assert acn["total"] == 2746, f"ACN: {acn['total']}"
assert acn["pairs_detected"] >= 0

bi = log.bad_integrity()
assert bi["total"] == 47, f"BAD INTEGRITY: {bi['total']}"
assert len(bi["by_parameter"]) >= 4

stby = log.standby_events()
assert stby["total"] == 75
assert stby["recovery_pairs"] == 37

il = log.interlock_cycling()
assert il["total"] == 130, f"Interlocks: {il['total']}"
assert len(il["by_module"]) >= 11

io = log.io_failures()
assert io["total"] == 19, f"I/O failures: {io['total']}"

el = log.event_limited()
assert el["total"] == 3

sec = log.security_events()
assert sec["total"] == 7

hart = log.hart_events()
assert len(hart) >= 0

hw = log.hardware_alarms()
assert hw["total"] == 65

proc = log.process_events()
assert proc["total"] > 0

# Filtering
node_events = log.events_for_node("52CIOCSJB07")
assert len(node_events) > 0

matched = log.events_matching(node="52CIOCSJB07", event_type="EVENT")
assert len(matched) > 0

# Summary methods
assert len(types) >= 7
assert len(cats) >= 12

nodes = log.node_summary()
assert len(nodes) >= 10
assert nodes[0][1] >= nodes[-1][1]  # sorted desc

alarms = log.alarm_summary()
assert alarms["total"] == 472
assert len(alarms["by_description"]) > 50

# Full analysis
d = log.comprehensive_analysis()
assert d["total_events"] == 4621
assert dict(d["event_types"])["EVENT"] == 3491

json_out = log.to_json()
assert '"total_events": 4621' in json_out

print(f"ALL TESTS PASSED")
print(f"  {t} events | {tr[0]} → {tr[1]}")
print(f"  EVENTS={types['EVENT']}  ALARMS={types['ALARM']}  CHANGES={types['CHANGE']}  STATUS={types['STATUS']}")
print(f"  ACN switches: {acn['total']}  BAD INTEGRITY: {bi['total']}  Standby: {stby['total']}")
print(f"  Recovery pairs: {stby['recovery_pairs']}  Interlock cycles: {il['total']}")
print(f"  I/O failures: {io['total']}  EVENT LIMITED: {el['total']}  Security: {sec['total']}")
print(f"  HART events: {len(hart)}  Hardware alarms: {hw['total']}")
