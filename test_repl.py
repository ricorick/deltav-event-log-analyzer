"""Test REPL command handlers directly."""
import sys
sys.path.insert(0, '/mnt/c/Users/rickc/Hermes_Safe_Zone/deltav-analyzer')
import io
from contextlib import redirect_stdout

from analyzer import DeltaVEventLog
from repl import DeltaVRepl

path = '/mnt/c/Users/rickc/Hermes_Safe_Zone/event_logs/Events202656121944.txt'
log = DeltaVEventLog(path)
app = DeltaVRepl()
app.log = log

# Capture output of each command
commands = [
    ("/help", None),
    ("/brief", None),
    ("/summary", None),
    ("/acn", None),
    ("/bad", None),
    ("/standby", None),
    ("/interlocks", None),
    ("/node 52CIOCSJB07", None),
    ("/node 52PK02", None),
    ("/alarms", None),
    ("/top 5", None),
    ("/hardware", None),
    ("/io", None),
    ("/security", None),
    ("/events", None),
    ("/limited", None),
    ("/process", None),
    ("/export /tmp/test_export.json", "/tmp/test_export.json"),
]

for cmd, check_file in commands:
    buf = io.StringIO()
    with redirect_stdout(buf):
        app._handle(cmd)
    output = buf.getvalue()
    lines = len(output.strip().split("\n"))
    status = "OK" if lines > 1 else "SHORT"
    print(f"[{status}] /{cmd.split()[0].lstrip('/')}: {lines} lines")
    # Show first 2 lines as preview
    for line in output.strip().split("\n")[:2]:
        print(f"       {line}")
    if check_file:
        import json
        with open(check_file) as f:
            data = json.load(f)
            print(f"       → {check_file}: {len(data)} keys, total_events={data.get('total_events', 'N/A')}")
    print()

print("ALL REPL COMMANDS EXECUTED SUCCESSFULLY")
