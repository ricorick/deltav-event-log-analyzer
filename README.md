# DeltaV Event Log Analyzer

Local analysis tool for DeltaV DCS event log exports (TSV format).
No cloud calls. All processing is offline.

## Quick Start

```bash
# No dependencies needed for basic usage
python3 repl.py /path/to/event_log.txt

# Or for the full REPL experience:
pip install prompt_toolkit
python3 repl.py
```

## REPL Commands

```
/load <path>   Load a DeltaV event log TSV file
/summary       Full comprehensive analysis
/brief         Quick overview stats
/node <name>   Show all events for a specific node
/acn           ACN COMM network switch analysis
/bad           BAD INTEGRITY analysis
/standby       Standby/redundancy recovery analysis
/alarms        Alarm summary
/interlocks    Interlock cycling analysis
/io            I/O transfer failures
/hart          HART-related events
/limited       EVENT_LIMITED (buffer overflow) events
/hardware      Hardware category alarms
/process       Process events
/security      Security events (failed logons)
/top <n>       Top N event patterns (default 20)
/export <path> Export comprehensive analysis as JSON
/filter <k=v>  Filter events by column
/clear         Clear screen
/help          Show help
/quit          Exit
```

## One-Shot Mode

```bash
python3 repl.py event_log.txt    # Load + brief, then interactive
python3 -c "
from analyzer import DeltaVEventLog
log = DeltaVEventLog('event_log.txt')
print(log.to_json())
" > report.json
```

## Output Structure

The `/summary` command organizes findings by priority:

1. **ACN COMM Network Instability** — switch counts, dominant nodes
2. **BAD INTEGRITY** — which nodes, still bad vs cleared
3. **Standby/Redundancy** — recovery times, pattern detection
4. **I/O Failures** — transfer failures by module
5. **Interlock Cycling** — modules cycling tracking conditions
6. **Hardware Alarms** — hardware category breakdown
7. **Security Events** — failed logon attempts
8. **Process Events** — deviation alarms, tracking

## Export for LLM Analysis

```bash
# Export structured data for a local Ollama model
python3 repl.py event_log.txt
> /export report.json
> /quit

# Then pipe to a local model
cat report.json | ollama run qwen2.5:7b "Analyze this DeltaV event log..."
```

## Moving to Windows

Copy the `deltav-analyzer/` folder to any machine with Python 3.8+.
Install `prompt_toolkit` if you want the nice REPL.
Point `/load` at your event log TSV exports.
No WSL needed on the target machine.
