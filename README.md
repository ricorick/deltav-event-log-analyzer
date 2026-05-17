# DeltaV Event Log Analyzer

Offline analysis toolkit for DeltaV DCS event log TSV exports. Parse, filter,
summarize, and export structured reports. Optional LLM-powered root-cause
analysis via a local Ollama model — no cloud calls.

Runs anywhere with Python 3.10+ stdlib. Zero pip required for basic usage.

---

## Quick Start

```bash
# Interactive REPL
python analyze_core.py /path/to/event_log.txt

# One-shot mode (load + summary, then exit)
python analyze_core.py /load event_log.txt /summary

# LLM-powered root-cause analysis (requires local Ollama)
python summarize_analysis.py /path/to/event_log.txt

# Operational health assessment (requires local Ollama)
python ops_analyzer.py /path/to/event_log.txt
```

---

## File Reference

**`analyze_core.py`** — THE canonical parser. Single source of truth for all
event log parsing. Standalone — contains its own parser, analysis logic, and
interactive REPL. Run it with or without a file argument.

| Mode | Command |
|------|---------|
| Interactive | `python analyze_core.py` |
| One-shot | `python analyze_core.py event_log.txt` |
| Auto-load | `python analyze_core.py /load path/to/file` |

**`summarize_analysis.py`** — Consumes the output of `analyze_core.py` (no
duplicate parsing). Sends structured event data to a local Ollama model for
causal root-cause analysis. Uses `analysis:14b` (qwen2.5:14b).

**`ops_analyzer.py`** — Operational health assessment tool. Scores event logs
0-100 using hard-coded deduction rules plus LLM narrative. Designed for
routine health checks rather than incident RCA. Uses `analysis:14b` directly.

**`repl.py`** — Earlier REPL implementation. Contains its own (now-deprecated)
parser. Maintaining for reference only — new work should use `analyze_core.py`.

**`v1_analyze_events.py`**, **`v2_analyze_events.py`**, **`v3_analyze_events.py`** —
Historical development versions. Preserved for collaboration reference only.
All deprecated.

**`test_*.py`** — Test scripts. Run with any Python 3.10+.

---

## REPL Commands (analyze_core.py)

```
/load <path>   Load a DeltaV event log TSV file
/summary       Full comprehensive analysis
/brief         Quick overview stats
/node <name>   Show all events for a specific node
/acn           ACN COMM network switch analysis
/bad           BAD INTEGRITY analysis
/cascade       Port Cascade analysis — identifies WIOC-hopping cascading port errors
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

---

## LLM Root-Cause Analysis

```bash
# Prerequisites
ollama pull qwen2.5:14b
ollama create analysis:14b -f Modelfiles/analysis_14b

# Run analysis
python summarize_analysis.py event_log.txt

# Or run ops health check
python ops_analyzer.py event_log.txt
```

The script:
1. Consumes parsed output from `analyze_core.py` output
2. Classifies events into issue categories (ACN storms, BAD INTEGRITY, connection failures)
3. Sends structured JSON to the local model for root-cause identification
4. Outputs a severity-graded report with evidence links back to raw events

No data leaves your machine.

---

## Model History

| Period | Model | Notes |
|--------|-------|-------|
| Initial | analysis:base (qwen2.5:3b) | Severely truncated output, hallucinated counts |
| Upgrade 1 | analysis:7b (qwen2.5:7b) | Reliable, ~4.7 GB, ~18 tok/s on iGPU |
| Current | analysis:14b (qwen2.5:14b) | Best accuracy, ~9 GB, handles 29K prompt. See README_UPDATES.md |
| Rejected | qwen3.5:9b | HTTP 500 OOM on large prompts, hallucinated ghost nodes, QwQ output quirks |

---

## Analysis Priority

Reports organize findings by operational impact:

1. **ACN COMM Network Instability** — switch counts, dominant nodes, timing
2. **Cascade Port Errors** — WIOC-hopping cascading failures (collateral from ACN flapping)
3. **BAD INTEGRITY** — which nodes, still bad vs resolved
4. **Standby/Redundancy** — recovery times, pattern detection
5. **I/O Failures** — transfer failures by module
6. **Interlock Cycling** — modules cycling, tracking conditions
7. **Hardware Alarms** — hardware category breakdown
8. **Security Events** — failed logon attempts
9. **Process Events** — deviation alarms, tracking

---

## Cross-Platform

Copy the folder to any machine with Python 3.10+. Works on Windows, Linux,
macOS. No WSL needed on Windows — pure Python stdlib.

```bash
# Windows (native Python, no WSL)
python analyze_core.py C:\path\to\event_log.txt

# Linux / macOS
python3 analyze_core.py /path/to/event_log.txt
```

---

## License

MIT
