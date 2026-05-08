# DeltaV Event Log Analyzer

Offline analysis toolkit for DeltaV DCS event log TSV exports. Parse, filter,
summarize, and export structured reports. Optional LLM-powered root-cause
analysis via a local Ollama model — no cloud calls.

Runs anywhere with Python 3.10+ stdlib. Zero pip required for basic usage.

---

## Quick Start

```bash
# REPL — browse and analyze a log interactively
python repl.py /path/to/event_log.txt

# One-shot summary to stdout
python repl.py /load event_log.txt /summary

# Analyzer module — scriptable from Python
python -c "
from analyzer import DeltaVEventLog
log = DeltaVEventLog('event_log.txt')
print(log.to_json())
" > report.json

# LLM-powered root-cause analysis (requires local Ollama)
python summarize_analysis.py /path/to/event_log.txt
```

---

## Project Structure

### Current tools (recommended)

| File | Purpose |
|------|---------|
| `analyzer.py` | Core engine — `DeltaVEventLog` class. Parses TSV, detects ACN switches, BAD INTEGRITY, standby recovery, interlock cycling, alarm storms, EVENT_LIMITED, HART failures, I/O transfer errors. Pure stdlib, no deps. |
| `repl.py` | Interactive shell built on `analyzer.py`. Colorized terminal output, `/` commands for drill-down, `/export` to JSON. Also runs in one-shot mode. |
| `summarize_analysis.py` | Builds structured JSON from event data, sends to a local Ollama model for causal root-cause analysis. Uses `analysis:base` model (qwen2.5:3b tuned for this task). Produces severity-graded summaries with evidence links. |

### Development history (v1–v4)

Standalone scripts that evolved into the modular architecture above. Kept in
the repo for collaboration and reference:

| File | Lines | What it does |
|------|-------|-------------|
| `v1_analyze_events.py` | ~390 | First pass — basic TSV parse + event type counts |
| `v2_analyze_events.py` | ~360 | Added node-level drill-down, /node, /bad, /acn commands |
| `v3_analyze_events.py` | ~410 | Compressed output mode, ANSI color, /export to JSON |
| `v4_analyze_events.py` | ~426 | Pre-analyzer refactor. /summary cross-references ACN + BAD + standby. Ollama pipe-out support |

### Test files

All stdlib-only. Run with any Python 3.10+:

```bash
python test_smoke.py      # basic parse + summary smoke test
python test_repl.py       # REPL command routing
python test_windows.py    # Windows line-ending compat
python test_condensed.py  # compression/condensed output
python test_models.py     # model loading
python test_qwen25.py     # qwen2.5-specific tests
```

---

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

---

## LLM Root-Cause Analysis

`summarize_analysis.py` sends structured event data to a local Ollama instance
for causal analysis. It uses a custom `analysis:base` model (built on qwen2.5:3b
with an optimized system prompt).

```bash
# Prerequisites
ollama pull qwen2.5:3b
ollama create analysis:base -f Modelfiles/analysis   # if Modelfile exists locally

# Run analysis
python summarize_analysis.py event_log.txt
```

The script:
1. Parses and structures the event log into a compact JSON payload
2. Classifies events into issue categories (ACN storms, BAD INTEGRITY, connection failures, etc.)
3. Sends to the local model for root-cause identification
4. Outputs a severity-graded report with evidence links back to the raw events

No data leaves your machine — all model inference stays local.

### Hints for good results

The model uses an `analysis_hints` system that short-circuits on "normal
operations" when no unrecovered outages or connection failures are detected.
This avoids hallucinated root causes on clean logs.

For 3B-class models: do not embed example output templates in prompts —
they parrot templates instead of reasoning. The tool handles this via a
structured prompt strategy.

---

## Output Structure

The `/summary` command and `summarize_analysis.py` both organize findings by
priority:

1. **ACN COMM Network Instability** — switch counts, dominant nodes, timing
2. **BAD INTEGRITY** — which nodes, still bad vs resolved
3. **Standby/Redundancy** — recovery times, pattern detection
4. **I/O Failures** — transfer failures by module
5. **Interlock Cycling** — modules cycling, tracking conditions
6. **Hardware Alarms** — hardware category breakdown
7. **Security Events** — failed logon attempts
8. **Process Events** — deviation alarms, tracking

---

## Cross-Platform

Copy the `deltav-analyzer/` folder to any machine with Python 3.10+.
Works on Windows, Linux, macOS. No WSL needed on Windows — pure Python.

```bash
# Windows (native Python, no WSL required)
python repl.py C:\path\to\event_log.txt

# Linux / macOS
python3 repl.py /path/to/event_log.txt
```

Optional dependency: `pip install prompt_toolkit` enables tab completion,
command history, and Vi-mode editing in the REPL.

---

## License

MIT — do what you want with it.
