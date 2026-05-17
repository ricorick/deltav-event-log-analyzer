# README Updates — Post-Initial Release

## 14B Model Upgrade

`summarize_analysis.py` and `ops_analyzer.py` now use `analysis:14b`
(built from `qwen2.5:14b`) instead of `analysis:7b` (qwen2.5:7b) or
`analysis:base` (qwen2.5:3b).

### Setup

```powershell
ollama pull qwen2.5:14b

# Create Modelfile at Modelfiles\analysis_14b with:
#   FROM qwen2.5:14b
#   SYSTEM "You are a DeltaV process control expert..."
#   PARAMETER temperature 0.3
#   PARAMETER top_p 0.9
#   PARAMETER repeat_penalty 1.1

ollama create analysis:14b -f .\Modelfiles\analysis_14b
```

After building, verify with:
```powershell
ollama list
# Should show analysis:14b
```

### What Changed (14B vs 7B)

| Setting | 7B | 14B |
|---------|----|-----|
| Model | `analysis:7b` | `analysis:14b` |
| Size | ~4.7 GB | ~9 GB |
| Max tokens | 1536 | 4096 |
| Timeout | 300s | 600s |
| RAM pressure | Low | Significant on shared iGPU VRAM (8GB) |
| Handles 29K prompt | Partial (truncation risk) | Yes — full analysis |
| Hallucinates ghost nodes | No | No |
| HTTP 500 OOM on large prompts | No | No |

### Why 14B

The 7B model could handle most single-incident files but began to struggle
with complex multi-cause scenarios or files with high event counts. The 14B
model reliably processes the full ~29K character prompt that the parser
generates for a 31-node plant file, and produces correct root-cause analysis
without truncation.

### Performance Note

The 14B model is approximately twice the size of 7B. On the AMD Radeon 860M
iGPU (8GB shared VRAM), expect:
- Load time: ~30-60 seconds
- Inference: ~8-12 tok/s (vs ~18 tok/s for 7B)
- First-time load may fail with Vulkan buffer errors — retry once

Run time for a full 31-node plant analysis: ~500-600 seconds.
This is expected — the model is doing genuine analysis, not pattern matching.

### Modelfile iGPU Quirk (Persists from 7B Era)

Custom Modelfiles built FROM 14B models may fail transiently with
`unable to allocate Vulkan0 buffer` while the base `qwen2.5:14b` model
loads fine. Retry. If persistent, use the base model name directly in
the API call — the SYSTEM prompt is overridden by the API payload anyway.

### Keeping 7B as Fallback

`analysis:7b` is preserved. To switch back, change `MODEL` in both
scripts to `"analysis:7b"`.

---

## Model Comparison: qwen3.5:9b Rejected

On 2026-05-16, qwen3.5:9b was tested as a candidate replacement for
analysis:14b. Results:

| Criteria | analysis:14b | qwen3.5:9b |
|----------|-------------|-------------|
| Root cause: 52PK02 | Yes (exact) | Yes |
| Time: 10:44 AM | Yes | Yes |
| Node count: 31 | Yes | Yes |
| Network diagnosis | Yes | Yes |
| Secondary: CIOCSJB06 flapping | Yes | Yes |
| Speed | 531s | N/A (failed) |
| Ghost node hallucination | None | ~30 ghost WIOC nodes |
| Large prompt (29K) | Handles cleanly | HTTP 500 OOM |
| Output format | Standard response | QwQ `thinking` field quirk |

**Verdict:** qwen3.5:9b matched accuracy on the ground-truth file but
cannot handle large event log prompts due to OOM crashes and hallucinates
ghost nodes. Not suitable for this workload. 14B remains the recommended
model.

---

## 7B Model Upgrade

`summarize_analysis.py` now uses `analysis:7b` (built from `qwen2.5:7b`)
instead of `analysis:base` (qwen2.5:3b).

### Setup

```powershell
ollama pull qwen2.5:7b

# Create Modelfile at Modelfiles\analysis_7b with:
#   FROM qwen2.5:7b
#   SYSTEM "You are a DeltaV process control expert..."
#   PARAMETER temperature 0.3
#   PARAMETER top_p 0.9
#   PARAMETER repeat_penalty 1.1

ollama create analysis:7b -f .\Modelfiles\analysis_7b
```

After building, verify with:
```powershell
ollama list
# Should show analysis:7b
```

### What Changed (7B vs 3B)

| Setting | Before (3B) | After (7B) |
|---------|-------------|------------|
| Model | `analysis:base` | `analysis:7b` |
| Temperature | 0.4 | 0.3 |
| Max tokens | 1024 | 1536 |
| Timeout | 120s | 300s |
| Example output in prompt | **Never** — 3B parrots it | **Yes** — 7B adapts values correctly |

### Why 7B (Historical)

The 3B model (qwen2.5:3b) had known limitations:
- Truncated long node names (52WIOCDCS02B -> 52WIOCDS02)
- Hallucinated small counts ("3 unrecovered outages" when data showed exactly 1)
- Could not handle example output templates without copying them verbatim
- Required heavy guardrails and pre-computed short-circuit logic

The 7B model resolved all of these. Example output in prompts now tightens
output format — the model fills in correct values instead of copying placeholders.

### Keeping 3B as Fallback

`analysis:base` is preserved and not deleted. To switch back, change the
`MODEL` variable in `summarize_analysis.py` from `"analysis:7b"` to
`"analysis:base"`.

---

## GPU Acceleration

### Critical: Remove `num_gpu: 0`

If any Python script in this repo contains `"num_gpu": 0` in the Ollama API
call options, the model runs **entirely on CPU** regardless of GPU availability.

This is the single most common cause of perceived slowness with 7B and 14B models.
The scripts do NOT include `num_gpu` — they omit the field entirely, which lets
Ollama auto-detect GPU.

**Check any new or forked scripts for:**
```python
"options": {
    "num_gpu": 0,     # DELETE this line — forces CPU
    "temperature": 0.3,
}
```

### Hardware Context (Current)

- **GPU:** AMD Radeon 860M iGPU (Ryzen AI 7 350, shared 8GB VRAM)
- **Driver:** DirectML on Windows (Ollama auto-detects via DirectX)
- **Expected performance:**
  - 7B (Q4_K_M, ~4.7 GB): ~18 tok/s with GPU, ~3-5 tok/s without
  - 14B (Q4_K_M, ~9 GB): ~8-12 tok/s with GPU (VRAM pressure), ~2-3 tok/s without
- **14B note:** At ~9 GB model size, pressure against the shared 8GB VRAM ceiling
  is unavoidable. Some spillover to system RAM is normal and doesn't prevent
  successful analysis.

### Modelfile iGPU Quirk

Custom Modelfiles built FROM base models may fail transiently with
`unable to allocate Vulkan0 buffer` while the base model loads fine. This is
a GPU memory fragmentation issue on shared-VRAM iGPUs — retrying the same
model load usually succeeds.

**Fix:** Use the base model name directly in the API call when overriding
the system prompt. The Modelfile's SYSTEM prompt is already overridden by
the `prompt` field in the API payload, so there is no functional loss.

---

## ops_analyzer.py — Operational Health Assessment

A sibling tool with a different purpose than root-cause analysis.

### Comparison

| Aspect | `summarize_analysis.py` | `ops_analyzer.py` |
|--------|------------------------|-------------------|
| Purpose | Root-cause analysis | Operational health assessment |
| Default assumption | Something may have failed | Normal operations |
| Output | Root Cause, Scope, Risk, Recommendation | HEALTH SCORE, Summary, Patterns, Anomalies, Recommendation |
| Health score | No | Yes — 0-100 |
| Model | analysis:14b (Modelfile + prompt) | analysis:14b (prompt override in API call) |
| Example output? | Yes (14B handles it) | Yes (14B handles it) |

### Health Score Interpretation

The 0-100 score is computed entirely in Python from hard deduction rules.
The LLM never recomputes it — it receives the score as fact and writes
narrative around it.

| Score | Meaning | Recommendation |
|-------|---------|---------------|
| >= 90 | Clean operations | None required |
| 70-89 | Minor anomalies | Monitor |
| 50-69 | Degraded | Investigate deductions |
| < 50 | Unhealthy | Immediate action |

### Deduction Rules (Hard-Coded)

| Category | Threshold | Deduction |
|----------|-----------|-----------|
| Unrecovered outages | per outage | -25 each (max -50) |
| Connection failure targets | per target | -10 each (max -30) |
| BAD/FAIL % | >10% / >5% | -15 / -8 |
| CRITICAL % | >5% / >2% / >0.5% | -15 / -8 / -3 |
| I/O failure clusters | any | -10 |
| ACN COMM events | >50 / >10 | -10 / -5 |
| Output Transfer Failure | >10 / >0 | -10 / -5 |
| EVENT_LIMITED | any | -5 |
| Total events | >5000 | -5 |

### Calibration Notes

The deduction values and thresholds are initial estimates based on
operational experience with this specific plant's DeltaV system. They
will need tuning as more data is analyzed:

- If the tool consistently scores < 70 on clean shutdown files, the
  thresholds are too aggressive — increase BAD/FAIL % and CRITICAL %
  thresholds.
- If it misses a genuine outage in a busy file (>1000 events from normal
  operations), the unrecovered outage deduction may be too strong or the
  file-size deduction too weak.
- The -25 per unrecovered outage is intentionally aggressive — any
  permanent redundancy loss warrants a low score.

To recalibrate, edit the deduction values in `ops_analyzer.py` under
`_compute_health_score()`. Run on known-good and known-bad files to
verify the new thresholds produce the expected scores.

---

## Known Limitations

### File Size / Performance

`build_json_summary()` in both tools uses O(N*M) passes for categorization.
Files >50,000 events will take several minutes to build the JSON payload.
Known tested: 88,000 events took ~10 minutes and still didn't finish
cleanly.

**Workaround for large files:** Use `analyze_core.py` interactive REPL
for quick triage (`/summary`, `/alarms`, `/bad`, `/cascade` commands)
instead of the LLM tools. The REPL loads and displays large files in
under 5 seconds.

**Planned fix:** Rebuild categorization as single-pass counters instead
of multi-pass grouping.

### AMD GPU Variability (Radeon 860M)

This hardware uses shared system RAM for GPU (no dedicated VRAM). Model
loading and inference speeds vary depending on:
- Current system memory pressure (other apps, browser tabs)
- GPU driver state after sleep/resume cycles
- DirectML backend availability after Windows updates

14B models at Q4_K_M (~9 GB) push against the 8GB shared VRAM ceiling.
This is expected — the model still runs correctly with some spillover to
system RAM. If the Modelfile consistently fails with `unable to allocate
Vulkan0 buffer`:

```powershell
# Fallback: use base model directly
ollama run qwen2.5:14b
# Then switch MODEL in both scripts to "qwen2.5:14b"
```

### Threshold Tuning Required

The deduction thresholds in `ops_analyzer.py` are initial estimates and
will likely need adjustment after several weeks of real operational data:

- **Aggregate trend data** — Track health scores over multiple files to
  find the natural baseline for this plant. What scores "normal ops"
  consistently at 85+? Where does a real outage land?
- **False positives** — If the tool frequently flags clean startups as
  degraded (< 70), the BAD/FAIL % threshold (>10%) or CRITICAL % threshold
  (>5%) during startup sequencing may be too sensitive.
- **False negatives** — If a known WIOC failure scores > 70, the
  unrecovered outage deduction (-25 each) may need to increase to -35,
  or the max deduction cap (-50) should be removed.

### Short-Circuit and Model Independence

Both tools short-circuit when no anomaly exists:
- `summarize_analysis.py` checks `analysis_hints.likely_normal_operations`
  before making any model call. If True, returns a data-driven canned
  summary from `generate_normal_ops_summary()` with ZERO inference.
- `ops_analyzer.py` uses the health score: >= 70 instructs the LLM to
  output "None required — normal operations."

This means the tools remain useful even when the Ollama server is down
or the model is not loaded — parsing, scoring, and short-circuit logic
all run in pure Python stdlib.

### Hardcoded Paths

This repo should not contain hardcoded local paths. The Ollama URL
(`172.29.64.1:11434` for WSL-to-Windows) and model name are set at
the top of each script as module-level constants, intended to be
configured per deployment. Before committing, verify no absolute
local paths (e.g. `C:\Users\rickc\...`) exist in committed code.
