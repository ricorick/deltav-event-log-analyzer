import json, os, subprocess, urllib.request, urllib.error

INPUT_FILE = "/tmp/condensed.json"
ANALYSIS_JSON = json.loads(open(INPUT_FILE).read())

SYSTEM_PROMPT = """You are a senior process control specialist summarizing a DeltaV DCS event log analysis. Your audience is an experienced plant-floor engineer who needs to know what's abnormal, what's normal background noise, and what to investigate next.

Given the structured event log analysis below, produce a concise operational summary. Follow these rules:
- Keep it under 200 words
- Lead with the biggest concern first
- Call out abnormal patterns: excessive ACN switching, interlock cycling, bad integrity, standby recovery times
- Distinguish between faults and cleared/self-recovering events
- Use specific node names and counts
- Use plant-floor language like "ACN flapping", "interlock cycling", "bad integrity cleared", "standby failover", "buffer overflow"
- End with a single clear recommendation for next action"""

def test_model(name):
    # Build prompt as {system}\n\nEVENT LOG ANALYSIS:\n{data}\n\nOPERATIONAL SUMMARY:
    data_str = json.dumps(ANALYSIS_JSON, indent=0)
    prompt = f"{SYSTEM_PROMPT}\n\nEVENT LOG ANALYSIS:\n{data_str}\n\nOPERATIONAL SUMMARY:"
    
    approx_tok = len(prompt) // 4
    print(f"\n{'='*65}")
    print(f"  MODEL: {name}  |  Input: ~{approx_tok} tokens")
    print(f"{'='*65}")
    
    body = json.dumps({
        "model": name,
        "prompt": prompt,
        "stream": False,
        "temperature": 0.3,
        "max_tokens": 500,
        "options": {"num_ctx": 4096}
    }).encode('utf-8')
    
    try:
        req = urllib.request.Request(
            "http://172.29.64.1:11434/api/generate",
            data=body,
            headers={"Content-Type": "application/json"}
        )
        resp = urllib.request.urlopen(req, timeout=180)
        result = json.loads(resp.read())
        output = result.get("response", "NO RESPONSE")
        tok_in = result.get("prompt_eval_count", "?")
        tok_out = result.get("eval_count", "?")
        dur = result.get("eval_duration", 0) / 1e9
        print(f"  Tokens: {tok_in} in -> {tok_out} out  |  {dur:.1f}s")
        print(f"{'-'*65}")
        print(output)
    except Exception as e:
        print(f"  ERROR: {e}")

for m in ["granite4.1:3b", "granite4.1:8b", "qwen2.5:3b"]:
    test_model(m)
