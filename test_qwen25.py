import json, urllib.request, urllib.error

INPUT_FILE = "/tmp/condensed.json"
ANALYSIS_JSON = json.loads(open(INPUT_FILE).read())

SYSTEM_PROMPT = """You are a senior process control specialist summarizing a DeltaV DCS event log analysis. Your audience is an experienced plant-floor engineer. Keep it under 200 words. Lead with the biggest concern. Call out abnormal patterns: excessive ACN switching, interlock cycling, bad integrity, standby recovery times. Use specific node names and counts. End with a clear recommendation."""

prompt = SYSTEM_PROMPT + "\n\nEVENT LOG ANALYSIS:\n" + json.dumps(ANALYSIS_JSON, indent=0) + "\n\nOPERATIONAL SUMMARY:"

body = json.dumps({"model": "qwen2.5:3b", "prompt": prompt, "stream": False, "temperature": 0.3, "max_tokens": 500, "options": {"num_ctx": 4096}}).encode()

req = urllib.request.Request("http://172.29.64.1:11434/api/generate", data=body, headers={"Content-Type": "application/json"})
resp = urllib.request.urlopen(req, timeout=180)
result = json.loads(resp.read())
print(result.get("response", "NO RESPONSE"))
tok_in = result.get("prompt_eval_count", "?")
tok_out = result.get("eval_count", "?")
dur = result.get("eval_duration", 0) / 1e9
print(f"\n--- Tokens: {tok_in} in -> {tok_out} out | {dur:.1f}s ---")
