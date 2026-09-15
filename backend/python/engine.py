#!/usr/bin/env python3
"""Required CI/desktop parity backend. One JSON request per line."""
import sys, json, base64, hashlib, math

def analyze(data):
    counts = [0] * 256
    printable = 0
    for b in data:
        counts[b] += 1
        if 0x20 <= b <= 0x7e or b in (9, 10, 13): printable += 1
    entropy = 0.0
    if data:
        n = len(data)
        entropy = sum(-(c/n) * math.log2(c/n) for c in counts if c)
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "entropy": entropy,
            "printable": printable * 100 / len(data) if data else 0.0,
            "binary": bool(data) and printable / len(data) < 0.18}

def main():
    for line in sys.stdin:
        try:
            req = json.loads(line); op = req.get("op")
            if op not in ("analyze", "sha256"): raise ValueError("unsupported operation")
            data = base64.b64decode(req.get("dataBase64", ""), validate=True)
            result = analyze(data)
            if op == "sha256": result = {"sha256": result["sha256"], "bytes": result["bytes"]}
            print(json.dumps(result), flush=True)
        except Exception as e: print(json.dumps({"error": str(e)}), flush=True)

if __name__ == "__main__": main()
