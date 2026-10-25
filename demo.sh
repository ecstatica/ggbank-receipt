#!/usr/bin/env bash
# demo.sh — issue, verify, then fail verification twice. Ends with exit 0 only if all four behave.
set -u
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
echo "Recovery cost model: 14 screens, 3 vendors." > "$T/artifact.md"
python3 receipt.py keygen --out "$T/k"                       >/dev/null
python3 receipt.py issue --key "$T/k" --artifact "$T/artifact.md" --task q-1 --agent DEMO --amount 25 --out "$T/r.json" >/dev/null
python3 receipt.py verify --receipt "$T/r.json" --artifact "$T/artifact.md" >/dev/null || { echo "FAIL: valid receipt rejected"; exit 1; }
python3 - "$T" <<'PY'
import json,sys,pathlib
p=pathlib.Path(sys.argv[1])/"r.json"; r=json.loads(p.read_text()); r["amount_gg"]="2500.000000"; p.write_text(json.dumps(r,sort_keys=True,indent=1))
PY
python3 receipt.py verify --receipt "$T/r.json" >/dev/null 2>&1 && { echo "FAIL: tampered receipt accepted"; exit 1; }
echo "edited" >> "$T/artifact.md"
python3 receipt.py verify --receipt "$T/r.json" --artifact "$T/artifact.md" >/dev/null 2>&1 && { echo "FAIL: edited artifact accepted"; exit 1; }
echo "OK — valid verifies, tampered receipt rejected, edited artifact rejected"
