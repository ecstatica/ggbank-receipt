# receipt

**Sign the work your agent did. Let anyone verify it offline.**

A receipt binds an agent, a task and a file with an Ed25519 signature. Verification needs no account, no
chain, no network and no permission from us. Change one character of the file or one field of the
receipt, and verification fails.

This is the smallest useful thing in the agent economy: the payment rails arrived before the proof rails.
x402 passed 138 million payments while most agent jobs remain unfunded and unevaluated by anyone
independent.

## Install

```bash
git clone https://github.com/ecstatica/ggbank-receipt
cd ggbank-receipt
python3 -m pip install --user cryptography
```

No dependency beyond `cryptography`. Python 3.10+.

## Use

```bash
# 1. your agent's key (Ed25519, private key mode 0600)
python3 receipt.py keygen --out ~/.agent.key

# 2. sign a receipt over the artifact the agent delivered
python3 receipt.py issue \
  --key ~/.agent.key \
  --artifact report.pdf \
  --task q-1042 \
  --agent VOID-9 \
  --amount 25 \
  --out q-1042.receipt.json

# 3. anyone can verify it, offline
python3 receipt.py verify --receipt q-1042.receipt.json --artifact report.pdf
```

```
OK   signature valid · issuer QRs56MmYfzwtOAih…
OK   artifact matches 04002a7e5527bbad…
     deliver · VOID-9 · task q-1042 · 25.0 GG · 2026-10-25T11:56:24Z
```

Send the receipt with the file. The buyer runs one command and knows the file is the one that agent
produced and has not changed since.

## What it proves, and what it does not

**Proves:** this key signed this artifact hash with these fields at this time, and nothing has changed
since.

**Does not prove:** that the work is good, or that the key belongs to a particular human. Quality is a
separate judgement; identity is a separate claim.

## What a receipt contains

```json
{
 "spec": "ggbank.receipt/1",
 "verb": "deliver",
 "agent": "VOID-9",
 "task": "q-1042",
 "artifact": {"name": "report.pdf", "sha256": "04002a7e…", "bytes": 18422},
 "amount_gg": "25.000000",
 "fee_gg": "0.125000",
 "issued_at": "2026-10-25T11:56:24Z",
 "issuer": "<base64 public key>",
 "nonce": "…",
 "signature": "<base64>"
}
```

Canonical JSON (sorted keys, no whitespace) is signed, so the signed bytes are reproducible in any
language. Money fields are decimal strings, never floats.

## Tamper detection, tested

```bash
python3 receipt.py verify --receipt tampered.json     # FAIL signature: InvalidSignature
python3 receipt.py verify --receipt good.json --artifact edited.pdf
                                                      # FAIL artifact: hash mismatch
```

## Licence

MIT.
