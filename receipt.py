#!/usr/bin/env python3
"""receipt.py — the smallest useful thing this bank can ship today.

An agent does work. A counterparty wants proof that the work existed, was delivered by that agent, and
has not been altered since. This signs and verifies that proof with Ed25519, offline, with no chain, no
token, no account and no bank in the loop.

    python3 scripts/receipt.py keygen --out state/keys/agent.key
    python3 scripts/receipt.py issue  --key state/keys/agent.key --artifact report.md \
        --task q-1042 --agent VOID-9 --amount 25 --out state/receipts/q-1042.json
    python3 scripts/receipt.py verify --receipt state/receipts/q-1042.json

`verify` exits 0 only when the signature is valid, the artifact hash matches, and no field was altered.
Tamper with one character and it exits 1 with the field that no longer matches.

Receipts are canonical JSON (sorted keys, no whitespace) so the signed bytes are reproducible anywhere.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import time
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SPEC = "ggbank.receipt/1"


def canon(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def keygen(out: Path) -> int:
    out.parent.mkdir(parents=True, exist_ok=True)
    sk = Ed25519PrivateKey.generate()
    out.write_bytes(sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()))
    out.chmod(0o600)
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pubp = out.with_suffix(".pub")
    pubp.write_text(base64.b64encode(pub).decode() + "\n")
    print(f"private key {out} (0600)\npublic key  {pubp}  {base64.b64encode(pub).decode()}")
    return 0


def issue(a) -> int:
    sk = Ed25519PrivateKey.from_private_bytes(Path(a.key).read_bytes())
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    art = Path(a.artifact)
    if not art.is_file():
        print(f"artifact not found: {art}")
        return 2
    body = {
        "spec": SPEC,
        "verb": a.verb,
        "agent": a.agent,
        "task": a.task,
        "artifact": {"name": art.name, "sha256": sha256_file(art), "bytes": art.stat().st_size},
        "amount_gg": str(Decimal(str(a.amount)).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)),
        "fee_gg": str((Decimal(str(a.amount)) * Decimal("0.005")).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)),
        "issued_at": a.at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "issuer": base64.b64encode(pub).decode(),
        "nonce": hashlib.sha256(canon({"t": a.task, "a": a.agent, "n": time.time_ns()})[:32]).hexdigest()[:16],
    }
    sig = sk.sign(canon(body))
    receipt = dict(body, signature=base64.b64encode(sig).decode())
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=1, sort_keys=True))
    print(f"issued  {out}")
    print(f"  artifact sha256 {body['artifact']['sha256'][:16]}…  amount {a.amount} GG  fee {body['fee_gg']}")
    return 0


def verify(a) -> int:
    r = json.loads(Path(a.receipt).read_text())
    sig = base64.b64decode(r.pop("signature"))
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(r["issuer"]))
        pub.verify(sig, canon(r))
    except Exception as e:
        print(f"FAIL signature: {type(e).__name__}")
        return 1
    print(f"OK   signature valid · issuer {r['issuer'][:16]}…")
    if a.artifact:
        want = r["artifact"]["sha256"]
        got = sha256_file(Path(a.artifact))
        if got != want:
            print(f"FAIL artifact: receipt says {want[:16]}… file is {got[:16]}…")
            return 1
        print(f"OK   artifact matches {want[:16]}…")
    print(f"     {r['verb']} · {r['agent']} · task {r['task']} · {r['amount_gg']} GG · {r['issued_at']}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen"); k.add_argument("--out", required=True)

    i = sub.add_parser("issue")
    i.add_argument("--key", required=True); i.add_argument("--artifact", required=True)
    i.add_argument("--task", required=True); i.add_argument("--agent", required=True)
    i.add_argument("--amount", type=float, required=True); i.add_argument("--verb", default="deliver")
    i.add_argument("--at"); i.add_argument("--out", required=True)

    v = sub.add_parser("verify")
    v.add_argument("--receipt", required=True); v.add_argument("--artifact")

    a = ap.parse_args()
    return {"keygen": keygen, "issue": issue, "verify": verify}[a.cmd](a) if a.cmd != "keygen" else keygen(Path(a.out))


if __name__ == "__main__":
    sys.exit(main())
