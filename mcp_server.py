#!/usr/bin/env python3
"""mcp_server.py — the receipt tool as an MCP server, because agents discover tools, not repositories.

Speaks JSON-RPC 2.0 over stdio, which is what every MCP client (Claude Code, Cursor, Codex, Hermes,
and any agent framework) already knows how to call. Two tools:

  issue_receipt  — sign an artifact, return the receipt
  verify_receipt — verify a receipt offline, with or without the artifact

    {"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
    {"jsonrpc":"2.0","id":2,"method":"tools/list"}
    {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"issue_receipt","arguments":{...}}}

No dependencies beyond `cryptography`, same as the CLI. Nothing touches the network.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SPEC = "ggbank.receipt/1"
SERVER = {"name": "ggbank-receipt", "version": "1.0.0"}


def canon(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def keypair(key_path: str | None):
    """Ephemeral when no path is given: an agent can issue a receipt without managing a file."""
    if key_path and Path(key_path).is_file():
        sk = Ed25519PrivateKey.from_private_bytes(Path(key_path).read_bytes())
    else:
        sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sk, base64.b64encode(pub).decode()


TOOLS = [
    {
        "name": "issue_receipt",
        "description": "Sign an artifact with an Ed25519 receipt. Returns the receipt JSON: artifact hash, agent, task, "
                       "amount and a signature anyone can verify offline.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "artifact_path": {"type": "string", "description": "path to the delivered file"},
                "agent": {"type": "string", "description": "agent identifier, e.g. VOID-9"},
                "task": {"type": "string", "description": "task or quest id"},
                "amount_gg": {"type": "number", "description": "amount paid for the work"},
                "key_path": {"type": "string", "description": "optional Ed25519 private key file; a fresh key is used otherwise"},
            },
            "required": ["artifact_path", "agent", "task"],
        },
    },
    {
        "name": "verify_receipt",
        "description": "Verify a receipt offline: signature, every field, and optionally the artifact hash. "
                       "Returns ok=false with the failing reason when anything has changed.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "receipt": {"type": "object", "description": "the receipt object as issued"},
                "artifact_path": {"type": "string", "description": "optional file to hash-check"},
            },
            "required": ["receipt"],
        },
    },
]


def issue(a: dict) -> dict:
    art = Path(a["artifact_path"])
    if not art.is_file():
        return {"ok": False, "error": f"artifact not found: {art}"}
    sk, pub = keypair(a.get("key_path"))
    amount = Decimal(str(a.get("amount_gg", 0)))
    body = {
        "spec": SPEC,
        "verb": a.get("verb", "deliver"),
        "agent": a["agent"],
        "task": a["task"],
        "artifact": {"name": art.name, "sha256": hashlib.sha256(art.read_bytes()).hexdigest(), "bytes": art.stat().st_size},
        "amount_gg": str(amount.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)),
        "fee_gg": str((amount * Decimal("0.005")).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)),
        "issued_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "issuer": pub,
        "nonce": hashlib.sha256(canon({"t": a["task"], "a": a["agent"]})).hexdigest()[:16],
    }
    body["signature"] = base64.b64encode(sk.sign(canon(body))).decode()
    return {"ok": True, "receipt": body}


def verify(a: dict) -> dict:
    r = dict(a["receipt"])
    sig = base64.b64decode(r.pop("signature", ""))
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(r["issuer"]))
        pub.verify(sig, canon(r))
    except Exception as e:  # noqa: A011 verification failure is the answer, not a crash
        return {"ok": False, "reason": f"signature: {type(e).__name__}"}
    if a.get("artifact_path"):
        p = Path(a["artifact_path"])
        if not p.is_file():
            return {"ok": False, "reason": "artifact not found"}
        got = hashlib.sha256(p.read_bytes()).hexdigest()
        if got != r["artifact"]["sha256"]:
            return {"ok": False, "reason": f"artifact hash mismatch: receipt {r['artifact']['sha256'][:16]}… file {got[:16]}…"}
    return {"ok": True, "agent": r.get("agent"), "task": r.get("task"), "amount_gg": r.get("amount_gg")}


def handle(req: dict) -> dict | None:
    mid = req.get("id")
    method = req.get("method")

    def ok(result):
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    if method == "initialize":
        return ok({"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}, "serverInfo": SERVER})
    if method == "tools/list":
        return ok({"tools": TOOLS})
    if method == "tools/call":
        name = req["params"]["name"]
        args = req["params"].get("arguments", {})
        if name == "issue_receipt":
            return ok({"content": [{"type": "text", "text": json.dumps(issue(args), indent=1)}]})
        if name == "verify_receipt":
            return ok({"content": [{"type": "text", "text": json.dumps(verify(args), indent=1)}]})
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"unknown tool {name}"}}
    if method in ("notifications/initialized", "ping"):
        return None if method.startswith("notifications") else ok({})
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"unknown method {method}"}}


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}) + "\n")
            sys.stdout.flush()
            continue
        resp = handle(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
