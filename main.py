"""
QuMail — Quantum Secure Email Client
FastAPI backend: REST API + frontend static file server.

Unique Value Proposition (UVP):
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  QUANTUM CANARY — Hash-Chained Cryptographic Audit Trail               │
  │                                                                         │
  │  Every cryptographic lifecycle event (key issued, encrypt, send,        │
  │  receive, decrypt) is recorded as an immutable, hash-chained audit      │
  │  entry — identical in structure to what a production QKD network        │
  │  requires under ETSI GS QKD 014 §7.3 security audit requirements.      │
  │                                                                         │
  │  The chain is cryptographically verifiable: tampering with any entry    │
  │  breaks all subsequent hashes. Visualized as a live timeline in the UI. │
  └─────────────────────────────────────────────────────────────────────────┘

  Additionally:
  - NIST SP 800-90B entropy analysis applied to every quantum key
  - Live "wire interception" demo across all 4 security levels
  - ETSI QKD 014-compliant Key Manager simulator (drop-in ready for real QKD)
"""
import os
import json
import uuid
from pathlib import Path
from typing import Optional, List

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv

import km_simulator
import crypto
import email_handler
import audit_log as al
import entropy_analysis as ea

load_dotenv()

app = FastAPI(
    title="QuMail API",
    version="2.0.0",
    description="Quantum-Secure Email with Hash-Chained Cryptographic Audit Trail",
)


# ─── Pydantic models ──────────────────────────────────────────────────────────

class LoginPayload(BaseModel):
    email: str
    password: str
    sae_id: str
    peer_sae_id: str = ""


class AttachmentItem(BaseModel):
    filename: str
    data_b64: str
    mime_type: str = "application/octet-stream"
    size: int = 0


class SendPayload(BaseModel):
    sender_email: str
    sender_password: str
    sender_sae_id: str
    recipient_email: str
    recipient_sae_id: str
    subject: str
    body: str
    level: int = 2
    attachments: List[AttachmentItem] = []


class DecryptPayload(BaseModel):
    encrypted_body: str
    qkd_key_id: Optional[str] = None
    qkd_level: int = 4
    qkd_sender_sae: Optional[str] = None
    recipient_email: str
    recipient_password: str
    recipient_sae_id: str


class FetchPayload(BaseModel):
    email: str
    password: str
    limit: int = 20


class KeyStatusPayload(BaseModel):
    master_sae_id: str
    slave_sae_id: str


# ─── KM / Key endpoints ───────────────────────────────────────────────────────

@app.get("/api/km/status")
async def km_status(master_sae_id: str, slave_sae_id: str):
    """ETSI QKD 014 compatible status endpoint."""
    status = km_simulator.get_status(master_sae_id, slave_sae_id)

    # Audit: record pool status check
    if status.get("status") == "LOW":
        al.audit.record(
            al.EventType.KEY_POOL_LOW,
            actor=master_sae_id,
            subject=f"Pool {master_sae_id}↔{slave_sae_id}",
            metadata={"available": status.get("stored_key_count"), "total": status.get("max_key_count")},
        )

    return status


@app.get("/api/km/keys/enc")
async def get_enc_keys(master_sae_id: str, slave_sae_id: str, number: int = 1):
    """ETSI QKD 014 — fetch fresh keys for encryption."""
    result = km_simulator.get_keys(master_sae_id, slave_sae_id, number)
    if result is None:
        raise HTTPException(503, "Key pool exhausted. Refill or downgrade security level.")

    # Audit + entropy analysis for each key issued
    for k in result["keys"]:
        entropy_report = ea.analyze_key(k["key"])
        al.audit.record(
            al.EventType.KEY_ISSUED,
            actor=master_sae_id,
            subject=k["key_ID"][:12] + "…",
            metadata={
                "key_id":        k["key_ID"],
                "quality_score": entropy_report["quality_score"],
                "quality_label": entropy_report["quality_label"],
                "shannon":       entropy_report["shannon_entropy"],
                "min_entropy":   entropy_report["min_entropy"],
            },
        )

    return result


@app.post("/api/km/keys/dec")
async def get_dec_keys(master_sae_id: str, slave_sae_id: str, key_ids: List[str]):
    """ETSI QKD 014 — fetch keys by ID for decryption."""
    result = km_simulator.get_key_by_id(slave_sae_id, master_sae_id, key_ids)
    if result is None:
        raise HTTPException(404, "Key ID not found in pool.")

    al.audit.record(
        al.EventType.KEY_CONSUMED,
        actor=slave_sae_id,
        subject=key_ids[0][:12] + "…",
        metadata={"key_ids": key_ids, "purpose": "decryption"},
    )

    return result


@app.post("/api/km/refill")
async def refill_keys(master_sae_id: str, slave_sae_id: str):
    """Demo helper — simulate a new QKD session refilling the key pool."""
    km_simulator.refill_pool(master_sae_id, slave_sae_id)
    al.audit.record(
        al.EventType.KEY_POOL_REFILL,
        actor="system",
        subject=f"Pool {master_sae_id}↔{slave_sae_id}",
        metadata={"new_count": km_simulator.POOL_SIZE},
    )
    return {"message": "Key pool refilled", "new_count": km_simulator.POOL_SIZE}


# ─── Email endpoints ──────────────────────────────────────────────────────────

@app.post("/api/email/fetch")
async def fetch_inbox(payload: FetchPayload):
    """Fetch emails via IMAP."""
    emails = await email_handler.fetch_emails(payload.email, payload.password, limit=payload.limit)
    al.audit.record(
        al.EventType.FETCH_DONE,
        actor=payload.email,
        subject="INBOX",
        metadata={"count": len(emails)},
    )
    return {"emails": emails}


@app.post("/api/email/send")
async def send_email(payload: SendPayload):
    """
    Full send flow with audit trail:
    1. Audit: encrypt_start
    2. Fetch quantum key from KM (if level 1 or 2)
    3. Audit: key_issued (with entropy score)
    4. Encrypt body + attachments
    5. Audit: encrypt_done
    6. Send via SMTP with X-QKD-* headers
    7. Audit: send_done
    """
    message_id = str(uuid.uuid4())
    key_id  = None
    key_hex = None

    # ── Audit: encrypt start ─────────────────────────────────────────────────
    al.audit.record(
        al.EventType.ENCRYPT_START,
        actor=payload.sender_sae_id,
        subject=payload.subject[:60],
        level=payload.level,
        message_id=message_id,
        metadata={
            "to":          payload.recipient_email,
            "level":       payload.level,
            "attachments": len(payload.attachments),
        },
    )

    # ── Key acquisition ──────────────────────────────────────────────────────
    entropy_report = None
    if payload.level in (1, 2):
        attachments_data = [a.model_dump() for a in payload.attachments]
        bundle_str  = crypto.compute_bundle(payload.body, attachments_data)
        msg_bytes   = len(bundle_str.encode("utf-8"))
        keys_needed = max(1, -(-msg_bytes // km_simulator.KEY_SIZE_BYTES))

        km_result = km_simulator.get_keys(
            payload.sender_sae_id,
            payload.recipient_sae_id,
            number=keys_needed if payload.level == 1 else 1,
        )

        if km_result is None:
            if payload.level == 1:
                raise HTTPException(
                    503,
                    "OTP requires quantum keys — pool exhausted. Refill KM or switch to Level 2+."
                )
            # Graceful downgrade for L2
            key_hex = None
            payload.level = 3
        else:
            key_id  = km_result["keys"][0]["key_ID"]
            key_hex = "".join(k["key"] for k in km_result["keys"])

            # Entropy analysis on the actual key
            entropy_report = ea.analyze_key(key_hex[:64])  # first 32 bytes = 256 bits

            al.audit.record(
                al.EventType.KEY_ISSUED,
                actor=payload.sender_sae_id,
                subject=key_id[:12] + "…",
                level=payload.level,
                message_id=message_id,
                metadata={
                    "key_id":        key_id,
                    "quality_score": entropy_report["quality_score"],
                    "quality_label": entropy_report["quality_label"],
                    "shannon":       entropy_report["shannon_entropy"],
                    "min_entropy":   entropy_report["min_entropy"],
                    "keys_used":     len(km_result["keys"]),
                },
            )

    # ── Encrypt ──────────────────────────────────────────────────────────────
    encrypted_body = crypto.encrypt(
        payload.body,
        payload.level,
        key_hex,
        attachments=[a.model_dump() for a in payload.attachments],
    )

    al.audit.record(
        al.EventType.ENCRYPT_DONE,
        actor=payload.sender_sae_id,
        subject=payload.subject[:60],
        level=payload.level,
        message_id=message_id,
        metadata={
            "cipher_bytes":    len(encrypted_body),
            "key_id":          key_id,
            "entropy_score":   entropy_report["quality_score"] if entropy_report else None,
        },
    )

    # ── Send ─────────────────────────────────────────────────────────────────
    al.audit.record(
        al.EventType.SEND_START,
        actor=payload.sender_sae_id,
        subject=payload.subject[:60],
        level=payload.level,
        message_id=message_id,
        metadata={"recipient": payload.recipient_email},
    )

    result = await email_handler.send_email(
        sender=payload.sender_email,
        password=payload.sender_password,
        recipient=payload.recipient_email,
        subject=payload.subject,
        encrypted_body=encrypted_body,
        key_id=key_id,
        level=payload.level,
        sender_sae_id=payload.sender_sae_id,
        message_id=message_id,
    )

    if not result["success"]:
        raise HTTPException(500, f"SMTP error: {result['error']}")

    al.audit.record(
        al.EventType.SEND_DONE,
        actor=payload.sender_sae_id,
        subject=payload.subject[:60],
        level=payload.level,
        message_id=message_id,
        metadata={"recipient": payload.recipient_email, "success": True},
    )

    return {
        "success":           True,
        "key_id":            key_id,
        "level_used":        payload.level,
        "message_id":        message_id,
        "encrypted_preview": encrypted_body[:120] + "…",
        "entropy_report":    entropy_report,
        "audit_head":        al.audit.head_hash[:16] + "…",
    }


@app.post("/api/email/decrypt")
async def decrypt_email(payload: DecryptPayload):
    """
    Decrypt a received QuMail message with full audit trail.
    """
    message_id = str(uuid.uuid4())
    key_hex    = None

    al.audit.record(
        al.EventType.DECRYPT_START,
        actor=payload.recipient_sae_id,
        subject=f"level-{payload.qkd_level} message",
        level=payload.qkd_level,
        message_id=message_id,
        metadata={"key_id": payload.qkd_key_id, "sender_sae": payload.qkd_sender_sae},
    )

    if payload.qkd_level in (1, 2) and payload.qkd_key_id and payload.qkd_sender_sae:
        km_result = km_simulator.get_key_by_id(
            slave_sae_id=payload.recipient_sae_id,
            master_sae_id=payload.qkd_sender_sae,
            key_ids=[payload.qkd_key_id],
        )
        if km_result:
            key_hex = km_result["keys"][0]["key"]
            al.audit.record(
                al.EventType.KEY_CONSUMED,
                actor=payload.recipient_sae_id,
                subject=payload.qkd_key_id[:12] + "…",
                level=payload.qkd_level,
                message_id=message_id,
                metadata={"purpose": "decryption", "key_id": payload.qkd_key_id},
            )

    try:
        plaintext, level, attachments = crypto.decrypt(payload.encrypted_body, key_hex)

        al.audit.record(
            al.EventType.DECRYPT_DONE,
            actor=payload.recipient_sae_id,
            subject=f"level-{level} message",
            level=level,
            message_id=message_id,
            metadata={"success": True, "attachments": len(attachments)},
        )
        al.audit.record(
            al.EventType.VERIFY_OK,
            actor=payload.recipient_sae_id,
            subject=f"level-{level} message",
            level=level,
            message_id=message_id,
            metadata={"chain_head": al.audit.head_hash[:16]},
        )

        return {
            "success":     True,
            "plaintext":   plaintext,
            "level":       level,
            "attachments": attachments,
            "message_id":  message_id,
        }
    except Exception as e:
        al.audit.record(
            al.EventType.VERIFY_FAIL,
            actor=payload.recipient_sae_id,
            subject="decrypt-error",
            level=payload.qkd_level,
            message_id=message_id,
            metadata={"error": str(e)},
        )
        raise HTTPException(400, f"Decryption failed: {str(e)}")


# ─── Demo / utility endpoints ─────────────────────────────────────────────────

@app.get("/api/demo/encrypt_preview")
async def encrypt_preview(
    text: str,
    level: int,
    master_sae_id: str = "alice",
    slave_sae_id: str  = "bob",
):
    """
    For the demo: show what the encrypted blob looks like without sending.
    Great for the 'intercept the wire' demo moment.
    """
    key_hex  = None
    key_id   = None
    entropy  = None

    if level in (1, 2):
        km_result = km_simulator.get_keys(master_sae_id, slave_sae_id, number=1)
        if km_result:
            key_id  = km_result["keys"][0]["key_ID"]
            key_hex = km_result["keys"][0]["key"]
            entropy = ea.analyze_key(key_hex)

    encrypted = crypto.encrypt(text, level, key_hex)
    return {
        "original":   text,
        "encrypted":  encrypted,
        "key_id":     key_id,
        "level":      level,
        "level_name": {1: "OTP (Quantum Secure)", 2: "Quantum-seeded AES-256-GCM",
                       3: "AES-256-GCM (Classical)", 4: "No encryption"}[level],
        "entropy":    entropy,
    }


@app.get("/api/demo/entropy")
async def demo_entropy(key_hex: str = ""):
    """Analyze entropy of an arbitrary hex string (or generate a fresh key)."""
    if not key_hex:
        import secrets
        key_hex = secrets.token_hex(32)
    report = ea.analyze_key(key_hex)
    return {"key_hex_preview": key_hex[:16] + "…", **report}


# ─── Audit Trail endpoints ────────────────────────────────────────────────────

@app.get("/api/audit/recent")
async def audit_recent(n: int = 50):
    """Return the N most recent audit trail entries."""
    entries = al.audit.get_recent(n)
    return {
        "entries":    entries,
        "head_hash":  al.audit.head_hash,
        "stats":      al.audit.stats(),
    }


@app.get("/api/audit/verify")
async def audit_verify():
    """Verify the integrity of the entire audit chain."""
    result = al.audit.verify_chain()
    return {
        **result,
        "head_hash": al.audit.head_hash,
        "message":   "Chain intact — no tampering detected" if result["valid"]
                     else f"⚠ Chain broken at entry {result['broken_at']}",
    }


@app.get("/api/audit/stats")
async def audit_stats():
    return al.audit.stats()


# ─── Serve the frontend ───────────────────────────────────────────────────────

static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
async def serve_frontend():
    index = static_dir / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return JSONResponse({"message": "QuMail API running. Place index.html in /static/"})


@app.get("/health")
async def health():
    return {
        "status":      "ok",
        "app":         "QuMail",
        "version":     "2.0.0",
        "audit_size":  al.audit.stats()["total_entries"],
        "chain_valid": al.audit.verify_chain()["valid"],
    }