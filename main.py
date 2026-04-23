"""
QuMail — Quantum Secure Email Client
FastAPI backend: serves REST API + the frontend HTML as a static file.
Single process, deploy anywhere with: uvicorn main:app
"""
import os
import json
from pathlib import Path
from typing import Optional, List

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv

import km_simulator
import crypto
import email_handler

load_dotenv()

app = FastAPI(title="QuMail API", version="1.0.0")


# ─── Pydantic models ──────────────────────────────────────────────────────────

class LoginPayload(BaseModel):
    email: str
    password: str
    sae_id: str                 # This user's SAE ID registered with KM
    peer_sae_id: str = ""       # Pre-populate for demo convenience


class AttachmentItem(BaseModel):
    """A single file attachment, base64-encoded by the browser before transit."""
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
    level: int = 2              # Default to Level 2 (quantum-seeded AES)
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
    return km_simulator.get_status(master_sae_id, slave_sae_id)


@app.get("/api/km/keys/enc")
async def get_enc_keys(master_sae_id: str, slave_sae_id: str, number: int = 1):
    """ETSI QKD 014 — fetch fresh keys for encryption."""
    result = km_simulator.get_keys(master_sae_id, slave_sae_id, number)
    if result is None:
        raise HTTPException(503, "Key pool exhausted. Refill or downgrade security level.")
    return result


@app.post("/api/km/keys/dec")
async def get_dec_keys(master_sae_id: str, slave_sae_id: str, key_ids: List[str]):
    """ETSI QKD 014 — fetch keys by ID for decryption."""
    result = km_simulator.get_key_by_id(slave_sae_id, master_sae_id, key_ids)
    if result is None:
        raise HTTPException(404, "Key ID not found in pool.")
    return result


@app.post("/api/km/refill")
async def refill_keys(master_sae_id: str, slave_sae_id: str):
    """Demo helper — simulate a new QKD session refilling the key pool."""
    km_simulator.refill_pool(master_sae_id, slave_sae_id)
    return {"message": "Key pool refilled", "new_count": km_simulator.POOL_SIZE}


# ─── Email endpoints ──────────────────────────────────────────────────────────

@app.post("/api/email/fetch")
async def fetch_inbox(payload: FetchPayload):
    """Fetch emails via IMAP."""
    emails = await email_handler.fetch_emails(payload.email, payload.password, limit=payload.limit)
    return {"emails": emails}


@app.post("/api/email/send")
async def send_email(payload: SendPayload):
    """
    Full send flow:
    1. Fetch quantum key from KM (if level 1 or 2)
    2. Encrypt body with chosen security level
    3. Send via SMTP with X-QKD-* headers
    """
    key_id = None
    key_hex = None

    if payload.level in (1, 2):
        # Key sizing: for OTP use the post-compression byte count (matching what
        # crypto.encrypt() actually XORs); for L2 a single key always suffices.
        attachments_data = [a.model_dump() for a in payload.attachments]
        if payload.level == 1:
            msg_bytes = crypto.compute_otp_byte_count(payload.body, attachments_data)
        else:
            bundle_str = crypto.compute_bundle(payload.body, attachments_data)
            msg_bytes = len(bundle_str.encode("utf-8"))
        keys_needed = max(1, -(-msg_bytes // km_simulator.KEY_SIZE_BYTES))  # ceiling division
        km_result = km_simulator.get_keys(
            payload.sender_sae_id,
            payload.recipient_sae_id,
            number=keys_needed if payload.level == 1 else 1,
        )
        if km_result is None:
            if payload.level == 1:
                raise HTTPException(503, "OTP requires quantum keys — pool exhausted. Refill KM or switch to Level 2+.")
            key_hex = None
            payload.level = 3
        else:
            # Concatenate all fetched key material for OTP (or just use first for L2)
            key_id = km_result["keys"][0]["key_ID"]
            key_hex = "".join(k["key"] for k in km_result["keys"])

    encrypted_body = crypto.encrypt(
        payload.body,
        payload.level,
        key_hex,
        attachments=[a.model_dump() for a in payload.attachments],
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
    )

    if not result["success"]:
        raise HTTPException(500, f"SMTP error: {result['error']}")

    return {
        "success": True,
        "key_id": key_id,
        "level_used": payload.level,
        "encrypted_preview": encrypted_body[:120] + "...",
    }


@app.post("/api/email/decrypt")
async def decrypt_email(payload: DecryptPayload):
    """
    Decrypt a received QuMail message:
    1. Use X-QKD-KeyID header to fetch key from KM
    2. Decrypt with the stored level
    """
    key_hex = None

    if payload.qkd_level in (1, 2) and payload.qkd_key_id and payload.qkd_sender_sae:
        km_result = km_simulator.get_key_by_id(
            slave_sae_id=payload.recipient_sae_id,
            master_sae_id=payload.qkd_sender_sae,
            key_ids=[payload.qkd_key_id],
        )
        if km_result:
            key_hex = km_result["keys"][0]["key"]

    try:
        plaintext, level, attachments = crypto.decrypt(payload.encrypted_body, key_hex)
        return {"success": True, "plaintext": plaintext, "level": level, "attachments": attachments}
    except Exception as e:
        raise HTTPException(400, f"Decryption failed: {str(e)}")


# ─── Demo / utility endpoints ─────────────────────────────────────────────────

@app.get("/api/demo/encrypt_preview")
async def encrypt_preview(text: str, level: int, master_sae_id: str = "alice", slave_sae_id: str = "bob"):
    """
    For the demo: show what the encrypted blob looks like without sending.
    Great for the 'intercept the wire' demo moment.
    """
    key_hex = None
    key_id = None
    if level in (1, 2):
        km_result = km_simulator.get_keys(master_sae_id, slave_sae_id, number=1)
        if km_result:
            key_id = km_result["keys"][0]["key_ID"]
            key_hex = km_result["keys"][0]["key"]
    encrypted = crypto.encrypt(text, level, key_hex)
    return {
        "original": text,
        "encrypted": encrypted,
        "key_id": key_id,
        "level": level,
        "level_name": {1: "OTP (Quantum Secure)", 2: "Quantum-seeded AES", 3: "AES-256-GCM", 4: "No encryption"}[level],
    }


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
    return {"status": "ok", "app": "QuMail"}