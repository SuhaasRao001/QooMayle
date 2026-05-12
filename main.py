"""
QuMail v2 — Quantum-Secure Email Backend
FastAPI + Uvicorn
"""

import os
import json
import base64
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv

load_dotenv()

from models import (
    LoginPayload, EncryptPayload, SendPayload, DecryptPayload,
    DecKeysPayload, KyberDecryptPayload
)
from database import init_db, save_message, fetch_inbox, get_message, log_audit, get_audit_log
from km_simulator import get_keys, get_key_by_id, get_status, get_keys_for_otp, combine_key_material
from crypto import (
    compute_bundle, unpack_bundle,
    otp_encrypt, otp_decrypt,
    qaes_encrypt, qaes_decrypt,
    kyber_encrypt, kyber_decrypt, kyber_generate_keypair,
    plaintext_encrypt, plaintext_decrypt,
    KYBER_AVAILABLE
)
from email_handler import send_email, fetch_emails, detect_provider

# ── JWT ────────────────────────────────────────────────────────────────────────
from jose import jwt, JWTError

JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-prod")
JWT_EXPIRY = int(os.getenv("JWT_EXPIRY", "900"))
ALLOW_LEVEL4 = os.getenv("ALLOW_LEVEL4", "false").lower() == "true"

# ── App setup ──────────────────────────────────────────────────────────────────
app = FastAPI(title="QuMail v2", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

security = HTTPBearer(auto_error=False)


# ── Auth helpers ───────────────────────────────────────────────────────────────

def create_token(email: str, sae_id: str) -> str:
    payload = {
        "sub": email,
        "sae_id": sae_id,
        "exp": datetime.utcnow() + timedelta(seconds=JWT_EXPIRY)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=["HS256"])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# ══════════════════════════════════════════════════════════════
# Routes
# ══════════════════════════════════════════════════════════════

@app.get("/")
async def serve_frontend():
    return FileResponse(os.path.join(static_dir, "index.html"))


# ── Auth ───────────────────────────────────────────────────────────────────────

@app.post("/api/login")
async def login(payload: LoginPayload):
    """Authenticate and return JWT. In production, validate against real auth provider."""
    if not payload.email or not payload.password or not payload.sae_id:
        raise HTTPException(status_code=400, detail="Missing credentials")

    token = create_token(payload.email, payload.sae_id)
    return {"token": token, "expires_in": JWT_EXPIRY, "email": payload.email, "sae_id": payload.sae_id}


@app.post("/api/refresh")
async def refresh_token(user=Depends(get_current_user)):
    token = create_token(user["sub"], user["sae_id"])
    return {"token": token, "expires_in": JWT_EXPIRY}


# ── KM endpoints ───────────────────────────────────────────────────────────────

@app.get("/api/km/status")
async def km_status(
    master_sae: str = Query(...),
    slave_sae: str = Query(...),
    user=Depends(get_current_user)
):
    status = get_status(master_sae, slave_sae)
    return status


@app.get("/api/km/keys/enc")
async def km_get_keys_enc(
    master_sae: str = Query(...),
    slave_sae: str = Query(...),
    number: int = Query(1),
    user=Depends(get_current_user)
):
    """Fetch fresh keys for encryption (marks as used)."""
    try:
        keys = get_keys(master_sae, slave_sae, number)
        return {"keys": keys}
    except ValueError as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.post("/api/km/keys/dec")
async def km_get_keys_dec(
    payload: DecKeysPayload,
    user=Depends(get_current_user)
):
    """Retrieve keys by ID for decryption."""
    try:
        keys = get_key_by_id(payload.master_sae, payload.slave_sae, payload.key_ids)
        return {"keys": keys}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ── Kyber keypair ──────────────────────────────────────────────────────────────

@app.get("/api/kyber/keypair")
async def get_kyber_keypair(user=Depends(get_current_user)):
    """Generate ephemeral Kyber-768 keypair for Level 3."""
    kp = kyber_generate_keypair()
    kp["kyber_native"] = KYBER_AVAILABLE
    return kp


# ── Encrypt ────────────────────────────────────────────────────────────────────

@app.post("/api/email/encrypt")
async def encrypt_email(payload: EncryptPayload, user=Depends(get_current_user)):
    """
    Encrypt email body + attachments bundle.
    Returns encrypted payload + key_id for later decryption.
    """
    if payload.level == 4 and not ALLOW_LEVEL4:
        raise HTTPException(status_code=403, detail="Level 4 (plaintext) is disabled. Set ALLOW_LEVEL4=true in .env to enable.")

    if payload.level not in [1, 2, 3, 4]:
        raise HTTPException(status_code=400, detail="Invalid security level (1-4)")

    bundle = compute_bundle(
        payload.body,
        [a.model_dump() for a in (payload.attachments or [])]
    )
    attachments_count = len(payload.attachments or [])

    try:
        if payload.level == 1:
            # OTP: need enough key bytes
            bundle_bytes = bundle.encode("utf-8")
            import gzip
            compressed_size = len(gzip.compress(bundle_bytes))
            km_keys = get_keys_for_otp(payload.master_sae, payload.slave_sae, compressed_size)
            key_material = combine_key_material(km_keys).hex()
            key_id = km_keys[0]["key_ID"]  # store first key ID as reference
            result = otp_encrypt(bundle, key_material)
            encrypted_blob = json.dumps({
                "level": 1,
                "ciphertext_b64": result["ciphertext_b64"],
                "msg_len": result["msg_len"],
                "key_ids": [k["key_ID"] for k in km_keys]
            })

        elif payload.level == 2:
            km_keys = get_keys(payload.master_sae, payload.slave_sae, 1)
            key_id = km_keys[0]["key_ID"]
            key_hex = km_keys[0]["key"]
            result = qaes_encrypt(bundle, key_hex)
            encrypted_blob = json.dumps({
                "level": 2,
                "ciphertext_b64": result["ciphertext_b64"],
                "nonce_b64": result["nonce_b64"],
                "tag_b64": result["tag_b64"]
            })

        elif payload.level == 3:
            # Generate ephemeral Kyber keypair
            kp = kyber_generate_keypair()
            result = kyber_encrypt(bundle, kp["public_key_b64"])
            key_id = "kyber-" + kp["public_key_b64"][:16]
            encrypted_blob = json.dumps({
                "level": 3,
                "ciphertext_b64": result["ciphertext_b64"],
                "encapsulated_secret_b64": result["encapsulated_secret_b64"],
                "nonce_b64": result["nonce_b64"],
                "tag_b64": result["tag_b64"],
                "secret_key_b64": kp["secret_key_b64"],  # stored for decryption
                "kyber_available": result["kyber_available"]
            })

        else:  # Level 4
            result = plaintext_encrypt(bundle)
            key_id = "plaintext"
            encrypted_blob = json.dumps({
                "level": 4,
                "ciphertext_b64": result["ciphertext_b64"]
            })

        log_audit("encrypt", payload.level, key_id, user["sub"], True)

        return {
            "encrypted_body": encrypted_blob,
            "key_id": key_id,
            "size_bytes": len(encrypted_blob.encode()),
            "level": payload.level,
            "attachments_count": attachments_count
        }

    except ValueError as e:
        log_audit("encrypt", payload.level, "N/A", user["sub"], False)
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        log_audit("encrypt", payload.level, "N/A", user["sub"], False)
        raise HTTPException(status_code=500, detail=f"Encryption failed: {str(e)}")


# ── Send ───────────────────────────────────────────────────────────────────────

@app.post("/api/email/send")
async def send_email_endpoint(payload: SendPayload, user=Depends(get_current_user)):
    """Send encrypted email via SMTP and save to DB."""
    # Save to local DB first
    blob = json.loads(payload.encrypted_body)
    msg_id = save_message(
        sender=payload.sender,
        recipient=payload.recipient,
        subject=payload.subject,
        encrypted_body=payload.encrypted_body,
        level=payload.level,
        key_id=payload.key_id,
        attachments_count=blob.get("attachments_count", 0),
        slave_sae=payload.slave_sae
    )

    # Send via SMTP
    result = await send_email(
        sender=payload.sender,
        password=payload.password,
        recipient=payload.recipient,
        subject=payload.subject,
        encrypted_body=payload.encrypted_body,
        key_id=payload.key_id,
        level=payload.level,
        sae_id=payload.sae_id,
        slave_sae=payload.slave_sae
    )

    log_audit("send", payload.level, payload.key_id, payload.sender, result["success"])

    if not result["success"]:
        return {"success": False, "msg_id": msg_id, "error": result.get("error", "SMTP failed"), "saved_locally": True}

    return {"success": True, "msg_id": msg_id}


# ── Inbox ──────────────────────────────────────────────────────────────────────

@app.get("/api/email/inbox")
async def get_inbox(limit: int = Query(50), user=Depends(get_current_user)):
    """Fetch inbox from local DB."""
    messages = fetch_inbox(user["sub"], limit)
    return {"messages": messages, "count": len(messages)}


@app.get("/api/email/{msg_id}")
async def get_email(msg_id: str, user=Depends(get_current_user)):
    """Fetch a single message from DB."""
    msg = get_message(msg_id)
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    return msg


# ── Decrypt ────────────────────────────────────────────────────────────────────

@app.post("/api/email/decrypt")
async def decrypt_email(payload: DecryptPayload, user=Depends(get_current_user)):
    """
    Fetch message from DB, retrieve key from KM, decrypt, and return body + attachments.
    """
    msg = get_message(payload.msg_id)
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")

    try:
        blob = json.loads(msg["encrypted_body"])
        level = blob["level"]

        if level == 1:
            key_ids = blob["key_ids"]
            master_sae = payload.recipient_sae_id
            slave_sae = msg.get("slave_sae") or msg["sender"]
            km_keys = get_key_by_id(master_sae, slave_sae, key_ids)
            key_material = combine_key_material(km_keys).hex()
            plaintext = otp_decrypt(blob["ciphertext_b64"], key_material, blob["msg_len"])

        elif level == 2:
            master_sae = payload.recipient_sae_id
            slave_sae = msg.get("slave_sae") or ""
            try:
                km_keys = get_key_by_id(master_sae, slave_sae, [msg["key_id"]])
                key_hex = km_keys[0]["key"]
            except:
                raise HTTPException(status_code=404, detail="Key not found in KM. Ensure sender and recipient share the same SAE pair.")
            plaintext = qaes_decrypt(
                blob["ciphertext_b64"],
                blob["nonce_b64"],
                blob["tag_b64"],
                key_hex
            )

        elif level == 3:
            if not KYBER_AVAILABLE:
                raise HTTPException(status_code=503, detail="liboqs not installed. Level 3 decryption unavailable.")
            plaintext = kyber_decrypt(
                blob["ciphertext_b64"],
                blob["encapsulated_secret_b64"],
                blob["secret_key_b64"],
                blob["nonce_b64"],
                blob["tag_b64"]
            )

        elif level == 4:
            if not ALLOW_LEVEL4:
                raise HTTPException(status_code=403, detail="Level 4 disabled")
            plaintext = plaintext_decrypt(blob["ciphertext_b64"])

        else:
            raise HTTPException(status_code=400, detail="Unknown level")

        body, attachments = unpack_bundle(plaintext)
        log_audit("decrypt", level, msg["key_id"], user["sub"], True)
        return {"success": True, "body": body, "attachments": attachments, "level": level}

    except HTTPException:
        raise
    except Exception as e:
        log_audit("decrypt", msg.get("level", 0), msg.get("key_id", ""), user["sub"], False)
        raise HTTPException(status_code=500, detail=f"Decryption failed: {str(e)}")


# ── Admin ──────────────────────────────────────────────────────────────────────

@app.get("/api/admin/audit")
async def get_audit(limit: int = Query(100), user=Depends(get_current_user)):
    """Retrieve audit log."""
    logs = get_audit_log(limit)
    return {"logs": logs, "count": len(logs)}


# ── Demo: simulate receiving an email ─────────────────────────────────────────

@app.post("/api/demo/receive")
async def demo_receive(data: dict, user=Depends(get_current_user)):
    """Demo endpoint to inject a pre-encrypted email into inbox (for testing without real IMAP)."""
    msg_id = save_message(
        sender=data.get("sender", "demo@example.com"),
        recipient=user["sub"],
        subject=data.get("subject", "Demo QuMail Message"),
        encrypted_body=data.get("encrypted_body", ""),
        level=data.get("level", 2),
        key_id=data.get("key_id", "demo-key"),
        attachments_count=data.get("attachments_count", 0),
        slave_sae=data.get("slave_sae", user.get("sae_id", ""))
    )
    return {"success": True, "msg_id": msg_id}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)