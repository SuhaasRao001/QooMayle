"""
Crypto Engine — implements all 4 QuMail security levels.

Level 1 — One-Time Pad (OTP)
    XOR plaintext with quantum key bytes. Unconditionally secure.
    Requires quantum key bytes equal in length to the message.

Level 2 — Quantum-seeded AES-256-GCM
    Quantum key bytes are used as entropy to derive an AES key via HKDF.
    Encrypts arbitrary-length messages. Strong classical + quantum seed.

Level 3 — Standard AES-256-GCM (no quantum)
    Classical AES with a random key. PQC-ready placeholder.
    Use when KM is unreachable.

Level 4 — No encryption (plaintext)
    Message sent as-is. Baseline for demo comparison.
"""
import os
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()

def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode())


# ─── Bundle helpers ──────────────────────────────────────────────────────────

def _pack_bundle(body: str, attachments: list = None) -> str:
    """Combine message body + attachment list into one JSON string before encryption.
    Attachments is a list of {filename, data_b64, mime_type, size} dicts.
    """
    return json.dumps({"body": body, "attachments": attachments or []})


def _unpack_bundle(decrypted_text: str) -> tuple:
    """Extract body + attachments from a decrypted bundle string.
    Falls back gracefully for legacy messages that contain raw plaintext.
    """
    try:
        obj = json.loads(decrypted_text)
        if isinstance(obj, dict) and "body" in obj:
            return obj["body"], obj.get("attachments", [])
    except Exception:
        pass
    # Legacy / non-QuMail message — treat entire text as body
    return decrypted_text, []


def compute_bundle(body: str, attachments: list = None) -> str:
    """Return the bundle string that will be encrypted.
    Exposed so callers (e.g. main.py) can compute byte-length for OTP key sizing.
    """
    return _pack_bundle(body, attachments)


# ─── Level 1: One-Time Pad ────────────────────────────────────────────────────

def otp_encrypt(plaintext: str, key_hex: str) -> dict:
    pt_bytes = plaintext.encode("utf-8")
    key_bytes = bytes.fromhex(key_hex)
    if len(key_bytes) < len(pt_bytes):
        raise ValueError(
            f"OTP requires key ≥ message length. "
            f"Key: {len(key_bytes)}B, Message: {len(pt_bytes)}B. "
            "Request a longer key or use Level 2."
        )
    key_slice = key_bytes[:len(pt_bytes)]
    ciphertext = bytes(a ^ b for a, b in zip(pt_bytes, key_slice))
    return {
        "level": 1,
        "ciphertext": _b64(ciphertext),
        "msg_len": len(pt_bytes),
    }


def otp_decrypt(payload: dict, key_hex: str) -> str:
    ct = _unb64(payload["ciphertext"])
    key_bytes = bytes.fromhex(key_hex)[:payload["msg_len"]]
    return bytes(a ^ b for a, b in zip(ct, key_bytes)).decode("utf-8")


# ─── Level 2: Quantum-seeded AES-256-GCM ─────────────────────────────────────

def qaes_encrypt(plaintext: str, key_hex: str) -> dict:
    quantum_seed = bytes.fromhex(key_hex)
    # Derive 32-byte AES key from quantum seed
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"QuMail-Level2-AES",
    ).derive(quantum_seed)
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return {
        "level": 2,
        "nonce": _b64(nonce),
        "ciphertext": _b64(ct),
    }


def qaes_decrypt(payload: dict, key_hex: str) -> str:
    quantum_seed = bytes.fromhex(key_hex)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"QuMail-Level2-AES",
    ).derive(quantum_seed)
    nonce = _unb64(payload["nonce"])
    ct = _unb64(payload["ciphertext"])
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ct, None).decode("utf-8")


# ─── Level 3: Standard AES-256-GCM (no quantum) ──────────────────────────────

def aes_encrypt(plaintext: str) -> dict:
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return {
        "level": 3,
        "key": _b64(aes_key),   # key travels with message for demo; in prod use PKI
        "nonce": _b64(nonce),
        "ciphertext": _b64(ct),
    }


def aes_decrypt(payload: dict) -> str:
    aes_key = _unb64(payload["key"])
    nonce = _unb64(payload["nonce"])
    ct = _unb64(payload["ciphertext"])
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ct, None).decode("utf-8")


# ─── Level 4: No encryption ───────────────────────────────────────────────────

def plain_encrypt(plaintext: str) -> dict:
    return {"level": 4, "plaintext": plaintext}


def plain_decrypt(payload: dict) -> str:
    return payload["plaintext"]


# ─── Unified interface ────────────────────────────────────────────────────────

def encrypt(plaintext: str, level: int, key_hex: str = None, attachments: list = None) -> str:
    """Returns JSON string to embed in email body.

    Attachments (list of {filename, data_b64, mime_type, size} dicts) are bundled
    with the body *before* any crypto function runs, so the chosen security level
    protects the full message payload atomically.
    """
    bundle = _pack_bundle(plaintext, attachments)
    if level == 1:
        payload = otp_encrypt(bundle, key_hex)
    elif level == 2:
        payload = qaes_encrypt(bundle, key_hex)
    elif level == 3:
        payload = aes_encrypt(bundle)
    else:
        payload = plain_encrypt(bundle)
    return json.dumps(payload)


def decrypt(payload_json: str, key_hex: str = None) -> tuple:
    """Returns (plaintext, level, attachments).

    attachments is a list of {filename, data_b64, mime_type, size} dicts.
    It is an empty list for messages sent without attachments or by older clients.
    """
    payload = json.loads(payload_json)
    level = payload.get("level", 4)
    if level == 1:
        raw = otp_decrypt(payload, key_hex)
    elif level == 2:
        raw = qaes_decrypt(payload, key_hex)
    elif level == 3:
        raw = aes_decrypt(payload)
    else:
        raw = plain_decrypt(payload)
    body, attachments = _unpack_bundle(raw)
    return body, level, attachments