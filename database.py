import sqlite3
import uuid
import json
from datetime import datetime
from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("DATABASE_URL", "sqlite:///./qumail.db").replace("sqlite:///", "")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            subject TEXT NOT NULL,
            encrypted_body TEXT NOT NULL,
            level INTEGER NOT NULL,
            key_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            attachments_count INTEGER DEFAULT 0,
            kyber_encapsulated_secret TEXT,
            kyber_public_key TEXT,
            slave_sae TEXT DEFAULT ""
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            operation TEXT NOT NULL,
            level INTEGER,
            key_id TEXT,
            sender TEXT,
            timestamp TEXT NOT NULL,
            success INTEGER DEFAULT 1
        );
    """)
    conn.commit()
    conn.close()


def save_message(sender: str, recipient: str, subject: str, encrypted_body: str,
                 level: int, key_id: str, attachments_count: int = 0,
                 kyber_encapsulated_secret: str = None, kyber_public_key: str = None,
                 slave_sae: str = "") -> str:
    msg_id = str(uuid.uuid4())
    conn = get_conn()
    conn.execute(
        """INSERT INTO messages 
           (id, sender, recipient, subject, encrypted_body, level, key_id, timestamp, 
            attachments_count, kyber_encapsulated_secret, kyber_public_key, slave_sae)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (msg_id, sender, recipient, subject, encrypted_body, level, key_id,
         datetime.utcnow().isoformat(), attachments_count,
         kyber_encapsulated_secret, kyber_public_key, slave_sae)
    )
    conn.commit()
    conn.close()
    return msg_id


def fetch_inbox(email: str, limit: int = 50) -> list:
    conn = get_conn()
    rows = conn.execute(
        """SELECT id, sender, subject, timestamp, level, attachments_count 
           FROM messages WHERE recipient = ? 
           ORDER BY timestamp DESC LIMIT ?""",
        (email, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_message(msg_id: str) -> dict:
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM messages WHERE id = ?", (msg_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def log_audit(operation: str, level: int, key_id: str, sender: str, success: bool = True):
    conn = get_conn()
    conn.execute(
        """INSERT INTO audit_log (id, operation, level, key_id, sender, timestamp, success)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (str(uuid.uuid4()), operation, level, key_id, sender,
         datetime.utcnow().isoformat(), 1 if success else 0)
    )
    conn.commit()
    conn.close()


def get_audit_log(limit: int = 100) -> list:
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]