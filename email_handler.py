"""
Email Handler — IMAP fetch and SMTP send.
Works with Gmail (requires App Password), Yahoo, and any IMAP/SMTP provider.

QuMail encryption happens BEFORE aiosmtplib touches the message.
The email body contains a JSON payload — Gmail sees an opaque blob.
The X-QKD-KeyID and X-QKD-Level headers tell the recipient which key to fetch.
"""
import asyncio
import ssl
import email as email_lib
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional
import aiosmtplib
import aioimaplib


SMTP_CONFIGS = {
    "gmail": {"host": "smtp.gmail.com", "port": 465},
    "yahoo": {"host": "smtp.mail.yahoo.com", "port": 465},
    "outlook": {"host": "smtp-mail.outlook.com", "port": 587},
}

IMAP_CONFIGS = {
    "gmail": {"host": "imap.gmail.com", "port": 993},
    "yahoo": {"host": "imap.mail.yahoo.com", "port": 993},
    "outlook": {"host": "outlook.office365.com", "port": 993},
}


def detect_provider(email_addr: str) -> str:
    domain = email_addr.split("@")[-1].lower()
    if "gmail" in domain:
        return "gmail"
    elif "yahoo" in domain:
        return "yahoo"
    elif "outlook" in domain or "hotmail" in domain:
        return "outlook"
    return "gmail"  # default fallback


async def send_email(
    sender: str,
    password: str,
    recipient: str,
    subject: str,
    encrypted_body: str,
    key_id: Optional[str],
    level: int,
    sender_sae_id: str,
) -> dict:
    """Send an email with encrypted body and QKD headers."""
    try:
        provider = detect_provider(sender)
        cfg = SMTP_CONFIGS[provider]

        msg = MIMEMultipart()
        msg["From"] = sender
        msg["To"] = recipient
        msg["Subject"] = subject

        # QKD metadata headers — recipient's app reads these to know which key to fetch
        if key_id:
            msg["X-QKD-KeyID"] = key_id
            msg["X-QKD-SenderSAE"] = sender_sae_id
        msg["X-QKD-Level"] = str(level)
        msg["X-QKD-App"] = "QuMail-1.0"

        # The encrypted_body JSON blob already contains any attachments bundled
        # and protected under the same quantum-secure level as the message body.
        # No plaintext MIME attachments are added here.
        msg.attach(MIMEText(encrypted_body, "plain"))

        if provider == "outlook":
            # Outlook uses STARTTLS on 587
            await aiosmtplib.send(msg, hostname=cfg["host"], port=cfg["port"],
                                  username=sender, password=password, start_tls=True)
        else:
            await aiosmtplib.send(msg, hostname=cfg["host"], port=cfg["port"],
                                  username=sender, password=password, use_tls=True)

        return {"success": True}

    except Exception as e:
        return {"success": False, "error": str(e)}


async def fetch_emails(email_addr: str, password: str, folder: str = "INBOX", limit: int = 20) -> list:
    """Fetch recent emails via IMAP. Returns list of parsed email dicts."""
    provider = detect_provider(email_addr)
    cfg = IMAP_CONFIGS[provider]

    try:
        imap = aioimaplib.IMAP4_SSL(host=cfg["host"], port=cfg["port"])
        await imap.wait_hello_from_server()
        await imap.login(email_addr, password)
        await imap.select(folder)

        # Fetch most recent N message IDs
        _, data = await imap.search("ALL")
        if not data or not data[0]:
            await imap.logout()
            return []

        ids = data[0].split()
        recent_ids = ids[-limit:]  # last N emails

        emails = []
        for uid in reversed(recent_ids):
            _, msg_data = await imap.fetch(uid.decode(), "(RFC822)")
            if not msg_data or len(msg_data) < 2:
                continue

            raw = msg_data[1]
            if isinstance(raw, (bytes, bytearray)):
                parsed = email_lib.message_from_bytes(raw)
            else:
                continue

            body = ""
            if parsed.is_multipart():
                for part in parsed.walk():
                    if part.get_content_type() == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = payload.decode("utf-8", errors="replace")
                            break
            else:
                payload = parsed.get_payload(decode=True)
                if payload:
                    body = payload.decode("utf-8", errors="replace")

            emails.append({
                "uid": uid.decode(),
                "from": parsed.get("From", ""),
                "to": parsed.get("To", ""),
                "subject": parsed.get("Subject", "(no subject)"),
                "date": parsed.get("Date", ""),
                "body": body,
                "qkd_key_id": parsed.get("X-QKD-KeyID", None),
                "qkd_level": int(parsed.get("X-QKD-Level", 4)),
                "qkd_sender_sae": parsed.get("X-QKD-SenderSAE", None),
                "is_qumail": parsed.get("X-QKD-App", None) == "QuMail-1.0",
            })

        await imap.logout()
        return emails

    except Exception as e:
        return [{"error": str(e)}]