"""
QuMail Email Handler
Handles SMTP sending and IMAP fetching for Gmail, Yahoo, and Outlook.
QKD metadata is embedded in custom X-QKD-* headers.
"""

import asyncio
import ssl
import os
from typing import List, Dict, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.parser import BytesParser
from email import policy as email_policy
import email.utils
from dotenv import load_dotenv

load_dotenv()

# ── Provider config ────────────────────────────────────────────────────────────

SMTP_CONFIGS = {
    "gmail": {
        "host": os.getenv("GMAIL_SMTP_HOST", "smtp.gmail.com"),
        "port": int(os.getenv("GMAIL_SMTP_PORT", "465")),
        "use_ssl": True
    },
    "yahoo": {
        "host": os.getenv("YAHOO_SMTP_HOST", "smtp.mail.yahoo.com"),
        "port": int(os.getenv("YAHOO_SMTP_PORT", "465")),
        "use_ssl": True
    },
    "outlook": {
        "host": os.getenv("OUTLOOK_SMTP_HOST", "smtp-mail.outlook.com"),
        "port": int(os.getenv("OUTLOOK_SMTP_PORT", "587")),
        "use_ssl": False  # STARTTLS
    }
}

IMAP_CONFIGS = {
    "gmail": {
        "host": os.getenv("GMAIL_IMAP_HOST", "imap.gmail.com"),
        "port": int(os.getenv("GMAIL_IMAP_PORT", "993"))
    },
    "yahoo": {
        "host": os.getenv("YAHOO_IMAP_HOST", "imap.mail.yahoo.com"),
        "port": int(os.getenv("YAHOO_IMAP_PORT", "993"))
    },
    "outlook": {
        "host": os.getenv("OUTLOOK_IMAP_HOST", "imap-mail.outlook.com"),
        "port": int(os.getenv("OUTLOOK_IMAP_PORT", "993"))
    }
}


def detect_provider(email: str) -> str:
    """Detect email provider from address domain."""
    domain = email.split("@")[-1].lower()
    if "gmail" in domain:
        return "gmail"
    elif "yahoo" in domain or "ymail" in domain:
        return "yahoo"
    elif "outlook" in domain or "hotmail" in domain or "live" in domain or "msn" in domain:
        return "outlook"
    else:
        return "gmail"  # default fallback


async def send_email(
    sender: str,
    password: str,
    recipient: str,
    subject: str,
    encrypted_body: str,
    key_id: str,
    level: int,
    sae_id: str,
    slave_sae: str = ""
) -> Dict:
    """
    Send a QKD-encrypted email via SMTP.
    Embeds encryption metadata in X-QKD-* headers.
    The encrypted_body (JSON string) goes in the email body.
    """
    try:
        import aiosmtplib

        provider = detect_provider(sender)
        cfg = SMTP_CONFIGS[provider]

        msg = MIMEMultipart("alternative")
        msg["From"] = sender
        msg["To"] = recipient
        msg["Subject"] = subject
        msg["Date"] = email.utils.formatdate(localtime=True)

        # QKD metadata headers
        msg["X-QKD-App"] = "QuMail-v2"
        msg["X-QKD-KeyID"] = key_id
        msg["X-QKD-Level"] = str(level)
        msg["X-QKD-SenderSAE"] = sae_id
        if slave_sae:
            msg["X-QKD-SlaveSAE"] = slave_sae

        # Encrypted payload as plain text body
        msg.attach(MIMEText(encrypted_body, "plain", "utf-8"))

        if cfg["use_ssl"]:
            ctx = ssl.create_default_context()
            smtp = aiosmtplib.SMTP(
                hostname=cfg["host"],
                port=cfg["port"],
                use_tls=True,
                tls_context=ctx
            )
        else:
            smtp = aiosmtplib.SMTP(
                hostname=cfg["host"],
                port=cfg["port"],
                start_tls=True
            )

        async with smtp:
            await smtp.login(sender, password)
            await smtp.send_message(msg)

        return {"success": True}

    except Exception as e:
        return {"success": False, "error": str(e)}


async def fetch_emails(
    email_addr: str,
    password: str,
    folder: str = "INBOX",
    limit: int = 20
) -> List[Dict]:
    """
    Fetch emails via IMAP, parsing X-QKD-* headers.
    Returns list of parsed email dicts.
    """
    try:
        import aioimaplib

        provider = detect_provider(email_addr)
        cfg = IMAP_CONFIGS[provider]

        client = aioimaplib.IMAP4_SSL(host=cfg["host"], port=cfg["port"])
        await client.wait_hello_from_server()
        await client.login(email_addr, password)
        await client.select(folder)

        # Fetch message UIDs
        _, data = await client.search("ALL")
        uids = data[0].split()

        if not uids:
            await client.logout()
            return []

        # Fetch latest `limit` messages
        recent_uids = uids[-limit:]
        results = []

        for uid in reversed(recent_uids):
            _, msg_data = await client.fetch(uid.decode(), "(RFC822)")
            if msg_data and len(msg_data) >= 2:
                raw = msg_data[1]
                parsed = BytesParser(policy=email_policy.default).parsebytes(raw)

                # Extract QKD headers
                key_id = parsed.get("X-QKD-KeyID", "")
                level = int(parsed.get("X-QKD-Level", "4"))
                sender_sae = parsed.get("X-QKD-SenderSAE", "")
                slave_sae = parsed.get("X-QKD-SlaveSAE", "")
                is_qumail = parsed.get("X-QKD-App", "") == "QuMail-v2"

                # Get body
                body = ""
                if parsed.is_multipart():
                    for part in parsed.walk():
                        if part.get_content_type() == "text/plain":
                            body = part.get_content()
                            break
                else:
                    body = parsed.get_content()

                results.append({
                    "uid": uid.decode(),
                    "from": str(parsed["From"]),
                    "subject": str(parsed["Subject"] or "(no subject)"),
                    "date": str(parsed["Date"] or ""),
                    "body": body.strip(),
                    "key_id": key_id,
                    "level": level,
                    "sender_sae": sender_sae,
                    "slave_sae": slave_sae,
                    "is_qumail": is_qumail
                })

        await client.logout()
        return results

    except Exception as e:
        return [{"error": str(e)}]