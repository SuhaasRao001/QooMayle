from pydantic import BaseModel, EmailStr
from typing import Optional, List
from enum import IntEnum


class SecurityLevel(IntEnum):
    OTP = 1
    QAES = 2
    KYBER = 3
    PLAINTEXT = 4


class AttachmentItem(BaseModel):
    filename: str
    data_b64: str
    mime_type: str
    size: int


class LoginPayload(BaseModel):
    email: str
    password: str
    sae_id: str


class EncryptPayload(BaseModel):
    body: str
    attachments: Optional[List[AttachmentItem]] = []
    level: int = 2
    master_sae: str
    slave_sae: str


class SendPayload(BaseModel):
    sender: str
    password: str
    recipient: str
    subject: str
    encrypted_body: str
    key_id: str
    level: int
    sae_id: str
    slave_sae: str


class DecryptPayload(BaseModel):
    msg_id: str
    recipient_email: str
    recipient_password: str
    recipient_sae_id: str


class KyberDecryptPayload(BaseModel):
    ciphertext_b64: str
    encapsulated_secret_b64: str
    secret_key_b64: str


class DecKeysPayload(BaseModel):
    master_sae: str
    slave_sae: str
    key_ids: List[str]