"""Cryptographic utilities for securing GitHub App credentials and webhook verification."""
import base64
import hashlib
import json
from typing import Any, Dict, Optional
from cryptography.fernet import Fernet, InvalidToken

from ...core.config import settings
from ...core.errors import AppSecException


class CredentialEncryptionError(AppSecException):
    def __init__(self, message: str = "Credential encryption/decryption failed"):
        super().__init__(message=message, code="CREDENTIAL_CRYPTO_ERROR", status_code=500)


def _get_fernet_cipher() -> Fernet:
    """Derive a reproducible 32-byte URL-safe base64 key from application SECRET_KEY."""
    derived_32_bytes = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
    b64_key = base64.urlsafe_b64encode(derived_32_bytes)
    return Fernet(b64_key)


def encrypt_credentials(payload: Dict[str, Any]) -> str:
    """Encrypt sensitive integration credentials (e.g. private keys, access tokens) at rest."""
    try:
        cipher = _get_fernet_cipher()
        raw_json = json.dumps(payload).encode("utf-8")
        encrypted = cipher.encrypt(raw_json)
        return encrypted.decode("utf-8")
    except Exception as exc:
        raise CredentialEncryptionError(f"Failed to encrypt integration credentials: {str(exc)}")


def decrypt_credentials(encrypted_text: str) -> Dict[str, Any]:
    """Decrypt stored integration credentials back to payload dictionary."""
    if not encrypted_text:
        return {}
    try:
        cipher = _get_fernet_cipher()
        decrypted = cipher.decrypt(encrypted_text.encode("utf-8"))
        return json.loads(decrypted.decode("utf-8"))
    except InvalidToken:
        raise CredentialEncryptionError("Corrupted or invalid credential token; decryption failed.")
    except Exception as exc:
        raise CredentialEncryptionError(f"Failed to decrypt credentials: {str(exc)}")


def encrypt_credential(raw_token: str) -> str:
    """Encrypt a raw token string at rest."""
    try:
        cipher = _get_fernet_cipher()
        encrypted = cipher.encrypt(raw_token.encode("utf-8"))
        return encrypted.decode("utf-8")
    except Exception as exc:
        raise CredentialEncryptionError(f"Failed to encrypt credential: {str(exc)}")


def decrypt_credential(encrypted_text: str) -> str:
    """Decrypt an encrypted credential string."""
    if not encrypted_text:
        return ""
    try:
        cipher = _get_fernet_cipher()
        decrypted = cipher.decrypt(encrypted_text.encode("utf-8"))
        return decrypted.decode("utf-8")
    except InvalidToken:
        raise CredentialEncryptionError("Corrupted or invalid credential token; decryption failed.")
    except Exception as exc:
        raise CredentialEncryptionError(f"Failed to decrypt credential: {str(exc)}")


def hash_webhook_secret(secret: str) -> str:
    """Hash webhook secret using random salt and SHA-256."""
    import secrets
    salt = secrets.token_hex(16)
    digest = hashlib.sha256(f"{salt}:{secret}".encode("utf-8")).hexdigest()
    return f"{salt}:{digest}"


def verify_webhook_secret_hash(secret: str, stored_hash: str) -> bool:
    """Constant-time verification of webhook secret hash."""
    import hmac
    if ":" not in stored_hash:
        return False
    salt, expected_digest = stored_hash.split(":", 1)
    computed_digest = hashlib.sha256(f"{salt}:{secret}".encode("utf-8")).hexdigest()
    return hmac.compare_digest(computed_digest, expected_digest)


def compute_secret_digest(secret: str) -> str:
    """Compute a salted SHA-256 digest of webhook secret for tamper-detection storage."""
    salt = settings.SECRET_KEY[:16]
    return hashlib.sha256(f"{salt}:{secret}".encode("utf-8")).hexdigest()
