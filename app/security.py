"""Secret handling helpers: Fernet encryption for stored mailbox passwords + CSRF."""
import base64
import hashlib
import hmac
import secrets

from cryptography.fernet import Fernet, InvalidToken
from flask import abort, current_app, request, session


def _fernet():
    key = hashlib.sha256(current_app.config["SECRET_KEY"].encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt(value: str) -> str:
    return _fernet().encrypt((value or "").encode()).decode()


def decrypt(token: str) -> str:
    try:
        return _fernet().decrypt((token or "").encode()).decode()
    except InvalidToken:
        return ""


def csrf_token() -> str:
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


def csrf_protect():
    if not current_app.config.get("WTF_CSRF_ENABLED", True):
        return
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and not request.path.startswith("/api/"):
        sent = request.form.get("_csrf", "")
        if not hmac.compare_digest(sent, session.get("_csrf", "x")):
            abort(400, "Invalid or missing CSRF token")


def new_api_key() -> str:
    return "cs_" + secrets.token_urlsafe(32)
