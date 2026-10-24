"""Gmail API OAuth2 integration.

This module provides:
- OAuth2 authorization URL generation
- Token exchange (code → access + refresh token)
- Token refresh when expired
- Gmail message fetching via the Gmail REST API (not IMAP)
- Incremental sync using Gmail history IDs

REQUIREMENTS (not in requirements.txt yet — added to optional section):
  google-auth>=2.0
  google-auth-oauthlib>=1.0
  google-api-python-client>=2.0

If these packages are not installed the module degrades gracefully:
gmail_available() returns False and all public functions raise RuntimeError
with a clear message rather than ImportError.

PRIVACY NOTE: We store the access/refresh tokens Fernet-encrypted in the
OAuthToken model. We never transmit email bodies to external services.
"""

from __future__ import annotations

import base64
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

log = logging.getLogger(__name__)

# ── Dependency guard ─────────────────────────────────────────────────────────
_DEPS_OK = False
try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import Flow
    from googleapiclient.discovery import build as _build_service
    from googleapiclient.errors import HttpError
    _DEPS_OK = True
except ImportError:
    log.info(
        "Gmail API dependencies not installed. "
        "Run: pip install google-auth google-auth-oauthlib google-api-python-client"
    )


def gmail_available() -> bool:
    """Return True only when the google-api-python-client packages are installed."""
    return _DEPS_OK


def _require_deps():
    if not _DEPS_OK:
        raise RuntimeError(
            "Gmail API libraries not installed. "
            "Install them with: pip install google-auth google-auth-oauthlib google-api-python-client"
        )


# ── OAuth2 flow helpers ───────────────────────────────────────────────────────

def get_authorization_url(cfg: dict) -> Tuple[str, str]:
    """Return (authorization_url, state) to redirect the user to Google."""
    _require_deps()
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": cfg["GMAIL_CLIENT_ID"],
                "client_secret": cfg["GMAIL_CLIENT_SECRET"],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [cfg["GMAIL_REDIRECT_URI"]],
            }
        },
        scopes=cfg["GMAIL_SCOPES"],
        redirect_uri=cfg["GMAIL_REDIRECT_URI"],
    )
    url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    return url, state


def exchange_code(cfg: dict, code: str, state: str) -> dict:
    """Exchange an authorization code for access + refresh tokens.

    Returns a dict with keys:
      access_token, refresh_token, expiry (datetime), email, scopes
    """
    _require_deps()
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": cfg["GMAIL_CLIENT_ID"],
                "client_secret": cfg["GMAIL_CLIENT_SECRET"],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [cfg["GMAIL_REDIRECT_URI"]],
            }
        },
        scopes=cfg["GMAIL_SCOPES"],
        redirect_uri=cfg["GMAIL_REDIRECT_URI"],
        state=state,
    )
    flow.fetch_token(code=code)
    creds = flow.credentials
    # Get the email address from userinfo
    service = _build_service("oauth2", "v2", credentials=creds)
    info = service.userinfo().get().execute()
    return {
        "access_token": creds.token,
        "refresh_token": creds.refresh_token or "",
        "expiry": creds.expiry,  # datetime or None
        "email": info.get("email", ""),
        "scopes": " ".join(creds.scopes or []),
    }


def _make_credentials(token: "OAuthToken", cfg: dict) -> "Credentials":
    """Build a google.oauth2.credentials.Credentials from an OAuthToken record."""
    _require_deps()
    expiry = token.token_expiry
    if expiry and expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    creds = Credentials(
        token=token.access_token,
        refresh_token=token.refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=cfg["GMAIL_CLIENT_ID"],
        client_secret=cfg["GMAIL_CLIENT_SECRET"],
        scopes=cfg["GMAIL_SCOPES"],
        expiry=expiry,
    )
    return creds


def refresh_token_if_needed(token: "OAuthToken", cfg: dict) -> bool:
    """Refresh the access token if it has expired. Returns True if refreshed."""
    _require_deps()
    if not token.is_expired:
        return False
    try:
        creds = _make_credentials(token, cfg)
        creds.refresh(Request())
        token.access_token = creds.token
        if creds.refresh_token:
            token.refresh_token = creds.refresh_token
        token.token_expiry = creds.expiry.replace(tzinfo=None) if creds.expiry else None
        return True
    except Exception as e:
        log.warning("Gmail token refresh failed for %s: %s", token.email, e)
        token.last_status = f"Token refresh failed: {str(e)[:200]}"
        return False


# ── Gmail API fetch helpers ───────────────────────────────────────────────────

def _decode_message_part(part: dict) -> bytes:
    """Base64url-decode a message part body."""
    data = part.get("body", {}).get("data", "")
    if not data:
        return b""
    return base64.urlsafe_b64decode(data + "==")


def _build_raw_rfc822(msg: dict) -> bytes:
    """Re-serialize a Gmail API message resource as RFC822 bytes.

    Gmail's `format=raw` returns the full RFC822 message base64url-encoded.
    """
    raw = msg.get("raw", "")
    if raw:
        return base64.urlsafe_b64decode(raw + "==")
    # Fallback: can't reconstruct a proper RFC822 from parsed form
    return b""


def fetch_new_messages(token: "OAuthToken", cfg: dict, limit: int = 50):
    """Fetch new unread messages from Gmail using the Gmail API.

    Uses incremental history sync when a history_id is stored, otherwise
    falls back to fetching the latest *limit* messages.

    Yields (message_id_str, raw_rfc822_bytes) tuples.
    """
    _require_deps()
    creds = _make_credentials(token, cfg)
    if token.is_expired:
        if not refresh_token_if_needed(token, cfg):
            raise RuntimeError("Cannot refresh expired Gmail OAuth token")
        creds = _make_credentials(token, cfg)

    service = _build_service("gmail", "v1", credentials=creds)

    try:
        if token.last_history_id:
            # Incremental: list changes since last_history_id
            try:
                history = (
                    service.users().history()
                    .list(userId="me", startHistoryId=token.last_history_id,
                          historyTypes=["messageAdded"])
                    .execute()
                )
                new_ids = []
                for record in history.get("history", []):
                    for added in record.get("messagesAdded", []):
                        new_ids.append(added["message"]["id"])
                token.last_history_id = history.get("historyId", token.last_history_id)
            except HttpError as e:
                if e.resp.status == 404:
                    # History expired — fall back to full fetch
                    log.info("Gmail history expired for %s, falling back to full fetch", token.email)
                    token.last_history_id = ""
                    new_ids = _list_recent_ids(service, limit)
                else:
                    raise
        else:
            new_ids = _list_recent_ids(service, limit)
            # Record latest history ID for next run
            profile = service.users().getProfile(userId="me").execute()
            token.last_history_id = profile.get("historyId", "")

        for msg_id in new_ids[:limit]:
            try:
                msg = (service.users().messages()
                       .get(userId="me", id=msg_id, format="raw")
                       .execute())
                raw = _build_raw_rfc822(msg)
                if raw:
                    yield msg_id, raw
            except Exception as e:
                log.warning("Failed to fetch Gmail message %s: %s", msg_id, e)

    except HttpError as e:
        log.error("Gmail API error for %s: %s", token.email, e)
        raise


def _list_recent_ids(service, limit: int):
    """List the latest *limit* message IDs from Gmail INBOX."""
    result = (service.users().messages()
              .list(userId="me", labelIds=["INBOX"], maxResults=limit)
              .execute())
    return [m["id"] for m in result.get("messages", [])]


def scan_gmail_account(token: "OAuthToken", limit: int = 50) -> dict:
    """Poll one Gmail OAuth account. Returns stats dict; commits its own work."""
    from flask import current_app
    from ..extensions import db
    from ..services.scanner import build_context, scan_raw_message
    from ..models import User

    cfg = current_app.config
    stats = {"scanned": 0, "quarantined": 0, "blocked": 0, "errors": 0}
    user = User.query.get(token.user_id)
    if not user:
        return stats

    try:
        refresh_token_if_needed(token, cfg)
        ctx = build_context(user)
        for msg_id, raw in fetch_new_messages(token, cfg, limit=limit):
            try:
                scan = scan_raw_message(
                    user, raw, source="gmail", ctx=ctx,
                )
                stats["scanned"] += 1
                if scan.action != "allowed":
                    action_key = scan.action if scan.action in stats else "quarantined"
                    stats[action_key] = stats.get(action_key, 0) + 1
                db.session.commit()
            except Exception:
                db.session.rollback()
                stats["errors"] += 1
                log.exception("Failed to process Gmail message %s", msg_id)

        token.last_status = (
            f"OK - {stats['scanned']} scanned, "
            f"{stats['quarantined'] + stats['blocked']} held"
        )
    except Exception as e:
        db.session.rollback()
        token.last_status = f"ERROR: {str(e)[:200]}"
        stats["errors"] += 1
        log.warning("Gmail OAuth account %s failed: %s", token.email, e)

    from ..models import utcnow
    token.last_checked = utcnow()
    db.session.commit()
    return stats
