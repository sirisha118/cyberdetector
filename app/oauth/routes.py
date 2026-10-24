"""Gmail OAuth2 flow routes.

GET  /oauth/gmail/connect   — redirects user to Google consent screen
GET  /oauth/gmail/callback  — handles the OAuth callback, saves token
POST /oauth/gmail/<id>/scan  — manually trigger a scan of a connected Gmail account
POST /oauth/gmail/<id>/delete — remove a connected Gmail account
"""
import logging

from flask import (Blueprint, current_app, flash, redirect,
                   render_template, request, session, url_for)
from flask_login import current_user, login_required

from ..extensions import db
from ..models import OAuthToken, utcnow

log = logging.getLogger(__name__)
bp = Blueprint("oauth", __name__, url_prefix="/oauth")


def _gmail_cfg():
    return current_app.config


@bp.route("/gmail/connect")
@login_required
def gmail_connect():
    """Start the Gmail OAuth2 flow."""
    from ..services.gmail_oauth import get_authorization_url, gmail_available
    if not gmail_available():
        flash(
            "Gmail API libraries are not installed on this server. "
            "Install them with: pip install google-auth google-auth-oauthlib google-api-python-client",
            "warning",
        )
        return redirect(url_for("main.accounts"))
    cfg = _gmail_cfg()
    if not cfg.get("GMAIL_CLIENT_ID"):
        flash(
            "Gmail OAuth is not configured. Set GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, "
            "and GMAIL_REDIRECT_URI in .env first.",
            "warning",
        )
        return redirect(url_for("main.accounts"))
    try:
        url, state = get_authorization_url(cfg)
        session["gmail_oauth_state"] = state
        return redirect(url)
    except Exception as e:
        log.exception("Gmail connect failed")
        flash(f"Could not start Gmail OAuth: {str(e)[:200]}", "danger")
        return redirect(url_for("main.accounts"))


@bp.route("/gmail/callback")
@login_required
def gmail_callback():
    """Handle the OAuth2 callback from Google."""
    from ..services.gmail_oauth import exchange_code, gmail_available
    if not gmail_available():
        flash("Gmail API libraries not installed.", "danger")
        return redirect(url_for("main.accounts"))

    error = request.args.get("error")
    if error:
        flash(f"Gmail authorisation denied: {error}", "warning")
        return redirect(url_for("main.accounts"))

    code = request.args.get("code")
    state = request.args.get("state")
    if not code or state != session.pop("gmail_oauth_state", None):
        flash("Invalid OAuth state. Please try again.", "danger")
        return redirect(url_for("main.accounts"))

    try:
        cfg = _gmail_cfg()
        token_data = exchange_code(cfg, code, state)
    except Exception as e:
        log.exception("Gmail token exchange failed")
        flash(f"Gmail authorisation failed: {str(e)[:200]}", "danger")
        return redirect(url_for("main.accounts"))

    # Upsert token record for this Google account
    tok = OAuthToken.query.filter_by(
        user_id=current_user.id,
        provider="gmail",
        email=token_data["email"],
    ).first()
    if tok is None:
        tok = OAuthToken(user_id=current_user.id, provider="gmail",
                         email=token_data["email"])
        db.session.add(tok)

    tok.access_token = token_data["access_token"]
    if token_data.get("refresh_token"):
        tok.refresh_token = token_data["refresh_token"]
    tok.token_expiry = token_data.get("expiry")
    tok.scopes = token_data.get("scopes", "")
    tok.last_status = "Connected"
    db.session.commit()

    flash(f"Gmail account {token_data['email']} connected successfully.", "success")
    return redirect(url_for("main.accounts"))


@bp.route("/gmail/<int:token_id>/scan", methods=["POST"])
@login_required
def gmail_scan(token_id):
    """Manually trigger a scan of a connected Gmail account."""
    from ..services.gmail_oauth import scan_gmail_account, gmail_available
    tok = _own_token(token_id)
    if not gmail_available():
        flash("Gmail API libraries not installed.", "danger")
        return redirect(url_for("main.accounts"))
    try:
        stats = scan_gmail_account(tok, limit=current_app.config.get("GMAIL_POLL_LIMIT", 50))
        flash(
            f"Gmail scan done: {stats['scanned']} scanned, "
            f"{stats['quarantined']} quarantined, {stats['blocked']} blocked, "
            f"{stats['errors']} errors.",
            "info" if not stats["errors"] else "warning",
        )
    except Exception as e:
        flash(f"Gmail scan failed: {str(e)[:200]}", "danger")
    return redirect(url_for("main.accounts"))


@bp.route("/gmail/<int:token_id>/delete", methods=["POST"])
@login_required
def gmail_delete(token_id):
    """Disconnect (remove) a Gmail OAuth token."""
    tok = _own_token(token_id)
    db.session.delete(tok)
    db.session.commit()
    flash(f"Gmail account {tok.email} disconnected.", "info")
    return redirect(url_for("main.accounts"))


def _own_token(token_id: int) -> OAuthToken:
    from flask import abort
    tok = db.session.get(OAuthToken, token_id)
    if not tok or tok.user_id != current_user.id:
        abort(404)
    return tok
