"""REST API (authenticate with header  X-API-Key: <your key>)."""
from functools import wraps

from flask import Blueprint, current_app, g, jsonify, request

from ..extensions import db
from ..models import Alert, EmailScan, SenderRule, User
from ..services.scanner import scan_raw_message
from ..services.stats import dashboard_stats

bp = Blueprint("api", __name__)


def api_auth(f):
    @wraps(f)
    def wrapper(*a, **kw):
        key = request.headers.get("X-API-Key", "")
        user = User.query.filter_by(api_key=key).first() if key else None
        if not user:
            return jsonify(error="Invalid or missing X-API-Key"), 401
        g.api_user = user
        return f(*a, **kw)
    return wrapper


@bp.route("/health")
def health():
    return jsonify(status="ok")


@bp.route("/scan", methods=["POST"])
@api_auth
def scan():
    """Body: raw RFC822 (Content-Type: message/rfc822 or text/plain) OR JSON
    {"from": "...", "subject": "...", "body": "...", "to": "..."}"""
    if request.is_json:
        d = request.get_json(silent=True) or {}
        if not d.get("body") and not d.get("subject"):
            return jsonify(error="Provide 'subject' and/or 'body'"), 400
        raw = (f"From: {d.get('from', '')}\r\nTo: {d.get('to', '')}\r\nSubject: {d.get('subject', '')}\r\n"
               f"Content-Type: text/plain; charset=utf-8\r\n\r\n{d.get('body', '')}").encode("utf-8", "replace")
    else:
        raw = request.get_data()
        if not raw.strip():
            return jsonify(error="Empty request body"), 400
    s = scan_raw_message(g.api_user, raw, source="api")
    db.session.commit()
    result_dict = s.to_dict(detail=True)
    return jsonify(result_dict), 201


@bp.route("/scans")
@api_auth
def scans():
    q = EmailScan.query.filter_by(user_id=g.api_user.id)
    for k, col in (("action", EmailScan.action), ("level", EmailScan.threat_level), ("verdict", EmailScan.verdict)):
        if request.args.get(k):
            q = q.filter(col == request.args[k])
    p = q.order_by(EmailScan.scanned_at.desc()).paginate(page=request.args.get("page", 1, type=int),
                                                        per_page=min(request.args.get("per_page", 25, type=int), 100),
                                                        error_out=False)
    return jsonify(items=[s.to_dict() for s in p.items], page=p.page, pages=p.pages, total=p.total)


@bp.route("/scans/<int:scan_id>")
@api_auth
def scan_detail(scan_id):
    s = db.session.get(EmailScan, scan_id)
    if not s or s.user_id != g.api_user.id:
        return jsonify(error="Not found"), 404
    return jsonify(s.to_dict(detail=True))


@bp.route("/stats")
@api_auth
def stats():
    return jsonify(dashboard_stats(g.api_user.id, days=min(request.args.get("days", 14, type=int), 90)))


@bp.route("/senders", methods=["GET", "POST"])
@api_auth
def senders():
    if request.method == "POST":
        d = request.get_json(silent=True) or {}
        pattern, ltype = (d.get("pattern") or "").strip().lower(), d.get("list_type", "block")
        if not pattern or ltype not in ("block", "allow"):
            return jsonify(error="'pattern' and list_type block|allow required"), 400
        if SenderRule.query.filter_by(user_id=g.api_user.id, pattern=pattern, list_type=ltype).first():
            return jsonify(error="Already exists"), 409
        r = SenderRule(user_id=g.api_user.id, pattern=pattern, list_type=ltype, reason=(d.get("reason") or "")[:255])
        db.session.add(r)
        db.session.commit()
        return jsonify(r.to_dict()), 201
    rules = SenderRule.query.filter_by(user_id=g.api_user.id).all()
    return jsonify(items=[r.to_dict() for r in rules])


@bp.route("/senders/<int:rule_id>", methods=["DELETE"])
@api_auth
def delete_sender(rule_id):
    r = db.session.get(SenderRule, rule_id)
    if not r or r.user_id != g.api_user.id:
        return jsonify(error="Not found"), 404
    db.session.delete(r)
    db.session.commit()
    return "", 204


@bp.route("/alerts")
@api_auth
def alerts():
    q = Alert.query.filter_by(user_id=g.api_user.id).order_by(Alert.created_at.desc()).limit(100)
    return jsonify(items=[{"id": a.id, "level": a.level, "message": a.message, "is_read": a.is_read,
                           "scan_id": a.scan_id, "created_at": a.created_at.isoformat()} for a in q])


# ── SMS / messaging scan API ──────────────────────────────────────────────────

@bp.route("/sms/scan", methods=["POST"])
@api_auth
def api_sms_scan():
    """Scan an SMS or messaging notification.

    Accepts JSON:
    {
        "sender": "+91XXXXXXXXXX",        # phone number or display name
        "text": "Your OTP is 123456...",  # full message text (required)
        "source": "sms",                  # sms / whatsapp / telegram / messenger / manual
        "sender_name": "HDFCBK",         # optional display name
        "recipient": "+91XXXXXXXXXX",     # optional
        "received_at": "2026-01-01T12:00:00"  # optional ISO8601 UTC
    }
    """
    from ..services.sms_scanner import scan_sms
    from ..models import SmsScan
    from ..extensions import db as _db

    d = request.get_json(silent=True) or {}
    text = (d.get("text") or "").strip()
    if not text:
        return jsonify(error="'text' is required"), 400

    source = d.get("source", "sms")
    if source not in ("sms", "whatsapp", "telegram", "messenger", "manual"):
        source = "manual"

    received_at = None
    if d.get("received_at"):
        try:
            from datetime import datetime
            received_at = datetime.fromisoformat(d["received_at"].replace("Z", "+00:00"))
            received_at = received_at.replace(tzinfo=None)
        except Exception:
            pass

    scan = scan_sms(
        g.api_user,
        sender=d.get("sender", ""),
        text=text,
        source=source,
        sender_name=d.get("sender_name", ""),
        recipient=d.get("recipient", ""),
        received_at=received_at,
    )
    _db.session.commit()
    return jsonify(scan.to_dict(detail=True)), 201


@bp.route("/sms/scans")
@api_auth
def api_sms_scans():
    """List SMS scan history with optional filters."""
    from ..models import SmsScan

    q = SmsScan.query.filter_by(user_id=g.api_user.id)
    for k, col in (
        ("action", SmsScan.action),
        ("level", SmsScan.threat_level),
        ("verdict", SmsScan.verdict),
        ("source", SmsScan.source),
    ):
        if request.args.get(k):
            q = q.filter(col == request.args[k])

    p = q.order_by(SmsScan.scanned_at.desc()).paginate(
        page=request.args.get("page", 1, type=int),
        per_page=min(request.args.get("per_page", 25, type=int), 100),
        error_out=False,
    )
    return jsonify(items=[s.to_dict() for s in p.items],
                   page=p.page, pages=p.pages, total=p.total)


@bp.route("/sms/scans/<int:scan_id>")
@api_auth
def api_sms_scan_detail(scan_id):
    from ..models import SmsScan

    s = db.session.get(SmsScan, scan_id)
    if not s or s.user_id != g.api_user.id:
        return jsonify(error="Not found"), 404
    return jsonify(s.to_dict(detail=True))


@bp.route("/sms/stats")
@api_auth
def api_sms_stats():
    """Quick stats for SMS scans."""
    from ..models import SmsScan
    from datetime import timedelta
    from ..models import utcnow

    days = min(request.args.get("days", 14, type=int), 90)
    since = utcnow() - timedelta(days=days)
    qs = SmsScan.query.filter(
        SmsScan.user_id == g.api_user.id,
        SmsScan.scanned_at >= since,
    )
    total = qs.count()
    by_action = {}
    by_verdict = {}
    by_source = {}
    for scan in qs.all():
        by_action[scan.action] = by_action.get(scan.action, 0) + 1
        by_verdict[scan.verdict] = by_verdict.get(scan.verdict, 0) + 1
        by_source[scan.source] = by_source.get(scan.source, 0) + 1
    return jsonify(total=total, days=days,
                   by_action=by_action, by_verdict=by_verdict, by_source=by_source)


# ── URL quick-scan API ────────────────────────────────────────────────────────

@bp.route("/url/scan", methods=["POST"])
@api_auth
def api_url_scan():
    """Scan a single URL directly (no email needed).

    Accepts JSON: {"url": "https://example.com"}
    Returns: {url, host, score, flagged, reasons, final_url}
    """
    from ..services.url_reputation import local_checks, external_checks

    d = request.get_json(silent=True) or {}
    url = (d.get("url") or "").strip()
    if not url or not url.lower().startswith(("http://", "https://")):
        return jsonify(error="'url' must be an http:// or https:// URL"), 400

    cfg = current_app.config
    opts = {
        "dns_check": cfg.get("URL_DNS_CHECK", False),
        "dnsbl": cfg.get("DNSBL_ENABLED", False),
        "safe_browsing_key": cfg.get("GOOGLE_SAFE_BROWSING_KEY", ""),
        "virustotal_key": cfg.get("VIRUSTOTAL_API_KEY", ""),
        "urlscan_key": cfg.get("URLSCAN_API_KEY", ""),
        "timeout": cfg.get("REPUTATION_TIMEOUT", 3),
    }

    finding = local_checks(url)
    if d.get("external", True):
        external_checks(finding, opts)

    return jsonify({
        "url": finding.url,
        "host": finding.host,
        "score": finding.score,
        "flagged": finding.flagged,
        "reasons": finding.reasons,
        "final_url": getattr(finding, "final_url", ""),
        "risk_level": (
            "safe" if finding.score < 20 else
            "low" if finding.score < 40 else
            "medium" if finding.score < 70 else
            "high" if finding.score < 90 else
            "critical"
        ),
    })
