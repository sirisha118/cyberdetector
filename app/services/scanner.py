"""Glue between the detector, the database, alerts and mailboxes."""
import json
import logging

from flask import current_app

from ..extensions import db
from ..ml.classifier import get_classifier
from ..models import (LEVELS, EmailScan, ScanAttachment, ScanUrl, SenderRule, utcnow)
from .alerts import create_alert
from .detector import DetectionContext, analyze
from .parser import parse_email

log = logging.getLogger(__name__)


def build_context(user) -> DetectionContext:
    cfg = current_app.config
    settings = user.get_settings()
    rules = user.sender_rules
    try:
        clf = get_classifier(cfg) if settings.use_ml else None
    except Exception:  # model problems must not stop scanning
        log.exception("ML classifier unavailable")
        clf = None
    return DetectionContext(
        settings=settings.as_dict(),
        custom_rules=[r.as_dict() for r in user.custom_rules],
        blocked=[r.pattern for r in rules if r.list_type == "block"],
        allowed=[r.pattern for r in rules if r.list_type == "allow"],
        classifier=clf,
        url_opts={"dns_check": cfg["URL_DNS_CHECK"], "dnsbl": cfg["DNSBL_ENABLED"],
                  "safe_browsing_key": cfg["GOOGLE_SAFE_BROWSING_KEY"],
                  "virustotal_key": cfg["VIRUSTOTAL_API_KEY"],
                  "urlscan_key": cfg.get("URLSCAN_API_KEY", ""),
                  "follow_redirects": cfg.get("URL_FOLLOW_REDIRECTS", False),
                  "follow_timeout": cfg.get("URL_FOLLOW_TIMEOUT", 5),
                  "timeout": cfg["REPUTATION_TIMEOUT"]},
    )


def scan_raw_message(user, raw, account=None, uid=None, source="manual", ctx=None):
    """Analyze one raw RFC822 message and persist the result. Caller commits."""
    parsed = parse_email(raw)
    if account is not None and parsed.message_id:
        dup = EmailScan.query.filter_by(user_id=user.id, account_id=account.id,
                                        message_id=parsed.message_id[:512]).first()
        if dup:
            return dup
    ctx = ctx or build_context(user)
    result = analyze(parsed, ctx)
    settings = user.get_settings()

    scan = EmailScan(
        user_id=user.id, account_id=account.id if account else None, uid=uid, source=source,
        message_id=parsed.message_id[:512], sender=parsed.from_addr[:320], sender_name=parsed.from_name[:255],
        sender_domain=parsed.from_domain[:255], recipient=", ".join(parsed.to_addrs)[:512],
        subject=parsed.subject[:998], body_excerpt=parsed.body[:4000], sent_at=parsed.date,
        scanned_at=utcnow(), risk_score=result.score, threat_level=result.level,
        verdict=result.verdict, action=result.action,
        status="held" if result.action != "allowed" else "delivered",
        ml_probability=result.ml["probability"] if result.ml else None,
    )
    scan.reasons = result.reasons
    for f in result.urls:
        scan.urls.append(ScanUrl(url=f.url[:4000], host=f.host[:255], score=f.score,
                                 flagged=f.flagged, reasons_json=json.dumps(f.reasons)))
    for f in result.attachments:
        scan.attachments.append(ScanAttachment(filename=f.filename[:512], content_type=f.content_type[:128],
                                               size=f.size, sha256=f.sha256, score=f.score,
                                               flagged=f.flagged, reasons_json=json.dumps(f.reasons)))
    db.session.add(scan)

    # Track hits on matched list entries; auto-block repeat offenders
    if result.sender_rule == "block":
        for r in user.sender_rules:
            if r.list_type == "block" and _match(r.pattern, parsed):
                r.hits += 1
    elif result.action == "blocked" and settings.auto_block_sender and parsed.from_addr and result.sender_rule is None:
        exists = SenderRule.query.filter_by(user_id=user.id, pattern=parsed.from_addr, list_type="block").first()
        if not exists:
            db.session.add(SenderRule(user_id=user.id, pattern=parsed.from_addr, list_type="block",
                                      reason=f"Auto-blocked: {result.verdict} (score {result.score})",
                                      auto_added=True, hits=1))
    db.session.flush()

    if result.action != "allowed" and LEVELS.index(result.level) >= LEVELS.index(settings.alert_level):
        create_alert(user, scan, account)
    return scan


def _match(pattern, parsed):
    from .detector import sender_matches
    return sender_matches(pattern, parsed.from_addr, parsed.from_domain)
