"""SMS / messaging scam detection service.

Reuses the existing URL reputation pipeline and heuristics engine.
Does NOT require any Twilio dependency — messages are submitted via
the REST API (POST /api/v1/sms/scan) or the manual scan UI.

An Android companion app can POST messages via the API using the user's
API key (X-API-Key header). The server never pulls SMS data autonomously.
"""
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

from flask import current_app

from ..extensions import db
from ..models import LEVELS, SmsScan, SmsAlert, utcnow
from .heuristics import (
    BRANDS, CREDENTIALS, FREEMAIL, SPAM, URGENCY, BEC,
    lookalike_brand, registrable_label, _normalize, _hits,
)
from .url_reputation import (
    UrlFinding, analyze_urls, url_points, local_checks,
)

log = logging.getLogger(__name__)

# --- SMS-specific word lists -------------------------------------------

SMS_SMISHING = [
    # Banking / OTP theft
    "otp", "one-time password", "one time password", "do not share", "bank otp",
    "verify otp", "transaction otp", "your otp", "otp is",
    # Fake bank/KYC
    "kyc", "kyc update", "update your kyc", "complete kyc", "kyc expired",
    "account blocked", "your account is blocked", "account suspended",
    "re-verify", "reverify", "video kyc",
    # Parcel delivery scams
    "parcel is on hold", "delivery attempt failed", "package undeliverable",
    "customs fee", "pending delivery", "tracking number", "reschedule delivery",
    # Fake prizes / lottery
    "you have won", "lottery winner", "prize money", "claim your reward",
    "free gift", "congratulations you won",
    # Loan / financial fraud
    "instant loan", "pre-approved loan", "loan approved", "low interest loan",
    "easy emi", "credit line", "cash back offer",
    # Generic smishing
    "click to claim", "click to verify", "tap here", "reply stop to unsubscribe",
    "reply 1 to", "reply yes to",
]

SMS_BRAND_IMPERSONATION = [
    "sbi", "hdfc", "icici", "axis bank", "pnb", "kotak", "idfc",
    "paytm", "phonepe", "gpay", "google pay", "amazon pay", "flipkart",
    "uidai", "aadhaar", "income tax", "it dept", "epfo", "pf",
    "irctc", "railway", "indian post", "india post",
    "trai", "jio", "airtel", "bsnl", "vi", "vodafone",
    "rbi", "reserve bank",
]

# Phone number patterns that indicate suspicious senders
SUSPICIOUS_SENDER_PATTERNS = [
    re.compile(r"^[+]?1\d{9,12}$"),   # US long codes often used for smishing
    re.compile(r"^\d{5,6}$"),          # Short code — not inherently bad but note it
]

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)


@dataclass
class SmsAnalysisResult:
    score: int = 0
    level: str = "safe"
    verdict: str = "clean"
    action: str = "allowed"
    reasons: List[dict] = field(default_factory=list)
    urls: List[dict] = field(default_factory=list)
    score_breakdown: dict = field(default_factory=dict)


def _level_for(score: int) -> str:
    if score < 20:
        return "safe"
    if score < 40:
        return "low"
    if score < 70:
        return "medium"
    if score < 90:
        return "high"
    return "critical"


def _add(r: SmsAnalysisResult, pts: int, code: str, detail: str, cat: str = "generic"):
    r.reasons.append({"code": code, "points": pts, "detail": detail, "category": cat})
    r.score_breakdown[cat] = r.score_breakdown.get(cat, 0) + max(pts, 0)


def _extract_links(text: str):
    """Return a list of ParsedLink-compatible namedtuples from plain text."""
    from .parser import ParsedLink
    seen, links = set(), []
    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:!?)")
        if url not in seen:
            seen.add(url)
            links.append(ParsedLink(url=url, text=""))
    return links


def analyze_sms(
    sender: str,
    text: str,
    source: str = "sms",
    settings: Optional[dict] = None,
    url_opts: Optional[dict] = None,
) -> SmsAnalysisResult:
    """Analyze a single SMS/message and return a scored result.

    Parameters
    ----------
    sender : str
        Phone number or display name of the sender.
    text : str
        Full message text (up to ~2000 chars used).
    source : str
        One of: sms / whatsapp / telegram / messenger / manual
    settings : dict, optional
        Security policy dict (quarantine_threshold, block_threshold …).
    url_opts : dict, optional
        Options passed to url_reputation.analyze_urls().
    """
    if settings is None:
        settings = {"quarantine_threshold": 40, "block_threshold": 70,
                    "check_urls": True, "use_external_reputation": True}
    if url_opts is None:
        url_opts = {}

    r = SmsAnalysisResult()
    body = text[:2000]
    body_l = body.lower()

    # ── 1. Smishing-specific patterns ──────────────────────────────────────
    h = _hits(body_l, SMS_SMISHING)
    if h:
        pts = min(25, 5 * len(h))
        _add(r, pts, "smishing-words",
             f"Smishing pattern detected: {', '.join(h[:4])}", "smishing")

    # ── 2. Urgency / pressure wording ──────────────────────────────────────
    h = _hits(body_l, URGENCY)
    if h:
        _add(r, min(15, 4 * len(h)), "urgency",
             f"Urgent / pressure wording: {', '.join(h[:4])}", "phishing")

    # ── 3. Credential / sensitive data requests ─────────────────────────────
    h = _hits(body_l, CREDENTIALS)
    if h:
        _add(r, min(12, 4 * len(h)), "credentials",
             f"Requests sensitive data: {', '.join(h[:4])}", "phishing")

    # ── 4. Spam wording ────────────────────────────────────────────────────
    h = _hits(body_l, SPAM)
    if h:
        _add(r, min(18, 5 * len(h)), "spam-words",
             f"Spam wording: {', '.join(h[:4])}", "spam")

    # ── 5. Brand impersonation keywords in message ─────────────────────────
    h = _hits(body_l, SMS_BRAND_IMPERSONATION)
    if h:
        # Brand mentioned in text without a verified sender — suspicious
        _add(r, min(15, 5 * len(h)), "brand-impersonation",
             f"Message mentions financial/govt brand(s): {', '.join(h[:4])}", "phishing")

    # ── 6. Sender analysis ─────────────────────────────────────────────────
    sender_l = (sender or "").lower().strip()
    if sender_l:
        # Check if sender looks like it impersonates a brand
        for brand in SMS_BRAND_IMPERSONATION:
            if brand in sender_l and "@" not in sender_l:
                _add(r, 20, "sender-brand-spoof",
                     f"Sender name '{sender}' claims to be {brand.upper()}", "phishing")
                break
        # Lookalike domain in sender (if it contains @)
        if "@" in sender_l:
            domain = sender_l.rsplit("@", 1)[-1]
            la = lookalike_brand(domain)
            if la:
                _add(r, 25, "sender-lookalike",
                     f"Sender domain {domain} imitates {la[0]} ({la[1]})", "phishing")

    # ── 7. URL extraction and analysis ─────────────────────────────────────
    if settings.get("check_urls", True):
        links = _extract_links(body)
        if links:
            opts = dict(url_opts)
            opts["external"] = settings.get("use_external_reputation", True)
            findings = analyze_urls(links, opts, limit=10)
            r.urls = [
                {"url": f.url, "host": f.host, "score": f.score,
                 "flagged": f.flagged, "reasons": f.reasons,
                 "final_url": getattr(f, "final_url", "")}
                for f in findings
            ]
            up = url_points(findings)
            if up:
                worst = max(findings, key=lambda f: f.score)
                _add(r, up, "bad-urls",
                     f"Suspicious link {worst.host}: {worst.reasons[0] if worst.reasons else ''}",
                     "phishing")

    # ── 8. Excessive exclamations / caps ───────────────────────────────────
    if body.count("!") >= 3:
        _add(r, 3, "exclamations", "Excessive exclamation marks", "spam")
    letters = [c for c in body if c.isalpha()]
    if len(letters) >= 10 and sum(c.isupper() for c in letters) / len(letters) > 0.65:
        _add(r, 4, "caps-text", "Message text is mostly uppercase", "spam")

    # ── Finalize ───────────────────────────────────────────────────────────
    total = sum(x["points"] for x in r.reasons)
    r.score = max(0, min(100, total))
    r.level = _level_for(r.score)
    cats = r.score_breakdown

    if r.score < 20:
        r.verdict = "clean"
    else:
        real = {k: v for k, v in cats.items()
                if k in ("phishing", "spam", "smishing", "malware") and v > 0}
        r.verdict = max(real, key=real.get) if real else "suspicious"

    if r.score >= settings.get("block_threshold", 70):
        r.action = "blocked"
    elif r.score >= settings.get("quarantine_threshold", 40):
        r.action = "quarantined"
    else:
        r.action = "allowed"

    r.reasons.sort(key=lambda x: -x["points"])
    return r


def _message_hash(sender: str, text: str) -> str:
    digest = hashlib.sha256(f"{sender}|{text[:500]}".encode("utf-8", "replace")).hexdigest()
    return digest


def scan_sms(user, sender: str, text: str, source: str = "sms",
             sender_name: str = "", recipient: str = "",
             received_at: Optional[datetime] = None) -> SmsScan:
    """Analyze one SMS/message and persist the result. Caller must commit."""
    cfg = current_app.config
    settings_obj = user.get_settings()
    settings = settings_obj.as_dict()
    url_opts = {
        "dns_check": cfg.get("URL_DNS_CHECK", False),
        "dnsbl": cfg.get("DNSBL_ENABLED", False),
        "safe_browsing_key": cfg.get("GOOGLE_SAFE_BROWSING_KEY", ""),
        "virustotal_key": cfg.get("VIRUSTOTAL_API_KEY", ""),
        "urlscan_key": cfg.get("URLSCAN_API_KEY", ""),
        "follow_redirects": cfg.get("URL_FOLLOW_REDIRECTS", False),
        "follow_timeout": cfg.get("URL_FOLLOW_TIMEOUT", 5),
        "timeout": cfg.get("REPUTATION_TIMEOUT", 3),
    }

    # Deduplication
    msg_hash = _message_hash(sender or "", text or "")
    existing = SmsScan.query.filter_by(user_id=user.id, message_hash=msg_hash).first()
    if existing:
        return existing

    result = analyze_sms(
        sender=sender, text=text, source=source,
        settings=settings, url_opts=url_opts,
    )

    scan = SmsScan(
        user_id=user.id,
        source=source,
        sender=(sender or "")[:255],
        sender_name=(sender_name or "")[:255],
        recipient=(recipient or "")[:255],
        message_text=text[:2000] if text else "",
        message_excerpt=(text or "")[:500],
        message_hash=msg_hash,
        received_at=received_at,
        scanned_at=utcnow(),
        risk_score=result.score,
        threat_level=result.level,
        verdict=result.verdict,
        action=result.action,
    )
    scan.reasons = result.reasons
    scan.urls = result.urls
    db.session.add(scan)
    db.session.flush()

    # Create alert if warranted
    if result.action != "allowed" and LEVELS.index(result.level) >= LEVELS.index(settings_obj.alert_level):
        verb = "Blocked" if result.action == "blocked" else "Flagged"
        msg = (f"{verb} {result.verdict} {source.upper()} from {sender or 'unknown'} "
               f"(risk {result.score}/100): {text[:100] if text else ''}")
        alert = SmsAlert(
            user_id=user.id,
            sms_scan_id=scan.id,
            level=result.level,
            message=msg[:500],
        )
        db.session.add(alert)

    return scan
