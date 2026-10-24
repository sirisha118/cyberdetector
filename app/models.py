"""Database models."""
import json
from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db, login_manager
from .security import decrypt, encrypt, new_api_key


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


LEVELS = ["safe", "low", "medium", "high", "critical"]

# Message source types (EmailScan.source + SmsScan.source)
SOURCE_IMAP = "imap"
SOURCE_MANUAL = "manual"
SOURCE_API = "api"
SOURCE_GMAIL = "gmail"
SOURCE_SMS = "sms"
SOURCE_WHATSAPP = "whatsapp"
SOURCE_MESSENGER = "messenger"


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(16), default="user", nullable=False)
    api_key = db.Column(db.String(80), unique=True, index=True, default=new_api_key)
    created_at = db.Column(db.DateTime, default=utcnow)

    settings = db.relationship("UserSettings", uselist=False, backref="user", cascade="all, delete-orphan")
    accounts = db.relationship("MailAccount", backref="user", cascade="all, delete-orphan")
    scans = db.relationship("EmailScan", backref="user", cascade="all, delete-orphan")
    sender_rules = db.relationship("SenderRule", backref="user", cascade="all, delete-orphan")
    custom_rules = db.relationship("SecurityRule", backref="user", cascade="all, delete-orphan")
    alerts = db.relationship("Alert", backref="user", cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == "admin"

    def get_settings(self):
        if self.settings is None:
            self.settings = UserSettings()
            db.session.add(self.settings)
            db.session.flush()
        return self.settings


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class UserSettings(db.Model):
    """Configurable security policy for a user."""
    __tablename__ = "user_settings"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), unique=True, nullable=False)
    quarantine_threshold = db.Column(db.Integer, default=40, nullable=False)
    block_threshold = db.Column(db.Integer, default=70, nullable=False)
    auto_block_sender = db.Column(db.Boolean, default=True, nullable=False)
    use_ml = db.Column(db.Boolean, default=True, nullable=False)
    check_urls = db.Column(db.Boolean, default=True, nullable=False)
    check_attachments = db.Column(db.Boolean, default=True, nullable=False)
    use_external_reputation = db.Column(db.Boolean, default=True, nullable=False)
    alert_level = db.Column(db.String(16), default="medium", nullable=False)
    alert_email = db.Column(db.Boolean, default=False, nullable=False)
    retention_days = db.Column(db.Integer, default=30, nullable=False)
    # SMS / messaging settings
    sms_scan_enabled = db.Column(db.Boolean, default=True, nullable=False)
    notify_sms_threats = db.Column(db.Boolean, default=True, nullable=False)

    def as_dict(self):
        return {
            "quarantine_threshold": self.quarantine_threshold or 40,
            "block_threshold": self.block_threshold or 70,
            "auto_block_sender": bool(self.auto_block_sender),
            "use_ml": bool(self.use_ml),
            "check_urls": bool(self.check_urls),
            "check_attachments": bool(self.check_attachments),
            "use_external_reputation": bool(self.use_external_reputation),
            "sms_scan_enabled": bool(self.sms_scan_enabled) if self.sms_scan_enabled is not None else True,
            "notify_sms_threats": bool(self.notify_sms_threats) if self.notify_sms_threats is not None else True,
        }

    def __getitem__(self, key):
        return getattr(self, key)


class MailAccount(db.Model):
    __tablename__ = "mail_accounts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    imap_host = db.Column(db.String(255), nullable=False)
    imap_port = db.Column(db.Integer, default=993, nullable=False)
    imap_ssl = db.Column(db.Boolean, default=True, nullable=False)
    smtp_host = db.Column(db.String(255))
    smtp_port = db.Column(db.Integer, default=587)
    username = db.Column(db.String(255), nullable=False)
    _password = db.Column("password", db.Text, nullable=False)
    folder = db.Column(db.String(100), default="INBOX", nullable=False)
    quarantine_folder = db.Column(db.String(100), default="CyberShield-Quarantine", nullable=False)
    auto_move = db.Column(db.Boolean, default=True, nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    poll_minutes = db.Column(db.Integer, default=5, nullable=False)
    last_uid = db.Column(db.Integer, default=0, nullable=False)
    last_checked = db.Column(db.DateTime)
    last_status = db.Column(db.String(255))

    @property
    def password(self):
        return decrypt(self._password)

    @password.setter
    def password(self, value):
        self._password = encrypt(value)


class EmailScan(db.Model):
    __tablename__ = "email_scans"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    account_id = db.Column(db.Integer, db.ForeignKey("mail_accounts.id", ondelete="SET NULL"))
    uid = db.Column(db.Integer)
    message_id = db.Column(db.String(512), index=True)
    sender = db.Column(db.String(320), index=True)
    sender_name = db.Column(db.String(255))
    sender_domain = db.Column(db.String(255), index=True)
    recipient = db.Column(db.String(512))
    subject = db.Column(db.String(998))
    body_excerpt = db.Column(db.Text)
    sent_at = db.Column(db.DateTime)
    scanned_at = db.Column(db.DateTime, default=utcnow, index=True)
    source = db.Column(db.String(16), default="manual")  # imap / manual / api
    risk_score = db.Column(db.Integer, default=0, nullable=False)
    threat_level = db.Column(db.String(16), default="safe", nullable=False, index=True)
    verdict = db.Column(db.String(16), default="clean", nullable=False)  # clean/spam/phishing/malware/suspicious
    action = db.Column(db.String(16), default="allowed", nullable=False, index=True)  # allowed/quarantined/blocked
    status = db.Column(db.String(16), default="delivered", nullable=False, index=True)  # delivered/held/released/deleted
    ml_probability = db.Column(db.Float)
    reasons_json = db.Column(db.Text, default="[]")

    urls = db.relationship("ScanUrl", backref="scan", cascade="all, delete-orphan")
    attachments = db.relationship("ScanAttachment", backref="scan", cascade="all, delete-orphan")
    account = db.relationship("MailAccount")

    @property
    def reasons(self):
        try:
            return json.loads(self.reasons_json or "[]")
        except ValueError:
            return []

    @reasons.setter
    def reasons(self, value):
        self.reasons_json = json.dumps(value)

    def to_dict(self, detail=False):
        d = {
            "id": self.id, "message_id": self.message_id, "sender": self.sender,
            "sender_domain": self.sender_domain, "recipient": self.recipient,
            "subject": self.subject, "scanned_at": self.scanned_at.isoformat() if self.scanned_at else None,
            "risk_score": self.risk_score, "threat_level": self.threat_level,
            "verdict": self.verdict, "action": self.action, "status": self.status,
            "ml_probability": self.ml_probability, "source": self.source,
        }
        if detail:
            d["reasons"] = self.reasons
            d["urls"] = [u.to_dict() for u in self.urls]
            d["attachments"] = [a.to_dict() for a in self.attachments]
        return d


class ScanUrl(db.Model):
    __tablename__ = "scan_urls"
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("email_scans.id"), nullable=False, index=True)
    url = db.Column(db.Text, nullable=False)
    host = db.Column(db.String(255))
    score = db.Column(db.Integer, default=0)
    flagged = db.Column(db.Boolean, default=False)
    reasons_json = db.Column(db.Text, default="[]")

    @property
    def reasons(self):
        return json.loads(self.reasons_json or "[]")

    def to_dict(self):
        return {"url": self.url, "host": self.host, "score": self.score,
                "flagged": self.flagged, "reasons": self.reasons}


class ScanAttachment(db.Model):
    __tablename__ = "scan_attachments"
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("email_scans.id"), nullable=False, index=True)
    filename = db.Column(db.String(512))
    content_type = db.Column(db.String(128))
    size = db.Column(db.Integer, default=0)
    sha256 = db.Column(db.String(64))
    score = db.Column(db.Integer, default=0)
    flagged = db.Column(db.Boolean, default=False)
    reasons_json = db.Column(db.Text, default="[]")

    @property
    def reasons(self):
        return json.loads(self.reasons_json or "[]")

    def to_dict(self):
        return {"filename": self.filename, "content_type": self.content_type, "size": self.size,
                "sha256": self.sha256, "score": self.score, "flagged": self.flagged,
                "reasons": self.reasons}


class SenderRule(db.Model):
    """Block list / allow list entry. pattern is an address or a domain."""
    __tablename__ = "sender_rules"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    pattern = db.Column(db.String(320), nullable=False)
    list_type = db.Column(db.String(8), default="block", nullable=False)  # block / allow
    reason = db.Column(db.String(255))
    auto_added = db.Column(db.Boolean, default=False)
    hits = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=utcnow)
    __table_args__ = (db.UniqueConstraint("user_id", "pattern", "list_type", name="uq_sender_rule"),)

    def to_dict(self):
        return {"id": self.id, "pattern": self.pattern, "list_type": self.list_type,
                "reason": self.reason, "auto_added": self.auto_added, "hits": self.hits,
                "created_at": self.created_at.isoformat()}


class SecurityRule(db.Model):
    """Custom keyword / regex rule that adds (or subtracts) risk points."""
    __tablename__ = "security_rules"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    field = db.Column(db.String(16), default="body", nullable=False)  # subject/body/sender/any
    match_type = db.Column(db.String(16), default="contains", nullable=False)  # contains/regex
    pattern = db.Column(db.String(500), nullable=False)
    score = db.Column(db.Integer, default=20, nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)

    def as_dict(self):
        return {"name": self.name, "field": self.field, "match_type": self.match_type,
                "pattern": self.pattern, "score": self.score, "enabled": self.enabled}


class Alert(db.Model):
    __tablename__ = "alerts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("email_scans.id", ondelete="SET NULL"))
    level = db.Column(db.String(16), default="medium")
    message = db.Column(db.String(500), nullable=False)
    is_read = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    scan = db.relationship("EmailScan")


# ── OAuth tokens (Gmail API, future providers) ────────────────────────────────


class OAuthToken(db.Model):
    """Stores OAuth2 access/refresh tokens for connected provider accounts (e.g. Gmail API)."""
    __tablename__ = "oauth_tokens"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    provider = db.Column(db.String(32), nullable=False, default="gmail")  # gmail / outlook
    email = db.Column(db.String(255), nullable=False)
    _access_token = db.Column("access_token", db.Text, nullable=False, default="")
    _refresh_token = db.Column("refresh_token", db.Text, nullable=False, default="")
    token_expiry = db.Column(db.DateTime)
    scopes = db.Column(db.String(512), default="")
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    last_checked = db.Column(db.DateTime)
    last_history_id = db.Column(db.String(64), default="")  # Gmail history ID for incremental sync
    last_status = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=utcnow)

    user = db.relationship("User", backref=db.backref("oauth_tokens", cascade="all, delete-orphan"))

    @property
    def access_token(self):
        return decrypt(self._access_token) if self._access_token else ""

    @access_token.setter
    def access_token(self, value):
        self._access_token = encrypt(value) if value else ""

    @property
    def refresh_token(self):
        return decrypt(self._refresh_token) if self._refresh_token else ""

    @refresh_token.setter
    def refresh_token(self, value):
        self._refresh_token = encrypt(value) if value else ""

    @property
    def is_expired(self):
        if not self.token_expiry:
            return True
        return utcnow() >= self.token_expiry

    def to_dict(self):
        return {
            "id": self.id, "provider": self.provider, "email": self.email,
            "enabled": self.enabled, "scopes": self.scopes,
            "last_checked": self.last_checked.isoformat() if self.last_checked else None,
            "last_status": self.last_status,
        }


# ── SMS / messaging scans ─────────────────────────────────────────────────────


class SmsScan(db.Model):
    """Scanned SMS messages and messaging app notifications."""
    __tablename__ = "sms_scans"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    # Source: sms / whatsapp / telegram / messenger / manual
    source = db.Column(db.String(24), default="sms", nullable=False, index=True)
    sender = db.Column(db.String(255), index=True)       # phone number or display name
    sender_name = db.Column(db.String(255))
    recipient = db.Column(db.String(255))
    message_text = db.Column(db.Text)                    # full message (up to ~2000 chars stored)
    message_excerpt = db.Column(db.String(500))          # first 500 chars for display
    message_hash = db.Column(db.String(64), index=True)  # SHA-256 of sender+text for dedup
    received_at = db.Column(db.DateTime)
    scanned_at = db.Column(db.DateTime, default=utcnow, index=True)
    risk_score = db.Column(db.Integer, default=0, nullable=False)
    threat_level = db.Column(db.String(16), default="safe", nullable=False, index=True)
    verdict = db.Column(db.String(24), default="clean", nullable=False)
    action = db.Column(db.String(16), default="allowed", nullable=False, index=True)
    reasons_json = db.Column(db.Text, default="[]")
    urls_json = db.Column(db.Text, default="[]")  # list of {url, host, score, flagged, reasons}
    is_read = db.Column(db.Boolean, default=False, index=True)

    user = db.relationship("User", backref=db.backref("sms_scans", cascade="all, delete-orphan"))
    alerts = db.relationship("SmsAlert", backref="sms_scan", cascade="all, delete-orphan")

    @property
    def reasons(self):
        try:
            return json.loads(self.reasons_json or "[]")
        except (ValueError, TypeError):
            return []

    @reasons.setter
    def reasons(self, value):
        self.reasons_json = json.dumps(value)

    @property
    def urls(self):
        try:
            return json.loads(self.urls_json or "[]")
        except (ValueError, TypeError):
            return []

    @urls.setter
    def urls(self, value):
        self.urls_json = json.dumps(value)

    def to_dict(self, detail=False):
        d = {
            "id": self.id, "source": self.source, "sender": self.sender,
            "sender_name": self.sender_name, "message_excerpt": self.message_excerpt,
            "received_at": self.received_at.isoformat() if self.received_at else None,
            "scanned_at": self.scanned_at.isoformat() if self.scanned_at else None,
            "risk_score": self.risk_score, "threat_level": self.threat_level,
            "verdict": self.verdict, "action": self.action, "is_read": self.is_read,
        }
        if detail:
            d["reasons"] = self.reasons
            d["urls"] = self.urls
        return d


class SmsAlert(db.Model):
    """Alert linked to an SmsScan (mirrors Alert for email scans)."""
    __tablename__ = "sms_alerts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    sms_scan_id = db.Column(db.Integer, db.ForeignKey("sms_scans.id", ondelete="SET NULL"))
    level = db.Column(db.String(16), default="medium")
    message = db.Column(db.String(500), nullable=False)
    is_read = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)

    user = db.relationship("User", backref=db.backref("sms_alerts", cascade="all, delete-orphan"))
