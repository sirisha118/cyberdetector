"""In-app security alerts and optional e-mail notifications via SMTP."""
import logging
import smtplib
from email.message import EmailMessage

from flask import current_app

from ..extensions import db
from ..models import Alert

log = logging.getLogger(__name__)


def create_alert(user, scan, account=None):
    verb = "Blocked" if scan.action == "blocked" else "Quarantined"
    msg = (f"{verb} {scan.verdict} e-mail from {scan.sender or 'unknown'} "
           f"(risk {scan.risk_score}/100): {scan.subject[:120] or '(no subject)'}")
    alert = Alert(user_id=user.id, scan_id=scan.id, level=scan.threat_level, message=msg[:500])
    db.session.add(alert)
    if user.get_settings().alert_email:
        send_email(user.email, f"[CyberShield] {verb} {scan.verdict} e-mail", msg, account)
    return alert


def send_email(to_addr: str, subject: str, body: str, account=None) -> bool:
    cfg = current_app.config
    host, port, user, pwd, sender = cfg["ALERT_SMTP_HOST"], cfg["ALERT_SMTP_PORT"], cfg["ALERT_SMTP_USER"], \
        cfg["ALERT_SMTP_PASSWORD"], cfg["ALERT_FROM"]
    if account is not None and account.smtp_host:
        host, port, user, pwd, sender = account.smtp_host, account.smtp_port or 587, account.username, \
            account.password, account.username
    if not host:
        return False
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender, to_addr, subject
    msg.set_content(body)
    try:
        if int(port) == 465:
            smtp = smtplib.SMTP_SSL(host, int(port), timeout=10)
        else:
            smtp = smtplib.SMTP(host, int(port), timeout=10)
            smtp.starttls()
        with smtp:
            if user:
                smtp.login(user, pwd)
            smtp.send_message(msg)
        return True
    except Exception as e:
        log.warning("Alert e-mail failed: %s", e)
        return False
