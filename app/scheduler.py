"""APScheduler: periodic mailbox polling and quarantine retention clean-up."""
import logging
from datetime import timedelta

from apscheduler.schedulers.background import BackgroundScheduler

from .extensions import db
from .models import EmailScan, MailAccount, OAuthToken, UserSettings, utcnow

log = logging.getLogger(__name__)
scheduler = BackgroundScheduler(daemon=True, job_defaults={"coalesce": True, "max_instances": 1})


def poll_mailboxes(app):
    from .services.mailbox import scan_account
    with app.app_context():
        now = utcnow()
        for acc in MailAccount.query.filter_by(enabled=True).all():
            due = acc.last_checked is None or acc.last_checked + timedelta(minutes=acc.poll_minutes) <= now
            if due:
                log.info("Polling mailbox %s", acc.name)
                scan_account(acc, limit=app.config["MAX_SCAN_PER_RUN"])


def poll_gmail_accounts(app):
    """Poll all enabled Gmail OAuth accounts."""
    from .services.gmail_oauth import gmail_available, scan_gmail_account
    if not gmail_available():
        return
    with app.app_context():
        for tok in OAuthToken.query.filter_by(provider="gmail", enabled=True).all():
            try:
                log.info("Polling Gmail OAuth account %s", tok.email)
                scan_gmail_account(tok, limit=app.config.get("GMAIL_POLL_LIMIT", 50))
            except Exception as e:
                log.warning("Gmail poll failed for %s: %s", tok.email, e)


def purge_old(app):
    with app.app_context():
        for st in UserSettings.query.all():
            cutoff = utcnow() - timedelta(days=st.retention_days or 30)
            old = EmailScan.query.filter(EmailScan.user_id == st.user_id, EmailScan.scanned_at < cutoff).all()
            for s in old:
                db.session.delete(s)
        db.session.commit()


def init_scheduler(app):
    if scheduler.running:
        return
    scheduler.add_job(poll_mailboxes, "interval", seconds=app.config["SCHEDULER_TICK_SECONDS"],
                      args=[app], id="poll_mailboxes", replace_existing=True)
    scheduler.add_job(poll_gmail_accounts, "interval", seconds=app.config["SCHEDULER_TICK_SECONDS"],
                      args=[app], id="poll_gmail_accounts", replace_existing=True)
    scheduler.add_job(purge_old, "cron", hour=3, minute=15, args=[app], id="purge_old", replace_existing=True)
    scheduler.start()
    log.info("Scheduler started")
