"""IMAP integration: poll a mailbox, scan new mail, quarantine threats, release on request."""
import imaplib
import logging
import re

from ..extensions import db
from ..models import utcnow

log = logging.getLogger(__name__)


def _q(name: str) -> str:
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


class ImapSession:
    def __init__(self, account, timeout=20):
        self.a = account
        self.timeout = timeout
        self.conn = None

    def __enter__(self):
        cls = imaplib.IMAP4_SSL if self.a.imap_ssl else imaplib.IMAP4
        self.conn = cls(self.a.imap_host, self.a.imap_port, timeout=self.timeout)
        self.conn.login(self.a.username, self.a.password)
        return self

    def __exit__(self, *exc):
        try:
            self.conn.logout()
        except Exception:
            pass

    def select(self, folder, readonly=False):
        typ, data = self.conn.select(_q(folder), readonly=readonly)
        if typ != "OK":
            raise imaplib.IMAP4.error(f"Cannot open folder {folder}: {data}")

    def ensure_folder(self, folder):
        typ, _ = self.conn.create(_q(folder))  # OK or "already exists" -- both fine
        try:
            self.conn.subscribe(_q(folder))
        except Exception:
            pass

    def fetch_new(self, last_uid: int, limit: int):
        typ, data = self.conn.uid("SEARCH", None, "ALL")
        uids = sorted(int(x) for x in (data[0] or b"").split())
        new = [u for u in uids if u > last_uid]
        new = new[-limit:] if last_uid == 0 else new[:limit]
        out = []
        for uid in new:
            typ, msg = self.conn.uid("FETCH", str(uid), "(BODY.PEEK[])")
            if typ == "OK" and msg and isinstance(msg[0], tuple):
                out.append((uid, msg[0][1]))
        return out

    def move(self, uid: int, dest: str):
        self.ensure_folder(dest)
        caps = getattr(self.conn, "capabilities", ())
        if "MOVE" in caps:
            typ, _ = self.conn.uid("MOVE", str(uid), _q(dest))
            if typ == "OK":
                return
        typ, _ = self.conn.uid("COPY", str(uid), _q(dest))
        if typ != "OK":
            raise imaplib.IMAP4.error("COPY failed")
        self.conn.uid("STORE", str(uid), "+FLAGS", "(\\Deleted)")
        self.conn.expunge()

    def find_by_message_id(self, message_id: str):
        mid = re.sub(r'["\\\r\n]', "", message_id)
        typ, data = self.conn.uid("SEARCH", None, "HEADER", "Message-ID", _q(mid))
        ids = (data[0] or b"").split()
        return int(ids[0]) if ids else None


def test_connection(account) -> str:
    with ImapSession(account) as s:
        s.select(account.folder, readonly=True)
    return "IMAP login and folder access OK"


def scan_account(account, limit=50) -> dict:
    """Poll one mailbox. Returns counters; commits its own work."""
    from .scanner import build_context, scan_raw_message
    stats = {"scanned": 0, "quarantined": 0, "blocked": 0, "errors": 0}
    user = account.user
    try:
        with ImapSession(account) as s:
            s.select(account.folder)
            ctx = build_context(user)
            for uid, raw in s.fetch_new(account.last_uid, limit):
                try:
                    scan = scan_raw_message(user, raw, account=account, uid=uid, source="imap", ctx=ctx)
                    stats["scanned"] += 1
                    if scan.action != "allowed":
                        stats[scan.action] += 1
                        if account.auto_move:
                            s.move(uid, account.quarantine_folder)
                    account.last_uid = max(account.last_uid, uid)
                    db.session.commit()
                except Exception:
                    db.session.rollback()
                    stats["errors"] += 1
                    log.exception("Failed to process uid %s", uid)
                    account.last_uid = max(account.last_uid, uid)  # do not retry poison messages forever
        account.last_status = (f"OK - {stats['scanned']} scanned, "
                               f"{stats['quarantined'] + stats['blocked']} held")
    except Exception as e:
        db.session.rollback()
        account.last_status = f"ERROR: {str(e)[:200]}"
        stats["errors"] += 1
        log.warning("Mailbox %s failed: %s", account.name, e)
    account.last_checked = utcnow()
    db.session.commit()
    return stats


def release_message(account, message_id: str) -> bool:
    """Move a quarantined message back to the inbox. Returns True if moved."""
    if not message_id:
        return False
    with ImapSession(account) as s:
        s.select(account.quarantine_folder)
        uid = s.find_by_message_id(message_id)
        if uid is None:
            return False
        s.move(uid, account.folder)
        return True
