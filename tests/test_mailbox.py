"""Mailbox polling logic tested against an in-memory fake IMAP session."""
from app.extensions import db
from app.models import EmailScan, MailAccount
from app.services import mailbox
from conftest import sample


class FakeSession:
    moved = []
    store = {1: sample("legitimate.eml"), 2: sample("phishing.eml"), 3: sample("malware.eml")}

    def __init__(self, account):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def select(self, folder, readonly=False):
        pass

    def fetch_new(self, last_uid, limit):
        return [(u, r) for u, r in sorted(self.store.items()) if u > last_uid][:limit]

    def move(self, uid, dest):
        FakeSession.moved.append((uid, dest))

    def find_by_message_id(self, mid):
        return 99


def make_account(user):
    acc = MailAccount(user_id=user.id, name="t", imap_host="x", username="u")
    acc.password = "secret"
    db.session.add(acc)
    db.session.commit()
    return acc


def test_scan_account_quarantines_threats(app, user, monkeypatch):
    monkeypatch.setattr(mailbox, "ImapSession", FakeSession)
    FakeSession.moved = []
    acc = make_account(user)
    assert acc.password == "secret" and acc._password != "secret"  # stored encrypted
    stats = mailbox.scan_account(acc)
    assert stats["scanned"] == 3 and stats["errors"] == 0
    assert {u for u, _ in FakeSession.moved} == {2, 3}
    assert acc.last_uid == 3 and acc.last_status.startswith("OK")
    # second poll sees nothing new
    assert mailbox.scan_account(acc)["scanned"] == 0
    assert EmailScan.query.count() == 3


def test_release_moves_back(app, user, monkeypatch):
    monkeypatch.setattr(mailbox, "ImapSession", FakeSession)
    FakeSession.moved = []
    acc = make_account(user)
    assert mailbox.release_message(acc, "<x@y>") is True
    assert FakeSession.moved == [(99, "INBOX")]


def test_connection_failure_is_recorded(app, user, monkeypatch):
    class Boom(FakeSession):
        def __enter__(self):
            raise OSError("connection refused")
    monkeypatch.setattr(mailbox, "ImapSession", Boom)
    acc = make_account(user)
    assert mailbox.scan_account(acc)["errors"] == 1
    assert "connection refused" in acc.last_status
