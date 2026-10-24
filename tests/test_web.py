import json

from app.extensions import db
from app.models import Alert, EmailScan, SenderRule
from conftest import sample


def test_register_login_logout(client):
    r = client.post("/register", data={"username": "bob", "email": "bob@example.com",
                                       "password": "Secret123!", "confirm": "Secret123!"}, follow_redirects=True)
    assert b"Threat overview" in r.data
    client.post("/logout")
    assert client.get("/dashboard").status_code == 302
    r = client.post("/login", data={"username": "bob", "password": "bad"})
    assert b"Invalid username or password" in r.data


def test_pages_require_login(client):
    for path in ("/dashboard", "/emails", "/quarantine", "/senders", "/rules", "/accounts", "/alerts"):
        assert client.get(path).status_code == 302


def test_manual_scan_quarantine_release(auth_client, app, user):
    r = auth_client.post("/scan", data={"raw": sample("phishing.eml").decode()}, follow_redirects=True)
    assert r.status_code == 200 and b"Why this verdict" in r.data
    scan = EmailScan.query.first()
    assert scan.status == "held" and scan.action in ("quarantined", "blocked")
    assert Alert.query.count() == 1
    assert b"paypa1-support.com" in auth_client.get("/quarantine").data
    auth_client.post(f"/emails/{scan.id}/release", data={"trust_sender": "on"})
    assert db.session.get(EmailScan, scan.id).status == "released"
    assert SenderRule.query.filter_by(list_type="allow").count() == 1


def test_auto_block_sender(auth_client, app):
    auth_client.post("/scan", data={"raw": sample("malware.eml").decode()})
    rule = SenderRule.query.filter_by(list_type="block").first()
    assert rule and rule.auto_added and rule.pattern == "billing@invoices-portal.net"


def test_dashboard_and_data(auth_client):
    auth_client.post("/scan", data={"raw": sample("spam.eml").decode()})
    d = auth_client.get("/dashboard/data").get_json()
    assert d["total"] == 1 and sum(d["daily_threats"]) + sum(d["daily_clean"]) == 1
    assert auth_client.get("/dashboard").status_code == 200
    assert auth_client.get("/emails?action=quarantined").status_code == 200


def test_rules_validation(auth_client, user):
    r = auth_client.post("/rules", data={"quarantine_threshold": "80", "block_threshold": "60"}, follow_redirects=True)
    assert b"Thresholds must be" in r.data
    auth_client.post("/rules", data={"quarantine_threshold": "30", "block_threshold": "60", "use_ml": "on"})
    assert user.get_settings().quarantine_threshold == 30
    auth_client.post("/rules/custom", data={"name": "x", "pattern": "([", "match_type": "regex", "score": "10"})
    assert len(user.custom_rules) == 0  # bad regex rejected


def test_user_isolation(client, app, user):
    from app.models import User
    other = User(username="eve", email="eve@example.com")
    other.set_password("Password123!")
    db.session.add(other)
    db.session.commit()
    client.post("/login", data={"username": "alice", "password": "Password123!"})
    client.post("/scan", data={"raw": sample("spam.eml").decode()})
    client.post("/logout")
    client.post("/login", data={"username": "eve", "password": "Password123!"})
    sid = EmailScan.query.first().id
    assert client.get(f"/emails/{sid}").status_code == 404


def test_csrf_enforced(app, user):
    app.config["WTF_CSRF_ENABLED"] = True
    c = app.test_client()
    assert c.post("/login", data={"username": "alice", "password": "Password123!"}).status_code == 400


def test_rest_api(client, user):
    h = {"X-API-Key": user.api_key}
    assert client.get("/api/v1/scans").status_code == 401
    assert client.get("/api/v1/health").status_code == 200
    r = client.post("/api/v1/scan", headers=h, json={
        "from": "PayPal <alert@paypa1.com>", "subject": "Verify your account immediately",
        "body": "Unusual activity detected. Confirm your password within 24 hours: http://198.51.100.9/login"})
    assert r.status_code == 201
    body = r.get_json()
    assert body["action"] != "allowed" and body["reasons"]
    r = client.post("/api/v1/scan", headers={**h, "Content-Type": "message/rfc822"}, data=sample("legitimate.eml"))
    assert r.get_json()["action"] == "allowed"
    assert client.get("/api/v1/scans?action=allowed", headers=h).get_json()["total"] == 1
    assert client.get(f"/api/v1/scans/{body['id']}", headers=h).get_json()["id"] == body["id"]
    assert client.get("/api/v1/stats", headers=h).get_json()["total"] == 2
    r = client.post("/api/v1/senders", headers=h, json={"pattern": "bad.com", "list_type": "block"})
    assert r.status_code == 201
    assert client.post("/api/v1/senders", headers=h, json={"pattern": "bad.com"}).status_code == 409
    assert client.delete(f"/api/v1/senders/{r.get_json()['id']}", headers=h).status_code == 204
    assert client.get("/api/v1/alerts", headers=h).status_code == 200
