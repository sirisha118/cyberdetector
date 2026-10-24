"""Tests for SMS / messaging scam detection."""
import pytest

from app.services.sms_scanner import analyze_sms, _message_hash


# ── analyze_sms unit tests ────────────────────────────────────────────────────

def test_smishing_otp_theft():
    r = analyze_sms(
        sender="HDFCBK",
        text="Your HDFC Bank OTP is 456123. Do not share this OTP with anyone. "
             "Verify your account immediately: http://bit.ly/hdfc-kyc",
    )
    assert r.action in ("quarantined", "blocked"), f"Expected quarantine/block, got {r.action}"
    assert r.score >= 20
    assert any(x["code"] == "smishing-words" for x in r.reasons)


def test_fake_bank_kyc():
    r = analyze_sms(
        sender="+919876543210",
        text="Dear Customer, Your SBI account KYC is expired. Update KYC now to avoid "
             "account suspension: http://sbi-kyc-update.xyz/login",
    )
    # Should detect threats (phishing verdict, positive score)
    assert r.score > 0
    assert r.verdict in ("phishing", "smishing", "spam", "suspicious")
    # Should flag: smishing words, urgency, brand impersonation, bad URL
    codes = {x["code"] for x in r.reasons}
    assert len(codes) >= 2


def test_fake_parcel():
    r = analyze_sms(
        sender="DELHVRY",
        text="Your parcel is on hold due to customs fee. Pay Rs. 49 to reschedule delivery: "
             "http://198.51.100.5/customs",
    )
    assert r.score >= 15


def test_spam_prize():
    r = analyze_sms(
        sender="PRIZE",
        text="CONGRATULATIONS!!! You have won Rs. 50,00,000 lottery. Claim your prize now. "
             "Click: http://lucky-prizes.click/claim",
    )
    # Should be flagged as spam/phishing with elevated score
    assert r.score >= 20
    assert r.verdict in ("spam", "phishing", "suspicious")


def test_legitimate_sms():
    r = analyze_sms(
        sender="+919876543210",
        text="Hi, are you free for lunch on Thursday?",
    )
    assert r.action == "allowed"
    assert r.score < 20
    assert r.verdict == "clean"


def test_clean_otp_from_known_service():
    # OTP from a legitimate number should be moderate but not auto-blocked
    r = analyze_sms(
        sender="GOOGLE",
        text="Your Google verification code is 123456. Don't share it with anyone.",
    )
    # "do not share" and "otp" words trigger smishing, but no bad URL -> moderate
    # Action depends on threshold but should not be "blocked" for a bare OTP text
    assert r.score < 70  # Not critical threat from OTP text alone


def test_whatsapp_source():
    r = analyze_sms(
        sender="John",
        text="Check this out: http://bit.ly/free-iphone-now you have won free iPhone!!!",
        source="whatsapp",
    )
    assert r.score >= 10
    assert r.action in ("quarantined", "blocked", "allowed")  # depends on threshold


def test_url_extraction():
    r = analyze_sms(
        sender="SCAMMER",
        text="Click http://paypa1.com/verify to confirm your account",
        url_opts={"dns_check": False, "dnsbl": False},
    )
    assert len(r.urls) >= 1
    assert any(u["flagged"] for u in r.urls)


def test_message_hash_dedup():
    h1 = _message_hash("+91123", "hello world")
    h2 = _message_hash("+91123", "hello world")
    h3 = _message_hash("+91123", "hello WORLD")
    assert h1 == h2
    assert h1 != h3


def test_score_breakdown():
    r = analyze_sms(
        sender="HDFC",
        text="Your OTP is 123456. Update KYC at http://bit.ly/kyc",
    )
    assert isinstance(r.score_breakdown, dict)
    assert r.score_breakdown  # not empty when there are detections


# ── Web + API integration tests ───────────────────────────────────────────────

def test_sms_scan_web(auth_client):
    """Manual SMS scan via web UI returns detail page."""
    r = auth_client.post("/sms/scan", data={
        "text": "Your OTP is 456789. Do not share. Verify at http://bit.ly/kyc-now",
        "sender": "HDFCBK",
        "source": "sms",
        "_csrf": "",  # CSRF disabled in testing config
    }, follow_redirects=True)
    assert r.status_code == 200
    # Should land on the detail page
    assert b"Why this verdict" in r.data or b"Message scan" in r.data


def test_sms_list_page(auth_client):
    r = auth_client.get("/sms")
    assert r.status_code == 200


def test_api_sms_scan(client, user):
    """POST /api/v1/sms/scan with JSON."""
    h = {"X-API-Key": user.api_key}
    r = client.post("/api/v1/sms/scan", headers=h, json={
        "sender": "+91999",
        "text": "URGENT: Your account will be suspended. Verify KYC at http://198.51.100.5/kyc",
        "source": "sms",
    })
    assert r.status_code == 201
    body = r.get_json()
    assert "risk_score" in body
    assert "verdict" in body
    assert body["action"] in ("allowed", "quarantined", "blocked")


def test_api_sms_scan_missing_text(client, user):
    h = {"X-API-Key": user.api_key}
    r = client.post("/api/v1/sms/scan", headers=h, json={"sender": "+91999"})
    assert r.status_code == 400


def test_api_sms_scan_requires_auth(client):
    r = client.post("/api/v1/sms/scan", json={"text": "hello"})
    assert r.status_code == 401


def test_api_sms_scans_list(client, user):
    h = {"X-API-Key": user.api_key}
    # Seed one scan
    client.post("/api/v1/sms/scan", headers=h, json={"text": "test message", "sender": "TEST"})
    r = client.get("/api/v1/sms/scans", headers=h)
    assert r.status_code == 200
    assert r.get_json()["total"] >= 1


def test_api_url_scan(client, user):
    h = {"X-API-Key": user.api_key}
    r = client.post("/api/v1/url/scan", headers=h, json={
        "url": "http://paypa1.com/login", "external": False
    })
    assert r.status_code == 200
    body = r.get_json()
    assert body["flagged"] is True
    assert body["score"] > 0
    assert "risk_level" in body


def test_api_url_scan_invalid(client, user):
    h = {"X-API-Key": user.api_key}
    r = client.post("/api/v1/url/scan", headers=h, json={"url": "not-a-url"})
    assert r.status_code == 400
