from app.ml.classifier import get_classifier
from app.services.attachments import inspect_attachment
from app.services.detector import DetectionContext, analyze, level_for, sender_matches
from app.services.heuristics import lookalike_brand
from app.services.parser import ParsedAttachment, parse_email
from app.services.url_reputation import local_checks
from conftest import sample


def ctx(app, **kw):
    return DetectionContext(classifier=get_classifier(app.config), **kw)


def test_phishing_is_blocked(app):
    r = analyze(parse_email(sample("phishing.eml")), ctx(app))
    assert r.verdict == "phishing"
    assert r.action in ("blocked", "quarantined")
    assert r.score >= 60
    assert any(x["code"] == "lookalike-domain" for x in r.reasons)


def test_malware_always_blocked(app):
    r = analyze(parse_email(sample("malware.eml")), ctx(app))
    assert r.verdict == "malware" and r.action == "blocked" and r.level in ("high", "critical")


def test_spam_detected(app):
    r = analyze(parse_email(sample("spam.eml")), ctx(app))
    assert r.verdict in ("spam", "phishing") and r.action != "allowed"


def test_legitimate_allowed(app):
    r = analyze(parse_email(sample("legitimate.eml")), ctx(app))
    assert r.action == "allowed" and r.score < 20 and r.verdict == "clean"


def test_blocklist_and_allowlist(app):
    p = parse_email(sample("legitimate.eml"))
    r = analyze(p, ctx(app, blocked=["company-example.org"]))
    assert r.action == "blocked" and r.sender_rule == "block"
    p2 = parse_email(sample("phishing.eml"))
    r2 = analyze(p2, ctx(app, allowed=["paypa1-support.com"]))
    assert r2.action == "allowed" and r2.sender_rule == "allow"
    # allow list must not override confirmed malware
    r3 = analyze(parse_email(sample("malware.eml")), ctx(app, allowed=["invoices-portal.net"]))
    assert r3.action == "blocked"


def test_custom_rule_and_thresholds(app):
    p = parse_email(sample("legitimate.eml"))
    rules = [{"name": "roadmap", "field": "subject", "match_type": "contains", "pattern": "roadmap",
              "score": 50, "enabled": True}]
    c = ctx(app, custom_rules=rules)
    c.settings["quarantine_threshold"] = 30
    r = analyze(p, c)
    assert r.action == "quarantined"


def test_sender_matching():
    assert sender_matches("evil.com", "a@x.evil.com", "x.evil.com")
    assert sender_matches("a@evil.com", "a@evil.com", "evil.com")
    assert not sender_matches("a@evil.com", "b@evil.com", "evil.com")
    assert not sender_matches("evil.com", "a@notevil.com", "notevil.com")


def test_lookalike_and_urls():
    assert lookalike_brand("paypa1.com")[0] == "paypal"
    assert lookalike_brand("paypal.com") is None
    assert lookalike_brand("example.com") is None
    f = local_checks("http://192.0.2.1/login", "https://www.google.com")
    assert f.flagged and f.score >= 60
    assert not local_checks("https://github.com/anthropics").flagged


def test_attachment_checks():
    def att(name, data):
        return ParsedAttachment(name, "application/octet-stream", len(data), "0" * 64, data)
    assert inspect_attachment(att("run.exe", b"MZ....")).flagged
    assert inspect_attachment(att("report.pdf", b"MZ\x90\x00")).score >= 55
    assert inspect_attachment(att("notes.txt", b"hello")).score == 0
    assert inspect_attachment(att("a.docm", b"PK")).flagged


def test_levels():
    # Updated spec thresholds: 0-19 safe, 20-39 low, 40-69 medium, 70-89 high, 90-100 critical
    assert [level_for(s) for s in (0, 25, 50, 75, 95)] == ["safe", "low", "medium", "high", "critical"]
    assert level_for(89) == "high"
    assert level_for(90) == "critical"
