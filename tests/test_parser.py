from app.services.parser import parse_email
from conftest import sample


def test_parse_headers_and_links():
    p = parse_email(sample("phishing.eml"))
    assert p.from_domain == "paypa1-support.com"
    assert p.reply_to_domain == "mail-recovery.top"
    assert "spf=fail" in p.auth_results
    urls = [l.url for l in p.links]
    assert any("198.51.100.23" in u for u in urls)
    # anchor text vs href captured from HTML part
    html_link = next(l for l in p.links if "198.51.100.23" in l.url)
    assert "paypal.com" in html_link.text


def test_parse_attachment():
    p = parse_email(sample("malware.eml"))
    assert len(p.attachments) == 1
    assert p.attachments[0].filename == "Invoice_2024.pdf.exe"
    assert len(p.attachments[0].sha256) == 64


def test_parse_garbage_does_not_raise():
    p = parse_email(b"\xff\xfe not an email at all")
    assert p.subject == ""
