"""Tests for URL reputation improvements: redirect following, URLScan.io, SSRF guard."""
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

import pytest

from app.services.url_reputation import (
    _follow_redirect, _is_private_host, _urlscan, analyze_urls, local_checks,
)
from app.services.parser import ParsedLink


# ── SSRF guard tests ──────────────────────────────────────────────────────────

def test_private_host_detection():
    assert _is_private_host("192.168.1.1")
    assert _is_private_host("10.0.0.1")
    assert _is_private_host("127.0.0.1")
    assert _is_private_host("localhost")
    assert not _is_private_host("8.8.8.8")  # public


def test_follow_redirect_blocks_private(monkeypatch):
    """Redirects to private addresses must be blocked."""
    mock_resp = MagicMock()
    mock_resp.url = "http://192.168.0.1/malware"
    with patch("app.services.url_reputation.requests.head", return_value=mock_resp):
        # Even though the shortener redirects to a private IP, we must get the original URL back
        result = _follow_redirect("http://bit.ly/test", timeout=5)
        assert result == "http://bit.ly/test"  # original returned, not the private redirect


def test_follow_redirect_public(monkeypatch):
    """Public redirects should be followed."""
    mock_resp = MagicMock()
    mock_resp.url = "http://phishing.example.com/steal-data"
    with patch("app.services.url_reputation.requests.head", return_value=mock_resp):
        with patch("app.services.url_reputation._is_private_host", return_value=False):
            result = _follow_redirect("http://bit.ly/test", timeout=5)
            assert result == "http://phishing.example.com/steal-data"


def test_follow_redirect_non_shortener():
    """Non-shortener URLs should not be followed (no HTTP call made)."""
    with patch("app.services.url_reputation.requests.head") as mock_head:
        result = _follow_redirect("http://example.com/page", timeout=5)
        assert result == "http://example.com/page"
        mock_head.assert_not_called()


# ── URLScan.io tests ──────────────────────────────────────────────────────────

def test_urlscan_malicious(monkeypatch):
    mock_resp = MagicMock()
    mock_resp.ok = True
    mock_resp.json.return_value = {
        "results": [{"verdicts": {"overall": {"malicious": True, "suspicious": False}}}]
    }
    with patch("app.services.url_reputation.requests.get", return_value=mock_resp):
        result = _urlscan("http://evil.example.com", "fake-key", 3)
        assert result is not None
        assert result.get("overall", {}).get("malicious")


def test_urlscan_no_results(monkeypatch):
    mock_resp = MagicMock()
    mock_resp.ok = True
    mock_resp.json.return_value = {"results": []}
    with patch("app.services.url_reputation.requests.get", return_value=mock_resp):
        result = _urlscan("http://unknown.example.com", "fake-key", 3)
        assert result is None


def test_urlscan_api_error(monkeypatch):
    with patch("app.services.url_reputation.requests.get", side_effect=Exception("timeout")):
        result = _urlscan("http://example.com", "fake-key", 3)
        assert result is None


# ── Redirect integration in analyze_urls ─────────────────────────────────────

def test_analyze_urls_with_redirect_following(monkeypatch):
    """analyze_urls with follow_redirects=True should check the final URL."""
    mock_resp = MagicMock()
    mock_resp.url = "http://paypa1.com/login"  # phishing destination
    with patch("app.services.url_reputation.requests.head", return_value=mock_resp):
        with patch("app.services.url_reputation._is_private_host", return_value=False):
            links = [ParsedLink(url="http://bit.ly/abc123", text="")]
            findings = analyze_urls(links, {"follow_redirects": True, "external": False,
                                            "follow_timeout": 5}, limit=5)
            assert len(findings) == 1
            f = findings[0]
            # Should have detected the lookalike domain in final URL
            assert f.score > 0


def test_analyze_urls_no_redirect():
    """Without redirect following, shortener is only scored on its own domain."""
    links = [ParsedLink(url="http://bit.ly/abc123", text="")]
    findings = analyze_urls(links, {"follow_redirects": False, "external": False}, limit=5)
    assert len(findings) == 1
    # bit.ly itself scores as a shortener
    assert any("shortener" in r.lower() for r in findings[0].reasons)


# ── UrlFinding.final_url field ────────────────────────────────────────────────

def test_url_finding_has_final_url():
    f = local_checks("http://example.com")
    assert hasattr(f, "final_url")
    assert f.final_url == ""  # empty by default from local_checks
