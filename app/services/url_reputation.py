"""URL analysis: local heuristics + optional DNS / DNSBL / Safe Browsing / VirusTotal / URLScan."""
import base64
import logging
import re
import socket
import threading
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

import requests

from .heuristics import BRANDS, lookalike_brand, registrable_label

log = logging.getLogger(__name__)

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
              "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "lnkd.in"}
BAD_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "ga", "cf", "work", "loan",
            "support", "rest", "monster", "icu", "cyou", "buzz", "cam", "sbs"}
LURE_PATH = re.compile(r"(login|signin|verify|secure|update|account|confirm|password|banking|wallet)", re.I)
EXEC_EXT = re.compile(r"\.(exe|scr|bat|cmd|msi|jar|vbs|js|ps1|apk|hta|lnk)(\?|$)", re.I)
IP_RE = re.compile(r"^\[?(\d{1,3}\.){3}\d{1,3}\]?$")
FLAG_THRESHOLD = 30

_cache = {}
_lock = threading.Lock()

# Private / loopback ranges — never follow redirects to these (SSRF guard)
_PRIVATE_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|localhost|0\.0\.0\.0)", re.I
)


@dataclass
class UrlFinding:
    url: str
    host: str = ""
    score: int = 0
    reasons: List[str] = field(default_factory=list)
    final_url: str = ""          # URL after following redirects (filled when follow_redirects=True)

    @property
    def flagged(self):
        return self.score >= FLAG_THRESHOLD

    def add(self, pts, why):
        self.score = min(100, self.score + pts)
        self.reasons.append(why)


def _anchor_host(text: str) -> Optional[str]:
    m = re.search(r"((?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,})", text or "", re.I)
    if not m:
        return None
    return urlparse(m.group(1) if "//" in m.group(1) else "//" + m.group(1)).hostname


def _is_private_host(host: str) -> bool:
    """SSRF guard — returns True if host resolves to a private / loopback address."""
    if _PRIVATE_RE.match(host):
        return True
    try:
        addrs = socket.getaddrinfo(host, None)
        for _, _, _, _, sockaddr in addrs:
            if _PRIVATE_RE.match(sockaddr[0]):
                return True
    except Exception:
        pass
    return False


def _follow_redirect(url: str, timeout: int = 5) -> str:
    """Follow HTTP redirects for known shorteners; return the final URL.

    SSRF protection: refuses to follow to private addresses. On any error
    the original URL is returned unchanged.
    """
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if host not in SHORTENERS:
            return url
        if _is_private_host(host):
            return url
        resp = requests.head(url, allow_redirects=True, timeout=timeout,
                             headers={"User-Agent": "CyberShield/1.0 (URL-safety-check)"},
                             stream=False)
        final = resp.url
        # SSRF check on final destination
        final_host = (urlparse(final).hostname or "").lower()
        if _is_private_host(final_host):
            log.warning("Redirect to private address blocked: %s -> %s", url, final)
            return url
        return final
    except Exception as e:
        log.debug("Redirect follow failed for %s: %s", url, e)
        return url


def _anchor_host(text: str) -> Optional[str]:
    m = re.search(r"((?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,})", text or "", re.I)
    if not m:
        return None
    return urlparse(m.group(1) if "//" in m.group(1) else "//" + m.group(1)).hostname


def local_checks(url: str, anchor_text: str = "") -> UrlFinding:
    f = UrlFinding(url=url)
    try:
        u = urlparse(url)
        host = (u.hostname or "").lower()
    except ValueError:
        f.add(30, "Malformed URL")
        return f
    f.host = host
    if not host:
        f.add(30, "URL has no host")
        return f
    if u.scheme == "http":
        f.add(5, "Unencrypted HTTP link")
    if IP_RE.match(host):
        f.add(30, "Link points to a raw IP address")
    if "@" in (u.netloc or ""):
        f.add(25, "URL contains '@' (credential-style obfuscation)")
    if "xn--" in host:
        f.add(25, "Punycode (possible homograph attack)")
    if len(url) > 120:
        f.add(5, "Very long URL")
    if host.count(".") >= 4:
        f.add(10, "Excessive number of subdomains")
    if host in SHORTENERS:
        f.add(12, "URL shortener hides the destination")
    tld = host.rsplit(".", 1)[-1]
    if tld in BAD_TLDS:
        f.add(12, f"Suspicious top-level domain .{tld}")
    if u.port and u.port not in (80, 443):
        f.add(8, f"Non-standard port {u.port}")
    la = lookalike_brand(host)
    if la:
        f.add(30, f"Domain imitates {la[0]} ({la[1]})")
    else:
        reg = registrable_label(host)
        sub_labels = host.split(".")[:-2]
        for b in BRANDS:
            if reg != b and any(b in s for s in sub_labels):
                f.add(25, f"Brand name '{b}' used in subdomain of unrelated domain")
                break
    if EXEC_EXT.search(u.path or ""):
        f.add(25, "Link downloads an executable file")
    if LURE_PATH.search(u.path or "") and registrable_label(host) not in BRANDS:
        f.add(6, "Login/verification keywords in path of unfamiliar domain")
    ah = _anchor_host(anchor_text)
    if ah and registrable_label(ah) != registrable_label(host) and "." in ah:
        f.add(30, f"Link text shows {ah} but leads to {host}")
    return f


def _dns_resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return True


def _dnsbl_listed(host: str, timeout: float) -> bool:
    if IP_RE.match(host):
        return False
    try:
        import dns.resolver
        r = dns.resolver.Resolver()
        r.lifetime = timeout
        ans = r.resolve(f"{registrable_label(host)}.{host.split('.')[-1]}.dbl.spamhaus.org", "A")
        return any(str(a).startswith("127.0.1.") and not str(a).endswith(".255") for a in ans)
    except Exception:
        return False


def _safe_browsing(url: str, key: str, timeout: float) -> bool:
    body = {"client": {"clientId": "cybershield", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                           "threatEntries": [{"url": url}]}}
    try:
        r = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
                          json=body, timeout=timeout)
        return bool(r.ok and r.json().get("matches"))
    except Exception as e:
        log.debug("safe browsing failed: %s", e)
        return False


def _virustotal(url: str, key: str, timeout: float) -> int:
    uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{uid}",
                         headers={"x-apikey": key}, timeout=timeout)
        if r.ok:
            return int(r.json()["data"]["attributes"]["last_analysis_stats"].get("malicious", 0))
    except Exception as e:
        log.debug("virustotal failed: %s", e)
    return 0


def _urlscan(url: str, key: str, timeout: float) -> Optional[dict]:
    """Query urlscan.io for existing reports on the URL. Returns verdicts dict or None."""
    try:
        headers = {"API-Key": key} if key else {}
        r = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"page.url:{url}", "size": 1},
            headers=headers,
            timeout=timeout,
        )
        if r.ok:
            results = r.json().get("results", [])
            if results:
                return results[0].get("verdicts", {})
    except Exception as e:
        log.debug("urlscan failed: %s", e)
    return None


def external_checks(f: UrlFinding, opts: dict):
    timeout = opts.get("timeout", 3)
    key = (f.url, f.host)
    with _lock:
        cached = _cache.get(key)
    if cached is None:
        cached = []
        if opts.get("dns_check") and f.host and not IP_RE.match(f.host) and not _dns_resolves(f.host):
            cached.append((15, "Domain does not resolve in DNS"))
        if opts.get("dnsbl") and _dnsbl_listed(f.host, timeout):
            cached.append((45, "Domain listed on Spamhaus DBL"))
        if opts.get("safe_browsing_key") and _safe_browsing(f.url, opts["safe_browsing_key"], timeout):
            cached.append((60, "Flagged by Google Safe Browsing"))
        if opts.get("virustotal_key"):
            n = _virustotal(f.url, opts["virustotal_key"], timeout)
            if n >= 3:
                cached.append((55, f"Flagged malicious by {n} VirusTotal engines"))
            elif n:
                cached.append((20, f"Flagged by {n} VirusTotal engine(s)"))
        if opts.get("urlscan_key"):
            v = _urlscan(f.url, opts["urlscan_key"], timeout)
            if v is not None:
                overall = v.get("overall", {})
                if overall.get("malicious"):
                    cached.append((55, "Flagged as malicious by URLScan.io"))
                elif overall.get("suspicious"):
                    cached.append((20, "Flagged as suspicious by URLScan.io"))
        with _lock:
            if len(_cache) > 5000:
                _cache.clear()
            _cache[key] = cached
    for pts, why in cached:
        f.add(pts, why)


def analyze_urls(links, opts: dict, limit: int = 25) -> List[UrlFinding]:
    """Analyze up to *limit* unique links.

    If opts['follow_redirects'] is True, known shortener URLs are resolved to
    their final destination before scanning (SSRF-guarded).
    """
    findings, seen = [], set()
    follow = opts.get("follow_redirects", False)
    follow_timeout = int(opts.get("follow_timeout", 5))

    for link in links:
        if link.url in seen:
            continue
        seen.add(link.url)
        if len(findings) >= limit:
            break

        url = link.url
        final_url = url

        # Unshorten: follow redirects for known shorteners only
        if follow:
            resolved = _follow_redirect(url, timeout=follow_timeout)
            if resolved != url:
                final_url = resolved
                seen.add(resolved)

        f = local_checks(url, link.text)
        f.final_url = final_url

        # If we resolved a shortener, also run checks on the final URL
        if final_url != url:
            fdest = local_checks(final_url, link.text)
            if opts.get("external", True):
                external_checks(fdest, opts)
            # Merge results into the original URL finding
            combined_score = min(100, f.score + fdest.score)
            for reason in fdest.reasons:
                if reason not in f.reasons:
                    f.reasons.append(reason)
            f.score = combined_score

        if opts.get("external", True):
            external_checks(f, opts)
        findings.append(f)
    return findings


def url_points(findings: List[UrlFinding]) -> int:
    flagged = [f for f in findings if f.flagged]
    if not findings:
        return 0
    top = max(f.score for f in findings)
    if flagged:
        return min(45, round(top * 0.5 + 4 * (len(flagged) - 1)))
    return min(8, round(top * 0.25))
