"""E-mail parsing: headers, bodies, links and attachments."""
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import message_from_bytes, message_from_string, policy
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from typing import List, Optional

URL_RE = re.compile(r"""https?://[^\s<>"')\]]+""", re.I)
MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024


@dataclass
class ParsedAttachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    data: bytes = b""


@dataclass
class ParsedLink:
    url: str
    text: str = ""


@dataclass
class ParsedEmail:
    message_id: str = ""
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    from_domain: str = ""
    reply_to_addr: str = ""
    reply_to_domain: str = ""
    return_path_domain: str = ""
    to_addrs: List[str] = field(default_factory=list)
    date: Optional[datetime] = None
    text_body: str = ""
    html_body: str = ""
    links: List[ParsedLink] = field(default_factory=list)
    attachments: List[ParsedAttachment] = field(default_factory=list)
    auth_results: str = ""
    has_password_form: bool = False
    image_count: int = 0

    @property
    def body(self) -> str:
        return self.text_body or ""


class _HTMLScan(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.links = []
        self._href = None
        self._link_text = []
        self._skip = 0
        self.password_input = False
        self.has_form = False
        self.images = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a" and a.get("href"):
            self._href = a["href"].strip()
            self._link_text = []
        elif tag == "form":
            self.has_form = True
        elif tag == "input" and (a.get("type") or "").lower() == "password":
            self.password_input = True
        elif tag == "img":
            self.images += 1
        elif tag in ("br", "p", "div", "tr", "li"):
            self.text.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._href is not None:
            self.links.append(ParsedLink(self._href, " ".join("".join(self._link_text).split())))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._link_text.append(data)


def html_to_text(html: str):
    p = _HTMLScan()
    try:
        p.feed(html)
        p.close()
    except Exception:  # malformed HTML must never break a scan
        pass
    return re.sub(r"\n\s*\n+", "\n\n", "".join(p.text)).strip(), p


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].strip().lower() if "@" in addr else ""


def _part_text(part) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode(part.get_content_charset() or "utf-8", errors="replace")


def parse_email(raw) -> ParsedEmail:
    """Parse raw bytes/str RFC822 into a ParsedEmail. Never raises on odd input."""
    if isinstance(raw, str):
        msg = message_from_string(raw, policy=policy.default)
    else:
        msg = message_from_bytes(raw, policy=policy.default)

    p = ParsedEmail()
    p.message_id = str(msg.get("Message-ID", "") or "").strip()
    p.subject = str(msg.get("Subject", "") or "").strip()
    p.from_name, p.from_addr = parseaddr(str(msg.get("From", "") or ""))
    p.from_addr = p.from_addr.lower()
    p.from_domain = _domain(p.from_addr)
    _, rt = parseaddr(str(msg.get("Reply-To", "") or ""))
    p.reply_to_addr = rt.lower()
    p.reply_to_domain = _domain(p.reply_to_addr)
    _, rp = parseaddr(str(msg.get("Return-Path", "") or ""))
    p.return_path_domain = _domain(rp.lower())
    p.to_addrs = [a.lower() for _, a in getaddresses([str(msg.get("To", "") or "")]) if a]
    p.auth_results = " ".join(
        str(msg.get(h, "") or "") for h in ("Authentication-Results", "Received-SPF")
    ).lower()
    try:
        d = parsedate_to_datetime(str(msg.get("Date", "")))
        if d.tzinfo:
            d = d.astimezone(timezone.utc).replace(tzinfo=None)
        p.date = d
    except Exception:
        p.date = None

    html_parts, text_parts = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        fname = part.get_filename()
        disp = part.get_content_disposition()
        if fname or disp == "attachment":
            data = part.get_payload(decode=True) or b""
            p.attachments.append(ParsedAttachment(
                filename=str(fname or "unnamed"), content_type=ctype, size=len(data),
                sha256=hashlib.sha256(data).hexdigest(), data=data[:MAX_ATTACHMENT_BYTES]))
        elif ctype == "text/plain":
            text_parts.append(_part_text(part))
        elif ctype == "text/html":
            html_parts.append(_part_text(part))

    p.html_body = "\n".join(html_parts)
    p.text_body = "\n".join(text_parts).strip()
    links = []
    if p.html_body:
        text, scan = html_to_text(p.html_body)
        if not p.text_body:
            p.text_body = text
        links.extend(scan.links)
        p.has_password_form = scan.password_input
        p.image_count = scan.images
    seen = {l.url for l in links}
    for u in URL_RE.findall(p.text_body):
        u = u.rstrip(".,;:!?")
        if u not in seen:
            links.append(ParsedLink(u, ""))
            seen.add(u)
    p.links = [l for l in links if l.url.lower().startswith(("http://", "https://"))]
    return p
