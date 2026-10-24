"""Rule-based e-mail heuristics (headers, wording, impersonation)."""
import re

from .parser import ParsedEmail

URGENCY = ["urgent", "immediately", "within 24 hours", "act now", "account suspended", "account will be",
           "verify your account", "confirm your identity", "password expires", "unusual activity",
           "final notice", "limited time", "action required", "security alert", "deactivated",
           "unauthorized login", "failure to", "your account has been"]
CREDENTIALS = ["password", "login", "log in", "sign in", "ssn", "social security", "credit card",
               "bank account", "pin code", "otp", "one-time", "card number", "cvv", "update your payment"]
SPAM = ["you have won", "winner", "lottery", "free money", "viagra", "cheap pills", "100% free",
        "click here", "unsubscribe", "earn $", "crypto giveaway", "make money fast", "no obligation",
        "risk-free", "exclusive deal", "congratulations", "claim your prize", "weight loss", "casino"]
BEC = ["wire transfer", "gift card", "new bank details", "change of bank", "invoice attached",
       "are you available", "keep this confidential", "payment overdue", "transfer funds"]

BRANDS = {"paypal", "microsoft", "google", "amazon", "apple", "netflix", "facebook", "instagram",
          "linkedin", "dhl", "fedex", "docusign", "dropbox", "adobe", "hdfc", "icici", "sbi", "paytm",
          "irs", "chase", "wellsfargo", "bankofamerica", "coinbase", "binance", "whatsapp", "outlook",
          "office365", "usps", "ups", "steam", "spotify"}
FREEMAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "proton.me", "protonmail.com",
            "mail.com", "gmx.com", "yandex.com", "rediffmail.com"}
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registrable_label(domain: str) -> str:
    parts = [p for p in domain.lower().split(".") if p]
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL:
        return parts[-3]
    if len(parts) >= 2:
        return parts[-2]
    return parts[0] if parts else ""


def _normalize(label: str) -> str:
    s = label.replace("-", "").replace("_", "")
    for a, b in (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("4", "a"), ("5", "s"), ("$", "s")):
        s = s.replace(a, b)
    return s


def lookalike_brand(domain: str):
    """Return (brand, kind) if the domain imitates a known brand, else None."""
    label = registrable_label(domain)
    if not label or label in BRANDS:
        return None
    norm = _normalize(label)
    for brand in BRANDS:
        if norm == brand:
            return brand, "typosquat"
        if len(brand) >= 5 and levenshtein(norm, brand) <= (2 if len(brand) >= 8 else 1) and abs(len(norm) - len(brand)) <= 2:
            return brand, "typosquat"
        if len(brand) >= 5 and brand in label:
            return brand, "brand-keyword"
        if len(brand) >= 5 and brand in norm:
            return brand, "typosquat"
    return None


def _hits(text: str, words):
    t = text.lower()
    return [w for w in words if w in t]


def run_heuristics(p: ParsedEmail):
    """Return list of (points, code, detail, category)."""
    out = []
    text = f"{p.subject}\n{p.body}"

    h = _hits(text, URGENCY)
    if h:
        out.append((min(15, 4 * len(h)), "urgency", f"Urgent / pressure wording: {', '.join(h[:4])}", "phishing"))
    h = _hits(text, CREDENTIALS)
    if h:
        out.append((min(12, 4 * len(h)), "credentials", f"Requests sensitive data: {', '.join(h[:4])}", "phishing"))
    h = _hits(text, SPAM)
    if h:
        out.append((min(22, 6 * len(h)), "spam-words", f"Spam wording: {', '.join(h[:4])}", "spam"))
    h = _hits(text, BEC)
    if h:
        out.append((min(18, 6 * len(h)), "bec", f"Business-email-compromise wording: {', '.join(h[:3])}", "phishing"))

    # Sender impersonation
    name_l = re.sub(r"[^a-z0-9]", "", (p.from_name or "").lower())
    label = registrable_label(p.from_domain)
    for brand in BRANDS:
        if brand in name_l and label != brand:
            out.append((22, "display-name-spoof",
                        f"Display name '{p.from_name}' imitates {brand} but sender domain is {p.from_domain}", "phishing"))
            break
    la = lookalike_brand(p.from_domain) if p.from_domain else None
    if la:
        out.append((25, "lookalike-domain", f"Sender domain {p.from_domain} imitates {la[0]} ({la[1]})", "phishing"))
    if p.reply_to_domain and p.from_domain and registrable_label(p.reply_to_domain) != registrable_label(p.from_domain):
        out.append((10, "reply-to-mismatch", f"Reply-To domain ({p.reply_to_domain}) differs from From domain ({p.from_domain})", "phishing"))
    if re.fullmatch(r"\[?\d{1,3}(\.\d{1,3}){3}\]?", p.from_domain or ""):
        out.append((10, "ip-sender", "Sender domain is a raw IP address", "generic"))

    # Authentication
    auth = 0
    for mech in ("spf", "dkim", "dmarc"):
        if re.search(rf"{mech}\s*=\s*(fail|softfail|none|permerror)", p.auth_results):
            auth += 1
            out.append((8 if mech != "dmarc" else 10, f"{mech}-fail", f"{mech.upper()} check did not pass", "phishing"))
    if not p.message_id:
        out.append((3, "no-message-id", "Message has no Message-ID header", "generic"))

    # Style
    letters = [c for c in p.subject if c.isalpha()]
    if len(letters) >= 8 and sum(c.isupper() for c in letters) / len(letters) > 0.7:
        out.append((5, "caps-subject", "Subject is mostly uppercase", "spam"))
    if (p.subject + p.body).count("!") >= 4:
        out.append((4, "exclamations", "Excessive exclamation marks", "spam"))
    if p.has_password_form:
        out.append((25, "password-form", "HTML body embeds a password entry form", "phishing"))
    if len(p.links) > 10:
        out.append((5, "many-links", f"Contains {len(p.links)} links", "spam"))
    if p.html_body and len(p.body) < 20 and p.links:
        out.append((6, "image-only", "Almost no text but contains links (image-only lure)", "spam"))
    return out
