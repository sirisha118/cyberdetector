"""Threat detection pipeline: combines heuristics, ML, URLs, attachments and user rules."""
import re
from dataclasses import dataclass, field
from typing import List, Optional

from .attachments import attachment_points, inspect_all
from .heuristics import run_heuristics
from .parser import ParsedEmail
from .url_reputation import analyze_urls, url_points

LEVELS = ["safe", "low", "medium", "high", "critical"]


def level_for(score: int) -> str:
    """Map 0-100 risk score to a level name.

    Thresholds per specification:
      0–19  → safe (Low Risk)
      20–39 → low (Caution)
      40–69 → medium (Medium Risk)
      70–89 → high (High Risk)
      90–100 → critical (Critical Risk)
    """
    if score < 20:
        return "safe"
    if score < 40:
        return "low"
    if score < 70:
        return "medium"
    if score < 90:
        return "high"
    return "critical"


@dataclass
class DetectionContext:
    settings: dict = field(default_factory=lambda: {
        "quarantine_threshold": 40, "block_threshold": 70, "auto_block_sender": True,
        "use_ml": True, "check_urls": True, "check_attachments": True, "use_external_reputation": True})
    custom_rules: List[dict] = field(default_factory=list)
    blocked: List[str] = field(default_factory=list)
    allowed: List[str] = field(default_factory=list)
    classifier: Optional[object] = None
    url_opts: dict = field(default_factory=dict)


@dataclass
class DetectionResult:
    score: int = 0
    level: str = "safe"
    verdict: str = "clean"
    action: str = "allowed"
    reasons: List[dict] = field(default_factory=list)
    ml: Optional[dict] = None
    urls: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    sender_rule: Optional[str] = None  # 'block' / 'allow' when a list matched
    score_breakdown: dict = field(default_factory=dict)  # per-category point totals


def sender_matches(pattern: str, addr: str, domain: str) -> bool:
    p = pattern.lower().strip().lstrip("*")
    if not p:
        return False
    if "@" in p and not p.startswith("@"):
        return addr == p
    p = p.lstrip("@")
    return domain == p or domain.endswith("." + p)


def _rule_hit(rule: dict, p: ParsedEmail) -> bool:
    fields = {"subject": p.subject, "body": p.body, "sender": f"{p.from_name} <{p.from_addr}>"}
    haystack = "\n".join(fields.values()) if rule["field"] == "any" else fields.get(rule["field"], "")
    if rule["match_type"] == "regex":
        try:
            return re.search(rule["pattern"], haystack, re.I) is not None
        except re.error:
            return False
    return rule["pattern"].lower() in haystack.lower()


def analyze(p: ParsedEmail, ctx: DetectionContext) -> DetectionResult:
    s = ctx.settings
    r = DetectionResult()
    pts_by_cat = {}

    def add(points, code, detail, cat="generic"):
        r.reasons.append({"code": code, "points": points, "detail": detail, "category": cat})
        pts_by_cat[cat] = pts_by_cat.get(cat, 0) + max(points, 0)

    # 1. Sender block / allow lists
    blocked = next((x for x in ctx.blocked if sender_matches(x, p.from_addr, p.from_domain)), None)
    allowed = next((x for x in ctx.allowed if sender_matches(x, p.from_addr, p.from_domain)), None)
    if blocked and not allowed:
        add(100, "sender-blocked", f"Sender matches block list entry '{blocked}'", "generic")
        r.sender_rule = "block"
        return _finalize(r, p, ctx, forced=100)

    # 2. Heuristics
    for pts, code, detail, cat in run_heuristics(p):
        add(pts, code, detail, cat)

    # 3. Machine learning
    if s["use_ml"] and ctx.classifier is not None:
        text = f"{p.subject}\n{p.body}"
        r.ml = ctx.classifier.predict(text)
        prob = r.ml["probability"]
        if prob >= 0.3:
            add(round(prob * 40), "ml-model",
                f"ML classifier: {prob:.0%} likelihood of {r.ml['threat_label']}", r.ml["threat_label"])

    # 4. URLs
    if s["check_urls"] and p.links:
        opts = dict(ctx.url_opts)
        opts["external"] = s["use_external_reputation"]
        r.urls = analyze_urls(p.links, opts)
        up = url_points(r.urls)
        if up:
            worst = max(r.urls, key=lambda f: f.score)
            add(up, "bad-urls", f"Suspicious link {worst.host}: {worst.reasons[0] if worst.reasons else ''}", "phishing")

    # 5. Attachments
    if s["check_attachments"] and p.attachments:
        r.attachments = inspect_all(p.attachments)
        ap = attachment_points(r.attachments)
        if ap >= 30:
            worst = max(r.attachments, key=lambda f: f.score)
            add(ap, "bad-attachment", f"{worst.filename}: {worst.reasons[0]}", "malware")
        elif ap > 0:
            add(ap, "attachment-note", "Attachment has minor risk indicators", "generic")

    # 6. Custom user rules
    for rule in ctx.custom_rules:
        if rule.get("enabled", True) and _rule_hit(rule, p):
            add(rule["score"], "custom-rule", f"Custom rule '{rule['name']}' matched", "generic")

    # 7. Allow list overrides (but never for confirmed malware)
    if allowed:
        if pts_by_cat.get("malware", 0) < 60:
            r.sender_rule = "allow"
            r.reasons.append({"code": "sender-allowed", "points": 0,
                              "detail": f"Sender matches allow list entry '{allowed}'", "category": "generic"})
            return _finalize(r, p, ctx, forced=0)

    total = sum(x["points"] for x in r.reasons)
    # Confirmed malware attachment always reaches the block threshold
    if pts_by_cat.get("malware", 0) >= 60:
        total = max(total, s["block_threshold"])
    return _finalize(r, p, ctx, forced=max(0, min(100, total)), cats=pts_by_cat)


def _finalize(r, p, ctx, forced, cats=None):
    s = ctx.settings
    r.score = int(forced)
    r.level = level_for(r.score)
    cats = cats or {}
    r.score_breakdown = {k: v for k, v in cats.items()}
    if r.sender_rule == "block":
        r.verdict = "suspicious"
    elif r.score < 20:
        r.verdict = "clean"
    else:
        real = {k: v for k, v in cats.items() if k in ("phishing", "spam", "malware") and v > 0}
        r.verdict = max(real, key=real.get) if real else "suspicious"
        if cats.get("malware", 0) >= 60:
            r.verdict = "malware"
    if r.score >= s["block_threshold"]:
        r.action = "blocked"
    elif r.score >= s["quarantine_threshold"]:
        r.action = "quarantined"
    else:
        r.action = "allowed"
    r.reasons.sort(key=lambda x: -x["points"])
    return r
