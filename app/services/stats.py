"""Dashboard statistics (pandas)."""
from datetime import timedelta

import pandas as pd

from ..models import Alert, EmailScan, SmsScan, utcnow


def dashboard_stats(user_id: int, days: int = 14) -> dict:
    since = utcnow() - timedelta(days=days)
    rows = (EmailScan.query.filter(EmailScan.user_id == user_id, EmailScan.scanned_at >= since)
            .with_entities(EmailScan.scanned_at, EmailScan.action, EmailScan.threat_level, EmailScan.verdict,
                           EmailScan.sender_domain, EmailScan.risk_score, EmailScan.status,
                           EmailScan.source).all())
    df = pd.DataFrame(rows, columns=["scanned_at", "action", "threat_level", "verdict",
                                     "domain", "score", "status", "source"])
    labels = [(since + timedelta(days=i + 1)).strftime("%Y-%m-%d") for i in range(days)]
    out = {"total": int(len(df)), "labels": labels,
           "allowed": 0, "quarantined": 0, "blocked": 0, "avg_score": 0.0, "held": 0,
           "daily_threats": [0] * days, "daily_clean": [0] * days,
           "by_verdict": {}, "by_level": {}, "by_source": {}, "top_domains": [],
           "unread_alerts": Alert.query.filter_by(user_id=user_id, is_read=False).count()}

    if not df.empty:
        for a in ("allowed", "quarantined", "blocked"):
            out[a] = int((df["action"] == a).sum())
        out["held"] = int((df["status"] == "held").sum())
        out["avg_score"] = round(float(df["score"].mean()), 1)
        df["day"] = pd.to_datetime(df["scanned_at"]).dt.strftime("%Y-%m-%d")
        threats = df[df["action"] != "allowed"].groupby("day").size()
        clean = df[df["action"] == "allowed"].groupby("day").size()
        out["daily_threats"] = [int(threats.get(d, 0)) for d in labels]
        out["daily_clean"] = [int(clean.get(d, 0)) for d in labels]
        bad = df[df["action"] != "allowed"]
        out["by_verdict"] = {k: int(v) for k, v in bad["verdict"].value_counts().items()}
        out["by_level"] = {k: int(v) for k, v in df["threat_level"].value_counts().items()}
        out["by_source"] = {k: int(v) for k, v in df["source"].value_counts().items()}
        top = bad[bad["domain"].astype(bool)]["domain"].value_counts().head(5)
        out["top_domains"] = [{"domain": k, "count": int(v)} for k, v in top.items()]

    # SMS / messaging stats
    sms_rows = (SmsScan.query
                .filter(SmsScan.user_id == user_id, SmsScan.scanned_at >= since)
                .with_entities(SmsScan.action, SmsScan.threat_level,
                               SmsScan.verdict, SmsScan.source, SmsScan.risk_score)
                .all())
    sms_df = pd.DataFrame(sms_rows, columns=["action", "threat_level", "verdict", "source", "score"])
    out["sms_total"] = int(len(sms_df))
    out["sms_flagged"] = int((sms_df["action"] != "allowed").sum()) if not sms_df.empty else 0
    out["sms_avg_score"] = round(float(sms_df["score"].mean()), 1) if not sms_df.empty else 0.0
    out["sms_by_verdict"] = {}
    out["sms_by_source"] = {}
    if not sms_df.empty:
        bad_sms = sms_df[sms_df["action"] != "allowed"]
        out["sms_by_verdict"] = {k: int(v) for k, v in bad_sms["verdict"].value_counts().items()}
        out["sms_by_source"] = {k: int(v) for k, v in sms_df["source"].value_counts().items()}

    # Unread SMS alerts
    from ..models import SmsAlert
    out["unread_sms_alerts"] = SmsAlert.query.filter_by(user_id=user_id, is_read=False).count()

    return out
