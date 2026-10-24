import re

from flask import (Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, url_for)
from flask_login import current_user, login_required
from sqlalchemy import or_

from ..extensions import db
from ..models import LEVELS, Alert, EmailScan, MailAccount, SecurityRule, SenderRule
from ..services import mailbox
from ..services.scanner import scan_raw_message
from ..services.stats import dashboard_stats

bp = Blueprint("main", __name__)


def _own_scan(scan_id):
    scan = db.session.get(EmailScan, scan_id)
    if not scan or scan.user_id != current_user.id:
        abort(404)
    return scan


def _own(model, obj_id):
    obj = db.session.get(model, obj_id)
    if not obj or obj.user_id != current_user.id:
        abort(404)
    return obj


@bp.route("/")
def index():
    return redirect(url_for("main.dashboard") if current_user.is_authenticated else url_for("auth.login"))


@bp.route("/dashboard")
@login_required
def dashboard():
    stats = dashboard_stats(current_user.id)
    recent = (EmailScan.query.filter(EmailScan.user_id == current_user.id, EmailScan.action != "allowed")
              .order_by(EmailScan.scanned_at.desc()).limit(8).all())
    return render_template("dashboard.html", stats=stats, recent=recent)


@bp.route("/dashboard/data")
@login_required
def dashboard_data():
    return jsonify(dashboard_stats(current_user.id, days=min(int(request.args.get("days", 14)), 90)))


@bp.route("/emails")
@login_required
def emails():
    q = EmailScan.query.filter_by(user_id=current_user.id)
    action, level, verdict, text = (request.args.get(k, "") for k in ("action", "level", "verdict", "q"))
    if action:
        q = q.filter_by(action=action)
    if level:
        q = q.filter_by(threat_level=level)
    if verdict:
        q = q.filter_by(verdict=verdict)
    if text:
        like = f"%{text}%"
        q = q.filter(or_(EmailScan.subject.ilike(like), EmailScan.sender.ilike(like)))
    page = q.order_by(EmailScan.scanned_at.desc()).paginate(page=request.args.get("page", 1, type=int),
                                                           per_page=20, error_out=False)
    return render_template("emails.html", page=page, levels=LEVELS)


@bp.route("/emails/<int:scan_id>")
@login_required
def email_detail(scan_id):
    return render_template("email_detail.html", scan=_own_scan(scan_id))


@bp.route("/quarantine")
@login_required
def quarantine():
    items = (EmailScan.query.filter_by(user_id=current_user.id, status="held")
             .order_by(EmailScan.scanned_at.desc()).all())
    return render_template("quarantine.html", items=items)


@bp.route("/emails/<int:scan_id>/release", methods=["POST"])
@login_required
def release(scan_id):
    scan = _own_scan(scan_id)
    note = ""
    if scan.account is not None and scan.source == "imap":
        try:
            moved = mailbox.release_message(scan.account, scan.message_id)
            note = " and moved back to your inbox" if moved else " (message not found in quarantine folder)"
        except Exception as e:
            note = f" (mailbox move failed: {str(e)[:80]})"
    scan.status = "released"
    if request.form.get("trust_sender") and scan.sender:
        if not SenderRule.query.filter_by(user_id=current_user.id, pattern=scan.sender, list_type="allow").first():
            db.session.add(SenderRule(user_id=current_user.id, pattern=scan.sender, list_type="allow",
                                      reason="Released as false positive"))
        for r in SenderRule.query.filter_by(user_id=current_user.id, pattern=scan.sender, list_type="block"):
            db.session.delete(r)
        note += "; sender added to allow list"
    db.session.commit()
    flash(f"E-mail released{note}.", "success")
    return redirect(request.form.get("next") or url_for("main.quarantine"))


@bp.route("/emails/<int:scan_id>/delete", methods=["POST"])
@login_required
def delete_email(scan_id):
    scan = _own_scan(scan_id)
    scan.status = "deleted"
    db.session.commit()
    flash("E-mail marked as deleted (scan record kept for history).", "info")
    return redirect(url_for("main.quarantine"))


@bp.route("/emails/<int:scan_id>/block-sender", methods=["POST"])
@login_required
def block_sender(scan_id):
    scan = _own_scan(scan_id)
    target = scan.sender_domain if request.form.get("scope") == "domain" else scan.sender
    if target and not SenderRule.query.filter_by(user_id=current_user.id, pattern=target, list_type="block").first():
        db.session.add(SenderRule(user_id=current_user.id, pattern=target, list_type="block",
                                  reason=f"Blocked from scan #{scan.id}"))
        db.session.commit()
    flash(f"Blocked {target}.", "success")
    return redirect(url_for("main.email_detail", scan_id=scan.id))


@bp.route("/senders", methods=["GET", "POST"])
@login_required
def senders():
    if request.method == "POST":
        pattern = request.form.get("pattern", "").strip().lower().lstrip("*")
        ltype = request.form.get("list_type", "block")
        if ltype not in ("block", "allow") or not re.fullmatch(r"@?[a-z0-9._%+-]*@?[a-z0-9.-]+\.[a-z]{2,}|[^@\s]+@[^@\s]+", pattern):
            flash("Enter a valid e-mail address or domain.", "danger")
        elif SenderRule.query.filter_by(user_id=current_user.id, pattern=pattern, list_type=ltype).first():
            flash("That entry already exists.", "warning")
        else:
            db.session.add(SenderRule(user_id=current_user.id, pattern=pattern, list_type=ltype,
                                      reason=request.form.get("reason", "")[:255]))
            db.session.commit()
            flash(f"Added {pattern} to the {ltype} list.", "success")
        return redirect(url_for("main.senders"))
    rules = SenderRule.query.filter_by(user_id=current_user.id).order_by(SenderRule.created_at.desc()).all()
    return render_template("senders.html", blocked=[r for r in rules if r.list_type == "block"],
                           allowed=[r for r in rules if r.list_type == "allow"])


@bp.route("/senders/<int:rule_id>/delete", methods=["POST"])
@login_required
def delete_sender(rule_id):
    db.session.delete(_own(SenderRule, rule_id))
    db.session.commit()
    flash("Entry removed.", "info")
    return redirect(url_for("main.senders"))


@bp.route("/alerts")
@login_required
def alerts():
    page = (Alert.query.filter_by(user_id=current_user.id).order_by(Alert.created_at.desc())
            .paginate(page=request.args.get("page", 1, type=int), per_page=25, error_out=False))
    return render_template("alerts.html", page=page)


@bp.route("/alerts/read", methods=["POST"])
@login_required
def alerts_read():
    Alert.query.filter_by(user_id=current_user.id, is_read=False).update({"is_read": True})
    db.session.commit()
    return redirect(url_for("main.alerts"))


@bp.route("/rules", methods=["GET", "POST"])
@login_required
def rules():
    st = current_user.get_settings()
    if request.method == "POST":
        try:
            q, b = int(request.form["quarantine_threshold"]), int(request.form["block_threshold"])
            if not (1 <= q < b <= 100):
                raise ValueError
            st.quarantine_threshold, st.block_threshold = q, b
            st.retention_days = max(1, min(365, int(request.form.get("retention_days", 30))))
        except (KeyError, ValueError):
            flash("Thresholds must be integers with 1 ≤ quarantine < block ≤ 100.", "danger")
            return redirect(url_for("main.rules"))
        for f in ("auto_block_sender", "use_ml", "check_urls", "check_attachments",
                  "use_external_reputation", "alert_email",
                  "sms_scan_enabled", "notify_sms_threats"):
            setattr(st, f, request.form.get(f) == "on")
        lvl = request.form.get("alert_level", "medium")
        st.alert_level = lvl if lvl in LEVELS else "medium"
        db.session.commit()
        flash("Security policy saved.", "success")
        return redirect(url_for("main.rules"))
    return render_template("rules.html", st=st, custom=current_user.custom_rules, levels=LEVELS[1:])


@bp.route("/rules/custom", methods=["POST"])
@login_required
def add_rule():
    pattern = request.form.get("pattern", "").strip()
    name = request.form.get("name", "").strip() or pattern[:40]
    mtype = request.form.get("match_type", "contains")
    try:
        score = int(request.form.get("score", 20))
        if mtype == "regex":
            re.compile(pattern)
        assert pattern and -100 <= score <= 100 and mtype in ("contains", "regex")
    except (ValueError, re.error, AssertionError):
        flash("Invalid rule (check pattern/regex and score between -100 and 100).", "danger")
        return redirect(url_for("main.rules"))
    field = request.form.get("field", "body")
    db.session.add(SecurityRule(user_id=current_user.id, name=name[:100], pattern=pattern[:500], score=score,
                                match_type=mtype, field=field if field in ("subject", "body", "sender", "any") else "body"))
    db.session.commit()
    flash("Custom rule added.", "success")
    return redirect(url_for("main.rules"))


@bp.route("/rules/custom/<int:rule_id>/<action>", methods=["POST"])
@login_required
def rule_action(rule_id, action):
    rule = _own(SecurityRule, rule_id)
    if action == "delete":
        db.session.delete(rule)
    elif action == "toggle":
        rule.enabled = not rule.enabled
    else:
        abort(404)
    db.session.commit()
    return redirect(url_for("main.rules"))


@bp.route("/accounts", methods=["GET", "POST"])
@login_required
def accounts():
    if request.method == "POST":
        f = request.form
        try:
            acc = MailAccount(
                user_id=current_user.id, name=f["name"].strip()[:100], imap_host=f["imap_host"].strip(),
                imap_port=int(f.get("imap_port", 993)), imap_ssl=f.get("imap_ssl") == "on",
                smtp_host=f.get("smtp_host", "").strip() or None, smtp_port=int(f.get("smtp_port") or 587),
                username=f["username"].strip(), folder=f.get("folder", "INBOX").strip() or "INBOX",
                quarantine_folder=f.get("quarantine_folder", "CyberShield-Quarantine").strip() or "CyberShield-Quarantine",
                poll_minutes=max(1, int(f.get("poll_minutes", 5))), auto_move=f.get("auto_move") == "on")
            acc.password = f["password"]
            if not acc.name or not acc.imap_host or not acc.username:
                raise ValueError
        except (KeyError, ValueError):
            flash("Please fill all required mailbox fields correctly.", "danger")
            return redirect(url_for("main.accounts"))
        db.session.add(acc)
        db.session.commit()
        flash("Mailbox added. Use 'Test' to verify the connection.", "success")
        return redirect(url_for("main.accounts"))
    from ..models import OAuthToken
    oauth_tokens = OAuthToken.query.filter_by(user_id=current_user.id, provider="gmail").all()
    gmail_configured = bool(current_app.config.get("GMAIL_CLIENT_ID"))
    return render_template("accounts.html", accounts=current_user.accounts,
                           oauth_tokens=oauth_tokens, gmail_configured=gmail_configured)


@bp.route("/accounts/<int:acc_id>/<action>", methods=["POST"])
@login_required
def account_action(acc_id, action):
    acc = _own(MailAccount, acc_id)
    if action == "delete":
        EmailScan.query.filter_by(account_id=acc.id).update({"account_id": None})
        db.session.delete(acc)
        flash("Mailbox removed.", "info")
    elif action == "toggle":
        acc.enabled = not acc.enabled
    elif action == "test":
        try:
            flash(mailbox.test_connection(acc), "success")
        except Exception as e:
            flash(f"Connection failed: {str(e)[:150]}", "danger")
    elif action == "scan":
        res = mailbox.scan_account(acc)
        flash(f"Scan finished: {res['scanned']} scanned, {res['quarantined']} quarantined, "
              f"{res['blocked']} blocked, {res['errors']} errors.", "info" if not res["errors"] else "warning")
    else:
        abort(404)
    db.session.commit()
    return redirect(url_for("main.accounts"))


@bp.route("/scan", methods=["GET", "POST"])
@login_required
def manual_scan():
    if request.method == "POST":
        upload = request.files.get("eml")
        raw = upload.read() if upload and upload.filename else request.form.get("raw", "").encode("utf-8", "replace")
        if not raw.strip():
            flash("Paste raw e-mail source or upload an .eml file.", "danger")
            return redirect(url_for("main.manual_scan"))
        scan = scan_raw_message(current_user, raw, source="manual")
        db.session.commit()
        return redirect(url_for("main.email_detail", scan_id=scan.id))
    return render_template("scan.html")


# ── SMS / messaging manual scan ────────────────────────────────────────────

@bp.route("/sms", methods=["GET"])
@login_required
def sms_list():
    """List of scanned SMS / messaging messages."""
    from ..models import SmsScan
    q = SmsScan.query.filter_by(user_id=current_user.id)
    source = request.args.get("source", "")
    action = request.args.get("action", "")
    if source:
        q = q.filter_by(source=source)
    if action:
        q = q.filter_by(action=action)
    page = q.order_by(SmsScan.scanned_at.desc()).paginate(
        page=request.args.get("page", 1, type=int), per_page=20, error_out=False)
    return render_template("sms.html", page=page)


@bp.route("/sms/scan", methods=["GET", "POST"])
@login_required
def sms_scan():
    """Manual SMS / messaging message scan."""
    from ..services.sms_scanner import scan_sms
    if request.method == "POST":
        text = request.form.get("text", "").strip()
        sender = request.form.get("sender", "").strip()
        source = request.form.get("source", "sms")
        if source not in ("sms", "whatsapp", "telegram", "messenger", "manual"):
            source = "manual"
        if not text:
            flash("Enter the message text to scan.", "danger")
            return redirect(url_for("main.sms_scan"))
        scan = scan_sms(current_user, sender=sender, text=text, source=source)
        db.session.commit()
        return redirect(url_for("main.sms_detail", scan_id=scan.id))
    return render_template("sms_scan.html")


@bp.route("/sms/<int:scan_id>")
@login_required
def sms_detail(scan_id):
    """Detail page for a single SMS scan."""
    from ..models import SmsScan
    scan = db.session.get(SmsScan, scan_id)
    if not scan or scan.user_id != current_user.id:
        abort(404)
    return render_template("sms_detail.html", scan=scan)


@bp.route("/sms/<int:scan_id>/delete", methods=["POST"])
@login_required
def sms_delete(scan_id):
    from ..models import SmsScan
    scan = db.session.get(SmsScan, scan_id)
    if not scan or scan.user_id != current_user.id:
        abort(404)
    db.session.delete(scan)
    db.session.commit()
    flash("Message scan deleted.", "info")
    return redirect(url_for("main.sms_list"))
