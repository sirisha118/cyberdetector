"""CyberShield application factory."""
import logging
import os
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify, render_template, request

from config import config_by_name

from .extensions import db, login_manager
from .security import csrf_protect, csrf_token


def create_app(config_name=None):
    app = Flask(__name__)
    name = config_name or os.environ.get("FLASK_CONFIG", "development")
    app.config.from_object(config_by_name[name])
    if name == "production" and app.config["SECRET_KEY"] == "dev-only-change-me":
        raise RuntimeError("Set a strong SECRET_KEY before running in production")

    _setup_logging(app)
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "warning"

    from .api.routes import bp as api_bp
    from .auth.routes import bp as auth_bp
    from .main.routes import bp as main_bp
    from .oauth.routes import bp as oauth_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix="/api/v1")
    app.register_blueprint(oauth_bp)

    app.before_request(csrf_protect)
    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.context_processor
    def inject_globals():
        from flask_login import current_user
        unread = 0
        if current_user.is_authenticated:
            from .models import Alert, SmsAlert
            unread = (Alert.query.filter_by(user_id=current_user.id, is_read=False).count()
                      + SmsAlert.query.filter_by(user_id=current_user.id, is_read=False).count())
        return {"unread_alerts": unread}

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        return resp

    def _err(code, title):
        if request.path.startswith("/api/"):
            return jsonify(error=title), code
        return render_template("error.html", code=code, title=title), code

    for code, title in ((400, "Bad request"), (403, "Forbidden"), (404, "Page not found"), (500, "Server error")):
        app.register_error_handler(code, lambda e, c=code, t=title: _err(c, t))

    from .cli import register_cli
    register_cli(app)

    if app.config["AUTO_CREATE_TABLES"]:
        with app.app_context():
            db.create_all()

    if app.config["ENABLE_SCHEDULER"] and (not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true"):
        from .scheduler import init_scheduler
        init_scheduler(app)
    return app


def _setup_logging(app):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if app.testing:
        return
    try:
        os.makedirs(app.config["LOG_DIR"], exist_ok=True)
        fh = RotatingFileHandler(os.path.join(app.config["LOG_DIR"], "cybershield.log"),
                                 maxBytes=1_000_000, backupCount=5)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logging.getLogger().addHandler(fh)
    except OSError:
        pass
