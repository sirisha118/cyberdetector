"""Application configuration."""
import os

from dotenv import load_dotenv

load_dotenv()
BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def _bool(name, default):
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _db_url():
    url = os.environ.get(
        "DATABASE_URL",
        "postgresql+psycopg2://cybershield:cybershield@localhost:5432/cybershield",
    )
    if url.startswith("postgres://"):  # Heroku-style URL
        url = url.replace("postgres://", "postgresql+psycopg2://", 1)
    return url


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me")
    SQLALCHEMY_DATABASE_URI = _db_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}
    AUTO_CREATE_TABLES = True
    WTF_CSRF_ENABLED = True
    MAX_CONTENT_LENGTH = 25 * 1024 * 1024

    ALLOW_REGISTRATION = _bool("ALLOW_REGISTRATION", True)
    ENABLE_SCHEDULER = _bool("ENABLE_SCHEDULER", True)
    SCHEDULER_TICK_SECONDS = int(os.environ.get("SCHEDULER_TICK_SECONDS", 60))
    MAX_SCAN_PER_RUN = 50

    # URL / reputation providers
    GOOGLE_SAFE_BROWSING_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "")
    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
    URL_DNS_CHECK = _bool("URL_DNS_CHECK", True)
    DNSBL_ENABLED = _bool("DNSBL_ENABLED", True)
    REPUTATION_TIMEOUT = 3

    # ML
    MODEL_PATH = os.path.join(BASE_DIR, "app", "ml", "model.joblib")
    TRAINING_DATA = os.path.join(BASE_DIR, "app", "ml", "data", "sample_emails.csv")

    # Alert e-mail fallback SMTP
    ALERT_SMTP_HOST = os.environ.get("ALERT_SMTP_HOST", "")
    ALERT_SMTP_PORT = int(os.environ.get("ALERT_SMTP_PORT", 587))
    ALERT_SMTP_USER = os.environ.get("ALERT_SMTP_USER", "")
    ALERT_SMTP_PASSWORD = os.environ.get("ALERT_SMTP_PASSWORD", "")
    ALERT_FROM = os.environ.get("ALERT_FROM", "cybershield@localhost")

    LOG_DIR = os.path.join(BASE_DIR, "logs")

    # Gmail OAuth2 (optional – IMAP app-password still works without these)
    GMAIL_CLIENT_ID = os.environ.get("GMAIL_CLIENT_ID", "")
    GMAIL_CLIENT_SECRET = os.environ.get("GMAIL_CLIENT_SECRET", "")
    # Must match an authorised redirect URI in your Google Cloud Console
    GMAIL_REDIRECT_URI = os.environ.get("GMAIL_REDIRECT_URI", "http://localhost:5000/oauth/gmail/callback")
    # Scopes needed: read messages and manage labels
    GMAIL_SCOPES = [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.labels",
        "https://www.googleapis.com/auth/gmail.modify",
    ]
    GMAIL_POLL_LIMIT = int(os.environ.get("GMAIL_POLL_LIMIT", 50))

    # URL scanning extras
    URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "")
    # Enable redirect-following for known URL shorteners
    URL_FOLLOW_REDIRECTS = _bool("URL_FOLLOW_REDIRECTS", True)
    URL_FOLLOW_TIMEOUT = int(os.environ.get("URL_FOLLOW_TIMEOUT", 5))


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", False)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_ENGINE_OPTIONS = {}
    WTF_CSRF_ENABLED = False
    ENABLE_SCHEDULER = False
    URL_DNS_CHECK = False
    DNSBL_ENABLED = False
    GOOGLE_SAFE_BROWSING_KEY = ""
    VIRUSTOTAL_API_KEY = ""
    URLSCAN_API_KEY = ""
    GMAIL_CLIENT_ID = ""
    GMAIL_CLIENT_SECRET = ""
    URL_FOLLOW_REDIRECTS = False
    SECRET_KEY = "testing-secret"


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}
