"""Flask CLI helpers: flask init-db | create-admin | train-model | seed-demo | scan-now"""
import glob
import os
import random
from datetime import timedelta

import click

from .extensions import db


def register_cli(app):
    @app.cli.command("init-db")
    def init_db():
        """Create all database tables."""
        db.create_all()
        click.echo("Database tables created.")

    @app.cli.command("migrate-db")
    def migrate_db():
        """Add missing columns to existing tables (lightweight ALTER-TABLE migration).

        Use this after updating models that add columns to existing tables.
        New tables are created by init-db; this handles ALTER TABLE for
        columns that were added to tables that already exist.
        """
        from sqlalchemy import inspect, text
        engine = db.engine

        # Map: table_name -> [(column_name, column_type_sql), ...]
        migrations = {
            "user_settings": [
                ("sms_scan_enabled", "BOOLEAN DEFAULT 1 NOT NULL"),
                ("notify_sms_threats", "BOOLEAN DEFAULT 1 NOT NULL"),
            ],
        }

        inspector = inspect(engine)
        applied = 0
        for table, cols in migrations.items():
            if not inspector.has_table(table):
                click.echo(f"  Table '{table}' does not exist — skipping (run init-db first).")
                continue
            existing = {c["name"] for c in inspector.get_columns(table)}
            for col_name, col_def in cols:
                if col_name not in existing:
                    stmt = f'ALTER TABLE "{table}" ADD COLUMN "{col_name}" {col_def}'
                    try:
                        with engine.connect() as conn:
                            conn.execute(text(stmt))
                            conn.commit()
                        click.echo(f"  + {table}.{col_name}")
                        applied += 1
                    except Exception as e:
                        click.echo(f"  ! {table}.{col_name}: {e}")

        if applied == 0:
            click.echo("  All columns already present — nothing to migrate.")
        else:
            click.echo(f"  Applied {applied} column migration(s).")

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    @click.option("--email", prompt=True)
    @click.password_option()
    def create_admin(username, email, password):
        """Create an administrator account."""
        from .models import User
        u = User(username=username, email=email.lower(), role="admin")
        u.set_password(password)
        db.session.add(u)
        u.get_settings()
        db.session.commit()
        click.echo(f"Admin '{username}' created.")

    @app.cli.command("train-model")
    @click.option("--csv", "csv_path", default=None, help="CSV with columns text,label (ham/spam/phishing)")
    def train_model(csv_path):
        """Train the ML classifier and save it."""
        from .ml.classifier import reset_classifier, train
        m = train(csv_path or app.config["TRAINING_DATA"], app.config["MODEL_PATH"])
        reset_classifier()
        click.echo(f"Trained on {m['rows']} rows, hold-out accuracy {m['accuracy']:.3f}")

    @app.cli.command("seed-demo")
    @click.option("--count", default=40)
    def seed_demo(count):
        """Create a demo user (demo / Demo12345!) with scanned sample e-mails."""
        from .models import User, utcnow
        from .services.scanner import build_context, scan_raw_message
        user = User.query.filter_by(username="demo").first()
        if not user:
            user = User(username="demo", email="demo@example.com")
            user.set_password("Demo12345!")
            db.session.add(user)
            db.session.flush()
        user.get_settings()
        files = sorted(glob.glob(os.path.join(app.root_path, "..", "samples", "*.eml")))
        if not files:
            click.echo("No samples found in ./samples")
            return
        raws = [open(f, "rb").read() for f in files]
        ctx = build_context(user)
        for i in range(count):
            raw = random.choice(raws)
            raw = raw.replace(b"@cybershield.sample>", f".{i}@cybershield.sample>".encode(), 1)
            scan = scan_raw_message(user, raw, source="manual", ctx=ctx)
            scan.scanned_at = utcnow() - timedelta(days=random.randint(0, 12), hours=random.randint(0, 23))
        db.session.commit()
        click.echo(f"Seeded {count} scans. Login: demo / Demo12345!")

    @app.cli.command("scan-now")
    def scan_now():
        """Poll all enabled mailboxes once."""
        from .scheduler import poll_mailboxes
        poll_mailboxes(app)
        click.echo("Done.")
