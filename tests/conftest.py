import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from app.models import User  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def sample(name: str) -> bytes:
    with open(os.path.join(SAMPLES, name), "rb") as fh:
        return fh.read()


@pytest.fixture()
def app(tmp_path):
    app = create_app("testing")
    app.config["MODEL_PATH"] = str(tmp_path / "model.joblib")
    from app.ml.classifier import reset_classifier
    reset_classifier()
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def user(app):
    u = User(username="alice", email="alice@example.com", role="admin")
    u.set_password("Password123!")
    db.session.add(u)
    u.get_settings()
    db.session.commit()
    return u


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def auth_client(client, user):
    client.post("/login", data={"username": "alice", "password": "Password123!"})
    return client
