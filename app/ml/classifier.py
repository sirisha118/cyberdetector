"""TF-IDF + Logistic Regression text classifier (ham / spam / phishing)."""
import logging
import os
import threading

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

log = logging.getLogger(__name__)
_lock = threading.Lock()
_instance = None


def build_pipeline():
    return Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=1, sublinear_tf=True,
                                  strip_accents="unicode", max_features=50000)),
        ("clf", LogisticRegression(max_iter=1000, C=4.0, class_weight="balanced")),
    ])


def train(csv_path: str, model_path: str) -> dict:
    """Train on a CSV with columns text,label (ham/spam/phishing) and persist."""
    df = pd.read_csv(csv_path).dropna(subset=["text", "label"])
    X_tr, X_te, y_tr, y_te = train_test_split(df["text"], df["label"], test_size=0.2,
                                              random_state=7, stratify=df["label"])
    pipe = build_pipeline().fit(X_tr, y_tr)
    report = classification_report(y_te, pipe.predict(X_te), output_dict=True, zero_division=0)
    pipe = build_pipeline().fit(df["text"], df["label"])  # refit on everything
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(pipe, model_path)
    log.info("Model trained on %d rows, accuracy=%.3f", len(df), report["accuracy"])
    return {"rows": len(df), "accuracy": report["accuracy"], "report": report}


class ThreatClassifier:
    def __init__(self, pipeline):
        self.pipe = pipeline
        self.classes = list(pipeline.classes_)

    def predict(self, text: str) -> dict:
        probs = dict(zip(self.classes, self.pipe.predict_proba([text[:20000]])[0]))
        p_ham = probs.get("ham", 0.0)
        threats = {k: v for k, v in probs.items() if k != "ham"}
        label = max(threats, key=threats.get) if threats else "ham"
        return {"probability": float(1 - p_ham), "label": label if p_ham < 0.5 else "ham",
                "threat_label": label, "probs": {k: float(v) for k, v in probs.items()}}


def get_classifier(config) -> ThreatClassifier:
    """Load (or lazily train) the singleton model."""
    global _instance
    if _instance is not None:
        return _instance
    with _lock:
        if _instance is None:
            path = config["MODEL_PATH"]
            if not os.path.exists(path):
                log.warning("No trained model found; training from sample data")
                train(config["TRAINING_DATA"], path)
            _instance = ThreatClassifier(joblib.load(path))
    return _instance


def reset_classifier():
    global _instance
    _instance = None
