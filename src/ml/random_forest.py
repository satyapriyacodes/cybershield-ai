"""
Random Forest classifier for attack type prediction.
Trained on labeled synthetic data.
"""

import os
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from loguru import logger
from typing import Optional, Dict, Tuple, List
from src.ml.features import FEATURE_NAMES

MODEL_PATH = "models/random_forest.pkl"
ENCODER_PATH = "models/label_encoder.pkl"

ATTACK_CLASSES = ["normal", "brute_force", "unusual_time", "geo_anomaly", "impossible_travel", "privilege_escalation"]


class RandomForestDetector:
    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.model: Optional[RandomForestClassifier] = None
        self.label_encoder: Optional[LabelEncoder] = None

    def train(self, X: pd.DataFrame, y: pd.Series) -> "RandomForestDetector":
        logger.info("Training Random Forest classifier...")
        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y)

        X_train, X_test, y_train, y_test = train_test_split(
            X[FEATURE_NAMES], y_encoded, test_size=0.2, random_state=self.random_state, stratify=y_encoded
        )

        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            min_samples_split=5,
            class_weight="balanced",
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.model.fit(X_train, y_train)

        # Report
        y_pred = self.model.predict(X_test)
        logger.info("\n" + classification_report(y_test, y_pred, target_names=self.label_encoder.classes_))
        return self

    def predict_proba(self, X: pd.DataFrame) -> Tuple[np.ndarray, List[str]]:
        """Return class probabilities and class names."""
        if self.model is None:
            raise RuntimeError("Model not trained.")
        features = X[FEATURE_NAMES]
        probas = self.model.predict_proba(features)
        classes = list(self.label_encoder.classes_)
        return probas, classes

    def predict_attack_type(self, X: pd.DataFrame) -> Tuple[str, float]:
        """Return most-likely attack type and confidence for a single row."""
        probas, classes = self.predict_proba(X)
        idx = np.argmax(probas, axis=1)
        top_class = [classes[i] for i in idx]
        confidence = probas[np.arange(len(probas)), idx]
        return top_class, confidence

    def feature_importances(self) -> Dict[str, float]:
        if self.model is None:
            return {}
        return dict(zip(FEATURE_NAMES, self.model.feature_importances_))

    def save(self, model_path: str = MODEL_PATH, encoder_path: str = ENCODER_PATH):
        os.makedirs("models", exist_ok=True)
        joblib.dump(self.model, model_path)
        joblib.dump(self.label_encoder, encoder_path)
        logger.info(f"Random Forest saved → {model_path}")

    def load(self, model_path: str = MODEL_PATH, encoder_path: str = ENCODER_PATH) -> "RandomForestDetector":
        self.model = joblib.load(model_path)
        self.label_encoder = joblib.load(encoder_path)
        logger.info(f"Random Forest loaded from {model_path}")
        return self

    @classmethod
    def load_or_train(cls, X: pd.DataFrame, y: pd.Series) -> "RandomForestDetector":
        detector = cls()
        if os.path.exists(MODEL_PATH) and os.path.exists(ENCODER_PATH):
            detector.load()
        else:
            detector.train(X, y)
            detector.save()
        return detector
