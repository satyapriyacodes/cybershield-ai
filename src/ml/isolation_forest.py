"""
Isolation Forest anomaly detector.
Unsupervised — trained on all data (assumes ~10% contamination).
"""

import os
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from loguru import logger
from typing import List, Tuple, Optional
from src.ml.features import FEATURE_NAMES

MODEL_PATH = "models/isolation_forest.pkl"


class IsolationForestDetector:
    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model: Optional[IsolationForest] = None

    def train(self, X: pd.DataFrame) -> "IsolationForestDetector":
        logger.info("Training Isolation Forest...")
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=200,
            max_samples="auto",
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.model.fit(X[FEATURE_NAMES])
        logger.info("Isolation Forest trained.")
        return self

    def predict(self, X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Returns:
          labels: -1 (anomaly) or 1 (normal)
          scores: anomaly score in [0,1] where 1 = most anomalous
        """
        if self.model is None:
            raise RuntimeError("Model not trained. Call train() or load() first.")
        features = X[FEATURE_NAMES]
        labels = self.model.predict(features)        # -1 or 1
        raw_scores = self.model.score_samples(features)  # more negative = more anomalous
        # Normalise to [0,1]: higher = more anomalous
        min_s, max_s = raw_scores.min(), raw_scores.max()
        if max_s == min_s:
            scores = np.zeros_like(raw_scores)
        else:
            scores = 1 - (raw_scores - min_s) / (max_s - min_s)
        return labels, scores

    def save(self, path: str = MODEL_PATH):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self.model, path)
        logger.info(f"Isolation Forest saved → {path}")

    def load(self, path: str = MODEL_PATH) -> "IsolationForestDetector":
        self.model = joblib.load(path)
        logger.info(f"Isolation Forest loaded from {path}")
        return self

    @classmethod
    def load_or_train(cls, X: pd.DataFrame, path: str = MODEL_PATH) -> "IsolationForestDetector":
        detector = cls()
        if os.path.exists(path):
            detector.load(path)
        else:
            detector.train(X)
            detector.save(path)
        return detector
