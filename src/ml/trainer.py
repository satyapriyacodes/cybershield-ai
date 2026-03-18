"""
Model Training Pipeline
Loads data → engineers features → trains both models → saves to models/
Run: python src/ml/trainer.py
"""

import os
import sys
import pandas as pd
import numpy as np
from loguru import logger

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.data.log_generator import generate_logs
from src.ml.features import engineer_features_from_df, FEATURE_NAMES
from src.ml.isolation_forest import IsolationForestDetector
from src.ml.random_forest import RandomForestDetector


def load_data(path: str = "data/security_logs.csv") -> pd.DataFrame:
    if not os.path.exists(path):
        logger.info("Log file not found, generating synthetic data...")
        return generate_logs()
    df = pd.read_csv(path)
    logger.info(f"Loaded {len(df)} log entries from {path}")
    return df


def train_pipeline():
    os.makedirs("models", exist_ok=True)

    # 1. Load data
    df = load_data()

    # 2. Feature engineering
    logger.info("Engineering features...")
    X = engineer_features_from_df(df)

    # Ensure labels exist
    if "anomaly_label" not in df.columns:
        df["anomaly_label"] = "normal"
    y = df["anomaly_label"].fillna("normal")

    logger.info(f"Feature matrix: {X.shape}")
    logger.info(f"Label distribution:\n{y.value_counts()}")

    # 3. Isolation Forest (unsupervised)
    logger.info("Training Isolation Forest (unsupervised)...")
    if_detector = IsolationForestDetector(contamination=0.1)
    if_detector.train(X)
    if_detector.save()

    # Evaluate
    labels, scores = if_detector.predict(X)
    n_anomalies = (labels == -1).sum()
    logger.info(f"Isolation Forest flagged {n_anomalies}/{len(df)} entries as anomalous")

    # 4. Random Forest (supervised)
    logger.info("Training Random Forest (supervised)...")
    rf_detector = RandomForestDetector()
    rf_detector.train(X, y)
    rf_detector.save()

    importances = rf_detector.feature_importances()
    logger.info("Feature importances (top 5):")
    for feat, imp in sorted(importances.items(), key=lambda x: x[1], reverse=True)[:5]:
        logger.info(f"  {feat}: {imp:.4f}")

    logger.info("✅ All models trained and saved to models/")
    return if_detector, rf_detector


if __name__ == "__main__":
    train_pipeline()
