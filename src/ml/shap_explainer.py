"""
SHAP Explainer wrapper for ML model interpretability.
Produces waterfall values and feature importance for each prediction.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Any
from loguru import logger

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    logger.warning("SHAP not installed. Explainability features will be limited.")

from src.ml.features import FEATURE_NAMES


class ShapExplainer:
    def __init__(self):
        self.explainer = None
        self.model_type = None

    def setup(self, model: Any, X_background: pd.DataFrame, model_type: str = "tree"):
        """
        Initialise the SHAP explainer.
        model_type: 'tree' (RandomForest/IsolationForest) or 'linear'
        """
        if not SHAP_AVAILABLE:
            return self

        self.model_type = model_type
        X_bg = X_background[FEATURE_NAMES]

        try:
            if model_type == "tree":
                self.explainer = shap.TreeExplainer(model, X_bg)
            else:
                self.explainer = shap.Explainer(model, X_bg)
            logger.info(f"SHAP {model_type} explainer initialised.")
        except Exception as e:
            logger.warning(f"Could not set up SHAP explainer: {e}")

        return self

    def explain_single(self, X_row: pd.DataFrame) -> Dict[str, Any]:
        """
        Explain a single prediction.
        Returns dict with feature_names, shap_values, base_value.
        """
        if not SHAP_AVAILABLE or self.explainer is None:
            return self._fallback_explanation(X_row)

        try:
            row = X_row[FEATURE_NAMES]
            shap_vals = self.explainer.shap_values(row)

            # For classifiers (RF): shap_vals is list of arrays per class
            # Pick first output class or the anomaly class
            if isinstance(shap_vals, list):
                vals = shap_vals[0][0] if len(shap_vals) > 0 else shap_vals[0]
            else:
                vals = shap_vals[0] if shap_vals.ndim > 1 else shap_vals

            base_value = (
                float(self.explainer.expected_value[0])
                if hasattr(self.explainer.expected_value, "__len__")
                else float(self.explainer.expected_value)
            )

            feature_contributions = {
                name: float(val) for name, val in zip(FEATURE_NAMES, vals)
            }
            sorted_contributions = dict(
                sorted(feature_contributions.items(), key=lambda x: abs(x[1]), reverse=True)
            )

            return {
                "feature_names": FEATURE_NAMES,
                "shap_values": list(vals.astype(float)),
                "base_value": base_value,
                "feature_contributions": sorted_contributions,
                "top_features": list(sorted_contributions.keys())[:5],
            }

        except Exception as e:
            logger.warning(f"SHAP explanation failed: {e}")
            return self._fallback_explanation(X_row)

    def _fallback_explanation(self, X_row: pd.DataFrame) -> Dict[str, Any]:
        """Simple feature-value-based explanation when SHAP is unavailable."""
        row = X_row[FEATURE_NAMES].iloc[0]
        contributions = {}

        if row.get("failed_attempts", 0) > 3:
            contributions["failed_attempts"] = 0.35
        if row.get("is_anomalous_hour", 0) == 1:
            contributions["is_anomalous_hour"] = 0.30
        if row.get("location_risk", 0) > 0.5:
            contributions["location_risk"] = 0.25
        if row.get("is_suspicious_ip", 0) == 1:
            contributions["is_suspicious_ip"] = 0.20
        if row.get("bytes_transferred", 0) > 100000:
            contributions["bytes_transferred"] = 0.15

        # Fill remaining features with small values
        for feat in FEATURE_NAMES:
            if feat not in contributions:
                contributions[feat] = float(row.get(feat, 0)) * 0.01

        sorted_c = dict(sorted(contributions.items(), key=lambda x: abs(x[1]), reverse=True))
        return {
            "feature_names": FEATURE_NAMES,
            "shap_values": [contributions.get(f, 0.0) for f in FEATURE_NAMES],
            "base_value": 0.0,
            "feature_contributions": sorted_c,
            "top_features": list(sorted_c.keys())[:5],
        }

    def bulk_explain(self, X: pd.DataFrame) -> List[Dict[str, Any]]:
        """Explain multiple predictions."""
        results = []
        for i in range(len(X)):
            row = X.iloc[[i]]
            results.append(self.explain_single(row))
        return results
