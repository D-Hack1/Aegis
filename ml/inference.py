import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from features.schema import FEATURE_COLUMNS, from_dict
from ml.train import preprocess
from ml.explainability import configure_explainer, explain

logger = logging.getLogger("ml.inference")

# Threshold for threat classification confidence
THRESHOLD = 0.50

_ML_DIR = Path(__file__).resolve().parent

# Load models and encoders lazily
_xgb_model = None
_iso_forest = None
_label_encoder = None
_encoders = None
_iso_encoders = None
_explainer_configured = False

def _load_models():
    global _xgb_model, _iso_forest, _label_encoder, _encoders, _iso_encoders, _explainer_configured
    if _xgb_model is None:
        _xgb_model = joblib.load(_ML_DIR / "model.joblib")
    if _iso_forest is None:
        # iso_forest.joblib stores {"model", "threshold", "feature_columns", ...},
        # not the IsolationForest itself — calling .score_samples() on the raw
        # dict raises AttributeError.
        iso_data = joblib.load(_ML_DIR / "iso_forest.joblib")
        _iso_forest = iso_data["model"]
    if _label_encoder is None:
        _label_encoder = joblib.load(_ML_DIR / "label_encoder.joblib")
    if _encoders is None:
        _encoders = joblib.load(_ML_DIR / "encoders.joblib")
    if _iso_encoders is None:
        # train_isolation_forest.py fits and saves separate encoders for the
        # Isolation Forest's own preprocessing. Fall back to the XGBoost
        # encoders (not ideal, but not a crash) if that file hasn't been
        # generated yet.
        iso_encoders_path = _ML_DIR / "iso_forest_encoders.joblib"
        if iso_encoders_path.exists():
            _iso_encoders = joblib.load(iso_encoders_path)
        else:
            logger.warning(
                "%s not found — falling back to the XGBoost encoders for "
                "Isolation Forest preprocessing. Run "
                "ml/train_isolation_forest.py to generate dedicated encoders.",
                iso_encoders_path,
            )
            _iso_encoders = _encoders
    if not _explainer_configured:
        configure_explainer(
            _xgb_model,
            class_mapping={name: i for i, name in enumerate(_label_encoder.classes_)},
        )
        _explainer_configured = True

def infer(feature_row: dict) -> dict:
    """
    Run inference on a single feature row.
    Combines XGBoost classification and Isolation Forest anomaly detection.
    """
    _load_models()

    # Convert to DataFrame
    df = pd.DataFrame([feature_row])

    # Preprocess for XGBoost
    X, _ = preprocess(df, _encoders, fit=False)
    features = X.values

    # XGBoost Prediction
    probs = _xgb_model.predict_proba(features)[0]
    max_idx = np.argmax(probs)
    threat_class = _label_encoder.inverse_transform([max_idx])[0]
    confidence = float(np.max(probs))

    # Isolation Forest Anomaly Score — preprocessed with its own encoders
    X_iso, _ = preprocess(df, _iso_encoders, fit=False)
    anomaly_score = float(-_iso_forest.score_samples(X_iso.values)[0])

    final_class = threat_class if confidence > THRESHOLD else "unknown_anomaly"

    # SHAP evidence
    try:
        evidence_features = explain(feature_row, threat_class)
    except Exception as e:
        logger.error("SHAP explainability failed: %s", e)
        evidence_features = []

    return {
        "threat_class": final_class,
        "confidence": confidence,
        "anomaly_score": anomaly_score,
        "evidence_features": evidence_features
    }
