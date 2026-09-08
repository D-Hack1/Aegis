import joblib
import numpy as np
import pandas as pd
from features.schema import FEATURE_COLUMNS, from_dict
from ml.train import preprocess

# Threshold for threat classification confidence
THRESHOLD = 0.50

# Load models and encoders lazily
_xgb_model = None
_iso_forest = None
_label_encoder = None
_encoders = None

def _load_models():
    global _xgb_model, _iso_forest, _label_encoder, _encoders
    if _xgb_model is None:
        _xgb_model = joblib.load("ml/model.joblib")
    if _iso_forest is None:
        _iso_forest = joblib.load("ml/iso_forest.joblib")
    if _label_encoder is None:
        _label_encoder = joblib.load("ml/label_encoder.joblib")
    if _encoders is None:
        _encoders = joblib.load("ml/encoders.joblib")

def infer(feature_row: dict) -> dict:
    """
    Run inference on a single feature row.
    Combines XGBoost classification and Isolation Forest anomaly detection.
    """
    _load_models()

    # Convert to DataFrame
    df = pd.DataFrame([feature_row])
    
    # Preprocess
    X, _ = preprocess(df, _encoders, fit=False)
    features = X.values
    
    # XGBoost Prediction
    probs = _xgb_model.predict_proba(features)[0]
    max_idx = np.argmax(probs)
    threat_class = _label_encoder.inverse_transform([max_idx])[0]
    confidence = float(np.max(probs))
    
    # Isolation Forest Anomaly Score
    anomaly_score = float(-_iso_forest.score_samples(features)[0])
    
    # SHAP Evidence (Integration point for Gowri)
    evidence_features = []
    
    return {
        "threat_class": threat_class if confidence > THRESHOLD else "unknown_anomaly",
        "confidence": confidence,
        "anomaly_score": anomaly_score,
        "evidence_features": evidence_features
    }
