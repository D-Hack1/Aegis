import pytest
import numpy as np
import pandas as pd
from features.schema import FEATURE_COLUMNS
from ml.inference import infer

# Example feature row containing the right columns
mock_feature_row = {col: 0.0 for col in FEATURE_COLUMNS}
mock_feature_row["quic_pkt_size_mean"] = 0.0
mock_feature_row["quic_pkt_size_std"] = 0.0
mock_feature_row["quic_0rtt"] = 0

def test_infer_schema():
    """Test that the infer function returns the expected schema."""
    result = infer(mock_feature_row)
    
    assert isinstance(result, dict)
    assert "threat_class" in result
    assert "confidence" in result
    assert "anomaly_score" in result
    assert "evidence_features" in result
    
    assert isinstance(result["threat_class"], str)
    assert isinstance(result["confidence"], float)
    assert isinstance(result["anomaly_score"], float)
    assert isinstance(result["evidence_features"], list)
