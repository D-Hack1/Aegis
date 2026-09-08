# Inference Output Schema

The `infer` function in `ml/inference.py` returns a dictionary describing the threat classification and anomaly detection results for a given flow.

**Ebin:** The FastAPI `/infer` endpoint should return this exact schema.

## Example JSON Response

```json
{
  "threat_class": "c2_beaconing",
  "confidence": 0.985,
  "anomaly_score": 0.421,
  "evidence_features": [
    "Repeated communication at fixed intervals",
    "Single source contacted many ports or hosts"
  ]
}
```

## Fields

| Field | Type | Description |
|---|---|---|
| `threat_class` | `string` | The predicted attack class. Can be one of: `"benign"`, `"ddos"`, `"c2_beaconing"`, `"dns_anomaly"`, `"malware_tls"`, `"port_scan"`, `"exfiltration"`. If the XGBoost model confidence is below `THRESHOLD` (default 0.50), this will be `"unknown_anomaly"`. |
| `confidence` | `float` | The probability of the predicted `threat_class` (0.0 to 1.0). For `"unknown_anomaly"`, this is the max probability of any single known class. |
| `anomaly_score` | `float` | The Isolation Forest anomaly score. Higher values indicate more anomalous traffic compared to the baseline benign distribution. |
| `evidence_features` | `array[string]` | A list of human-readable strings explaining the most important features that led to the decision (e.g. from SHAP values). Empty by default until Gowri's SHAP module integrates this. |
