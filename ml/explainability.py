from dataclasses import asdict, is_dataclass
import math
from numbers import Integral

import numpy as np
import pandas as pd

from features.schema import FEATURE_COLUMNS


FEATURE_LABELS = {
    "packets_per_sec": "High packet rate",
    "bytes_per_sec": "High traffic volume",
    "outbound_inbound_ratio": "High outbound traffic ratio",
    "orig_bytes": "Large originator byte volume",
    "resp_bytes": "Large responder byte volume",
    "orig_pkts": "Many originator packets",
    "resp_pkts": "Many responder packets",
    "fan_out": "Connections to many destinations",
    "fan_in": "Many sources contacting this destination",
    "unique_dst_ips": "Many destination IPs contacted",
    "unique_dst_ports": "Many destination ports contacted",
    "iat_mean": "Average connection interval",
    "iat_std": "Variable connection timing",
    "iat_min": "Short connection interval",
    "iat_max": "Long connection interval",
    "connection_frequency": "Frequent connections from source",
    "src_ip_entropy": "Diverse destination IP activity",
    "periodicity_score": "Regular connection timing",
    "dns_query_entropy": "High DNS query entropy",
    "domain_length_mean": "Long DNS domain names",
    "domain_length_max": "Very long DNS domain name",
    "subdomain_count": "Many DNS subdomains",
    "dns_record_type_a_ratio": "High A-record query ratio",
    "dns_record_type_txt_ratio": "High TXT-record query ratio",
    "dns_query_count": "Frequent DNS queries",
    "tls_version": "TLS version",
    "cipher_suite_enc": "Unusual TLS cipher suite",
    "is_tls": "TLS traffic detected",
    "ja4_hash_enc": "Unusual JA4 fingerprint",
    "is_quic": "QUIC traffic detected",
    "quic_0rtt": "QUIC 0-RTT activity",
    "quic_pkt_size_mean": "Large QUIC packet size",
    "quic_pkt_size_std": "Irregular QUIC packet sizing",
    "src_port": "Source port",
    "dst_port": "Destination port",
    "duration": "Connection duration",
}


def feature_label(feature_name):
    """Return a readable label without failing on future schema features."""
    return FEATURE_LABELS.get(feature_name, feature_name)


def format_evidence(evidence):
    """Format structured SHAP evidence without making causal claims."""
    value = evidence["value"]
    if evidence["feature"] in {"is_tls", "is_quic", "quic_0rtt"} and value:
        text = f"{evidence['label']}"
    elif isinstance(value, (int, float, np.number)):
        text = f"{evidence['label']}: {float(value):.4g}"
    else:
        text = f"{evidence['label']}: {value}"
    return f"{text} ({evidence['direction']} prediction)"


class ThreatExplainer:
    """Explain one model-ready feature row with an injected XGBoost-compatible model."""

    def __init__(self, model, feature_names=None, class_mapping=None, explainer=None):
        self.model = model
        self.feature_names = tuple(feature_names or FEATURE_COLUMNS)
        if self.feature_names != tuple(FEATURE_COLUMNS):
            raise ValueError("feature_names must match features.schema.FEATURE_COLUMNS exactly")
        if len(set(self.feature_names)) != len(self.feature_names):
            raise ValueError("feature_names contains duplicate feature names")
        self.class_mapping = class_mapping

        if explainer is None:
            import shap

            explainer = shap.TreeExplainer(model)
        self.explainer = explainer

    def explain(self, feature_row, threat_class=None, top_k=5):
        """Return top SHAP contributions for one row in schema model-feature order."""
        if not isinstance(top_k, Integral) or top_k <= 0:
            raise ValueError("top_k must be a positive integer")

        model_row = self._model_row(feature_row)
        shap_values = self._normalise_shap_values(self.explainer.shap_values(model_row), threat_class)
        ranked = sorted(
            enumerate(shap_values), key=lambda item: (-abs(item[1]), item[0])
        )[: min(top_k, len(self.feature_names))]
        values = model_row.iloc[0]
        return [
            {
                "feature": self.feature_names[index],
                "label": feature_label(self.feature_names[index]),
                "value": values.iloc[index],
                "shap_value": float(shap_value),
                "direction": "supports" if shap_value >= 0 else "opposes",
            }
            for index, shap_value in ranked
        ]

    def _model_row(self, feature_row):
        if isinstance(feature_row, pd.DataFrame):
            if len(feature_row) != 1:
                raise ValueError("feature_row DataFrame must contain exactly one row")
            if feature_row.columns.duplicated().any():
                raise ValueError("feature_row contains duplicate feature names")
            values = feature_row.iloc[0].to_dict()
        elif isinstance(feature_row, pd.Series):
            if feature_row.index.duplicated().any():
                raise ValueError("feature_row contains duplicate feature names")
            values = feature_row.to_dict()
        elif is_dataclass(feature_row):
            values = asdict(feature_row)
        elif isinstance(feature_row, dict):
            values = feature_row
        else:
            raise TypeError("feature_row must be a dict, pandas Series/DataFrame, or FeatureRow")

        missing = [name for name in self.feature_names if name not in values]
        if missing:
            raise ValueError(f"feature_row is missing model features: {', '.join(missing)}")

        ordered = []
        for name in self.feature_names:
            value = values[name]
            if isinstance(value, bool):
                value = int(value)
            try:
                number = float(value)
            except (TypeError, ValueError):
                raise ValueError(f"feature_row has a malformed model value: {name}") from None
            if not math.isfinite(number):
                raise ValueError(f"feature_row has a non-finite model value: {name}")
            ordered.append(number)
        return pd.DataFrame([ordered], columns=self.feature_names)

    def _normalise_shap_values(self, raw_values, threat_class):
        values = raw_values.values if hasattr(raw_values, "values") else raw_values
        if isinstance(values, (list, tuple)):
            return self._select_class_values(values, threat_class)

        array = np.asarray(values)
        if array.ndim == 1:
            return self._validate_vector(array)
        if array.ndim == 2:
            if array.shape == (1, len(self.feature_names)):
                return self._validate_vector(array[0])
            raise ValueError("ambiguous SHAP output shape; provide a class mapping for multiclass output")
        if array.ndim == 3:
            if array.shape[0] == 1 and array.shape[1] == len(self.feature_names):
                class_index = self._resolve_class_index(threat_class, array.shape[2])
                return self._validate_vector(array[0, :, class_index])
            if array.shape[1] == 1 and array.shape[2] == len(self.feature_names):
                class_index = self._resolve_class_index(threat_class, array.shape[0])
                return self._validate_vector(array[class_index, 0, :])
        raise ValueError("unsupported SHAP output shape")

    def _select_class_values(self, class_values, threat_class):
        if len(class_values) == 1:
            values = np.asarray(class_values[0])
            if values.shape == (1, len(self.feature_names)):
                return self._validate_vector(values[0])
            if values.shape == (len(self.feature_names),):
                return self._validate_vector(values)
            raise ValueError("unsupported SHAP output shape")

        class_index = self._resolve_class_index(threat_class, len(class_values))
        values = np.asarray(class_values[class_index])
        if values.shape == (1, len(self.feature_names)):
            return self._validate_vector(values[0])
        if values.shape == (len(self.feature_names),):
            return self._validate_vector(values)
        raise ValueError("unsupported SHAP output shape")

    def _resolve_class_index(self, threat_class, class_count):
        if isinstance(threat_class, Integral):
            class_index = int(threat_class)
        elif threat_class is not None and self.class_mapping is not None:
            if threat_class not in self.class_mapping:
                raise ValueError(f"threat_class is not in the supplied class mapping: {threat_class}")
            class_index = self.class_mapping[threat_class]
        else:
            raise ValueError("multiclass SHAP output requires a class index or supplied class mapping")
        if not isinstance(class_index, Integral) or not 0 <= class_index < class_count:
            raise ValueError("threat_class does not resolve to a valid class index")
        return int(class_index)

    def _validate_vector(self, values):
        vector = np.asarray(values, dtype=float)
        if vector.shape != (len(self.feature_names),):
            raise ValueError("SHAP output does not match FEATURE_COLUMNS length")
        if not np.isfinite(vector).all():
            raise ValueError("SHAP output contains NaN or infinity")
        return vector
