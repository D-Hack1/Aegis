import math

import numpy as np
import pandas as pd
import pytest

from features.schema import FEATURE_COLUMNS
from ml.explainability import FEATURE_LABELS, ThreatExplainer, feature_label, format_evidence


class FakeExplainer:
    def __init__(self, values):
        self.values = values
        self.last_row = None

    def shap_values(self, feature_row):
        self.last_row = feature_row
        return self.values


def feature_row():
    return {feature: index + 1 for index, feature in enumerate(FEATURE_COLUMNS)}


def test_feature_labels_cover_model_features_and_fallback():
    assert set(FEATURE_COLUMNS) <= set(FEATURE_LABELS)
    assert feature_label("packets_per_sec") == "High packet rate"
    assert feature_label("future_feature") == "future_feature"


def test_ranks_signed_shap_values_and_respects_top_k():
    values = np.zeros(len(FEATURE_COLUMNS))
    values[:3] = [0.2, -1.5, 0.7]
    explainer = ThreatExplainer(object(), explainer=FakeExplainer(values))

    evidence = explainer.explain(feature_row(), top_k=3)

    assert [item["feature"] for item in evidence] == [
        FEATURE_COLUMNS[1], FEATURE_COLUMNS[2], FEATURE_COLUMNS[0]
    ]
    assert [item["direction"] for item in evidence] == ["opposes", "supports", "supports"]
    assert evidence[0]["shap_value"] == -1.5
    assert len(explainer.explain(feature_row())) == 5
    assert len(explainer.explain(feature_row(), top_k=999)) == len(FEATURE_COLUMNS)
    with pytest.raises(ValueError, match="top_k"):
        explainer.explain(feature_row(), top_k=0)


def test_input_is_reordered_to_schema_feature_order():
    row = feature_row()
    scrambled = dict(reversed(list(row.items())))
    fake = FakeExplainer(np.zeros(len(FEATURE_COLUMNS)))

    ThreatExplainer(object(), explainer=fake).explain(scrambled)

    assert list(fake.last_row.columns) == FEATURE_COLUMNS
    assert fake.last_row.iloc[0].tolist() == [float(row[name]) for name in FEATURE_COLUMNS]


def test_invalid_model_input_is_rejected():
    row = feature_row()
    row.pop(FEATURE_COLUMNS[0])
    explainer = ThreatExplainer(object(), explainer=FakeExplainer(np.zeros(len(FEATURE_COLUMNS))))

    with pytest.raises(ValueError, match="missing model features"):
        explainer.explain(row)
    with pytest.raises(ValueError, match="non-finite"):
        explainer.explain({**feature_row(), FEATURE_COLUMNS[0]: math.nan})


def test_supported_shap_shapes_and_multiclass_selection():
    row = feature_row()
    vector = np.arange(len(FEATURE_COLUMNS), dtype=float)
    two_dimensional = ThreatExplainer(object(), explainer=FakeExplainer([vector])).explain(row)
    assert two_dimensional[0]["feature"] == FEATURE_COLUMNS[-1]

    multiclass = np.stack([vector, -vector], axis=1)[np.newaxis, :, :]
    explainer = ThreatExplainer(
        object(), class_mapping={"benign": 0, "ddos": 1}, explainer=FakeExplainer(multiclass)
    )
    assert explainer.explain(row, threat_class="ddos")[0]["shap_value"] < 0
    with pytest.raises(ValueError, match="multiclass"):
        ThreatExplainer(object(), explainer=FakeExplainer(multiclass)).explain(row)


def test_structured_and_human_readable_evidence():
    values = np.zeros(len(FEATURE_COLUMNS))
    values[FEATURE_COLUMNS.index("is_quic")] = 1.0
    row = feature_row()
    row["is_quic"] = 1
    evidence = ThreatExplainer(object(), explainer=FakeExplainer(values)).explain(row, top_k=1)[0]

    assert set(evidence) == {"feature", "label", "value", "shap_value", "direction"}
    assert evidence["label"] == "QUIC traffic detected"
    assert "QUIC traffic detected" in format_evidence(evidence)


def test_dataframe_duplicate_columns_and_nonfinite_shap_are_rejected():
    row = feature_row()
    duplicate = pd.DataFrame([[*row.values(), 1]], columns=[*FEATURE_COLUMNS, FEATURE_COLUMNS[0]])
    explainer = ThreatExplainer(object(), explainer=FakeExplainer(np.zeros(len(FEATURE_COLUMNS))))

    with pytest.raises(ValueError, match="duplicate"):
        explainer.explain(duplicate)
    with pytest.raises(ValueError, match="NaN"):
        ThreatExplainer(object(), explainer=FakeExplainer(np.full(len(FEATURE_COLUMNS), np.nan))).explain(row)


def test_all_six_attack_classes_use_test_only_multiclass_mapping():
    attack_classes = ["syn_flood", "udp_flood", "port_scan", "c2_beacon", "dns_anomaly", "data_exfil"]
    class_mapping = {name: index for index, name in enumerate(attack_classes)}
    class_values = np.zeros((1, len(FEATURE_COLUMNS), len(attack_classes)))
    for index in range(len(attack_classes)):
        class_values[0, index, index] = index + 1
    explainer = ThreatExplainer(
        object(), class_mapping=class_mapping, explainer=FakeExplainer(class_values)
    )

    for index, attack_class in enumerate(attack_classes):
        evidence = explainer.explain(feature_row(), threat_class=attack_class, top_k=1)
        assert evidence[0]["feature"] == FEATURE_COLUMNS[index]
        assert set(evidence[0]) == {"feature", "label", "value", "shap_value", "direction"}


def test_anomalous_feature_ranking_is_non_causal_and_structured():
    row = feature_row()
    row["packets_per_sec"] = 100_000
    row["fan_out"] = 5_000
    values = np.zeros(len(FEATURE_COLUMNS))
    values[FEATURE_COLUMNS.index("fan_out")] = 4.0
    values[FEATURE_COLUMNS.index("packets_per_sec")] = 2.0

    evidence = ThreatExplainer(object(), explainer=FakeExplainer(values)).explain(row, top_k=2)
    wording = format_evidence(evidence[0]).lower()

    assert evidence[0]["feature"] == "fan_out"
    assert evidence[0]["label"] == "Connections to many destinations"
    assert "malicious" not in wording and "proves" not in wording
    assert evidence[0]["direction"] == "supports"


def test_real_treeexplainer_smoke_test():
    from xgboost import XGBClassifier

    feature_count = len(FEATURE_COLUMNS)
    dataset = np.vstack(
        [
            np.zeros(feature_count),
            np.full(feature_count, 0.1),
            np.ones(feature_count),
            np.full(feature_count, 0.9),
        ]
    )
    model = XGBClassifier(
        n_estimators=2, max_depth=1, learning_rate=1.0, n_jobs=1, random_state=0,
        eval_metric="logloss",
    ).fit(dataset, np.array([0, 0, 1, 1]))

    explainer = ThreatExplainer(model)
    evidence = explainer.explain(dict(zip(FEATURE_COLUMNS, dataset[2])), top_k=3)

    assert type(explainer.explainer).__name__ == "TreeExplainer"
    assert len(evidence) == 3
    assert all(np.isfinite(item["shap_value"]) for item in evidence)
