"""
ml/train.py — Aegis NIDS training pipeline.

What this file does, end to end:
─────────────────────────────────────────────────────────────────────────────
1. LOAD
   Reads every Parquet file in data/features/.
   Each file was produced by features/pipeline.py --scenario-name <name>.
   The scenario name (e.g. "syn_flood") is matched against data/labels/*.json
   to attach a threat class label to every row in that file.

2. SYNTHETIC DATA FALLBACK
   If no real Parquet files exist yet (Docker lab not run), a synthetic
   dataset is generated with realistic feature distributions per threat class.
   This lets the full pipeline be tested before any real captures exist.
   When real Parquet arrives, nothing changes — the synthetic path is skipped
   automatically.

3. PREPROCESS
   - Cap periodicity_score at 100 (avoids 1e9 values when IAT std ≈ 0)
   - Cast boolean columns to int (0/1)
   - Fill missing values with 0 for optional feature groups (DNS, TLS, QUIC)
   - Select exactly FEATURE_COLUMNS — no metadata, no raw strings
   - Fit frequency encoders for ja4_hash and cipher_suite on training data only
     and persist them so inference uses the same mapping

4. SPLIT
   Scenario-level split, not row-level.
   All rows from a scenario go entirely to train OR val OR test — never mixed.
   This prevents leakage where the same attack run appears in both train and test.
   Split: 70% train / 15% val / 15% test, stratified by class where possible.

5. CLASS IMBALANCE
   A SYN flood generates thousands of flows; a C2 beacon generates ~one per minute.
   Handled with XGBoost sample_weight (computed_sample_weight) so the model
   does not just learn "everything is ddos".

6. TRAIN
   XGBoost multi-class classifier.
   Optuna tunes: n_estimators, max_depth, learning_rate, min_child_weight.
   Best model is re-fit on train+val combined before final test evaluation.

7. EVALUATE
   Per-class precision, recall, F1 on the held-out test set.
   Confusion matrix saved as ml/confusion_matrix.png.
   Classification report saved as ml/classification_report.txt.

8. SAVE
   ml/model.joblib        — trained XGBoost model
   ml/label_encoder.joblib — LabelEncoder (class index ↔ class name)
   ml/encoders.joblib     — ja4_hash and cipher_suite frequency mappings
   ml/optuna_study.pkl    — full Optuna study (shows judges the tuning)

Usage:
    python3 -m ml.train
    python3 -m ml.train --features-dir data/features --labels-dir data/labels
    python3 -m ml.train --synthetic   # force synthetic data even if Parquet exists
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import argparse
import json
import pickle
import random
import warnings
from collections import Counter, defaultdict
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

# ── optional heavy deps — imported lazily so import errors are clear ──────
def _require(module_name: str):
    import importlib
    try:
        return importlib.import_module(module_name)
    except ImportError as exc:
        raise ImportError(
            f"Required package not installed: {module_name}\n"
            f"Run: pip install {module_name.split('.')[0]}"
        ) from exc


# ── project imports ───────────────────────────────────────────────────────
from features.schema import (
    BOOL_COLUMNS,
    FEATURE_COLUMNS,
    FILL_ZERO_COLUMNS,
)

# ── constants ─────────────────────────────────────────────────────────────

LABELS_DIR   = Path("data/labels")
FEATURES_DIR = Path("data/features")
ML_DIR       = Path("ml")

# Hard cap on periodicity_score — raw value can reach 1e9 when IAT std ≈ 0.
# Values above 100 all mean "perfectly regular timing"; capping preserves the
# signal without letting a single feature dominate the tree splits.
PERIODICITY_CAP = 100.0

# Ordered list of class names — this is the label taxonomy for the project.
# The order here defines the integer encoding used by XGBoost and LabelEncoder.
CLASS_NAMES: list[str] = [
    "benign",
    "ddos",
    "c2_beaconing",
    "dns_anomaly",
    "malware_tls",
    "port_scan",
    "exfiltration",
]

# Frequency-encoding cutoff: top-N most common values get an integer index;
# everything else maps to 0 ("rare / unknown").
TOP_N_CATEGORIES = 50

# Random seed — fixed so results are reproducible between runs.
RANDOM_SEED = 42

# Optuna: number of hyperparameter search trials.
OPTUNA_TRIALS = 20


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1 — LABEL LOADING
# ═══════════════════════════════════════════════════════════════════════════

def load_labels(labels_dir: Path = LABELS_DIR) -> dict[str, str]:
    """
    Read every JSON file in data/labels/ and return a mapping:
        scenario_name → attack_class

    For example:
        {"syn_flood": "ddos", "c2_beacon": "c2_beaconing", "benign": "benign", ...}

    This is the single source of truth for what label to attach to each
    Parquet file. A Parquet file named syn_flood.parquet gets label "ddos".
    """
    mapping: dict[str, str] = {}
    for path in sorted(labels_dir.glob("*.json")):
        with path.open() as f:
            data = json.load(f)
        scenario    = data["scenario"]
        attack_class = data["attack_class"]
        if attack_class not in CLASS_NAMES:
            warnings.warn(
                f"Label file {path.name} has unknown attack_class={attack_class!r}. "
                f"Known classes: {CLASS_NAMES}"
            )
        mapping[scenario] = attack_class
    return mapping


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2 — PARQUET LOADING
# ═══════════════════════════════════════════════════════════════════════════

def load_parquet_files(
    features_dir: Path,
    label_map: dict[str, str],
) -> pd.DataFrame:
    """
    Load all Parquet files from features_dir, attach labels, and concatenate.

    Each file is named <scenario_name>.parquet.
    The scenario name is looked up in label_map to get the attack_class.
    Files with no matching label are skipped with a warning.

    Returns a DataFrame with all FEATURE_COLUMNS plus:
        label    — the threat class string (e.g. "ddos")
        scenario — the scenario name (used for scenario-level splitting)
    """
    frames: list[pd.DataFrame] = []

    parquet_files = sorted(features_dir.glob("*.parquet"))
    if not parquet_files:
        return pd.DataFrame()

    for path in parquet_files:
        scenario = path.stem   # "syn_flood.parquet" → "syn_flood"
        if scenario not in label_map:
            warnings.warn(
                f"No label found for {path.name} — skipping. "
                f"Add {scenario}.json to {LABELS_DIR}."
            )
            continue

        df = pd.read_parquet(path)
        df["label"]    = label_map[scenario]
        df["scenario"] = scenario
        frames.append(df)
        print(f"  Loaded {len(df):>6} rows from {path.name}  →  label={label_map[scenario]}")

    if not frames:
        return pd.DataFrame()

    combined = pd.concat(frames, ignore_index=True)
    print(f"\n  Total: {len(combined)} rows, {combined['label'].value_counts().to_dict()}")
    return combined


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3 — SYNTHETIC DATA FALLBACK
# ═══════════════════════════════════════════════════════════════════════════

def _rng_col(rng: np.random.Generator, low: float, high: float, n: int) -> np.ndarray:
    """Uniform random column, clipped to [0, ∞)."""
    return np.clip(rng.uniform(low, high, n), 0, None)


def _norm_col(rng: np.random.Generator, mean: float, std: float, n: int) -> np.ndarray:
    """Normal random column, clipped to [0, ∞)."""
    return np.clip(rng.normal(mean, std, n), 0, None)


def generate_synthetic_data(n_per_class: int = 500, seed: int = RANDOM_SEED) -> pd.DataFrame:
    """
    Generate a synthetic dataset that matches FEATURE_COLUMNS exactly.

    Each threat class gets n_per_class rows with feature distributions that
    are realistic for that threat type. This is not training data quality —
    it is development/testing data so the full pipeline can be built and
    verified before real Parquet files exist.

    The distributions are derived from known attack behaviour:

    BENIGN
        Moderate flow rates, balanced outbound/inbound, normal DNS activity,
        low fan-out, irregular IATs (browsing, downloads, DNS).

    DDOS
        Extremely high packet rate, many short flows, high fan-in at victim,
        spoofed sources (high src_ip_entropy from attacker's perspective),
        very low resp_bytes (SYN flood — no handshake completes).

    C2_BEACONING
        Low packet rate, very regular IAT (low iat_std), high periodicity_score,
        low fan-out (always same C2 destination), moderate flow volume.

    DNS_ANOMALY (DGA + DNS tunnel)
        High dns_query_entropy (random-looking domain characters),
        long domain names, high subdomain count, elevated TXT record ratio,
        many DNS queries per window.

    PORT_SCAN
        High unique_dst_ports, high fan_out, many short flows,
        very low bytes per flow (just SYN packets), high connection_frequency.

    EXFILTRATION
        Very high outbound_inbound_ratio, high orig_bytes, low resp_bytes,
        sustained high bytes_per_sec.
    """
    rng = np.random.default_rng(seed)
    frames: list[pd.DataFrame] = []

    # ── class-specific distributions ─────────────────────────────────────
    specs: dict[str, dict] = {
        "benign": {
            "packets_per_sec":         (5,    10),
            "bytes_per_sec":           (1000, 5000),
            "outbound_inbound_ratio":  (0.8,  1.5),
            "orig_bytes":              (2000, 20000),
            "resp_bytes":              (2000, 20000),
            "orig_pkts":               (10,   80),
            "resp_pkts":               (10,   80),
            "fan_out":                 (1,    5),
            "fan_in":                  (1,    3),
            "unique_dst_ips":          (1,    4),
            "unique_dst_ports":        (1,    6),
            "iat_mean":                (5,    30),
            "iat_std":                 (3,    15),
            "iat_min":                 (0.5,  3),
            "iat_max":                 (10,   60),
            "connection_frequency":    (2,    8),
            "src_ip_entropy":          (0.5,  2.0),
            "periodicity_score":       (0.1,  1.0),
            "dns_query_entropy":       (3.0,  4.5),
            "domain_length_mean":      (10,   20),
            "domain_length_max":       (15,   30),
            "subdomain_count":         (1.5,  3.0),
            "dns_record_type_a_ratio": (0.6,  0.9),
            "dns_record_type_txt_ratio":(0.0, 0.05),
            "dns_query_count":         (3,    15),
            "tls_version":             (3,    4),
            "duration":                (1,    30),
        },
        "ddos": {
            "packets_per_sec":         (500,  5000),
            "bytes_per_sec":           (30000, 200000),
            "outbound_inbound_ratio":  (50,   500),
            "orig_bytes":              (40,   200),      # SYN only — tiny
            "resp_bytes":              (0,    5),         # no handshake
            "orig_pkts":               (1,    3),
            "resp_pkts":               (0,    1),
            "fan_out":                 (1,    3),
            "fan_in":                  (50,   500),       # many spoofed sources
            "unique_dst_ips":          (1,    2),
            "unique_dst_ports":        (1,    3),
            "iat_mean":                (0.001, 0.01),
            "iat_std":                 (0.0005, 0.005),
            "iat_min":                 (0.0001, 0.001),
            "iat_max":                 (0.005, 0.02),
            "connection_frequency":    (100,  1000),
            "src_ip_entropy":          (3.5,  5.0),      # many spoofed sources
            "periodicity_score":       (50,   100),
            "dns_query_entropy":       (0,    0.5),
            "domain_length_mean":      (0,    2),
            "domain_length_max":       (0,    2),
            "subdomain_count":         (0,    0.5),
            "dns_record_type_a_ratio": (0,    0.1),
            "dns_record_type_txt_ratio":(0,   0.02),
            "dns_query_count":         (0,    2),
            "tls_version":             (0,    0),
            "duration":                (0.001, 0.05),
        },
        "c2_beaconing": {
            "packets_per_sec":         (0.5,  3),
            "bytes_per_sec":           (50,   500),
            "outbound_inbound_ratio":  (0.5,  2.0),
            "orig_bytes":              (100,  1000),
            "resp_bytes":              (80,   900),
            "orig_pkts":               (3,    15),
            "resp_pkts":               (3,    15),
            "fan_out":                 (1,    2),         # always same C2 dest
            "fan_in":                  (1,    2),
            "unique_dst_ips":          (1,    1),
            "unique_dst_ports":        (1,    2),
            "iat_mean":                (55,   65),        # ~60 second beacon
            "iat_std":                 (0.1,  2.0),       # very regular
            "iat_min":                 (50,   58),
            "iat_max":                 (62,   75),
            "connection_frequency":    (1,    3),
            "src_ip_entropy":          (0,    0.5),       # one destination
            "periodicity_score":       (50,   100),       # high — very regular
            "dns_query_entropy":       (0,    1.0),
            "domain_length_mean":      (5,    15),
            "domain_length_max":       (8,    20),
            "subdomain_count":         (1,    2),
            "dns_record_type_a_ratio": (0.8,  1.0),
            "dns_record_type_txt_ratio":(0,   0.05),
            "dns_query_count":         (0,    3),
            "tls_version":             (3,    4),
            "duration":                (0.5,  5),
        },
        "dns_anomaly": {
            "packets_per_sec":         (2,    10),
            "bytes_per_sec":           (500,  3000),
            "outbound_inbound_ratio":  (1.0,  3.0),
            "orig_bytes":              (500,  5000),
            "resp_bytes":              (200,  4000),
            "orig_pkts":               (5,    30),
            "resp_pkts":               (5,    30),
            "fan_out":                 (1,    3),
            "fan_in":                  (1,    2),
            "unique_dst_ips":          (1,    3),
            "unique_dst_ports":        (1,    2),
            "iat_mean":                (0.5,  3),
            "iat_std":                 (0.2,  2),
            "iat_min":                 (0.1,  0.5),
            "iat_max":                 (2,    8),
            "connection_frequency":    (10,   40),
            "src_ip_entropy":          (0.5,  2.0),
            "periodicity_score":       (0.5,  5.0),
            "dns_query_entropy":       (4.2,  5.0),      # high — DGA/tunnel
            "domain_length_mean":      (30,   60),        # long DGA names
            "domain_length_max":       (50,   80),
            "subdomain_count":         (4,    8),         # many labels in FQDN
            "dns_record_type_a_ratio": (0.1,  0.4),       # low — not normal DNS
            "dns_record_type_txt_ratio":(0.3, 0.8),       # high — tunnel signal
            "dns_query_count":         (30,   100),       # many queries
            "tls_version":             (0,    1),
            "duration":                (0.1,  2),
        },
        "port_scan": {
            "packets_per_sec":         (50,   200),
            "bytes_per_sec":           (2000, 10000),
            "outbound_inbound_ratio":  (10,   100),
            "orig_bytes":              (40,   60),        # just SYN packets
            "resp_bytes":              (0,    20),
            "orig_pkts":               (1,    2),
            "resp_pkts":               (0,    1),
            "fan_out":                 (200,  1024),      # scanning many ports
            "fan_in":                  (1,    2),
            "unique_dst_ips":          (1,    2),
            "unique_dst_ports":        (200,  1024),      # the scan range
            "iat_mean":                (0.005, 0.02),
            "iat_std":                 (0.001, 0.005),
            "iat_min":                 (0.001, 0.005),
            "iat_max":                 (0.01,  0.05),
            "connection_frequency":    (50,   200),
            "src_ip_entropy":          (0,    0.5),       # one target
            "periodicity_score":       (50,   100),
            "dns_query_entropy":       (0,    1.0),
            "domain_length_mean":      (0,    5),
            "domain_length_max":       (0,    5),
            "subdomain_count":         (0,    1),
            "dns_record_type_a_ratio": (0,    0.2),
            "dns_record_type_txt_ratio":(0,   0.02),
            "dns_query_count":         (0,    2),
            "tls_version":             (0,    0),
            "duration":                (0.001, 0.01),
        },
        "exfiltration": {
            "packets_per_sec":         (20,   100),
            "bytes_per_sec":           (50000, 500000),   # high outbound volume
            "outbound_inbound_ratio":  (50,   1000),      # heavily asymmetric
            "orig_bytes":              (100000, 5000000),  # large upload
            "resp_bytes":              (100,  1000),       # tiny ACKs back
            "orig_pkts":               (100,  5000),
            "resp_pkts":               (10,   200),
            "fan_out":                 (1,    3),
            "fan_in":                  (1,    2),
            "unique_dst_ips":          (1,    2),
            "unique_dst_ports":        (1,    2),
            "iat_mean":                (30,   120),
            "iat_std":                 (10,   50),
            "iat_min":                 (5,    20),
            "iat_max":                 (60,   300),
            "connection_frequency":    (1,    5),
            "src_ip_entropy":          (0,    1.0),
            "periodicity_score":       (0.1,  2.0),
            "dns_query_entropy":       (2.0,  3.5),
            "domain_length_mean":      (8,    15),
            "domain_length_max":       (12,   20),
            "subdomain_count":         (1,    3),
            "dns_record_type_a_ratio": (0.5,  0.9),
            "dns_record_type_txt_ratio":(0,   0.1),
            "dns_query_count":         (1,    8),
            "tls_version":             (3,    4),
            "duration":                (30,   600),       # long sustained flows
        },
        "malware_tls": {
            # Malware inside encrypted sessions — metadata only, no payload
            # Distinguishing signals: unusual JA3/JA4, abnormal packet sizes,
            # irregular timing, TLS to non-standard ports
            "packets_per_sec":         (1,    20),
            "bytes_per_sec":           (500,  10000),
            "outbound_inbound_ratio":  (1.0,  4.0),
            "orig_bytes":              (500,  50000),
            "resp_bytes":              (300,  40000),
            "orig_pkts":               (5,    100),
            "resp_pkts":               (5,    100),
            "fan_out":                 (1,    3),
            "fan_in":                  (1,    2),
            "unique_dst_ips":          (1,    3),
            "unique_dst_ports":        (1,    3),
            "iat_mean":                (2,    30),
            "iat_std":                 (1,    15),
            "iat_min":                 (0.5,  5),
            "iat_max":                 (10,   120),
            "connection_frequency":    (1,    10),
            "src_ip_entropy":          (0,    1.5),
            "periodicity_score":       (1,    20),
            "dns_query_entropy":       (0,    2.0),
            "domain_length_mean":      (5,    15),
            "domain_length_max":       (8,    20),
            "subdomain_count":         (1,    3),
            "dns_record_type_a_ratio": (0.5,  0.9),
            "dns_record_type_txt_ratio":(0,   0.1),
            "dns_query_count":         (0,    5),
            "tls_version":             (1,    3),          # older TLS = suspicious
            "duration":                (5,    120),
        },
    }

    for label, dist in specs.items():
        n = n_per_class
        rows: dict[str, np.ndarray] = {}

        for col, (lo, hi) in dist.items():
            rows[col] = _rng_col(rng, lo, hi, n)

        # ── integer columns ────────────────────────────────────────────
        for col in ["orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
                    "unique_dst_ips", "unique_dst_ports", "dns_query_count"]:
            rows[col] = rows[col].astype(int)

        # ── port columns ───────────────────────────────────────────────
        rows["src_port"] = rng.integers(1024, 65535, n)
        rows["dst_port"] = rng.choice([80, 443, 53, 22, 8080, 8443, 21, 25], n)

        # ── boolean columns ────────────────────────────────────────────
        # TLS flows: benign, c2_beaconing, exfiltration are often TLS
        tls_prob = {"benign": 0.6, "ddos": 0.0, "c2_beaconing": 0.8,
                    "dns_anomaly": 0.1, "port_scan": 0.0, "exfiltration": 0.7,
                    "malware_tls": 1.0}   # always TLS by definition
        rows["is_tls"]    = (rng.random(n) < tls_prob[label]).astype(int)
        rows["is_quic"]   = (rng.random(n) < 0.05).astype(int)  # rare
        rows["quic_0rtt"] = (rows["is_quic"] & (rng.random(n) < 0.3)).astype(int)

        # ── QUIC packet size columns (0 when not QUIC) ─────────────────
        quic_mask = rows["is_quic"].astype(bool)
        rows["quic_pkt_size_mean"] = np.where(
            quic_mask, _norm_col(rng, 800, 200, n), 0.0
        )
        rows["quic_pkt_size_std"] = np.where(
            quic_mask, _norm_col(rng, 150, 50, n), 0.0
        )

        # ── encoded categorical columns ────────────────────────────────
        # During real training these are fit from data; synthetic uses small
        # integer values to exercise the same code paths.
        rows["ja4_hash_enc"]      = rng.integers(0, 20, n)
        rows["cipher_suite_enc"]  = rng.integers(0, 15, n)

        # ── cap periodicity_score ──────────────────────────────────────
        rows["periodicity_score"] = np.clip(rows["periodicity_score"], 0, PERIODICITY_CAP)

        df = pd.DataFrame(rows)
        df["label"]    = label
        df["scenario"] = f"synthetic_{label}"
        frames.append(df)

    combined = pd.concat(frames, ignore_index=True)

    # Ensure every FEATURE_COLUMN is present
    for col in FEATURE_COLUMNS:
        if col not in combined.columns:
            combined[col] = 0

    return combined[FEATURE_COLUMNS + ["label", "scenario"]]


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4 — PREPROCESSING
# ═══════════════════════════════════════════════════════════════════════════

def fit_frequency_encoder(series: pd.Series, top_n: int = TOP_N_CATEGORIES) -> dict[str, int]:
    """
    Build a frequency-encoding mapping for a categorical column.

    The top_n most common values get integer codes 1..top_n.
    Everything else (rare / unseen at inference) maps to 0.

    This is the same encoding strategy the feature pipeline uses for ja4_hash
    and cipher_suite. We fit it here on training data only, then persist it
    so that val/test/inference use the identical mapping.
    """
    counts = Counter(series.dropna().astype(str))
    top = [value for value, _ in counts.most_common(top_n)]
    return {value: idx + 1 for idx, value in enumerate(top)}


def apply_frequency_encoder(series: pd.Series, mapping: dict[str, int]) -> pd.Series:
    """Apply a persisted frequency-encoding mapping. Unknown values → 0."""
    return series.astype(str).map(lambda v: mapping.get(v, 0)).astype(int)


def preprocess(
    df: pd.DataFrame,
    encoders: dict | None = None,
    fit: bool = False,
) -> tuple[pd.DataFrame, dict]:
    """
    Convert a raw feature DataFrame into a clean numeric matrix ready for XGBoost.

    Steps:
      1. Fill NaN in FILL_ZERO_COLUMNS with 0
      2. Cast boolean columns to int (0/1)
      3. Cap periodicity_score at PERIODICITY_CAP
      4. Fit or apply frequency encoders for ja4_hash / cipher_suite
      5. Select exactly FEATURE_COLUMNS in the correct order

    Args:
        df:       DataFrame containing at least FEATURE_COLUMNS (and label/scenario).
        encoders: Pre-fitted encoder dicts from training. Pass None when fit=True.
        fit:      If True, fit new encoders from df. If False, use supplied encoders.

    Returns:
        (X, encoders) where X is a float64 DataFrame with columns = FEATURE_COLUMNS
        and encoders is the dict to persist alongside the model.
    """
    df = df.copy()

    # Step 1 — fill zero for optional feature groups
    for col in FILL_ZERO_COLUMNS:
        if col in df.columns:
            df[col] = df[col].fillna(0)

    # Step 2 — cast booleans
    for col in BOOL_COLUMNS:
        if col in df.columns:
            df[col] = df[col].fillna(False).astype(int)

    # Step 3 — cap periodicity_score
    if "periodicity_score" in df.columns:
        df["periodicity_score"] = df["periodicity_score"].clip(upper=PERIODICITY_CAP)

    # Step 4 — frequency encoding
    if encoders is None:
        encoders = {}

    if fit:
        # Fit encoders on training data only
        for raw_col, enc_col in [("ja4_hash", "ja4_hash_enc"), ("cipher_suite", "cipher_suite_enc")]:
            if raw_col in df.columns:
                encoders[raw_col] = fit_frequency_encoder(df[raw_col])
                df[enc_col] = apply_frequency_encoder(df[raw_col], encoders[raw_col])
            elif enc_col not in df.columns:
                df[enc_col] = 0
    else:
        # Apply pre-fitted encoders
        for raw_col, enc_col in [("ja4_hash", "ja4_hash_enc"), ("cipher_suite", "cipher_suite_enc")]:
            mapping = encoders.get(raw_col, {})
            if raw_col in df.columns:
                df[enc_col] = apply_frequency_encoder(df[raw_col], mapping)
            elif enc_col not in df.columns:
                df[enc_col] = 0

    # Step 5 — select exactly FEATURE_COLUMNS
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Preprocessing: missing feature columns: {missing}")

    X = df[FEATURE_COLUMNS].astype(float)
    return X, encoders


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5 — TRAIN / VAL / TEST SPLIT
# ═══════════════════════════════════════════════════════════════════════════

def scenario_split(
    df: pd.DataFrame,
    train_frac: float = 0.70,
    val_frac: float   = 0.15,
    seed: int         = RANDOM_SEED,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Split by scenario, not by individual row.

    Why this matters:
        A single attack scenario generates thousands of flows with correlated
        features (same src_ip, same timing pattern, same traffic volume).
        If we split rows randomly, the same attack run appears in both train
        and test — the model sees the attack's signature at train time and
        trivially recognises it at test time. That produces falsely high metrics.

        Scenario-level splitting ensures the test set contains attack runs the
        model has never seen, giving honest evaluation.

    Strategy:
        For each class, shuffle its scenarios and assign them to train/val/test
        proportionally. If a class has only one scenario, it goes to train only
        (with a warning — you need at least 3 scenarios per class for valid eval).

    Returns:
        (train_df, val_df, test_df)
    """
    rng = random.Random(seed)

    # Group scenarios by their class label
    class_scenarios: dict[str, list[str]] = defaultdict(list)
    for scenario, label in df.groupby("scenario")["label"].first().items():
        class_scenarios[label].append(scenario)

    train_scenarios, val_scenarios, test_scenarios = [], [], []

    for label, scenarios in class_scenarios.items():
        shuffled = scenarios.copy()
        rng.shuffle(shuffled)
        n = len(shuffled)

        if n == 1:
            warnings.warn(
                f"Class '{label}' has only 1 scenario ({shuffled[0]}). "
                f"It will only appear in train. Evaluation for this class will be unreliable."
            )
            train_scenarios.extend(shuffled)
            continue

        if n == 2:
            # One to train, one to val. Test gets zero rows for this class.
            # The classification report will simply have support=0 for this
            # class — not wrong, just something to expect and not panic about.
            train_scenarios.append(shuffled[0])
            val_scenarios.append(shuffled[1])
            warnings.warn(
                f"Class '{label}' has only 2 scenarios. "
                f"It will appear in train and val but NOT in the test set. "
                f"Expect support=0 for '{label}' in the classification report."
            )
            continue

        n_train = max(1, round(n * train_frac))
        n_val   = max(1, round(n * val_frac))
        # test gets the remainder
        train_scenarios.extend(shuffled[:n_train])
        val_scenarios.extend(shuffled[n_train:n_train + n_val])
        test_scenarios.extend(shuffled[n_train + n_val:])

    train_df = df[df["scenario"].isin(train_scenarios)].copy()
    val_df   = df[df["scenario"].isin(val_scenarios)].copy()
    test_df  = df[df["scenario"].isin(test_scenarios)].copy()

    print(f"\n  Split by scenario:")
    print(f"    Train : {len(train_df):>6} rows  {sorted(set(train_scenarios))}")
    print(f"    Val   : {len(val_df):>6} rows  {sorted(set(val_scenarios))}")
    print(f"    Test  : {len(test_df):>6} rows  {sorted(set(test_scenarios))}")

    return train_df, val_df, test_df


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6 — CLASS WEIGHT COMPUTATION
# ═══════════════════════════════════════════════════════════════════════════

def compute_sample_weights(y: np.ndarray) -> np.ndarray:
    """
    Compute per-sample weights to counteract class imbalance.

    A SYN flood run generates thousands of flows while a C2 beacon generates
    one per minute. Without balancing, XGBoost will bias toward the majority
    class and miss rare attack types entirely.

    Formula: weight_i = total_samples / (n_classes * count_of_class_i)

    This is the standard sklearn "balanced" class_weight formula, applied
    manually because XGBoost's native interface uses sample_weight arrays.
    """
    counts = Counter(y)
    n_total  = len(y)
    n_classes = len(counts)
    weight_map = {cls: n_total / (n_classes * count) for cls, count in counts.items()}
    return np.array([weight_map[label] for label in y])


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7 — OPTUNA HYPERPARAMETER TUNING
# ═══════════════════════════════════════════════════════════════════════════

def tune_with_optuna(
    X_train: pd.DataFrame,
    y_train: np.ndarray,
    sample_weights: np.ndarray,
    X_val: pd.DataFrame,
    y_val: np.ndarray,
    label_encoder,
    n_trials: int = OPTUNA_TRIALS,
    seed: int = RANDOM_SEED,
):
    """
    Search for the best XGBoost hyperparameters using Optuna.

    Optuna is a Bayesian optimisation library. Each trial picks a different
    combination of hyperparameters, trains a model, evaluates on the
    validation set, and reports the F1 macro score. Optuna uses the history
    of past trials to make smarter choices about where to search next.

    Search space:
        n_estimators:     50 – 400    (number of trees)
        max_depth:        3 – 10      (depth of each tree)
        learning_rate:    0.01 – 0.3  (step size / shrinkage)
        min_child_weight: 1 – 10      (minimum samples in a leaf)
        subsample:        0.6 – 1.0   (fraction of rows per tree)
        colsample_bytree: 0.6 – 1.0   (fraction of features per tree)

    Returns:
        (best_params dict, optuna Study object)
    """
    optuna = _require("optuna")
    xgb    = _require("xgboost")
    sklearn_metrics = _require("sklearn.metrics")

    optuna.logging.set_verbosity(optuna.logging.WARNING)

    # When val set is empty (synthetic data, 1 scenario per class) Optuna
    # cannot evaluate on a held-out set. Fall back to training-set F1 so
    # tuning still runs and picks reasonable hyperparameters.
    # On real data with multiple scenarios per class this never triggers.
    _use_train_fallback = len(X_val) == 0
    if _use_train_fallback:
        warnings.warn(
            "Validation set is empty — Optuna will evaluate on training data. "
            "Hyperparameter selection will be less meaningful. "
            "This is expected with synthetic data (1 scenario per class)."
        )

    def objective(trial):
        params = {
            "n_estimators":     trial.suggest_int("n_estimators", 50, 400),
            "max_depth":        trial.suggest_int("max_depth", 3, 10),
            "learning_rate":    trial.suggest_float("learning_rate", 0.01, 0.3, log=True),
            "min_child_weight": trial.suggest_int("min_child_weight", 1, 10),
            "subsample":        trial.suggest_float("subsample", 0.6, 1.0),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.6, 1.0),
            # use_label_encoder was removed in XGBoost ≥ 1.6 — do not pass it.
            "eval_metric":      "mlogloss",
            "random_state":     seed,
            "n_jobs":           -1,
        }
        model = xgb.XGBClassifier(**params)
        model.fit(X_train, y_train, sample_weight=sample_weights, verbose=False)

        if _use_train_fallback:
            # Evaluate on training data — not a real generalisation estimate,
            # but gives Optuna a non-nan signal to work with.
            y_pred = model.predict(X_train)
            eval_true = y_train
        else:
            y_pred = model.predict(X_val)
            eval_true = y_val

        score = sklearn_metrics.f1_score(
            eval_true, y_pred, average="macro", zero_division=0
        )
        # Guard: f1_score should never be nan here, but be safe.
        return float(score) if score == score else 0.0  # nan check: nan != nan

    study = optuna.create_study(
        direction="maximize",
        sampler=optuna.samplers.TPESampler(seed=seed),
    )
    study.optimize(objective, n_trials=n_trials, show_progress_bar=True)

    # Guard: if every trial somehow still failed, return safe defaults.
    completed = [t for t in study.trials if t.value is not None]
    if not completed:
        warnings.warn(
            "All Optuna trials failed. Using default XGBoost hyperparameters."
        )
        default_params = {
            "n_estimators": 200,
            "max_depth": 6,
            "learning_rate": 0.1,
            "min_child_weight": 1,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
        }
        return default_params, study

    print(f"\n  Best trial: F1 macro = {study.best_value:.4f}")
    print(f"  Best params: {study.best_params}")

    return study.best_params, study


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 8 — MODEL TRAINING
# ═══════════════════════════════════════════════════════════════════════════

def train_model(X: pd.DataFrame, y: np.ndarray, params: dict, sample_weights: np.ndarray, seed: int = RANDOM_SEED):
    """
    Train an XGBoost multi-class classifier with the given hyperparameters.

    XGBoost is chosen over simpler models because:
    - Handles mixed numeric / boolean / ordinal features without scaling
    - Native support for class imbalance via sample_weight
    - Fast inference (important for streaming pipeline)
    - SHAP integration via TreeExplainer (needed for evidence generation)
    - Strong empirical performance on tabular network traffic data

    Note: use_label_encoder was removed in XGBoost ≥ 1.6 — do not pass it.
    random_state is passed explicitly so the final model is reproducible.
    """
    xgb = _require("xgboost")
    # Strip any stale use_label_encoder that may have come through best_params
    clean_params = {k: v for k, v in params.items() if k != "use_label_encoder"}
    model = xgb.XGBClassifier(
        **clean_params,
        eval_metric="mlogloss",
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(X, y, sample_weight=sample_weights, verbose=False)
    return model


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 9 — EVALUATION + SAVING
# ═══════════════════════════════════════════════════════════════════════════

def evaluate_and_save(
    model,
    label_encoder,
    X_test: pd.DataFrame,
    y_test: np.ndarray,
    output_dir: Path = ML_DIR,
    X_fallback: pd.DataFrame | None = None,
    y_fallback: np.ndarray | None = None,
):
    """
    Evaluate the trained model on the held-out test set and save all artifacts.

    Produces:
        ml/classification_report.txt  — per-class precision/recall/F1
        ml/confusion_matrix.png       — heatmap (rows=actual, cols=predicted)

    The confusion matrix is the most important diagnostic:
    - Off-diagonal cells show misclassifications
    - A model that just predicts "ddos" for everything will have high recall
      for ddos but near-zero recall for all other classes
    - We want high values on the diagonal for every class
    """
    sklearn_metrics = _require("sklearn.metrics")
    matplotlib      = _require("matplotlib")
    import matplotlib.pyplot as plt

    # Guard: if test set is empty (synthetic data, 1 scenario per class),
    # evaluate on the fallback data (training set) and say so clearly.
    if len(X_test) == 0:
        if X_fallback is not None and len(X_fallback) > 0:
            print("  (Test set is empty — evaluating on training data for smoke-test purposes.)")
            print("  WARNING: These metrics are NOT a valid generalisation estimate.")
            X_test = X_fallback
            y_test = y_fallback
        else:
            print("  (Test set is empty and no fallback available — skipping evaluation.)")
            return ""

    y_pred = model.predict(X_test)
    class_names = label_encoder.classes_

    # Classification report
    report = sklearn_metrics.classification_report(
        y_test, y_pred,
        target_names=class_names,
        zero_division=0,
    )
    print("\n" + "─" * 60)
    print("CLASSIFICATION REPORT (test set)")
    print("─" * 60)
    print(report)

    report_path = output_dir / "classification_report.txt"
    report_path.write_text(report)
    print(f"  Saved: {report_path}")

    # Confusion matrix
    cm = sklearn_metrics.confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(8, 6))
    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    plt.colorbar(im, ax=ax)
    ax.set(
        xticks=range(len(class_names)),
        yticks=range(len(class_names)),
        xticklabels=class_names,
        yticklabels=class_names,
        xlabel="Predicted label",
        ylabel="True label",
        title="Confusion Matrix — Aegis NIDS",
    )
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
    thresh = cm.max() / 2
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, str(cm[i, j]),
                    ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "black")
    plt.tight_layout()
    cm_path = output_dir / "confusion_matrix.png"
    fig.savefig(cm_path, dpi=150)
    plt.close(fig)
    print(f"  Saved: {cm_path}")

    return report


def show_shap_examples(
    model,
    label_encoder,
    X_sample: pd.DataFrame,
    n_examples: int = 3,
):
    """
    Print SHAP evidence for a handful of test predictions.

    This uses ThreatExplainer from ml/explainability.py and shows judges
    what the model is "looking at" when it flags a flow as an attack.
    This is the "supporting evidence" output required by the SIH spec.

    Example output:
        Row 0  →  port_scan  (confidence 0.94)
          Connections to many destinations: 412.0  (supports prediction)
          Many destination ports contacted: 87.0   (supports prediction)
          Frequent connections from source: 56.3   (supports prediction)
    """
    try:
        from ml.explainability import ThreatExplainer
        import shap as _shap_module  # noqa: F401 — just checking it's installed
    except ImportError as exc:
        print(f"\n  (SHAP evidence skipped — {exc})")
        return

    class_mapping = {name: idx for idx, name in enumerate(label_encoder.classes_)}

    try:
        explainer = ThreatExplainer(model, class_mapping=class_mapping)
    except Exception as exc:
        print(f"\n  (ThreatExplainer init failed: {exc})")
        return

    rows = X_sample.head(n_examples)
    y_pred = model.predict(rows)

    print(f"\n{'─' * 60}")
    print(f"SHAP EVIDENCE — {len(rows)} example prediction(s)")
    print("─" * 60)

    for i in range(len(rows)):
        pred_idx   = int(y_pred[i])
        pred_class = label_encoder.inverse_transform([pred_idx])[0]
        proba      = float(model.predict_proba(rows.iloc[i:i+1])[0][pred_idx])

        print(f"\n  Row {i}  →  {pred_class}  (confidence {proba:.2f})")
        try:
            evidence = explainer.explain(rows.iloc[i], threat_class=pred_class, top_k=3)
            for ev in evidence:
                print(f"    {ev['label']}: {float(ev['value']):.4g}  ({ev['direction']} prediction)")
        except Exception as exc:
            print(f"    (explanation failed: {exc})")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 10 — MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def main(
    features_dir: Path = FEATURES_DIR,
    labels_dir:   Path = LABELS_DIR,
    output_dir:   Path = ML_DIR,
    force_synthetic: bool = False,
    n_synthetic:     int  = 500,
    n_trials:        int  = OPTUNA_TRIALS,
):
    sklearn_preprocessing = _require("sklearn.preprocessing")
    LabelEncoder = sklearn_preprocessing.LabelEncoder

    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Step 1: Load data ─────────────────────────────────────────────────
    print("\n══ STEP 1: LOADING DATA ══════════════════════════════════════")

    parquet_files = list(features_dir.glob("*.parquet")) if features_dir.exists() else []
    use_synthetic = force_synthetic or len(parquet_files) == 0

    if use_synthetic:
        print(f"  No Parquet files found in {features_dir} (or --synthetic flag set).")
        print(f"  Generating synthetic dataset ({n_synthetic} rows per class)...")
        df = generate_synthetic_data(n_per_class=n_synthetic, seed=RANDOM_SEED)
        print(f"  Synthetic dataset: {len(df)} rows, classes: {df['label'].value_counts().to_dict()}")
    else:
        print(f"  Found {len(parquet_files)} Parquet file(s) in {features_dir}.")
        label_map = load_labels(labels_dir)
        print(f"  Label map: {label_map}")
        df = load_parquet_files(features_dir, label_map)
        if df.empty:
            raise RuntimeError(
                "No labeled rows could be loaded. "
                "Check that label JSON files exist in data/labels/ for each Parquet file."
            )

    # ── Step 2: Encode labels ─────────────────────────────────────────────
    print("\n══ STEP 2: ENCODING LABELS ═══════════════════════════════════")
    le = LabelEncoder()
    le.fit(CLASS_NAMES)   # fit on full taxonomy so indices are stable
    df["label_enc"] = le.transform(df["label"])
    print(f"  Class mapping: { {name: idx for idx, name in enumerate(le.classes_)} }")

    # ── Step 3: Scenario-level split ──────────────────────────────────────
    print("\n══ STEP 3: SCENARIO-LEVEL SPLIT ══════════════════════════════")
    train_df, val_df, test_df = scenario_split(df, seed=RANDOM_SEED)

    if test_df.empty:
        warnings.warn(
            "Test set is empty — likely because each class has only 1-2 scenarios. "
            "Final evaluation will run on the validation set instead."
        )
        test_df = val_df

    # ── Step 4: Preprocessing ─────────────────────────────────────────────
    print("\n══ STEP 4: PREPROCESSING ═════════════════════════════════════")
    X_train, encoders = preprocess(train_df, fit=True)
    X_val,   _        = preprocess(val_df,   encoders=encoders, fit=False)
    X_test,  _        = preprocess(test_df,  encoders=encoders, fit=False)

    y_train = train_df["label_enc"].values
    y_val   = val_df["label_enc"].values
    y_test  = test_df["label_enc"].values

    print(f"  X_train: {X_train.shape},  X_val: {X_val.shape},  X_test: {X_test.shape}")
    print(f"  Train class counts: {Counter(le.inverse_transform(y_train))}")

    sample_weights = compute_sample_weights(y_train)
    print(f"  Sample weight range: [{sample_weights.min():.3f}, {sample_weights.max():.3f}]")

    # ── Step 5: Optuna tuning ─────────────────────────────────────────────
    print("\n══ STEP 5: HYPERPARAMETER TUNING (OPTUNA) ════════════════════")
    print(f"  Running {n_trials} trials...")
    best_params, study = tune_with_optuna(
        X_train, y_train, sample_weights,
        X_val, y_val,
        le,
        n_trials=n_trials,
        seed=RANDOM_SEED,
    )

    # ── Step 6: Final training on train+val ───────────────────────────────
    print("\n══ STEP 6: FINAL TRAINING (train + val combined) ═════════════")
    X_trainval = pd.concat([X_train, X_val], ignore_index=True)
    y_trainval = np.concatenate([y_train, y_val])
    sw_trainval = compute_sample_weights(y_trainval)

    final_model = train_model(X_trainval, y_trainval, best_params, sw_trainval, seed=RANDOM_SEED)
    print(f"  Trained on {len(X_trainval)} rows with best params.")

    # ── Step 7: Evaluation ────────────────────────────────────────────────
    print("\n══ STEP 7: EVALUATION (test set) ═════════════════════════════")
    evaluate_and_save(
        final_model, le, X_test, y_test, output_dir,
        X_fallback=X_trainval, y_fallback=y_trainval,
    )

    # ── Step 7b: SHAP evidence examples ───────────────────────────────────
    # Shows judges what features drove each prediction — the "supporting
    # evidence" required by the SIH output spec.
    # Skipped silently if shap is not installed.
    print("\n══ STEP 7b: SHAP EVIDENCE EXAMPLES ══════════════════════════")
    show_shap_examples(final_model, le, X_test, n_examples=3)

    # ── Step 8: Save artifacts ────────────────────────────────────────────
    print("\n══ STEP 8: SAVING ARTIFACTS ══════════════════════════════════")

    model_path   = output_dir / "model.joblib"
    encoder_path = output_dir / "label_encoder.joblib"
    enc_path     = output_dir / "encoders.joblib"
    study_path   = output_dir / "optuna_study.pkl"

    joblib.dump(final_model, model_path)
    joblib.dump(le,          encoder_path)
    joblib.dump(encoders,    enc_path)

    with open(study_path, "wb") as f:
        pickle.dump(study, f)

    print(f"  Saved: {model_path}")
    print(f"  Saved: {encoder_path}")
    print(f"  Saved: {enc_path}")
    print(f"  Saved: {study_path}")
    print("\n  Training complete.")


# ── CLI ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the Aegis NIDS XGBoost classifier.")
    parser.add_argument("--features-dir", default="data/features",
                        help="Directory containing scenario Parquet files (default: data/features)")
    parser.add_argument("--labels-dir",   default="data/labels",
                        help="Directory containing scenario label JSON files (default: data/labels)")
    parser.add_argument("--output-dir",   default="ml",
                        help="Directory to write model artifacts (default: ml)")
    parser.add_argument("--synthetic",    action="store_true",
                        help="Force synthetic data even if Parquet files exist")
    parser.add_argument("--n-synthetic",  type=int, default=500,
                        help="Rows per class for synthetic dataset (default: 500)")
    parser.add_argument("--trials",       type=int, default=OPTUNA_TRIALS,
                        help=f"Optuna trials (default: {OPTUNA_TRIALS})")
    args = parser.parse_args()

    main(
        features_dir     = Path(args.features_dir),
        labels_dir       = Path(args.labels_dir),
        output_dir       = Path(args.output_dir),
        force_synthetic  = args.synthetic,
        n_synthetic      = args.n_synthetic,
        n_trials         = args.trials,
    )
