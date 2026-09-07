"""
ml/evaluate.py — Standalone evaluation script for Aegis NIDS.

What this file does:
─────────────────────────────────────────────────────────────────────────────
Loads a trained model from ml/model.joblib and runs it against a test
Parquet file (or synthetic data if no file is provided).

This script is intentionally separate from train.py so that:
  - Judges can re-run evaluation independently without retraining
  - The demo can show live predictions on new data
  - Evaluation logic can be audited without touching the training code

Outputs to stdout:
  - Per-class precision, recall, F1 table
  - Overall accuracy
  - Which classes the model struggles with

Outputs to disk:
  - ml/classification_report.txt   (overwrites if exists)
  - ml/confusion_matrix.png        (overwrites if exists)

Usage:
    # Evaluate on synthetic data (no Parquet needed):
    python3 -m ml.evaluate

    # Evaluate on a specific Parquet file with its label:
    python3 -m ml.evaluate --parquet data/features/syn_flood.parquet --label ddos

    # Evaluate on all Parquet files in a directory (uses data/labels/ for mapping):
    python3 -m ml.evaluate --features-dir data/features --labels-dir data/labels
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


# ── project imports ───────────────────────────────────────────────────────
from features.schema import FEATURE_COLUMNS
from ml.train import (
    CLASS_NAMES,
    ML_DIR,
    FEATURES_DIR,
    LABELS_DIR,
    generate_synthetic_data,
    load_labels,
    load_parquet_files,
    preprocess,
)


def _require(module_name: str):
    import importlib
    try:
        return importlib.import_module(module_name)
    except ImportError as exc:
        raise ImportError(
            f"Required package not installed: {module_name}\n"
            f"Run: pip install {module_name.split('.')[0]}"
        ) from exc


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1 — LOAD ARTIFACTS
# ═══════════════════════════════════════════════════════════════════════════

def load_artifacts(ml_dir: Path = ML_DIR) -> tuple:
    """
    Load the three artifacts that train.py saves:
        model.joblib         — trained XGBoost classifier
        label_encoder.joblib — sklearn LabelEncoder (int ↔ class name)
        encoders.joblib      — frequency-encoding maps for ja4_hash / cipher_suite

    Raises a clear error if any artifact is missing — this means train.py
    has not been run yet.
    """
    required = {
        "model":         ml_dir / "model.joblib",
        "label_encoder": ml_dir / "label_encoder.joblib",
        "encoders":      ml_dir / "encoders.joblib",
    }
    for name, path in required.items():
        if not path.exists():
            raise FileNotFoundError(
                f"Artifact not found: {path}\n"
                f"Run 'python3 -m ml.train' first to train the model."
            )

    model         = joblib.load(required["model"])
    label_encoder = joblib.load(required["label_encoder"])
    encoders      = joblib.load(required["encoders"])
    return model, label_encoder, encoders


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2 — PREDICTION
# ═══════════════════════════════════════════════════════════════════════════

def predict(
    model,
    label_encoder,
    encoders: dict,
    df: pd.DataFrame,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Run the model on a labeled DataFrame and return predictions.

    Steps:
      1. Preprocess using the training-time encoders (not refitting)
      2. Encode the true labels using the same LabelEncoder
      3. Call model.predict() and model.predict_proba()

    Returns:
        y_true       — integer-encoded true labels
        y_pred       — integer-encoded predicted labels
        y_proba      — probability matrix, shape (n_rows, n_classes)
    """
    X, _ = preprocess(df, encoders=encoders, fit=False)

    # Encode true labels — rows whose label is not in the training taxonomy
    # are dropped with a warning rather than crashing.
    known_classes = set(label_encoder.classes_)
    unknown_mask  = ~df["label"].isin(known_classes)
    if unknown_mask.any():
        unknown = df.loc[unknown_mask, "label"].unique().tolist()
        warnings.warn(f"Dropping {unknown_mask.sum()} rows with unknown labels: {unknown}")
        df = df[~unknown_mask].copy()
        X  = X[~unknown_mask.values]

    y_true  = label_encoder.transform(df["label"].values)
    y_pred  = model.predict(X)
    y_proba = model.predict_proba(X)

    return y_true, y_pred, y_proba


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3 — REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════════════

def print_report(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: np.ndarray,
    label_encoder,
    output_dir: Path = ML_DIR,
) -> str:
    """
    Print a full classification report and save the confusion matrix PNG.

    The report shows per-class:
        precision — of all flows we labelled as X, what fraction were correct?
        recall    — of all actual X flows, what fraction did we catch?
        F1        — harmonic mean of precision and recall

    A class with low recall is being missed (false negatives).
    A class with low precision has many false alarms (false positives).
    Both matter for a threat detection system.

    For SIH evaluation the target is F1 > 0.85 per class.
    """
    sklearn_metrics = _require("sklearn.metrics")
    matplotlib      = _require("matplotlib")
    plt = matplotlib.pyplot

    class_names = label_encoder.classes_

    # ── text report ───────────────────────────────────────────────────────
    report = sklearn_metrics.classification_report(
        y_true, y_pred,
        target_names=class_names,
        zero_division=0,
    )
    accuracy = sklearn_metrics.accuracy_score(y_true, y_pred)

    separator = "─" * 60
    print(f"\n{separator}")
    print("CLASSIFICATION REPORT")
    print(separator)
    print(report)
    print(f"Overall accuracy: {accuracy:.4f}")

    # Flag any class below the F1 target
    report_dict = sklearn_metrics.classification_report(
        y_true, y_pred,
        target_names=class_names,
        zero_division=0,
        output_dict=True,
    )
    print(separator)
    print("F1 per class (target: > 0.85)")
    print(separator)
    below_target = []
    for cls in class_names:
        if cls not in report_dict:
            continue
        f1  = report_dict[cls]["f1-score"]
        sup = report_dict[cls]["support"]
        flag = "  ✓" if f1 >= 0.85 else "  ✗ BELOW TARGET"
        print(f"  {cls:<20} F1={f1:.3f}  support={sup}{flag}")
        if f1 < 0.85:
            below_target.append(cls)

    if below_target:
        print(f"\n  Classes below F1 target: {below_target}")
        print("  Likely causes: too few training scenarios, class imbalance,")
        print("  or features that don't distinguish this class well.")
    else:
        print("\n  All classes meet the F1 > 0.85 target.")

    # ── save text report ──────────────────────────────────────────────────
    report_path = output_dir / "classification_report.txt"
    report_path.write_text(report)
    print(f"\n  Saved: {report_path}")

    # ── confusion matrix PNG ──────────────────────────────────────────────
    cm = sklearn_metrics.confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(9, 7))
    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    plt.colorbar(im, ax=ax)
    ax.set(
        xticks=range(len(class_names)),
        yticks=range(len(class_names)),
        xticklabels=class_names,
        yticklabels=class_names,
        xlabel="Predicted label",
        ylabel="True label",
        title="Aegis NIDS — Confusion Matrix",
    )
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right", fontsize=9)
    thresh = cm.max() / 2
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(
                j, i, str(cm[i, j]),
                ha="center", va="center",
                color="white" if cm[i, j] > thresh else "black",
                fontsize=9,
            )
    plt.tight_layout()
    cm_path = output_dir / "confusion_matrix.png"
    fig.savefig(cm_path, dpi=150)
    plt.close(fig)
    print(f"  Saved: {cm_path}")

    return report


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4 — SHAP EVIDENCE SAMPLE (optional)
# ═══════════════════════════════════════════════════════════════════════════

def show_shap_examples(
    model,
    label_encoder,
    encoders: dict,
    df: pd.DataFrame,
    n_examples: int = 3,
):
    """
    Show SHAP evidence for a handful of predictions.

    This uses the ThreatExplainer from ml/explainability.py which your
    teammate already wrote and tested. It shows judges what the model
    "looks at" when making a prediction — the supporting evidence.

    Example output:
        Flow C8abc123  →  port_scan  (confidence 0.94)
        Evidence:
          unique_dst_ports: 412.0  (supports)
          fan_out: 87.0  (supports)
          connection_frequency: 56.3  (supports)
    """
    try:
        from ml.explainability import ThreatExplainer
    except ImportError:
        print("\n  (SHAP evidence skipped — ml.explainability not available)")
        return

    try:
        import shap as _shap
    except ImportError:
        print("\n  (SHAP evidence skipped — shap package not installed)")
        return

    X, _ = preprocess(df.head(n_examples * 10), encoders=encoders, fit=False)
    class_mapping = {name: idx for idx, name in enumerate(label_encoder.classes_)}

    try:
        explainer = ThreatExplainer(model, class_mapping=class_mapping)
    except Exception as exc:
        print(f"\n  (SHAP explainer init failed: {exc})")
        return

    y_pred = model.predict(X.head(n_examples))
    print(f"\n{'-' * 60}")
    print(f"SHAP EVIDENCE — {n_examples} example predictions")
    print("-" * 60)

    for i in range(min(n_examples, len(X))):
        row     = X.iloc[i]
        pred_idx = int(y_pred[i])
        pred_class = label_encoder.inverse_transform([pred_idx])[0]
        proba = model.predict_proba(X.iloc[i:i+1])[0][pred_idx]

        flow_id = df.iloc[i].get("flow_id", f"row_{i}") if "flow_id" in df.columns else f"row_{i}"
        print(f"\n  Flow: {flow_id}  →  {pred_class}  (confidence {proba:.2f})")

        try:
            evidence = explainer.explain(row, threat_class=pred_class, top_k=3)
            for ev in evidence:
                print(f"    {ev['label']}: {float(ev['value']):.4g}  ({ev['direction']})")
        except Exception as exc:
            print(f"    (explanation failed: {exc})")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5 — MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def main(
    parquet_path:   Path | None = None,
    single_label:   str  | None = None,
    features_dir:   Path        = FEATURES_DIR,
    labels_dir:     Path        = LABELS_DIR,
    ml_dir:         Path        = ML_DIR,
    force_synthetic: bool       = False,
    show_shap:      bool        = True,
):
    # ── load trained artifacts ────────────────────────────────────────────
    print("\n══ LOADING MODEL ARTIFACTS ═══════════════════════════════════")
    model, label_encoder, encoders = load_artifacts(ml_dir)
    print(f"  Model:         {ml_dir / 'model.joblib'}")
    print(f"  Classes:       {list(label_encoder.classes_)}")
    print(f"  Feature count: {len(FEATURE_COLUMNS)}")

    # ── load evaluation data ──────────────────────────────────────────────
    print("\n══ LOADING EVALUATION DATA ═══════════════════════════════════")

    if force_synthetic:
        print("  Using synthetic data (--synthetic flag).")
        df = generate_synthetic_data(n_per_class=200)

    elif parquet_path is not None:
        # Single file mode
        if not parquet_path.exists():
            sys.exit(f"Error: file not found: {parquet_path}")
        if single_label is None:
            # Try to infer from data/labels/
            label_map = load_labels(labels_dir)
            single_label = label_map.get(parquet_path.stem)
            if single_label is None:
                sys.exit(
                    f"Error: no label found for '{parquet_path.stem}'. "
                    f"Pass --label <class> explicitly or add {parquet_path.stem}.json to {labels_dir}."
                )
        df = pd.read_parquet(parquet_path)
        df["label"]    = single_label
        df["scenario"] = parquet_path.stem
        print(f"  Loaded {len(df)} rows from {parquet_path}  (label={single_label})")

    elif features_dir.exists() and any(features_dir.glob("*.parquet")):
        # Multi-file mode
        label_map = load_labels(labels_dir)
        df = load_parquet_files(features_dir, label_map)
        if df.empty:
            sys.exit("Error: no labeled rows loaded. Check data/labels/ and data/features/.")

    else:
        print(f"  No Parquet files found in {features_dir}. Using synthetic data.")
        df = generate_synthetic_data(n_per_class=200)

    print(f"  Total rows: {len(df)}")
    print(f"  Class distribution: {df['label'].value_counts().to_dict()}")

    # ── predict ───────────────────────────────────────────────────────────
    print("\n══ RUNNING PREDICTIONS ════════════════════════════════════════")
    y_true, y_pred, y_proba = predict(model, label_encoder, encoders, df)
    print(f"  Predicted {len(y_pred)} rows.")

    # ── report ────────────────────────────────────────────────────────────
    print_report(y_true, y_pred, y_proba, label_encoder, ml_dir)

    # ── SHAP examples ─────────────────────────────────────────────────────
    if show_shap:
        show_shap_examples(model, label_encoder, encoders, df)

    print("\n══ EVALUATION COMPLETE ════════════════════════════════════════\n")


# ── CLI ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Evaluate the trained Aegis NIDS model and produce a report."
    )
    parser.add_argument(
        "--parquet",
        type=Path,
        default=None,
        help="Path to a single Parquet file to evaluate (e.g. data/features/syn_flood.parquet)",
    )
    parser.add_argument(
        "--label",
        default=None,
        help="Attack class label for --parquet (e.g. 'ddos'). Inferred from data/labels/ if omitted.",
    )
    parser.add_argument(
        "--features-dir",
        type=Path,
        default=FEATURES_DIR,
        help="Directory of Parquet files (used when --parquet is not set)",
    )
    parser.add_argument(
        "--labels-dir",
        type=Path,
        default=LABELS_DIR,
        help="Directory of label JSON files (default: data/labels)",
    )
    parser.add_argument(
        "--ml-dir",
        type=Path,
        default=ML_DIR,
        help="Directory containing model artifacts (default: ml)",
    )
    parser.add_argument(
        "--synthetic",
        action="store_true",
        help="Force synthetic data for evaluation",
    )
    parser.add_argument(
        "--no-shap",
        action="store_true",
        help="Skip SHAP evidence examples (faster)",
    )
    args = parser.parse_args()

    main(
        parquet_path    = args.parquet,
        single_label    = args.label,
        features_dir    = args.features_dir,
        labels_dir      = args.labels_dir,
        ml_dir          = args.ml_dir,
        force_synthetic = args.synthetic,
        show_shap       = not args.no_shap,
    )
