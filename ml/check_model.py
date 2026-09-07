"""
ml/check_model.py — Quick sanity check for the trained model.

Run from the Aegis/ directory:
    python -m ml.check_model

What this does:
  1. Loads model.joblib, label_encoder.joblib, encoders.joblib
  2. Generates a FRESH held-out set with seed=999 (different from training seed=42)
     — these rows were NEVER seen during training
  3. Runs predictions and prints the classification report
  4. Prints what the Optuna tuning found
  5. Explains clearly whether the metrics are trustworthy or not

The key question: does the model generalise to new synthetic rows it
has never seen, or did it just memorise the training data?

If F1 is still ~1.0 on unseen synthetic data → the classes are so well
separated in the synthetic distributions that any decent model gets 100%.
That's fine for a pipeline smoke test but tells you nothing about real traffic.

If F1 drops significantly on unseen rows → the model overfit to training
distribution noise. That would be a problem worth investigating.
"""

import pickle

import joblib
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix

from ml.train import (
    FEATURE_COLUMNS,
    RANDOM_SEED,
    generate_synthetic_data,
    preprocess,
)


def main():
    print("=" * 60)
    print("AEGIS MODEL SANITY CHECK")
    print("=" * 60)

    # ── Load artifacts ────────────────────────────────────────────────────
    print("\n── Artifacts ────────────────────────────────────────────────")
    model = joblib.load("ml/model.joblib")
    le    = joblib.load("ml/label_encoder.joblib")
    encs  = joblib.load("ml/encoders.joblib")

    print(f"  Model type    : {type(model).__name__}")
    print(f"  n_estimators  : {model.n_estimators}")
    print(f"  Feature count : {len(FEATURE_COLUMNS)}")
    print(f"  Classes       : {list(le.classes_)}")

    # ── Optuna study ──────────────────────────────────────────────────────
    print("\n── Optuna Tuning Results ────────────────────────────────────")
    with open("ml/optuna_study.pkl", "rb") as f:
        study = pickle.load(f)
    print(f"  Trials completed : {len(study.trials)}")
    print(f"  Best val F1      : {study.best_value:.4f}")
    print(f"  Best params      :")
    for k, v in study.best_params.items():
        print(f"    {k:<22} = {v}")

    # ── Fresh held-out set ────────────────────────────────────────────────
    print("\n── Held-out Evaluation (seed=999, never seen during training) ")
    print("  Training used seed=42. This uses seed=999.")
    print("  These rows were NOT part of the training data.\n")

    df_test = generate_synthetic_data(n_per_class=200, seed=999)
    label_counts = df_test["label"].value_counts().to_dict()
    print(f"  Test rows : {len(df_test)}")
    print(f"  Per class : {label_counts}")

    X_test, _ = preprocess(df_test, encoders=encs, fit=False)
    y_test    = le.transform(df_test["label"].values)
    y_pred    = model.predict(X_test)

    report = classification_report(
        y_test, y_pred,
        target_names=le.classes_,
        zero_division=0,
    )
    print()
    print(report)

    # ── Confusion matrix (text) ───────────────────────────────────────────
    cm = confusion_matrix(y_test, y_pred)
    print("── Confusion Matrix (rows=actual, cols=predicted) ───────────")
    header = "          " + "  ".join(f"{c[:6]:>6}" for c in le.classes_)
    print(header)
    for i, row in enumerate(cm):
        label = le.classes_[i][:10]
        row_str = "  ".join(f"{v:>6}" for v in row)
        print(f"  {label:<10}  {row_str}")

    # ── Interpretation ────────────────────────────────────────────────────
    print("\n── What these numbers mean ──────────────────────────────────")
    from sklearn.metrics import f1_score
    macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)

    if macro_f1 >= 0.99:
        print("  F1 = {:.4f} on unseen synthetic data.".format(macro_f1))
        print()
        print("  This is expected. The synthetic class distributions are")
        print("  deliberately non-overlapping so any reasonable model gets")
        print("  near-perfect scores. This confirms the pipeline works")
        print("  end-to-end — data in, model trained, predictions made.")
        print()
        print("  DO NOT present these numbers as real performance metrics.")
        print("  Real evaluation requires real Parquet from the Docker lab.")
        print("  When your teammates deliver Parquet files, retrain and")
        print("  re-run this check. Those numbers will be honest.")
    elif macro_f1 >= 0.85:
        print("  F1 = {:.4f}. Pipeline works. Some class confusion exists.".format(macro_f1))
        print("  Check the confusion matrix for which classes are mixing.")
    else:
        print("  F1 = {:.4f}. Significant errors on synthetic data.".format(macro_f1))
        print("  Something may be wrong with preprocessing or label encoding.")
        print("  Check the confusion matrix and re-examine the pipeline.")

    print()
    print("  Saved artifacts:")
    print("    ml/model.joblib          — trained XGBoost model")
    print("    ml/label_encoder.joblib  — class index ↔ name mapping")
    print("    ml/encoders.joblib       — ja4/cipher frequency encoders")
    print("    ml/optuna_study.pkl      — full Optuna tuning history")
    print("    ml/classification_report.txt")
    print("    ml/confusion_matrix.png")
    print()


if __name__ == "__main__":
    main()
