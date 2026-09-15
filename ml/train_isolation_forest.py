import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import matplotlib.pyplot as plt
from pathlib import Path

from ml.train import preprocess
from features.schema import FEATURE_COLUMNS


# ============================================================
# CONFIGURATION
# ============================================================

FEATURES_DIR = Path("data/features")
ML_DIR = Path("ml")

BENIGN_PATTERN = "benign_*.parquet"

RANDOM_SEED = 42
N_ESTIMATORS = 200
CONTAMINATION = 0.01


# ============================================================
# LOAD BENIGN PARQUET FILES
# ============================================================

def load_benign_data():

    benign_files = sorted(
        FEATURES_DIR.glob(BENIGN_PATTERN)
    )

    if not benign_files:
        raise RuntimeError(
            f"No benign Parquet files found in "
            f"{FEATURES_DIR}/\n"
            f"Expected files like:\n"
            f"  benign_01.parquet\n"
            f"  benign_02.parquet\n"
            f"  ..."
        )

    print("\nBenign Parquet files found:")

    frames = []

    for path in benign_files:

        print(f"  Loading {path.name} ...")

        df = pd.read_parquet(path)

        print(f"      {len(df)} rows")

        # Keep track of which benign run produced the data.
        df["scenario"] = path.stem

        # These files are explicitly benign.
        df["label"] = "benign"

        frames.append(df)

    benign_df = pd.concat(
        frames,
        ignore_index=True
    )

    print(
        f"\nTotal benign samples: "
        f"{len(benign_df)}"
    )

    return benign_df


# ============================================================
# CHECK RAW INPUT COLUMNS
# ============================================================

def check_raw_columns(df):

    """
    FEATURE_COLUMNS contains some derived/preprocessed columns.

    For example:
        ja4_hash -> ja4_hash_enc

    Therefore we must NOT require ja4_hash_enc to already
    exist in the Parquet file.

    We only verify columns that preprocessing needs directly.
    """

    # These are created by preprocess().
    derived_columns = {
        "ja4_hash_enc",
    }

    # cipher_suite_enc already exists in your Parquet files,
    # but preprocess() can generate/use the encoded representation.
    #
    # Therefore we don't require it as a raw input either.
    derived_columns.add("cipher_suite_enc")

    required_raw_columns = [
        column
        for column in FEATURE_COLUMNS
        if column not in derived_columns
    ]

    missing_columns = [
        column
        for column in required_raw_columns
        if column not in df.columns
    ]

    if missing_columns:

        print("\nMissing raw feature columns:")

        for column in missing_columns:
            print(f"  - {column}")

        raise RuntimeError(
            "\nBenign Parquet files are missing raw columns "
            "required by the preprocessing pipeline."
        )

    print(
        f"Raw feature validation passed."
    )

    print(
        f"  Required raw columns checked: "
        f"{len(required_raw_columns)}"
    )

    print(
        f"  Derived columns created/handled by preprocessing: "
        f"{', '.join(sorted(derived_columns))}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print("\n")
    print("=" * 60)
    print("       AEGIS — ISOLATION FOREST TRAINING")
    print("=" * 60)

    # --------------------------------------------------------
    # STEP 1 — CHECK DIRECTORIES
    # --------------------------------------------------------

    if not FEATURES_DIR.exists():

        raise RuntimeError(
            f"Feature directory does not exist: "
            f"{FEATURES_DIR}"
        )

    ML_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # STEP 2 — LOAD ALL BENIGN PARQUETS
    # --------------------------------------------------------

    print("\n[1/6] Loading benign traffic...")

    benign_df = load_benign_data()

    if len(benign_df) == 0:

        raise RuntimeError(
            "Benign Parquet files contain zero rows."
        )

    # --------------------------------------------------------
    # STEP 3 — VERIFY RAW FEATURES
    # --------------------------------------------------------

    print("\n[2/6] Checking raw feature columns...")

    check_raw_columns(benign_df)

    # --------------------------------------------------------
    # STEP 4 — PREPROCESS
    # --------------------------------------------------------

    print("\n[3/6] Preprocessing benign traffic...")

    print(
        "Fitting categorical encoders on benign traffic..."
    )

    # IMPORTANT:
    #
    # We intentionally fit separate preprocessing encoders
    # for the Isolation Forest.
    #
    # This creates:
    #
    #     ja4_hash -> ja4_hash_enc
    #
    # and handles the other preprocessing operations defined
    # in ml.train.preprocess().
    #
    # These encoders are saved separately below and MUST be
    # loaded by inference when preprocessing data for the
    # Isolation Forest.

    X_benign, encoders = preprocess(
        benign_df,
        encoders=None,
        fit=True
    )

    print(
        f"Feature matrix: "
        f"{X_benign.shape[0]} rows × "
        f"{X_benign.shape[1]} features"
    )

    # Make absolutely sure preprocessing produced the
    # expected number of features.

    if X_benign.shape[1] != len(FEATURE_COLUMNS):

        raise RuntimeError(
            f"Preprocessing produced "
            f"{X_benign.shape[1]} features, but "
            f"FEATURE_COLUMNS contains "
            f"{len(FEATURE_COLUMNS)} features."
        )

    # Check for NaN / infinite values before training.

    if X_benign.isna().any().any():

        nan_columns = X_benign.columns[
            X_benign.isna().any()
        ].tolist()

        raise RuntimeError(
            "NaN values remain after preprocessing "
            f"in columns: {nan_columns}"
        )

    if not np.isfinite(X_benign.to_numpy()).all():

        raise RuntimeError(
            "Infinite values remain in the feature matrix "
            "after preprocessing."
        )

    print(
        "Preprocessing validation passed."
    )

    # --------------------------------------------------------
    # STEP 5 — TRAIN ISOLATION FOREST
    # --------------------------------------------------------

    print("\n[4/6] Training Isolation Forest...")

    iso_forest = IsolationForest(

        n_estimators=N_ESTIMATORS,

        contamination=CONTAMINATION,

        random_state=RANDOM_SEED,

        n_jobs=-1
    )

    iso_forest.fit(
        X_benign
    )

    print(
        "Isolation Forest training complete."
    )

    # --------------------------------------------------------
    # STEP 6 — CALCULATE ANOMALY THRESHOLD
    # --------------------------------------------------------

    print("\n[5/6] Calculating anomaly threshold...")

    # sklearn score_samples():
    #
    #     higher = more normal
    #     lower  = more anomalous
    #
    # Negating the score gives:
    #
    #     higher = more anomalous

    scores = -iso_forest.score_samples(
        X_benign
    )

    # We want the top 1% of benign traffic to be considered
    # anomalous.
    #
    # Therefore use the 99th percentile as our explicit
    # anomaly threshold.

    threshold = float(
        np.percentile(
            scores,
            99
        )
    )

    print(
        f"Minimum score  : {scores.min():.6f}"
    )

    print(
        f"Maximum score  : {scores.max():.6f}"
    )

    print(
        f"Mean score     : {scores.mean():.6f}"
    )

    print(
        f"Median score   : {np.median(scores):.6f}"
    )

    print(
        f"99th percentile: {threshold:.6f}"
    )

    # --------------------------------------------------------
    # SAVE MODEL
    # --------------------------------------------------------

    model_path = (
        ML_DIR /
        "iso_forest.joblib"
    )

    encoder_path = (
        ML_DIR /
        "iso_forest_encoders.joblib"
    )

    # Save the model AND the custom threshold together.

    joblib.dump(

        {
            "model": iso_forest,

            "threshold": threshold,

            "feature_columns": list(FEATURE_COLUMNS),

            "contamination": CONTAMINATION,

            "n_estimators": N_ESTIMATORS,

            "random_state": RANDOM_SEED,

        },

        model_path
    )

    # Save the preprocessing encoders separately.

    joblib.dump(
        encoders,
        encoder_path
    )

    print(
        f"\nSaved model:"
        f"\n  {model_path}"
    )

    print(
        f"Saved encoders:"
        f"\n  {encoder_path}"
    )

    # --------------------------------------------------------
    # CREATE ANOMALY SCORE DISTRIBUTION
    # --------------------------------------------------------

    print("\n[6/6] Creating anomaly score plot...")

    plt.figure(
        figsize=(10, 6)
    )

    plt.hist(
        scores,
        bins=50,
        alpha=0.7
    )

    plt.axvline(
        threshold,
        color="red",
        linestyle="dashed",
        linewidth=2,
        label=(
            f"99th Percentile = "
            f"{threshold:.3f}"
        )
    )

    plt.title(
        "Isolation Forest Anomaly "
        "Score Distribution — Benign Traffic"
    )

    plt.xlabel(
        "Anomaly Score "
        "(Higher = More Anomalous)"
    )

    plt.ylabel(
        "Number of Flows"
    )

    plt.legend()

    plot_path = (
        ML_DIR /
        "iso_forest_scores.png"
    )

    plt.savefig(
        plot_path,
        dpi=150,
        bbox_inches="tight"
    )

    plt.close()

    print(
        f"Saved plot:"
        f"\n  {plot_path}"
    )

    # --------------------------------------------------------
    # FINAL SUMMARY
    # --------------------------------------------------------

    print("\n")
    print("=" * 60)
    print("       ISOLATION FOREST TRAINING COMPLETE")
    print("=" * 60)

    benign_file_count = len(
        list(
            FEATURES_DIR.glob(
                BENIGN_PATTERN
            )
        )
    )

    print(
        f"\nBenign files used : "
        f"{benign_file_count}"
    )

    print(
        f"Benign flows used : "
        f"{len(benign_df)}"
    )

    print(
        f"Features used     : "
        f"{X_benign.shape[1]}"
    )

    print(
        f"Trees             : "
        f"{N_ESTIMATORS}"
    )

    print(
        f"Contamination     : "
        f"{CONTAMINATION}"
    )

    print(
        f"Threshold         : "
        f"{threshold:.6f}"
    )

    print(
        f"\nModel             : "
        f"{model_path}"
    )

    print(
        f"Encoders          : "
        f"{encoder_path}"
    )

    print(
        f"Score plot        : "
        f"{plot_path}"
    )

    print()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()