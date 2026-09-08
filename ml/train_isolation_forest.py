import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import matplotlib.pyplot as plt
from pathlib import Path
from features.schema import FEATURE_COLUMNS
from ml.train import load_labels, load_parquet_files, preprocess, LABELS_DIR, FEATURES_DIR

def main():
    labels = load_labels(LABELS_DIR)
    
    # Load all parquet files
    try:
        df = load_parquet_files(FEATURES_DIR, labels)
    except Exception as e:
        print("Failed to load real parquet, falling back to synthetic for Isolation Forest...")
        from ml.train import generate_synthetic_data
        df = generate_synthetic_data()

    if len(df) == 0:
        from ml.train import generate_synthetic_data
        df = generate_synthetic_data()

    # Filter for benign
    benign_df = df[df["label"] == "benign"].copy()
    print(f"Training on {len(benign_df)} benign samples.")
    
    # Preprocess
    encoders = joblib.load("ml/encoders.joblib") if Path("ml/encoders.joblib").exists() else {}
    X_benign, encoders = preprocess(benign_df, encoders, fit=False)

    # Train Isolation Forest
    # Contamination set to 0.01 (top 1% of benign flows)
    iso_forest = IsolationForest(contamination=0.01, random_state=42, n_jobs=-1)
    iso_forest.fit(X_benign)

    # Save model
    joblib.dump(iso_forest, "ml/iso_forest.joblib")
    print("Saved Isolation Forest to ml/iso_forest.joblib")

    # Plot anomaly score distribution
    scores = -iso_forest.score_samples(X_benign)
    plt.figure(figsize=(10, 6))
    plt.hist(scores, bins=50, alpha=0.7)
    plt.title("Anomaly Score Distribution (Benign Traffic)")
    plt.xlabel("Anomaly Score (Higher is more anomalous)")
    plt.ylabel("Frequency")
    
    threshold = np.percentile(scores, 99)
    plt.axvline(threshold, color='red', linestyle='dashed', linewidth=2, label=f'99th Percentile: {threshold:.3f}')
    plt.legend()
    plt.savefig("ml/iso_forest_scores.png")
    print("Saved plot to ml/iso_forest_scores.png")

if __name__ == "__main__":
    main()
