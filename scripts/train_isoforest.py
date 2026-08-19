"""Train Isolation Forest on benign-only flow feature vectors.

This script trains an Isolation Forest model for anomaly detection using benign network traffic data.
The model learns the normal patterns of network traffic and can flag anomalies.

Usage:
  python scripts/train_isoforest.py --input artifacts/processed/benign_features.npy --output artifacts
"""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


def main() -> None:
    ap = argparse.ArgumentParser(description="Train Isolation Forest for anomaly detection")
    ap.add_argument("--input", required=True, help=".npy file of shape (n, 44) benign only")
    ap.add_argument("--output", required=True, help="Output directory for model artifacts")
    ap.add_argument("--contamination", type=float, default=0.05, help="Expected proportion of outliers")
    ap.add_argument("--n-estimators", type=int, default=200, help="Number of trees in the forest")
    args = ap.parse_args()

    print(f"Loading benign features from {args.input}")
    x = np.load(args.input)
    print(f"Loaded {x.shape[0]} samples with {x.shape[1]} features")
    
    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)

    print("Training StandardScaler...")
    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(x)

    print(f"Training Isolation Forest (n_estimators={args.n_estimators}, contamination={args.contamination})...")
    clf = IsolationForest(n_estimators=args.n_estimators, contamination=args.contamination, random_state=42)
    clf.fit(x_scaled)

    print("Saving model artifacts...")
    joblib.dump(scaler, outdir / "scaler.joblib")
    joblib.dump(clf, outdir / "isoforest.joblib")
    
    print(f"Model saved to {outdir}")
    print("  - scaler.joblib")
    print("  - isoforest.joblib")


if __name__ == "__main__":
    main()
