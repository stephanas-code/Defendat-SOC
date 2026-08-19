"""Train XGBoost multi-class classifier for attack type classification.

This script trains an XGBoost classifier to categorize network traffic into different attack types
and benign traffic. It uses the CIC-IDS2017 dataset features.

Usage:
  python scripts/train_xgboost.py --features artifacts/processed/xgboost_features.npy --labels artifacts/processed/xgboost_labels.npy --label-names artifacts/processed/xgboost_label_names.txt --output artifacts
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import xgboost as xgb


def main() -> None:
    ap = argparse.ArgumentParser(description="Train XGBoost multi-class classifier")
    ap.add_argument("--features", required=True, help="features .npy shape (n, 44)")
    ap.add_argument("--labels", required=True, help="labels .npy shape (n,)")
    ap.add_argument("--label-names", required=True, help="label names text file (one per line)")
    ap.add_argument("--output", required=True, help="Output directory for model artifacts")
    ap.add_argument("--max-depth", type=int, default=6, help="Maximum tree depth")
    ap.add_argument("--eta", type=float, default=0.1, help="Learning rate")
    ap.add_argument("--rounds", type=int, default=200, help="Number of boosting rounds")
    args = ap.parse_args()

    print(f"Loading features from {args.features}")
    X = np.load(args.features).astype(np.float32)
    print(f"Loaded {X.shape[0]} samples with {X.shape[1]} features")
    
    print(f"Loading labels from {args.labels}")
    y = np.load(args.labels).astype(np.int64)
    print(f"Loaded {len(y)} labels")
    
    print(f"Loading label names from {args.label_names}")
    with open(args.label_names, "r", encoding="utf-8") as f:
        labels = [line.strip() for line in f if line.strip()]
    print(f"Found {len(labels)} classes: {labels}")

    print("Creating XGBoost DMatrix...")
    dtrain = xgb.DMatrix(X, label=y)
    
    params = {
        "objective": "multi:softprob",
        "num_class": len(labels),
        "max_depth": args.max_depth,
        "eta": args.eta,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "eval_metric": "mlogloss",
    }

    print(f"Training XGBoost model (max_depth={args.max_depth}, eta={args.eta}, rounds={args.rounds})...")
    booster = xgb.train(params, dtrain, num_boost_round=args.rounds)

    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)
    
    print("Saving model artifacts...")
    booster.save_model(outdir / "xgboost.json")
    with open(outdir / "xgboost_labels.json", "w", encoding="utf-8") as f:
        json.dump(labels, f)
    
    print(f"Model saved to {outdir}")
    print("  - xgboost.json")
    print("  - xgboost_labels.json")


if __name__ == "__main__":
    main()
