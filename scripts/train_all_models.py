"""Complete training pipeline for all ML models.

This script automates the entire training process:
1. Prepare training data from CSV artifacts (CIC-IDS2017 dataset)
2. Train Isolation Forest for anomaly detection
3. Train XGBoost for attack classification

Note: For DNS-specific training, use prepare_dns_training_data.py separately.

Usage:
  python scripts/train_all_models.py --artifacts-dir artifacts/CSVs --output-dir artifacts
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def run_command(cmd: list[str], description: str) -> bool:
    """Run a command and report success/failure."""
    print(f"\n{'='*60}")
    print(f"  {description}")
    print(f"{'='*60}")
    print(f"Running: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        print(f"✓ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ {description} failed")
        print("STDOUT:", e.stdout)
        print("STDERR:", e.stderr)
        return False


def main():
    ap = argparse.ArgumentParser(description="Train all ML models for attack detection")
    ap.add_argument("--artifacts-dir", default="artifacts/CSVs", help="Directory containing CIC-IDS2017 CSV files")
    ap.add_argument("--output-dir", default="artifacts", help="Output directory for model artifacts")
    ap.add_argument("--max-samples", type=int, default=10000, help="Max samples per CSV file for training")
    ap.add_argument("--skip-prep", action="store_true", help="Skip data preparation if already done")
    args = ap.parse_args()
    
    artifacts_dir = Path(args.artifacts_dir)
    output_dir = Path(args.output_dir)
    processed_dir = output_dir / "processed"
    
    # Check if artifacts directory exists
    if not artifacts_dir.exists():
        print(f"Error: Artifacts directory {artifacts_dir} does not exist")
        print("Please ensure you have the CSV files in the artifacts/CSVs directory")
        print("For DNS training, use: python scripts/prepare_dns_training_data.py")
        sys.exit(1)
    
    # Check if there are CSV files
    csv_files = list(artifacts_dir.glob("*.csv"))
    if not csv_files:
        print(f"Error: No CSV files found in {artifacts_dir}")
        print("For DNS training, use the BCCC-CIC-Bell-DNS2021 dataset:")
        print("  python scripts/prepare_dns_training_data.py --dns-dir artifacts/BCCC-CIC-Bell-DNS2021")
        sys.exit(1)
    
    print(f"Found {len(csv_files)} CSV files in {artifacts_dir}")
    print("Using CIC-IDS2017 dataset for network flow-based training")
    
    # Step 1: Prepare training data
    if not args.skip_prep:
        success = run_command([
            "python", "scripts/prepare_training_data.py",
            "--artifacts-dir", str(artifacts_dir),
            "--output-dir", str(processed_dir),
            "--max-samples", str(args.max_samples)
        ], "Step 1: Preparing training data")
        
        if not success:
            print("Failed to prepare training data. Exiting.")
            sys.exit(1)
    else:
        print("\nSkipping data preparation (using existing processed data)")
    
    # Check if processed data exists
    benign_features = processed_dir / "benign_features.npy"
    xgboost_features = processed_dir / "xgboost_features.npy"
    xgboost_labels = processed_dir / "xgboost_labels.npy"
    xgboost_label_names = processed_dir / "xgboost_label_names.txt"
    
    if not all([benign_features.exists(), xgboost_features.exists(), 
                xgboost_labels.exists(), xgboost_label_names.exists()]):
        print("Error: Processed data files not found. Run without --skip-prep first.")
        sys.exit(1)
    
    # Step 2: Train Isolation Forest
    success = run_command([
        "python", "scripts/train_isoforest.py",
        "--input", str(benign_features),
        "--output", str(output_dir)
    ], "Step 2: Training Isolation Forest (Anomaly Detection)")
    
    if not success:
        print("Failed to train Isolation Forest. Continuing with XGBoost...")
    
    # Step 3: Train XGBoost
    success = run_command([
        "python", "scripts/train_xgboost.py",
        "--features", str(xgboost_features),
        "--labels", str(xgboost_labels),
        "--label-names", str(xgboost_label_names),
        "--output", str(output_dir)
    ], "Step 3: Training XGBoost (Attack Classification)")
    
    if not success:
        print("Failed to train XGBoost.")
    
    # Summary
    print(f"\n{'='*60}")
    print("  Training Pipeline Complete")
    print(f"{'='*60}")
    print(f"Model artifacts saved to: {output_dir}")
    print("\nExpected files:")
    print(f"  - {output_dir}/scaler.joblib (feature scaler)")
    print(f"  - {output_dir}/isoforest.joblib (Isolation Forest model)")
    print(f"  - {output_dir}/xgboost.json (XGBoost model)")
    print(f"  - {output_dir}/xgboost_labels.json (attack type labels)")
    
    print("\nDNS Training (Optional):")
    print("For DNS-specific attack detection, use:")
    print("  python scripts/prepare_dns_training_data.py --dns-dir artifacts/BCCC-CIC-Bell-DNS2021")
    
    print("\nNext steps:")
    print("1. Restart the backend: docker-compose restart backend")
    print("2. Check model status: curl http://localhost:8000/health")
    print("3. Test with attack data: python scripts/replay_network_flows.py --csv artifacts/CSVs/ddos_loit.csv --backend http://localhost:8000")
    print("4. Monitor dashboard: http://localhost:3000")


if __name__ == "__main__":
    main()
