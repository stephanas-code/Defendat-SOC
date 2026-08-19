"""Prepare training data from CSV artifacts for ML model training.

This script processes the CIC-IDS2017 style CSV files in artifacts/CSVs/ 
and converts them to the format expected by the training scripts.

Usage:
  python scripts/prepare_training_data.py --artifacts-dir artifacts/CSVs --output-dir artifacts/processed
"""

from __future__ import annotations

import argparse
import csv
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple
import random


# Mapping from CSV column names to 44-feature schema
CSV_TO_FEATURES = {
    "duration": "flow_duration_ms",
    "packets_count": "tot_fwd_pkts", 
    "fwd_packets_count": "tot_fwd_pkts",
    "bwd_packets_count": "tot_bwd_pkts",
    "total_payload_bytes": "totlen_fwd_pkts",  # Will need adjustment
    "fwd_total_payload_bytes": "totlen_fwd_pkts",
    "bwd_total_payload_bytes": "totlen_bwd_pkts",
    "payload_bytes_max": "fwd_pkt_len_max",
    "payload_bytes_min": "fwd_pkt_len_min", 
    "payload_bytes_mean": "fwd_pkt_len_mean",
    "payload_bytes_std": "fwd_pkt_len_std",
    "payload_bytes_variance": "fwd_pkt_len_std",  # Will take sqrt
    "fwd_payload_bytes_max": "fwd_pkt_len_max",
    "fwd_payload_bytes_min": "fwd_pkt_len_min",
    "fwd_payload_bytes_mean": "fwd_pkt_len_mean",
    "fwd_payload_bytes_std": "fwd_pkt_len_std",
    "fwd_payload_bytes_variance": "fwd_pkt_len_std",
    "bwd_payload_bytes_max": "bwd_pkt_len_max",
    "bwd_payload_bytes_min": "bwd_pkt_len_min",
    "bwd_payload_bytes_mean": "bwd_pkt_len_mean",
    "bwd_payload_bytes_std": "bwd_pkt_len_std",
    "bwd_payload_bytes_variance": "bwd_pkt_len_std",
    "total_header_bytes": "fwd_header_len",  # Will need adjustment
    "fwd_total_header_bytes": "fwd_header_len",
    "bwd_total_header_bytes": "bwd_header_len",
    "max_header_bytes": "fwd_header_len",  # Approximation
    "min_header_bytes": "fwd_header_len",   # Approximation
    "mean_header_bytes": "fwd_header_len",  # Approximation
    "std_header_bytes": "fwd_header_len",   # Approximation
    "fwd_max_header_bytes": "fwd_header_len",
    "fwd_min_header_bytes": "fwd_header_len", 
    "fwd_mean_header_bytes": "fwd_header_len",
    "fwd_std_header_bytes": "fwd_header_len",
    "bwd_max_header_bytes": "bwd_header_len",
    "bwd_min_header_bytes": "bwd_header_len",
    "bwd_mean_header_bytes": "bwd_header_len",
    "bwd_std_header_bytes": "bwd_header_len",
    "fwd_avg_segment_size": "fwd_pkt_len_mean",  # Approximation
    "bwd_avg_segment_size": "bwd_pkt_len_mean",  # Approximation
    "avg_segment_size": "pkt_len_mean",         # Approximation
    "bytes_rate": "flow_byts_s",
    "fwd_bytes_rate": "flow_byts_s",            # Approximation
    "bwd_bytes_rate": "flow_byts_s",            # Approximation
    "packets_rate": "flow_pkts_s",
    "bwd_packets_rate": "bwd_pkts_s",
    "fwd_packets_rate": "fwd_pkts_s",
    "down_up_rate": "flow_byts_s",             # Approximation
    "active_min": "flow_iat_min",              # Approximation
    "active_max": "flow_iat_max",              # Approximation
    "active_mean": "flow_iat_mean",            # Approximation
    "active_std": "flow_iat_std",              # Approximation
    "idle_min": "flow_iat_min",                # Approximation
    "idle_max": "flow_iat_max",                # Approximation
    "idle_mean": "flow_iat_mean",              # Approximation
    "idle_std": "flow_iat_std",                # Approximation
    "packets_IAT_mean": "flow_iat_mean",
    "packet_IAT_std": "flow_iat_std",
    "packet_IAT_max": "flow_iat_max",
    "packet_IAT_min": "flow_iat_min",
    "packet_IAT_total": "fwd_iat_total",
    "fwd_packets_IAT_mean": "fwd_iat_mean",
    "fwd_packets_IAT_std": "fwd_iat_std",
    "fwd_packets_IAT_max": "fwd_iat_max",
    "fwd_packets_IAT_min": "fwd_iat_min",
    "fwd_packets_IAT_total": "fwd_iat_total",
    "bwd_packets_IAT_mean": "bwd_iat_mean",
    "bwd_packets_IAT_std": "bwd_iat_std",
    "bwd_packets_IAT_max": "bwd_iat_max",
    "bwd_packets_IAT_min": "bwd_iat_min",
    "bwd_packets_IAT_total": "bwd_iat_total",
    "subflow_fwd_packets": "tot_fwd_pkts",
    "subflow_bwd_packets": "tot_bwd_pkts",
    "subflow_fwd_bytes": "totlen_fwd_pkts",
    "subflow_bwd_bytes": "totlen_bwd_pkts",
    "fin_flag_counts": "fin_flag_cnt",
    "psh_flag_counts": "fwd_psh_flags",        # Will need adjustment
    "urg_flag_counts": "fwd_urg_flags",        # Will need adjustment
    "ece_flag_counts": 0,                      # Not in original schema
    "syn_flag_counts": "syn_flag_cnt",
    "ack_flag_counts": "ack_flag_cnt",
    "cwr_flag_counts": 0,                      # Not in original schema
    "rst_flag_counts": "rst_flag_cnt",
    "fwd_fin_flag_counts": "fin_flag_cnt",
    "fwd_psh_flag_counts": "fwd_psh_flags",
    "fwd_urg_flag_counts": "fwd_urg_flags",
    "fwd_ece_flag_counts": 0,
    "fwd_syn_flag_counts": "syn_flag_cnt",
    "fwd_ack_flag_counts": "ack_flag_cnt",
    "fwd_cwr_flag_counts": 0,
    "fwd_rst_flag_counts": "rst_flag_cnt",
    "bwd_fin_flag_counts": "fin_flag_cnt",
    "bwd_psh_flag_counts": "bwd_psh_flags",
    "bwd_urg_flag_counts": "bwd_urg_flags",
    "bwd_ece_flag_counts": 0,
    "bwd_syn_flag_counts": "syn_flag_cnt",
    "bwd_ack_flag_counts": "ack_flag_cnt",
    "bwd_cwr_flag_counts": 0,
    "bwd_rst_flag_counts": "rst_flag_cnt",
}

# The 44 features we need
FEATURES_44 = [
    "flow_duration_ms", "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts", "totlen_bwd_pkts",
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "flow_byts_s", "flow_pkts_s", "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_total", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fwd_header_len", "bwd_header_len", "fwd_pkts_s", "bwd_pkts_s",
    "pkt_len_min", "pkt_len_max", "pkt_len_mean", "pkt_len_std",
    "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "ack_flag_cnt"
]


def extract_features_from_csv_row(row: Dict[str, str]) -> np.ndarray:
    """Extract features from a CSV row."""
    features = np.zeros(len(FEATURES_44), dtype=np.float32)
    
    for i, feature_name in enumerate(FEATURES_44):
        # Try to find a matching CSV column
        value = 0.0
        for csv_col, mapped_feature in CSV_TO_FEATURES.items():
            if mapped_feature == feature_name and csv_col in row:
                try:
                    val = float(row[csv_col])
                    # Handle variance to std conversion
                    if "variance" in csv_col.lower() and val > 0:
                        value = np.sqrt(val)
                    else:
                        value = val
                    break
                except (ValueError, TypeError):
                    value = 0.0
        
        # Special handling for derived features
        if feature_name == "pkt_len_mean" and value == 0.0:
            # Approximate from fwd/bwd mean
            fwd_mean = 0.0
            bwd_mean = 0.0
            if "fwd_payload_bytes_mean" in row:
                try:
                    fwd_mean = float(row["fwd_payload_bytes_mean"])
                except:
                    pass
            if "bwd_payload_bytes_mean" in row:
                try:
                    bwd_mean = float(row["bwd_payload_bytes_mean"])
                except:
                    pass
            if fwd_mean > 0 or bwd_mean > 0:
                value = (fwd_mean + bwd_mean) / 2.0
        
        if feature_name == "pkt_len_max" and value == 0.0:
            # Take max of fwd/bwd max
            fwd_max = 0.0
            bwd_max = 0.0
            if "fwd_payload_bytes_max" in row:
                try:
                    fwd_max = float(row["fwd_payload_bytes_max"])
                except:
                    pass
            if "bwd_payload_bytes_max" in row:
                try:
                    bwd_max = float(row["bwd_payload_bytes_max"])
                except:
                    pass
            value = max(fwd_max, bwd_max)
        
        if feature_name == "pkt_len_min" and value == 0.0:
            # Take min of fwd/bwd min
            fwd_min = 0.0
            bwd_min = 0.0
            if "fwd_payload_bytes_min" in row:
                try:
                    fwd_min = float(row["fwd_payload_bytes_min"])
                except:
                    pass
            if "bwd_payload_bytes_min" in row:
                try:
                    bwd_min = float(row["bwd_payload_bytes_min"])
                except:
                    pass
            value = min(fwd_min, bwd_min) if fwd_min > 0 and bwd_min > 0 else fwd_min + bwd_min
        
        if feature_name == "pkt_len_std" and value == 0.0:
            # Approximate from fwd/bwd std
            fwd_std = 0.0
            bwd_std = 0.0
            if "fwd_payload_bytes_std" in row:
                try:
                    fwd_std = float(row["fwd_payload_bytes_std"])
                except:
                    pass
            if "bwd_payload_bytes_std" in row:
                try:
                    bwd_std = float(row["bwd_payload_bytes_std"])
                except:
                    pass
            value = (fwd_std + bwd_std) / 2.0
        
        # Handle bidirectional flag counts
        if feature_name == "fwd_psh_flags" and "fwd_psh_flag_counts" in row:
            try:
                value = float(row["fwd_psh_flag_counts"])
            except:
                pass
        if feature_name == "bwd_psh_flags" and "bwd_psh_flag_counts" in row:
            try:
                value = float(row["bwd_psh_flag_counts"])
            except:
                pass
        if feature_name == "fwd_urg_flags" and "fwd_urg_flag_counts" in row:
            try:
                value = float(row["fwd_urg_flag_counts"])
            except:
                pass
        if feature_name == "bwd_urg_flags" and "bwd_urg_flag_counts" in row:
            try:
                value = float(row["bwd_urg_flag_counts"])
            except:
                pass
        
        features[i] = value
    
    return features


def process_csv_file(csv_path: Path, label_filter: str = None, max_samples: int = None) -> Tuple[np.ndarray, List[str]]:
    """Process a CSV file and extract features with labels."""
    features_list = []
    labels_list = []
    
    print(f"Processing {csv_path.name}...")
    
    with open(csv_path, 'r', encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if max_samples and len(features_list) >= max_samples:
                break
                
            label = row.get('label', 'Unknown')
            
            # Apply label filter if specified
            if label_filter and label_filter.lower() not in label.lower():
                continue
                
            try:
                features = extract_features_from_csv_row(row)
                features_list.append(features)
                labels_list.append(label)
            except Exception as e:
                print(f"Error processing row: {e}")
                continue
    
    return np.array(features_list, dtype=np.float32), labels_list


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts-dir", default="artifacts/CSVs", help="Directory containing CSV files")
    ap.add_argument("--output-dir", default="artifacts/processed", help="Output directory for processed data")
    ap.add_argument("--max-samples", type=int, default=10000, help="Max samples per file")
    args = ap.parse_args()
    
    artifacts_dir = Path(args.artifacts_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Process benign data for Isolation Forest
    print("\n=== Processing Benign Data for Isolation Forest ===")
    benign_files = [f for f in artifacts_dir.glob("*.csv") if "benign" in f.name.lower()]
    
    all_benign_features = []
    for benign_file in benign_files:
        features, labels = process_csv_file(benign_file, label_filter="Benign", max_samples=args.max_samples)
        all_benign_features.append(features)
        print(f"  Extracted {len(features)} benign samples from {benign_file.name}")
    
    if all_benign_features:
        combined_benign = np.vstack(all_benign_features)
        np.save(output_dir / "benign_features.npy", combined_benign)
        print(f"Saved {len(combined_benign)} total benign samples to benign_features.npy")
    
    # Process attack data for XGBoost
    print("\n=== Processing Attack Data for XGBoost ===")
    attack_files = [f for f in artifacts_dir.glob("*.csv") if "benign" not in f.name.lower()]
    
    all_features = []
    all_labels = []
    label_mapping = {}
    label_counter = 0
    
    # First, collect some benign data too
    for benign_file in benign_files[:2]:  # Use first 2 benign files
        features, labels = process_csv_file(benign_file, max_samples=args.max_samples // 2)
        all_features.append(features)
        all_labels.extend(labels)
    
    for attack_file in attack_files:
        features, labels = process_csv_file(attack_file, max_samples=args.max_samples)
        all_features.append(features)
        
        # Create label mapping
        for label in labels:
            if label not in label_mapping:
                label_mapping[label] = label_counter
                label_counter += 1
        all_labels.extend(labels)
        print(f"  Extracted {len(features)} samples from {attack_file.name}")
    
    if all_features:
        combined_features = np.vstack(all_features)
        combined_labels = np.array([label_mapping[label] for label in all_labels], dtype=np.int64)
        
        np.save(output_dir / "xgboost_features.npy", combined_features)
        np.save(output_dir / "xgboost_labels.npy", combined_labels)
        
        # Save label mapping
        with open(output_dir / "xgboost_label_names.txt", "w", encoding="utf-8") as f:
            # Create reverse mapping
            reverse_mapping = {v: k for k, v in label_mapping.items()}
            for i in range(len(reverse_mapping)):
                f.write(f"{reverse_mapping[i]}\n")
        
        print(f"Saved {len(combined_features)} total samples with {len(label_mapping)} classes")
        print(f"Label mapping: {label_mapping}")
    
    print(f"\n=== Processing Complete ===")
    print(f"Output directory: {output_dir}")
    print(f"Files generated:")
    print(f"  - benign_features.npy (for Isolation Forest)")
    print(f"  - xgboost_features.npy (for XGBoost)")
    print(f"  - xgboost_labels.npy (for XGBoost)")
    print(f"  - xgboost_label_names.txt (for XGBoost)")


if __name__ == "__main__":
    main()
