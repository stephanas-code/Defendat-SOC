"""Prepare DNS-specific training data from BCCC-CIC-Bell-DNS2021 dataset.

This script processes DNS traffic data for specialized DNS attack detection.
It extracts DNS-specific features that can complement the 44-feature network flow analysis.

Usage:
  python scripts/prepare_dns_training_data.py --dns-dir artifacts/BCCC-CIC-Bell-DNS2021 --output-dir artifacts/processed_dns
"""

from __future__ import annotations

import argparse
import csv
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple


def extract_dns_features_from_csv_row(row: Dict[str, str]) -> np.ndarray:
    """Extract DNS-specific features from a CSV row."""
    # We'll extract a subset of features that are most relevant for DNS analysis
    # and can potentially be integrated with the 44-feature schema
    
    features = []
    
    # Basic flow features (compatible with 44-feature schema)
    try:
        duration = float(row.get("duration", 0))
        packets = int(row.get("packets_numbers", 0))
        total_bytes = int(row.get("total_bytes", 0))
        receiving_bytes = int(row.get("receiving_bytes", 0))
        sending_bytes = int(row.get("sending_bytes", 0))
        
        features.extend([duration, packets, total_bytes, receiving_bytes, sending_bytes])
    except (ValueError, TypeError):
        features.extend([0.0, 0, 0, 0, 0])
    
    # DNS-specific features
    try:
        domain_name = row.get("dns_domain_name", "")
        domain_length = len(domain_name)
        subdomain_count = domain_name.count('.') if domain_name else 0
        
        # Character analysis
        numerical_percentage = float(row.get("numerical_percentage", 0))
        character_entropy = float(row.get("character_entropy", 0))
        
        # Domain structure
        tld = row.get("dns_top_level_domain", "")
        second_level = row.get("dns_second_level_domain", "")
        tld_length = len(tld)
        second_level_length = len(second_level)
        
        features.extend([domain_length, subdomain_count, numerical_percentage, 
                       character_entropy, tld_length, second_level_length])
    except (ValueError, TypeError):
        features.extend([0, 0, 0.0, 0.0, 0, 0])
    
    # TTL analysis features
    try:
        ttl_min = float(row.get("ttl_values_min", -1))
        ttl_max = float(row.get("ttl_values_max", -1))
        ttl_mean = float(row.get("ttl_values_mean", -1))
        ttl_variance = float(row.get("ttl_values_variance", -1))
        distinct_ttl = int(row.get("distinct_ttl_values", 0))
        
        # Handle -1 values (indicating missing data)
        ttl_min = ttl_min if ttl_min >= 0 else 0
        ttl_max = ttl_max if ttl_max >= 0 else 0
        ttl_mean = ttl_mean if ttl_mean >= 0 else 0
        ttl_variance = ttl_variance if ttl_variance >= 0 else 0
        
        features.extend([ttl_min, ttl_max, ttl_mean, ttl_variance, distinct_ttl])
    except (ValueError, TypeError):
        features.extend([0.0, 0.0, 0.0, 0.0, 0])
    
    # DNS record features
    try:
        distinct_a = int(row.get("distinct_A_records", 0))
        distinct_ns = int(row.get("distinct_NS_records", 0))
        avg_authority = float(row.get("average_authority_resource_records", 0))
        avg_additional = float(row.get("average_additional_resource_records", 0))
        avg_answer = float(row.get("average_answer_resource_records", 0))
        
        features.extend([distinct_a, distinct_ns, avg_authority, avg_additional, avg_answer])
    except (ValueError, TypeError):
        features.extend([0, 0, 0.0, 0.0, 0.0])
    
    return np.array(features, dtype=np.float32)


def process_dns_csv_file(csv_path: Path, label_filter: str = None, max_samples: int = None) -> Tuple[np.ndarray, List[str]]:
    """Process a DNS CSV file and extract features with labels."""
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
                features = extract_dns_features_from_csv_row(row)
                features_list.append(features)
                labels_list.append(label)
            except Exception as e:
                print(f"Error processing row: {e}")
                continue
    
    return np.array(features_list, dtype=np.float32), labels_list


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dns-dir", default="artifacts/BCCC-CIC-Bell-DNS2021", help="Directory containing DNS CSV files")
    ap.add_argument("--output-dir", default="artifacts/processed_dns", help="Output directory for processed DNS data")
    ap.add_argument("--max-samples", type=int, default=5000, help="Max samples per file")
    args = ap.parse_args()
    
    dns_dir = Path(args.dns_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    if not dns_dir.exists():
        print(f"Error: DNS directory {dns_dir} does not exist")
        return
    
    # Process benign DNS data
    print("\n=== Processing Benign DNS Data ===")
    benign_files = [f for f in dns_dir.glob("*.csv") if "benign" in f.name.lower()]
    
    all_benign_features = []
    for benign_file in benign_files:
        features, labels = process_dns_csv_file(benign_file, label_filter="benign", max_samples=args.max_samples)
        all_benign_features.append(features)
        print(f"  Extracted {len(features)} benign samples from {benign_file.name}")
    
    if all_benign_features:
        combined_benign = np.vstack(all_benign_features)
        np.save(output_dir / "dns_benign_features.npy", combined_benign)
        print(f"Saved {len(combined_benign)} total benign samples to dns_benign_features.npy")
    
    # Process attack DNS data
    print("\n=== Processing Attack DNS Data ===")
    attack_files = [f for f in dns_dir.glob("*.csv") if "benign" not in f.name.lower()]
    
    all_features = []
    all_labels = []
    label_mapping = {}
    label_counter = 0
    
    for attack_file in attack_files:
        features, labels = process_dns_csv_file(attack_file, max_samples=args.max_samples)
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
        
        np.save(output_dir / "dns_attack_features.npy", combined_features)
        np.save(output_dir / "dns_attack_labels.npy", combined_labels)
        
        # Save label mapping
        with open(output_dir / "dns_attack_label_names.txt", "w", encoding="utf-8") as f:
            reverse_mapping = {v: k for k, v in label_mapping.items()}
            for i in range(len(reverse_mapping)):
                f.write(f"{reverse_mapping[i]}\n")
        
        print(f"Saved {len(combined_features)} total samples with {len(label_mapping)} classes")
        print(f"Label mapping: {label_mapping}")
    
    print(f"\n=== DNS Data Processing Complete ===")
    print(f"Output directory: {output_dir}")
    print(f"Files generated:")
    print(f"  - dns_benign_features.npy (for DNS anomaly detection)")
    print(f"  - dns_attack_features.npy (for DNS attack classification)")
    print(f"  - dns_attack_labels.npy (for DNS attack classification)")
    print(f"  - dns_attack_label_names.txt (for DNS attack classification)")
    
    print(f"\nNote: DNS-specific features require specialized DNS detection models.")
    print(f"These features complement but don't replace the 44-feature network flow analysis.")


if __name__ == "__main__":
    main()
