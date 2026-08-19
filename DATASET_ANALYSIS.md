# Dataset Analysis and Model Training Guide

## Overview

This document provides a comprehensive analysis of all datasets available in the `artifacts/` directory and recommends which datasets are best suited for each ML model in the AI Anomaly IDS system.

## Available Datasets

The artifacts folder contains three different types of datasets:

### 1. CIC-IDS2017 Network Flow Dataset (`artifacts/CSVs/`)

**Purpose**: Network traffic flow analysis with 44+ features

The system includes the CIC-IDS2017 dataset with the following files:

### Benign Traffic Files (for Normal Baseline)
- `monday_benign.csv` (395MB) - Normal traffic on Monday
- `tuesday_benign.csv` (317MB) - Normal traffic on Tuesday  
- `wednesday_benign.csv` (318MB) - Normal traffic on Wednesday
- `thursday_benign.csv` (107MB) - Normal traffic on Thursday
- `friday_benign.csv` (292MB) - Normal traffic on Friday

### Attack Traffic Files
- `ddos_loit.csv` (91MB) - DDoS LOIT attack
- `dos_hulk.csv` (274MB) - DoS Hulk attack
- `dos_golden_eye.csv` (8MB) - DoS GoldenEye attack
- `dos_slowloris.csv` (4MB) - DoS Slowloris attack
- `dos_slowhttptest.csv` (5MB) - DoS SlowHTTPTest attack
- `botnet_ares.csv` (3MB) - Botnet Ares attack
- `portscan.csv` (118MB) - Port scanning attack
- `web_brute_force.csv` (1MB) - Web brute force attack
- `web_sql_injection.csv` (20KB) - SQL injection attack
- `web_xss.csv` (934KB) - XSS attack
- `ftp_patator.csv` (7MB) - FTP brute force attack
- `ssh_patator-new.csv` (4MB) - SSH brute force attack
- `heartbleed.csv` (12KB) - Heartbleed attack

## Dataset Structure Analysis

All CSV files contain **44+ flow features** compatible with the CICFlowMeter-style feature extraction used by this system. Each row represents a network flow with:

- **Flow identifiers**: flow_id, timestamp, src_ip, dst_ip, ports, protocol
- **Packet statistics**: packet counts, bytes, sizes (forward/backward)
- **Timing features**: duration, inter-arrival times, active/idle times
- **Flag counts**: TCP flags (FIN, SYN, RST, ACK, PSH, URG, etc.)
- **Rate features**: bytes/sec, packets/sec
- **Label**: Attack type or "Benign"

### 2. BCCC-CIC-Bell-DNS2021 DNS Dataset (`artifacts/BCCC-CIC-Bell-DNS2021/`)

**Purpose**: DNS traffic analysis with domain-based features

**Files**:
- `output-of-benign-0.csv` (1.03GB) - Benign DNS traffic
- `output-of-benign-1.csv` (1.04GB) - Benign DNS traffic
- `output-of-benign-2.csv` (1.04GB) - Benign DNS traffic
- `output-of-benign-3.csv` (838MB) - Benign DNS traffic
- `output-of-malware.csv` (104MB) - Malware-related DNS traffic
- `output-of-phishing.csv` (55MB) - Phishing-related DNS traffic
- `output-of-spam.csv` (35MB) - Spam-related DNS traffic

**Dataset Structure**:
- **Flow identifiers**: flow_id, timestamp, src_ip, dst_ip, ports, protocol
- **Packet statistics**: packets_numbers, bytes, rates (receiving/sending)
- **Packet length features**: min, max, mean, median, mode, std, variance for both directions
- **Timing features**: duration, handshake, delta times
- **DNS-specific features**: 
  - Domain name analysis (domain_name, TLD, second-level domain)
  - Domain length and subdomain analysis
  - N-gram analysis (uni-gram, bi-gram, tri-gram)
  - Character distribution and entropy
  - Numerical/alphabetic pattern analysis
  - TTL values analysis (min, max, mean, mode, variance, etc.)
  - DNS record types (A records, NS records, authority/additional/answer records)
- **Label**: Benign, Malware, Phishing, Spam

**Special Characteristics**:
- **DNS-focused**: Specifically designed for DNS-based attack detection
- **Domain analysis**: Rich features for domain name pattern recognition
- **Large benign dataset**: 4 large files of benign DNS traffic for good baseline
- **Attack types**: Malware, phishing, and spam DNS communication patterns

### 3. Global Cybersecurity Threats Dataset (`artifacts/Global_Cybersecurity_Threats_2015-2024.csv`)

**Purpose**: Incident-level cybersecurity threat analysis (NOT for network flow training)

**File**: `Global_Cybersecurity_Threats_2015-2024.csv` (251KB)

**Dataset Structure**:
- **Geographic**: Country
- **Temporal**: Year (2015-2024)
- **Attack Type**: Phishing, Ransomware, Man-in-the-Middle, DDoS, SQL Injection, Malware
- **Target Industry**: Education, Retail, IT, Telecommunications, Government, Banking, Healthcare
- **Impact Metrics**: Financial loss (million $), Number of affected users
- **Attack Details**: Attack source (Hacker Group, Nation-state, Insider, Unknown)
- **Vulnerability**: Security vulnerability type (Unpatched Software, Weak Passwords, Social Engineering, Zero-day)
- **Defense**: Defense mechanism used (VPN, Firewall, AI-based Detection, Antivirus, Encryption)
- **Response**: Incident resolution time (hours)

**Special Characteristics**:
- **Incident-level data**: Contains summary statistics of cyber incidents, not network flows
- **Business impact**: Focuses on financial and operational impact
- **Geographic distribution**: Global threat landscape analysis
- **Time series**: 10-year trend analysis (2015-2024)
- **Small size**: Only 251KB with limited rows compared to network flow datasets

**IMPORTANT**: This dataset is **NOT suitable** for training the 44-feature NIDS models because:
- It lacks network flow features (packet sizes, timing, flags, etc.)
- It contains incident summaries rather than individual network flows
- It doesn't have the required 44 CICFlowMeter-style features
- It's designed for dashboard demo purposes and threat intelligence analysis

**Use Case**: Perfect for the `replay_global_threats_csv.py` script to demonstrate the dashboard with realistic threat scenarios.

## Dataset Suitability Analysis

### For Network Flow-Based ML Models (Isolation Forest, XGBoost)

**✅ RECOMMENDED**: CIC-IDS2017 Dataset (`artifacts/CSVs/`)
- Contains 44+ network flow features
- Designed for NIDS training
- Multiple attack types with clear patterns
- Large sample sizes for effective training

**⚠️ CONDITIONAL**: BCCC-CIC-Bell-DNS2021 Dataset (`artifacts/BCCC-CIC-Bell-DNS2021/`)
- Contains DNS-specific features, not general network flow features
- Excellent for DNS-based attack detection
- Requires feature mapping to 44-feature schema
- Best for specialized DNS attack detection models

**❌ NOT SUITABLE**: Global Cybersecurity Threats Dataset
- Incident-level data, not network flows
- Lacks required 44 features
- Only suitable for dashboard demonstrations

### For DNS-Specific Attack Detection

**✅ HIGHLY RECOMMENDED**: BCCC-CIC-Bell-DNS2021 Dataset
- DNS-focused features and domain analysis
- Large benign DNS baseline (4 files)
- Clear attack categories (malware, phishing, spam)
- Rich domain name pattern features

### For Dashboard Demonstration

**✅ RECOMMENDED**: Global Cybersecurity Threats Dataset
- Realistic threat scenarios
- Geographic diversity
- Business impact metrics
- Easy to replay via existing script

## Model-Specific Dataset Recommendations

### 1. Isolation Forest (Anomaly Detection)

**Purpose**: Detects anomalies by learning normal traffic patterns and flagging deviations.

**Best Dataset**: **Benign traffic files only**

**Why**: Isolation Forest is an unsupervised anomaly detection algorithm that learns the distribution of normal data. It should be trained exclusively on benign traffic to establish a baseline of normal network behavior.

**Recommended Training Data**:
- Primary: `monday_benign.csv` (largest benign dataset)
- Secondary: `tuesday_benign.csv`, `wednesday_benign.csv` (for diversity)
- Sample size: 10,000-50,000 flows (configurable)

**Training Command**:
```bash
python scripts/train_isoforest.py \
  --input artifacts/processed/benign_features.npy \
  --output artifacts
```

### 2. XGBoost (Multi-class Classification)

**Purpose**: Classifies traffic into specific attack types and benign traffic.

**Best Dataset**: **Mixed benign and attack traffic**

**Why**: XGBoost is a supervised learning algorithm that requires labeled data. It needs examples of both benign traffic and various attack types to learn the distinguishing characteristics of each class.

**Recommended Training Data**:
- **Benign**: 2-3 benign files (monday, tuesday, wednesday)
- **DDoS/DoS**: ddos_loit.csv, dos_hulk.csv (high volume for better learning)
- **Botnet**: botnet_ares.csv
- **Web Attacks**: web_brute_force.csv, web_sql_injection.csv, web_xss.csv
- **Brute Force**: ftp_patator.csv, ssh_patator-new.csv
- **Port Scanning**: portscan.csv
- Sample size: 5,000-10,000 flows per attack type (configurable)

**Training Command**:
```bash
python scripts/train_xgboost.py \
  --features artifacts/processed/xgboost_features.npy \
  --labels artifacts/processed/xgboost_labels.npy \
  --label-names artifacts/processed/xgboost_label_names.txt \
  --output artifacts
```

### 3. LSTM Autoencoder (Temporal Anomaly Detection)

**Purpose**: Detects temporal anomalies in sequential network traffic patterns.

**Best Dataset**: **Time-series benign traffic with temporal patterns**

**Why**: LSTM autoencoders learn temporal dependencies in sequential data. They need benign traffic with clear temporal patterns to establish normal behavior baselines.

**Recommended Training Data**:
- Primary: `monday_benign.csv` (sorted by timestamp)
- Secondary: `tuesday_benign.csv`
- Requirement: Flows must be sorted by timestamp for temporal sequencing
- Sample size: 20,000+ flows for adequate temporal pattern learning

**Note**: LSTM training is currently a stub in this system and requires PyTorch/TensorFlow.

### 4. DNS-Specific Attack Detection (Specialized Model)

**Purpose**: Detect DNS-based attacks using domain name patterns and DNS traffic features.

**Best Dataset**: **BCCC-CIC-Bell-DNS2021 Dataset**

**Why**: This dataset is specifically designed for DNS attack detection with rich domain-based features that are not available in general network flow datasets.

**Recommended Training Data**:
- **Benign DNS**: All 4 benign files (output-of-benign-0.csv through output-of-benign-3.csv)
- **Malware DNS**: output-of-malware.csv (malware communication patterns)
- **Phishing DNS**: output-of-phishing.csv (phishing domain patterns)
- **Spam DNS**: output-of-spam.csv (spam-related DNS patterns)
- Sample size: 10,000-20,000 flows per category

**Special Features Available**:
- Domain name analysis (n-grams, character entropy, numerical patterns)
- TTL value analysis (distribution, variance, statistical properties)
- DNS record type analysis (A, NS, authority, additional records)
- Domain length and subdomain structure analysis

**Implementation Note**: This would require a specialized DNS-focused model or significant feature engineering to map DNS-specific features to the 44-feature schema. Currently, the system is optimized for general network flow analysis.

## Feature Compatibility Analysis

### CSV Schema vs. 44-Feature Schema

The CSV files use slightly different column names than the 44-feature schema expected by the system. The `prepare_training_data.py` script handles the mapping:

**CSV Columns** → **44-Feature Schema**:
- `duration` → `flow_duration_ms`
- `packets_count` → `tot_fwd_pkts`
- `fwd_packets_count` → `tot_fwd_pkts`
- `bwd_packets_count` → `tot_bwd_pkts`
- `fwd_total_payload_bytes` → `totlen_fwd_pkts`
- `bwd_total_payload_bytes` → `totlen_bwd_pkts`
- And 35+ additional mappings...

**Approximations Used**:
- Some derived features (like `pkt_len_mean`) are approximated from forward/backward components
- Bidirectional flag counts are split into forward/backward components
- Variance values are converted to standard deviation (sqrt)
- Missing features are set to 0 or approximated from available data

## Data Quality Assessment

### High-Quality Datasets (Recommended)
1. **ddos_loit.csv** - Clear DDoS patterns, good volume
2. **dos_hulk.csv** - High volume, clear DoS characteristics
3. **monday_benign.csv** - Large benign dataset, diverse normal traffic
4. **portscan.csv** - Distinct scanning patterns
5. **botnet_ares.csv** - Clear botnet communication patterns

### Medium-Quality Datasets
1. **web_brute_force.csv** - Limited volume but clear patterns
2. **ftp_patator.csv** - Good brute force patterns
3. **ssh_patator-new.csv** - Good SSH attack patterns
4. **dos_slowloris.csv** - Distinct slow attack patterns

### Low-Quality Datasets (Use with Caution)
1. **web_sql_injection.csv** - Very small sample (20KB)
2. **heartbleed.csv** - Very small sample (12KB)
3. **web_xss.csv** - Limited sample (934KB)

## Training Pipeline

### Automated Training

The system provides an automated training pipeline that:

1. **Data Preparation**: Extracts and maps features from CSV files
2. **Feature Engineering**: Applies the 44-feature schema mappings
3. **Model Training**: Trains both Isolation Forest and XGBoost
4. **Artifact Generation**: Saves model files for deployment

**Complete Training Command**:
```bash
python scripts/train_all_models.py \
  --artifacts-dir artifacts/CSVs \
  --output-dir artifacts \
  --max-samples 10000
```

### Manual Training Steps

If you prefer manual control over the training process:

#### Step 1: Prepare Training Data
```bash
python scripts/prepare_training_data.py \
  --artifacts-dir artifacts/CSVs \
  --output-dir artifacts/processed \
  --max-samples 10000
```

This generates:
- `artifacts/processed/benign_features.npy` (for Isolation Forest)
- `artifacts/processed/xgboost_features.npy` (for XGBoost)
- `artifacts/processed/xgboost_labels.npy` (for XGBoost)
- `artifacts/processed/xgboost_label_names.txt` (for XGBoost)

#### Step 2: Train Isolation Forest
```bash
python scripts/train_isoforest.py \
  --input artifacts/processed/benign_features.npy \
  --output artifacts
```

#### Step 3: Train XGBoost
```bash
python scripts/train_xgboost.py \
  --features artifacts/processed/xgboost_features.npy \
  --labels artifacts/processed/xgboost_labels.npy \
  --label-names artifacts/processed/xgboost_label_names.txt \
  --output artifacts
```

## Model Performance Expectations

### Isolation Forest
- **Training Time**: 2-5 minutes (10,000 samples)
- **Inference Speed**: <10ms per flow
- **Memory Usage**: ~50MB model size
- **Expected Accuracy**: 85-95% anomaly detection rate
- **False Positive Rate**: 5-10% (configurable via contamination parameter)

### XGBoost
- **Training Time**: 5-15 minutes (50,000 samples, multiple classes)
- **Inference Speed**: <5ms per flow
- **Memory Usage**: ~100MB model size
- **Expected Accuracy**: 90-98% classification accuracy
- **Best Performing Classes**: DDoS, DoS, Port Scanning
- **Challenging Classes**: Web attacks (limited training data)

## Deployment Considerations

### Model Selection for Production

**For High-Security Environments**:
- Use both Isolation Forest and XGBoost
- Isolation Forest for unknown threat detection
- XGBoost for known attack classification

**For Resource-Constrained Environments**:
- Use XGBoost only (faster inference, better accuracy)
- Skip Isolation Forest if resource constraints exist

**For Research/Testing**:
- Train all models including LSTM (when implemented)
- Compare performance across different approaches

### Retraining Strategy

**When to Retrain**:
- New attack types emerge in your network
- Model performance degrades over time
- Significant network traffic pattern changes
- Quarterly maintenance schedule

**Retraining Process**:
1. Collect new labeled data from your network
2. Append to existing training datasets
3. Run training pipeline with updated data
4. Validate model performance before deployment
5. Hot-swap model files in artifacts directory
6. Restart backend service

## Troubleshooting

### Common Issues

**Issue**: "ModuleNotFoundError: No module named 'xgboost'"
- **Solution**: Install XGBoost: `pip install xgboost`

**Issue**: "MemoryError during training"
- **Solution**: Reduce `--max-samples` parameter or use smaller datasets

**Issue**: "Poor model performance"
- **Solution**: 
  - Increase training sample size
  - Use higher-quality datasets
  - Adjust model hyperparameters
  - Ensure feature mapping is correct

**Issue**: "Model not loading in backend"
- **Solution**: 
  - Verify model files exist in artifacts directory
  - Check file permissions
  - Restart backend service
  - Check backend logs for specific errors

## Conclusion

The CIC-IDS2017 datasets in the artifacts folder are well-suited for training both Isolation Forest and XGBoost models:

- **Isolation Forest**: Train on benign traffic files (monday_benign.csv recommended)
- **XGBoost**: Train on mixed benign and attack files for multi-class classification
- **Feature Compatibility**: CSV files are compatible with 44-feature schema via mapping
- **Automation**: Use `train_all_models.py` for complete training pipeline

The automated training pipeline handles data preparation, feature mapping, and model training, making it easy to deploy the system with trained models for live attack detection.
