# Artifacts Datasets Summary

## Overview

The `artifacts/` folder contains **three distinct datasets** designed for different purposes in the AI Anomaly IDS system. This document explains each dataset, which models should be trained with each, and why each model-dataset combination is optimal.

## Artifacts Folder Structure

```
artifacts/
├── CSVs/                                    # CIC-IDS2017 Network Flow Dataset
│   ├── monday_benign.csv                   # Benign traffic (395MB)
│   ├── tuesday_benign.csv                  # Benign traffic (317MB)
│   ├── wednesday_benign.csv                # Benign traffic (318MB)
│   ├── thursday_benign.csv                 # Benign traffic (107MB)
│   ├── friday_benign.csv                   # Benign traffic (292MB)
│   ├── ddos_loit.csv                       # DDoS LOIT attack (91MB)
│   ├── dos_hulk.csv                        # DoS Hulk attack (274MB)
│   ├── dos_golden_eye.csv                  # DoS GoldenEye (8MB)
│   ├── dos_slowloris.csv                   # DoS Slowloris (4MB)
│   ├── dos_slowhttptest.csv                # DoS SlowHTTPTest (5MB)
│   ├── botnet_ares.csv                     # Botnet Ares (3MB)
│   ├── portscan.csv                        # Port scanning (118MB)
│   ├── web_brute_force.csv                 # Web brute force (1MB)
│   ├── web_sql_injection.csv               # SQL injection (20KB)
│   ├── web_xss.csv                        # XSS attack (934KB)
│   ├── ftp_patator.csv                     # FTP brute force (7MB)
│   ├── ssh_patator-new.csv                 # SSH brute force (4MB)
│   └── heartbleed.csv                     # Heartbleed attack (12KB)
│
├── BCCC-CIC-Bell-DNS2021/                 # DNS-Specific Dataset
│   ├── output-of-benign-0.csv              # Benign DNS (1.03GB)
│   ├── output-of-benign-1.csv              # Benign DNS (1.04GB)
│   ├── output-of-benign-2.csv              # Benign DNS (1.04GB)
│   ├── output-of-benign-3.csv              # Benign DNS (838MB)
│   ├── output-of-malware.csv               # Malware DNS (104MB)
│   ├── output-of-phishing.csv              # Phishing DNS (55MB)
│   └── output-of-spam.csv                  # Spam DNS (35MB)
│
├── Global_Cybersecurity_Threats_2015-2024.csv  # Incident-level threats (251KB)
└── README.md                               # Dataset documentation
```

## Dataset Comparison Table

| Dataset | Location | Size | Primary Purpose | Recommended Models | Training Suitability |
|---------|----------|------|-----------------|-------------------|---------------------|
| **CIC-IDS2017** | `artifacts/CSVs/` | ~3GB | Network flow attack detection | Isolation Forest, XGBoost | ✅ **EXCELLENT** |
| **BCCC-CIC-Bell-DNS2021** | `artifacts/BCCC-CIC-Bell-DNS2021/` | ~4GB | DNS-specific attack detection | Specialized DNS models | ⚠️ **SPECIALIZED** |
| **Global Cybersecurity Threats** | `artifacts/Global_Cybersecurity_Threats_2015-2024.csv` | 251KB | Dashboard demo/threat intelligence | None (demo only) | ❌ **NOT SUITABLE** |

## Detailed Dataset-Model Analysis

### 1. CIC-IDS2017 Network Flow Dataset + Isolation Forest ✅

**Dataset**: `artifacts/CSVs/`
**Model**: Isolation Forest (Anomaly Detection)
**Training Files**: Benign traffic files only

#### Why This Combination is Optimal

**Dataset Strengths**:
- Contains 44+ CICFlowMeter-style network flow features
- Large benign traffic samples (monday_benign.csv: 395MB, tuesday_benign.csv: 317MB, etc.)
- Well-established benchmark dataset for NIDS
- Diverse normal traffic patterns across different days

**Model Strengths**:
- **Unsupervised learning**: Perfect for learning normal traffic patterns without labeled attack data
- **Anomaly detection**: Flags deviations from learned normal behavior
- **Fast inference**: <10ms per flow, suitable for real-time detection
- **Robust to outliers**: Handles noise in benign traffic well

**Why They Match Perfectly**:
1. **Feature Compatibility**: Dataset contains exact 44 features that Isolation Forest expects
2. **Learning Approach**: Isolation Forest learns from benign data only - dataset provides abundant benign samples
3. **Detection Capability**: Model detects unknown attacks by identifying deviations from normal patterns
4. **Production Ready**: Both dataset and model are industry standards for NIDS

**Training Command**:
```bash
python scripts/train_isoforest.py --input artifacts/processed/benign_features.npy --output artifacts
```

**Expected Performance**:
- Training time: 2-5 minutes (10,000-50,000 samples)
- Inference speed: <10ms per flow
- Anomaly detection rate: 85-95%
- False positive rate: 5-10% (configurable)

---

### 2. CIC-IDS2017 Network Flow Dataset + XGBoost ✅

**Dataset**: `artifacts/CSVs/`
**Model**: XGBoost (Multi-class Classification)
**Training Files**: Mixed benign + attack traffic files

#### Why This Combination is Optimal

**Dataset Strengths**:
- Multiple attack types with clear patterns (DDoS, DoS, Botnet, Web attacks, etc.)
- Large sample sizes for effective supervised learning
- Labeled data with specific attack categories
- Balanced representation of different attack vectors

**Model Strengths**:
- **Supervised learning**: Requires labeled data - dataset provides rich attack labels
- **Multi-class classification**: Can distinguish between different attack types
- **High accuracy**: 90-98% classification accuracy on network traffic
- **Feature importance**: Identifies which flow features are most predictive
- **Fast inference**: <5ms per flow

**Why They Match Perfectly**:
1. **Label Quality**: Dataset has accurate attack type labels needed for supervised learning
2. **Feature Richness**: 44 features provide sufficient information for accurate classification
3. **Attack Diversity**: Multiple attack types allow model to learn distinguishing characteristics
4. **Performance**: XGBoost excels at tabular data classification - perfect for flow features
5. **Interpretability**: Model can show which features indicate specific attack types

**Training Command**:
```bash
python scripts/train_xgboost.py --features artifacts/processed/xgboost_features.npy --labels artifacts/processed/xgboost_labels.npy --label-names artifacts/processed/xgboost_label_names.txt --output artifacts
```

**Expected Performance**:
- Training time: 5-15 minutes (50,000+ samples, multiple classes)
- Inference speed: <5ms per flow
- Classification accuracy: 90-98%
- Best performing classes: DDoS, DoS, Port Scanning
- Challenging classes: Web attacks (limited training data)

---

### 3. BCCC-CIC-Bell-DNS2021 DNS Dataset + Specialized DNS Models ⚠️

**Dataset**: `artifacts/BCCC-CIC-Bell-DNS2021/`
**Model**: Specialized DNS Detection Models (Custom Implementation Required)
**Training Files**: All DNS files (benign + attack)

#### Why This Combination is Specialized

**Dataset Strengths**:
- DNS-specific features not available in general network flow datasets
- Large benign DNS baseline (4 files totaling ~4GB)
- Clear DNS attack categories: malware, phishing, spam
- Rich domain analysis features (n-grams, character entropy, TTL analysis)

**Model Requirements**:
- **DNS-aware models**: Need to understand domain-based features
- **Sequence processing**: Domain names require sequential pattern recognition
- **Feature engineering**: DNS features need specialized processing
- **Multi-modal learning**: Combine domain features with traffic features

**Why This Requires Specialized Models**:
1. **Feature Mismatch**: DNS features don't map cleanly to 44-feature network flow schema
2. **Domain Analysis**: Requires NLP-like processing for domain names
3. **Specialized Threats**: DNS-based attacks have different patterns than general network attacks
4. **Complementary Detection**: Best used alongside general network flow analysis

**Processing Command**:
```bash
python scripts/prepare_dns_training_data.py --dns-dir artifacts/BCCC-CIC-Bell-DNS2021 --output-dir artifacts/processed_dns
```

**Recommended Model Approaches**:
- **Random Forest**: Can handle mixed feature types (domain + traffic)
- **LSTM/RNN**: For sequential domain name pattern recognition
- **Ensemble Methods**: Combine domain analysis with traffic features
- **Custom DNS Models**: Specifically designed for DNS threat detection

**Note**: This dataset is excellent for DNS-specific threat detection but requires custom model implementation. It's not a drop-in replacement for the CIC-IDS2017 dataset.

---

### 4. Global Cybersecurity Threats Dataset + No ML Models ❌

**Dataset**: `artifacts/Global_Cybersecurity_Threats_2015-2024.csv`
**Model**: None (Dashboard Demonstration Only)
**Use Case**: UI Testing and Threat Intelligence Display

#### Why ML Models Are Not Suitable

**Dataset Characteristics**:
- Incident-level summary data (not individual network flows)
- Business impact metrics (financial loss, affected users)
- Geographic and temporal trends
- High-level attack categorization

**Why ML Models Don't Work**:
1. **Missing Features**: Lacks 44 network flow features required by NIDS models
2. **Data Granularity**: Contains incident summaries, not individual traffic flows
3. **Wrong Purpose**: Designed for threat intelligence, not technical detection
4. **Sample Size**: Only 251KB with limited rows
5. **Feature Mismatch**: Contains business impact data, not technical traffic features

**Best Use Case**:
- **Dashboard Demonstration**: Realistic threat scenarios for UI testing
- **Threat Intelligence**: Geographic and industry threat analysis
- **Incident Analysis**: Business impact and trend analysis
- **Demo Purposes**: Showcasing dashboard capabilities

**Replay Command**:
```bash
python scripts/replay_global_threats_csv.py --csv artifacts/Global_Cybersecurity_Threats_2015-2024.csv --backend http://localhost:8000 --rate 5
```

**Important**: This dataset is intentionally NOT suitable for training ML models. It's designed for demonstrating the dashboard's alert and visualization capabilities.

## Model-Dataset Compatibility Matrix

| Model | CIC-IDS2017 | BCCC-DNS2021 | Global Threats | Best Dataset | Reason |
|-------|-------------|--------------|---------------|--------------|---------|
| **Isolation Forest** | ✅ **EXCELLENT** | ⚠️ Limited | ❌ No | CIC-IDS2017 | Perfect feature match, abundant benign data |
| **XGBoost** | ✅ **EXCELLENT** | ⚠️ Limited | ❌ No | CIC-IDS2017 | Rich labeled data, 44-feature compatibility |
| **LSTM Autoencoder** | ✅ **GOOD** | ⚠️ Possible | ❌ No | CIC-IDS2017 | Temporal patterns in network flows |
| **DNS-Specialized Models** | ⚠️ Limited | ✅ **EXCELLENT** | ❌ No | BCCC-DNS2021 | DNS-specific features, domain analysis |
| **Any ML Model** | ❌ No | ❌ No | ❌ No | **None** | Incident-level data, not network flows |

## Production Training Recommendations

### Primary Production Setup

**Dataset**: CIC-IDS2017 (`artifacts/CSVs/`)
**Models**: Isolation Forest + XGBoost
**Purpose**: Real-time network attack detection

**Training Pipeline**:
```bash
# Complete automated training
python scripts/train_all_models.py --artifacts-dir artifacts/CSVs --output-dir artifacts --max-samples 10000
```

**Why This Setup**:
- **Industry Standard**: CIC-IDS2017 is the benchmark dataset for NIDS
- **Model Synergy**: Isolation Forest detects unknown anomalies, XGBoost classifies known attacks
- **Feature Compatibility**: Perfect match with 44-feature system architecture
- **Production Proven**: Both models are widely deployed in production NIDS

### Advanced DNS Detection Setup

**Dataset**: BCCC-CIC-Bell-DNS2021 (`artifacts/BCCC-CIC-Bell-DNS2021/`)
**Models**: Custom DNS detection models
**Purpose**: DNS-specific threat detection

**Processing Pipeline**:
```bash
# Process DNS data for specialized models
python scripts/prepare_dns_training_data.py --dns-dir artifacts/BCCC-CIC-Bell-DNS2021 --output-dir artifacts/processed_dns
```

**Why This Setup**:
- **DNS Expertise**: Specialized dataset for DNS-based attack detection
- **Domain Analysis**: Rich features for malware/phishing/spam domain detection
- **Complementary**: Adds DNS layer to general network flow detection
- **Custom Implementation**: Requires specialized model development

### Dashboard Demonstration Setup

**Dataset**: Global Cybersecurity Threats (`artifacts/Global_Cybersecurity_Threats_2015-2024.csv`)
**Models**: None (alert replay only)
**Purpose**: UI testing and threat intelligence display

**Replay Pipeline**:
```bash
# Replay threat scenarios for dashboard demo
python scripts/replay_global_threats_csv.py --csv artifacts/Global_Cybersecurity_Threats_2015-2024.csv --backend http://localhost:8000 --rate 5
```

**Why This Setup**:
- **Realistic Scenarios**: Real incident data for authentic demo
- **Geographic Diversity**: Global threat distribution
- **Business Impact**: Shows financial and operational impact
- **No Training Required**: Direct replay to dashboard

## Summary and Recommendations

### For Production Deployment ✅

**Recommended**: CIC-IDS2017 + Isolation Forest + XGBoost

**Why**:
- Perfect feature compatibility (44-feature schema)
- Abundant training data (benign + multiple attack types)
- Industry-standard dataset and models
- Proven production performance
- Comprehensive attack coverage

**Training**:
```bash
python scripts/train_all_models.py --artifacts-dir artifacts/CSVs --output-dir artifacts
```

### For Advanced DNS Detection ⚠️

**Recommended**: BCCC-CIC-Bell-DNS2021 + Custom DNS Models

**Why**:
- DNS-specific features not available in network flow datasets
- Excellent for malware, phishing, spam domain detection
- Large benign DNS baseline for accurate anomaly detection
- Complements general network flow analysis

**Processing**:
```bash
python scripts/prepare_dns_training_data.py --dns-dir artifacts/BCCC-CIC-Bell-DNS2021 --output-dir artifacts/processed_dns
```

### For Dashboard Demonstration ❌

**Recommended**: Global Cybersecurity Threats + Alert Replay

**Why**:
- Realistic threat scenarios for UI testing
- No ML training required
- Geographic and industry diversity
- Business impact metrics for comprehensive demo

**Replay**:
```bash
python scripts/replay_global_threats_csv.py --csv artifacts/Global_Cybersecurity_Threats_2015-2024.csv --backend http://localhost:8000 --rate 5
```

## Conclusion

The artifacts folder provides a comprehensive dataset collection where each dataset serves a specific purpose:

1. **CIC-IDS2017** → **Isolation Forest + XGBoost** → Production network attack detection
2. **BCCC-CIC-Bell-DNS2021** → **Custom DNS Models** → Advanced DNS threat detection  
3. **Global Cybersecurity Threats** → **No ML Models** → Dashboard demonstration

**For production deployment**, the CIC-IDS2017 dataset with Isolation Forest and XGBoost models provides the optimal combination of feature compatibility, data quality, and proven performance for real-time network attack detection.

**Documentation**: See `DATASET_ANALYSIS.md` for detailed technical analysis of each dataset's features and model compatibility.
