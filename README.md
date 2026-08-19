# AI Anomaly IDS/IDP (NIDS)

End-to-end, self-hosted Network Intrusion Detection / Anomaly Detection system with real-time attack sensing capabilities.

## What’s included

- **Sensor (Scapy)**: live packet capture → bidirectional flow reconstruction → 44 CICFlowMeter-style flow features → Kafka.
- **Inference + API (FastAPI)**: IsolationForest anomaly scoring + XGBoost classification (+ optional temporal LSTM via ONNX) → severity-rated alerts → Redis dedup → TimescaleDB persistence → WebSocket stream.
- **Responder (optional IDP)**: consumes the `alerts` Kafka topic and (optionally) blocks source IPs using `iptables` for Critical/High alerts.
- **Modern Dashboard (React/TypeScript)**: Comprehensive monitoring interface with real-time alerts, threat maps, system health, and ML model status.
- **Attack Detection Datasets**: Pre-loaded with real attack patterns for testing and demonstration.

## Quick start

1. Copy environment file:

```bash
cp .env.example .env
```

2. Start infrastructure services:

```bash
docker-compose up -d redis timescaledb
```

3. Start backend and dashboard:

```bash
docker-compose up -d backend ai_threat_visor
```

4. Access the system:
- **Main Dashboard**: `http://localhost:3000`
- **Backend API**: `http://localhost:8000`
- **API Health**: `http://localhost:8000/health`
- **System Status**: `http://localhost:8000/status`

## Training ML Models (Required for Attack Detection)

The system includes **automated training scripts** that use the datasets in `artifacts/CSVs/` to train ML models for attack detection.

**If your PC or Kali VM is too slow:** use **[TRAINING_COLAB.md](TRAINING_COLAB.md)** (Google Colab, free).

**Live capture on Kali + VirtualBox + WiFi:** see **[implementation.md](implementation.md)** (full runbook).

### Quick Training (Recommended)

The easiest way to train all models:

```bash
# Train all models using datasets from artifacts folder
python scripts/train_all_models.py --artifacts-dir artifacts/CSVs --output-dir artifacts
```

This will:
1. Process CSV files from `artifacts/CSVs/` 
2. Extract 44 network flow features
3. Train Isolation Forest on benign traffic
4. Train XGBoost on mixed benign and attack traffic
5. Save model files to `artifacts/` directory

### Manual Training

For more control over the training process:

#### Step 1: Prepare Training Data
```bash
python scripts/prepare_training_data.py --artifacts-dir artifacts/CSVs --output-dir artifacts/processed
```

#### Step 2: Train Isolation Forest (Anomaly Detection)
```bash
python scripts/train_isoforest.py --input artifacts/processed/benign_features.npy --output artifacts
```

#### Step 3: Train XGBoost (Attack Classification)
```bash
python scripts/train_xgboost.py --features artifacts/processed/xgboost_features.npy --labels artifacts/processed/xgboost_labels.npy --label-names artifacts/processed/xgboost_label_names.txt --output artifacts
```

#### Step 4: Train LSTM Autoencoder (Temporal Anomaly Detection - Optional)
```bash
python scripts/train_lstm_autoencoder_export_onnx.py --input artifacts/processed/benign_features.npy --scaler artifacts/scaler.joblib --output artifacts
```

### Dataset Information

The artifacts folder contains **three different datasets** for different purposes:

#### 1. CIC-IDS2017 Network Flow Dataset (`artifacts/CSVs/`)
**Purpose**: ML model training for network-based attack detection

**Attack Types**:
- **DDoS/DoS**: LOIT, Hulk, GoldenEye, Slowloris, SlowHTTPTest
- **Botnet**: Ares
- **Web Attacks**: SQL Injection, XSS, Brute Force
- **Brute Force**: FTP, SSH Patator
- **Port Scanning**: Network reconnaissance
- **Benign Traffic**: Normal network traffic patterns

**Use**: Primary dataset for training Isolation Forest and XGBoost models

#### 2. BCCC-CIC-Bell-DNS2021 DNS Dataset (`artifacts/BCCC-CIC-Bell-DNS2021/`)
**Purpose**: DNS-specific attack detection with domain analysis

**Attack Types**:
- **Malware DNS**: Malware-related DNS communication
- **Phishing DNS**: Phishing domain patterns
- **Spam DNS**: Spam-related DNS traffic
- **Benign DNS**: Normal DNS traffic (4 large files)

**Use**: Specialized DNS attack detection (requires separate processing)

#### 3. Global Cybersecurity Threats Dataset (`artifacts/Global_Cybersecurity_Threats_2015-2024.csv`)
**Purpose**: Dashboard demonstration and threat intelligence

**Content**: Incident-level cyber threat data (2015-2024)
- Geographic threat distribution
- Attack types and target industries
- Financial impact and affected users
- Defense mechanisms and resolution times

**Use**: Dashboard demo via `replay_global_threats_csv.py` (NOT for ML training)

**For detailed dataset analysis and model recommendations**, see `DATASET_ANALYSIS.md`

## Testing Attack Detection

### Quick Test (Demo Mode)
```bash
# Windows
scripts\test_replay.bat

# Linux/Mac
chmod +x scripts/test_replay.sh
./scripts/test_replay.sh
```

### Real Attack Patterns (Production Mode)
```bash
python scripts/replay_network_flows.py \
  --csv artifacts/CSVs/ddos_loit.csv \
  --backend http://localhost:8000 \
  --rate 10
```

Available attack datasets in `artifacts/CSVs/`:
- DDoS attacks (ddos_loit.csv, dos_hulk.csv, dos_slowloris.csv)
- Botnet attacks (botnet_ares.csv)
- Web attacks (web_sql_injection.csv, web_xss.csv, web_brute_force.csv)
- Port scanning (portscan.csv)
- And many more...

## System Health Monitoring

The dashboard includes a comprehensive System Health page that shows:
- **Attack Sensing Status**: ACTIVE if ML models are loaded and operational
- **Component Status**: Real-time status of all pipeline components (Database, Redis, Kafka, ML models)
- **Alert Statistics**: Total alerts, critical threats, recent activity
- **Model Performance**: ML model accuracy, latency, and operational status

Run system health check:
```bash
# Windows
scripts\system_check.bat

# Linux/Mac
python scripts/system_check.py
```

## Production Deployment

For production deployment, see `DEPLOYMENT.md` for detailed instructions including:
- Security hardening
- Performance tuning
- Network capture setup
- Monitoring and alerting
- Backup strategies

## Notes

- Sensor uses `network_mode: host` and requires `CAP_NET_RAW` to sniff packets (Linux only).
- GeoIP enrichment is optional; place a GeoLite2 City `.mmdb` at `./data/GeoLite2-City.mmdb`.
- Model artifacts are expected under `./artifacts` (see `scripts/`).
- The modern dashboard (ai_threat_visor) provides enhanced visualization and monitoring capabilities.

## Deployment for Live Network Monitoring

To enable real network traffic monitoring with automatic threat blocking:

```bash
docker compose --profile capture up -d
```

This starts the sensor (network capture) and responder (threat blocking) components.

**Requirements (Kali Linux VM — not Windows host):**

- Kafka + Zookeeper must be running (included in `docker-compose.yml`)
- Trained models in `artifacts/` (see `TRAINING_COLAB.md` if needed)
- USB WiFi passed through to Kali, **managed mode** (`wlan0`), bridged networking

See **[implementation.md](implementation.md)** for VirtualBox, WiFi, and troubleshooting.

