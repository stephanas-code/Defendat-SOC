# AI Anomaly IDS Deployment Guide

## Production Deployment Instructions

This system is designed for live deployment with real-time attack detection capabilities.

### Prerequisites

- Docker and Docker Compose
- Python 3.9+ (for running replay scripts)
- Network interface access (for sensor component)

### Quick Start (Production)

1. **Start Infrastructure Services**
```bash
docker compose up -d zookeeper kafka redis timescaledb
```

2. **Start Backend and Frontend**
```bash
docker-compose up -d backend ai_threat_visor
```

3. **Access Dashboard**
- Main Dashboard: http://localhost:3000
- Backend API: http://localhost:8000
- API Status: http://localhost:8000/status
- Health Check: http://localhost:8000/health

### Training ML Models (Required for Attack Detection)

The system includes automated training scripts that use the datasets in `artifacts/CSVs/` to train ML models for attack detection.

#### Quick Training (Recommended)

```bash
# Train all models using datasets from artifacts folder
python scripts/train_all_models.py --artifacts-dir artifacts/CSVs --output-dir artifacts
```

This automated pipeline:
1. Processes CSV files from `artifacts/CSVs/` (CIC-IDS2017 dataset)
2. Extracts 44 network flow features compatible with the system
3. Trains Isolation Forest on benign traffic for anomaly detection
4. Trains XGBoost on mixed benign and attack traffic for classification
5. Saves model files to `artifacts/` directory for deployment

#### Manual Training (Advanced)

For granular control over the training process:

**Step 1: Prepare Training Data**
```bash
python scripts/prepare_training_data.py --artifacts-dir artifacts/CSVs --output-dir artifacts/processed --max-samples 10000
```

**Step 2: Train Isolation Forest**
```bash
python scripts/train_isoforest.py --input artifacts/processed/benign_features.npy --output artifacts
```

**Step 3: Train XGBoost**
```bash
python scripts/train_xgboost.py --features artifacts/processed/xgboost_features.npy --labels artifacts/processed/xgboost_labels.npy --label-names artifacts/processed/xgboost_label_names.txt --output artifacts
```

**Step 4: Train LSTM Autoencoder (Optional)**
```bash
python scripts/train_lstm_autoencoder_export_onnx.py --input artifacts/processed/benign_features.npy --scaler artifacts/scaler.joblib --output artifacts
```

#### Dataset Information

The training uses the **CIC-IDS2017** dataset with these attack types:
- **DDoS/DoS**: LOIT, Hulk, GoldenEye, Slowloris, SlowHTTPTest  
- **Botnet**: Ares
- **Web Attacks**: SQL Injection, XSS, Brute Force
- **Brute Force**: FTP, SSH Patator
- **Port Scanning**: Network reconnaissance
- **Benign**: Normal traffic patterns from multiple days

**Model Recommendations**:
- **Isolation Forest**: Trained on benign traffic only (anomaly detection)
- **XGBoost**: Trained on mixed benign + attack traffic (classification)

For detailed dataset analysis, see `DATASET_ANALYSIS.md`

### Testing Attack Detection

#### Option 1: Using Global Threats Dataset (Demo Mode)
```bash
# Windows
scripts\test_replay.bat

# Linux/Mac
chmod +x scripts/test_replay.sh
./scripts/test_replay.sh
```

#### Option 2: Using Real Network Flow Data (Production Mode)
```bash
python scripts/replay_network_flows.py \
  --csv artifacts/CSVs/ddos_loit.csv \
  --backend http://localhost:8000 \
  --rate 10 \
  --limit 100
```

Available attack datasets in `artifacts/CSVs/`:
- `ddos_loit.csv` - DDoS LOIT attack
- `dos_hulk.csv` - DoS Hulk attack  
- `botnet_ares.csv` - Botnet Ares attack
- `web_sql_injection.csv` - SQL Injection attack
- `web_xss.csv` - XSS attack
- `portscan.csv` - Port scanning attack
- And many more...

### System Health Monitoring

The System Health page (in the dashboard) shows:
- **Attack Sensing Status**: ACTIVE if ML models are loaded, INACTIVE otherwise
- **Component Status**: Real-time status of all pipeline components
- **Alert Statistics**: Total alerts, critical threats, recent activity
- **Model Status**: Which ML models are currently loaded and operational

### Production Configuration

For production deployment, update the `.env` file:

```env
# Backend
BACKEND_HOST=0.0.0.0
BACKEND_PORT=8000
BACKEND_LOG_LEVEL=warning  # Reduce log noise in production

# Detection Thresholds (tune based on your environment)
ISOFOREST_THRESHOLD=0.65
XGBOOST_CONFIDENCE_THRESHOLD=0.70

# IDP Blocking (enable if you want automatic blocking)
IDP_ENABLED=true
IDP_BLOCK_SECONDS=600
IDP_MAX_BLOCKS=50
```

### Starting Full System with Network Capture

To enable real network traffic monitoring:

```bash
docker-compose --profile capture up -d
```

This starts:
- Sensor (captures network traffic)
- Responder (blocks detected threats)
- All other components

**Note**: Sensor requires network interface access and proper permissions.

### Security Considerations for Production

1. **Change Default Passwords**
   - Update `POSTGRES_PASSWORD` in `.env`
   - Update Redis authentication if needed

2. **Network Security**
   - Use firewall rules to restrict access to backend ports
   - Deploy behind reverse proxy (nginx) for SSL/TLS
   - Use environment-specific CORS settings

3. **Data Persistence**
   - TimescaleDB data is persisted in Docker volume
   - Regular backups recommended for production

4. **Monitoring**
   - Monitor system health via `/status` endpoint
   - Set up alerts for high critical alert counts
   - Monitor ML model performance metrics

### Troubleshooting

**System shows "Attack Sensing: INACTIVE"**
- ML models are not trained. Run training scripts or use `TRAINING_COLAB.md`.

**Kafka shows disconnected on /status**
- Start Kafka: `docker compose up -d zookeeper kafka`
- Sensor/responder use `localhost:9094`; backend uses `kafka:9092`

**No alerts appearing in dashboard**
- Check backend is running: `curl http://localhost:8000/health`
- Check WebSocket connection in browser console
- Replay test data using provided scripts

**Database connection errors**
- Ensure TimescaleDB container is running: `docker-compose ps timescaledb`
- Check database credentials in `.env`

**High memory usage**
- LSTM models can be memory-intensive. Disable if not needed: `LSTM_ENABLED=false`

### Performance Tuning

For high-traffic environments:

1. **Increase Kafka throughput** - Add more Kafka brokers
2. **Scale backend** - Use Kubernetes or Docker Swarm for multiple instances
3. **Database optimization** - TimescaleDB automatically handles time-series data
4. **Caching** - Redis is already configured for alert deduplication

### Support and Maintenance

- Check logs: `docker-compose logs -f backend`
- Restart services: `docker-compose restart backend`
- Update models: Retrain with new data and replace model files
- Monitor disk space: Alert logs can grow over time

### Live Deployment Checklist

- [ ] Train all ML models
- [ ] Test with replay scripts
- [ ] Configure production `.env` settings
- [ ] Set up SSL/TLS termination
- [ ] Configure firewall rules
- [ ] Set up monitoring and alerting
- [ ] Test network capture (if using sensor)
- [ ] Configure IDP blocking rules (if enabled)
- [ ] Set up database backups
- [ ] Document operational procedures
