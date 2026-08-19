# Implementation Guide — Kali Linux + VirtualBox + Google Colab Training

> **Final-Year Project Runbook**  
> This document covers the complete end-to-end workflow:
> 1. Setting up Kali Linux VM (VirtualBox, Windows host)
> 2. Syncing the project into Kali
> 3. Training ML models on Google Colab (recommended — your PC cannot train locally)
> 4. Deploying the full detection stack on Kali
> 5. Testing intrusion and anomaly detection
>
> Follow sections **in order** the first time.

---

## Why Intrusions Are Not Being Detected (Quick Reference)

| # | Problem | Symptom | Fix |
|---|---------|---------|-----|
| 1 | **Kafka missing from stack** | `/status` shows `kafka: false`; sensor logs connection errors | Use the full `docker-compose.yml` (includes Zookeeper + Kafka). Restart stack (§5). |
| 2 | **ML models not trained** | `/health` shows all models `false`; dashboard says "Attack Sensing: INACTIVE" | Train on Google Colab (§3) — your PC/VM is too slow. |
| 3 | **Wrong network interface** | Sensor starts but zero flows/alerts | Set `SENSOR_INTERFACE=wlan0` (managed mode) — not `eth0` or `wlan0mon` (§6). |
| 4 | **Monitor mode misuse** | `tcpdump -i wlan0mon` shows 802.11 frames but sensor sees nothing | This IDS needs **IP-layer flows**. Use managed mode + bridged networking (§2). |
| 5 | **NAT networking on VM** | Only the VM's own traffic visible | Switch VirtualBox adapter to **Bridged Adapter** (§2). |
| 6 | **USB WiFi not passed to VM** | `iwconfig` on Kali shows no `wlan0` | USB passthrough from VirtualBox (§2). |
| 7 | **Capture profile not started** | Backend runs but no live capture | `docker compose --profile capture up -d sensor` (§5). |
| 8 | **Processed .npy files are empty** | Training fails immediately with shape errors | Re-run `prepare_training_data.py` — the current `artifacts/processed/*.npy` stubs (128 bytes) are placeholders. Colab notebook does this automatically. |

---

## System Architecture

```
[WiFi / LAN traffic on your network]
         |
         v
    Sensor (Scapy)   -->  Kafka (flows topic)  -->  Backend (ML inference)  -->  Dashboard
    wlan0, managed          localhost:9094               kafka:9092                  :3000
    network_mode: host      (sensor/responder)           (in-container)
                                                              |
                                            +-----------------+-----------------+
                                            v                 v                 v
                                         Redis           TimescaleDB        WebSocket
                                     (dedup cache)     (alert storage)   (live dashboard)
```

**Three requirements for live detection:**
1. Sensor captures IP packets on the correct interface.
2. Kafka routes flows to the backend.
3. Trained model files exist in `artifacts/` (`scaler.joblib`, `isoforest.joblib`, `xgboost.json`, `xgboost_labels.json`).

---

## §1 — Project Files Reference

| File | Purpose |
|------|---------|
| `implementation.md` | This runbook |
| `TRAINING_COLAB.md` | Step-by-step Google Colab training notebook |
| `ARTIFACTS_DATASETS_SUMMARY.md` | Dataset overview and model-dataset compatibility |
| `DATASET_ANALYSIS.md` | Deep technical analysis: feature schema, quality, training recommendations |
| `FEATURES_44.md` | The 44 CICFlowMeter-style features (contract between sensor and backend) |
| `DEPLOYMENT.md` | Production deployment and security hardening |
| `PRODUCTION_CHECKLIST.md` | Pre-launch checklist |
| `.env` | Runtime configuration (interface, thresholds, ports) |
| `.env.example` | Template for `.env` |
| `docker-compose.yml` | Full stack definition |
| `scripts/train_all_models.py` | One-command training (Kali/Colab) |
| `scripts/prepare_training_data.py` | Feature extraction from CSVs |
| `scripts/train_isoforest.py` | Train Isolation Forest only |
| `scripts/train_xgboost.py` | Train XGBoost only |
| `scripts/replay_network_flows.py` | Replay CIC-IDS2017 attack CSVs to test detection |
| `scripts/replay_global_threats_csv.py` | Replay Global Threats CSV (dashboard demo only) |
| `scripts/kali_setup_check.sh` | Pre-flight check: models, containers, Kafka, interface |
| `scripts/system_check.py` | Full system health audit |
| `artifacts/CSVs/` | CIC-IDS2017 training data (18 CSV files, ~3 GB) |
| `artifacts/processed/` | WARNING: Placeholder .npy stubs — regenerated during training |
| `artifacts/BCCC-CIC-Bell-DNS2021/` | DNS dataset (future work) |
| `artifacts/Global_Cybersecurity_Threats_2015-2024.csv` | Dashboard demo data (not for ML training) |

---

## §2 — VirtualBox Setup (Windows Host -> Kali VM)

These steps are done in **VirtualBox on your Windows PC**.

### 2.1 Pass the USB WiFi Adapter to Kali

1. Plug in your external USB WiFi adapter (supports monitor mode, e.g. Alfa AWUS036ACH, TP-Link TL-WN722N).
2. Open **VirtualBox -> select your Kali VM -> Settings -> USB**.
3. Enable **USB Controller** (USB 2.0 or 3.0 depending on adapter).
4. Click **+** to add a **USB Device Filter** -> select your WiFi adapter.
5. Start Kali -> **Devices menu -> USB** -> click your adapter to attach it to the VM.

Verify inside Kali:

```bash
lsusb          # Should show your WiFi adapter
iwconfig       # Should show wlan0 or wlan1
ip -br link    # List all interfaces
```

### 2.2 Network Adapter Mode (Critical)

| VirtualBox Setting | Required Value | Reason |
|---|---|---|
| Adapter 1 Type | **Bridged Adapter** | VM shares your LAN/WiFi — sensor sees real traffic |
| Promiscuous Mode | **Allow All** | See traffic beyond the VM's own packets |
| NAT | Avoid | You only see the VM's own packets — useless for IDS |

Bridged + USB WiFi: In VirtualBox, bridge to your **WiFi adapter** (not Ethernet) if the USB WiFi is passed through to Kali.

### 2.3 Shared Folder (Project Sync — Windows <-> Kali)

The project folder on Windows is shared with Kali so you can edit code on Windows and run it on Kali.

In VirtualBox: **Settings -> Shared Folders -> add folder** pointing to your project root, e.g. `C:\Users\Defendatafrika\Desktop\workspace\ai-anomaly-ids-idp`.

Inside Kali, mount it:

```bash
# Add yourself to vboxsf group (do once, then log out/in)
sudo usermod -aG vboxsf $USER

# Access the shared folder (adjust name if different)
ls /media/sf_ai-anomaly-ids-idp
# OR
ls ~/shared/ai-anomaly-ids-idp
```

After training on Colab and copying models into `artifacts/` on Windows, they automatically appear in the Kali shared folder — no manual copy needed.

---

## §3 — Train ML Models on Google Colab (Recommended)

Your Windows PC and Kali VM cannot train the models reliably (low RAM / slow CPU).
Google Colab is free and takes 5-15 minutes. Use **`TRAINING_COLAB.md`** for the full notebook.

### What You Will Produce

| File | Purpose |
|------|---------|
| `scaler.joblib` | Normalises the 44 flow features |
| `isoforest.joblib` | Anomaly detection (trained on benign-only traffic) |
| `xgboost.json` | Multi-class attack classifier (DDoS, DoS, portscan, etc.) |
| `xgboost_labels.json` | Label names for XGBoost classes |

### Training Data Used (CIC-IDS2017)

The 18 CSV files in `artifacts/CSVs/` (~3 GB total):

**Benign traffic** (for Isolation Forest baseline):
- `monday_benign.csv` (395 MB), `tuesday_benign.csv` (317 MB), `wednesday_benign.csv` (318 MB)
- `thursday_benign.csv` (107 MB), `friday_benign.csv` (292 MB)

**Attack traffic** (for XGBoost classification):
- `ddos_loit.csv` (91 MB) — DDoS LOIT
- `dos_hulk.csv` (274 MB) — DoS Hulk
- `dos_golden_eye.csv` (8 MB) — DoS GoldenEye
- `dos_slowloris.csv` (4 MB) — Slowloris
- `dos_slowhttptest.csv` (5 MB) — SlowHTTPTest
- `botnet_ares.csv` (4 MB) — Botnet Ares
- `portscan.csv` (118 MB) — Port scanning
- `web_brute_force.csv` (2 MB) — Web brute force
- `web_sql_injection.csv` (21 KB) — SQL injection (small — use with caution)
- `web_xss.csv` (935 KB) — XSS (small — use with caution)
- `ftp_patator.csv` (7 MB) — FTP brute force
- `ssh_patator-new.csv` (5 MB) — SSH brute force
- `heartbleed.csv` (12 KB) — Heartbleed (very small — use with caution)

### Step-by-Step: Google Colab Training

Full notebook code is in `TRAINING_COLAB.md` — follow it cell by cell.

**Overview:**
1. **Upload to Google Drive**: Zip `artifacts/CSVs/` and upload as `CSVs.zip`.
2. **Open Colab**: https://colab.research.google.com -> New notebook.
3. **Cell 1**: Install dependencies (`numpy`, `scikit-learn`, `xgboost`, `joblib`).
4. **Cell 2**: Mount Google Drive.
5. **Cell 3**: Set paths, unzip CSVs.
6. **Cell 4**: Feature extraction (maps CSV columns -> 44-feature schema). Generates `.npy` files.
7. **Cell 5**: Train Isolation Forest + XGBoost. Saves 4 model files.
8. **Cell 6**: Download `model_artifacts.zip` containing all 4 files.

**After download — place files here:**

```
ai-anomaly-ids-idp/
└── artifacts/
    ├── scaler.joblib          <- required
    ├── isoforest.joblib       <- required
    ├── xgboost.json           <- required
    └── xgboost_labels.json    <- required
```

Because the folder is shared with Kali via VirtualBox shared folders, the files appear automatically in the VM.

### Expected Model Performance

| Model | Training Time | Inference Speed | Expected Accuracy |
|-------|-------------|-----------------|-------------------|
| Isolation Forest | 2-5 min (10k samples) | < 10 ms/flow | 85-95% anomaly detection |
| XGBoost | 5-15 min (50k samples) | < 5 ms/flow | 90-98% classification |

---

## §4 — Kali Linux Prerequisites

Run these inside Kali after your VM is set up:

```bash
# Update and install required packages
sudo apt update
sudo apt install -y \
    docker.io \
    docker-compose-plugin \
    tcpdump \
    net-tools \
    curl \
    python3-pip \
    python3-venv

# Add your user to docker group (avoids needing sudo every time)
sudo usermod -aG docker $USER
newgrp docker   # apply group change immediately (or log out/in)
```

**Verify Docker:**

```bash
docker info          # Should not error
docker compose version   # Should show v2.x.x
```

---

## §5 — Configure and Start the Stack

From the project folder on Kali (your shared folder):

```bash
cd /media/sf_ai-anomaly-ids-idp
# OR
cd ~/shared/ai-anomaly-ids-idp

# Copy environment template if .env does not exist yet
cp .env.example .env
nano .env
```

### Minimum `.env` Changes for Live Capture

```env
# Your WiFi interface in MANAGED mode (check with: ip -br link)
SENSOR_INTERFACE=wlan0

# Keep internal Docker network settings as-is
KAFKA_BROKERS=kafka:9092

# Detection thresholds (lower for demo if getting no alerts)
ISOFOREST_THRESHOLD=0.65
XGBOOST_CONFIDENCE_THRESHOLD=0.70
```

### Start the Full Stack

```bash
# Start infrastructure + backend + dashboard
docker compose up -d zookeeper kafka redis timescaledb backend ai_threat_visor
```

Wait ~30 seconds, then verify:

```bash
curl -s http://localhost:8000/status | python3 -m json.tool
curl -s http://localhost:8000/health | python3 -m json.tool
```

Expected output after model files are in `artifacts/`:

```json
{
  "components": {
    "kafka": { "ok": true },
    "redis": { "ok": true },
    "database": { "ok": true }
  },
  "models": {
    "isoforest": true,
    "xgboost": true,
    "scaler": true
  }
}
```

### Start Live Capture (Sensor)

```bash
# Start sensor (requires network_mode: host for packet capture)
docker compose --profile capture up -d sensor

# Optional: Start IDP responder (blocks Critical/High IPs using iptables)
# docker compose --profile capture up -d responder
```

Check sensor logs:

```bash
docker compose logs -f sensor
# Look for: sniff_start iface=wlan0 filter=ip
# And periodic: flows_flushed=N
```

---

## §6 — WiFi: Managed Mode vs Monitor Mode

### What This Project Detects

The sensor uses **Scapy** with BPF filter `ip` to build **CICFlowMeter-style IP flows** (44 features). It expects normal **IP packets** (TCP/UDP/ICMP at layer 3).

### Why Managed Mode Is Required Here

| Mode | What it captures | This IDS? |
|------|-----------------|-----------|
| **Managed (`wlan0`)** | IP layer packets — TCP, UDP, ICMP flows | Required |
| Monitor (`wlan0mon`) | Raw 802.11 wireless frames (encrypted/unencrypted) | BPF filter `ip` matches nothing |

**For your final-year demo, always use managed mode:**

```bash
# Connect Kali to your lab WiFi
sudo nmcli dev wifi list
sudo nmcli dev wifi connect "YourLabSSID" password "yourpassword"

# Confirm interface name
ip -br addr show wlan0
```

**Verify capture works before starting Docker:**

```bash
# Should print 10-20 IP packets in a few seconds
sudo tcpdump -i wlan0 -c 20 ip

# If zero packets: fix bridged networking before continuing
```

---

## §7 — Run the Pre-flight Check

```bash
chmod +x scripts/kali_setup_check.sh
./scripts/kali_setup_check.sh
```

This script checks:
- Docker installed and running
- `.env` present with valid `SENSOR_INTERFACE`
- All 4 model files in `artifacts/`
- All core containers running (`kafka`, `backend`, `redis`, `timescaledb`)
- Backend `/health` endpoint reachable
- Kafka connected (via `/status`)
- IP packets actually captured on `wlan0`

All checks should show `[PASS]`. Fix any `[FAIL]` before proceeding.

---

## §8 — Validate Detection (Before Live WiFi Demo)

### 8.1 Replay Known Attack CSVs (Proves ML Works)

With backend running and models loaded:

```bash
# Replay DDoS attack — should trigger alerts within seconds
python scripts/replay_network_flows.py \
  --csv artifacts/CSVs/ddos_loit.csv \
  --backend http://localhost:8000 \
  --rate 10 \
  --limit 50

# Replay port scan
python scripts/replay_network_flows.py \
  --csv artifacts/CSVs/portscan.csv \
  --backend http://localhost:8000 \
  --rate 5 \
  --limit 30
```

Open dashboard: **http://localhost:3000** — you should see alerts within seconds.

### 8.2 Available Attack Test Files

| CSV File | Attack Type | Size |
|----------|-------------|------|
| `ddos_loit.csv` | DDoS LOIT | 91 MB |
| `dos_hulk.csv` | DoS Hulk | 274 MB |
| `dos_golden_eye.csv` | DoS GoldenEye | 8 MB |
| `dos_slowloris.csv` | DoS Slowloris | 4 MB |
| `dos_slowhttptest.csv` | DoS SlowHTTPTest | 5 MB |
| `botnet_ares.csv` | Botnet Ares | 4 MB |
| `portscan.csv` | Port Scanning | 118 MB |
| `web_brute_force.csv` | Web Brute Force | 2 MB |
| `web_sql_injection.csv` | SQL Injection | 21 KB |
| `web_xss.csv` | XSS | 935 KB |
| `ftp_patator.csv` | FTP Brute Force | 7 MB |
| `ssh_patator-new.csv` | SSH Brute Force | 5 MB |
| `heartbleed.csv` | Heartbleed | 12 KB |

### 8.3 Live WiFi / LAN Demo (For Viva)

Safe lab-only attacks — **only on networks you own/control**:

```bash
# Port scan from Kali to another machine — expect portscan / High severity alert
nmap -sS <target-ip>

# HTTP flood (test DoS detection)
hping3 -S -p 80 --flood <target-ip>

# Normal browsing — should NOT trigger alerts (benign traffic baseline)
```

Document for your report: date, interface, attack tool used, alert label, severity, latency (dashboard timestamp).

### 8.4 Dashboard Demo (Global Threats CSV)

To demo the dashboard UI without needing live detection:

```bash
python scripts/replay_global_threats_csv.py \
  --csv artifacts/Global_Cybersecurity_Threats_2015-2024.csv \
  --backend http://localhost:8000 \
  --rate 5
```

NOTE: This is display only — it replays incident-level data (2015-2024 stats), not real network flows. It does NOT test ML detection.

---

## §9 — IDP Mode (Optional — Automatic Blocking)

Default is **IDS-only** (`IDP_ENABLED=false`).

To enable automatic IP blocking on your lab network:

```env
# In .env
IDP_ENABLED=true
IDP_BLOCK_SECONDS=300
IDP_MAX_BLOCKS=20
```

```bash
docker compose --profile capture up -d responder
```

The responder uses `iptables` chain `AI_IDS_BLOCK` to block `Critical` and `High` severity source IPs.

WARNING: Lab networks only. This can disconnect clients. Never enable on a production or shared network.

---

## §10 — GeoIP Enrichment (Optional)

Download **GeoLite2-City.mmdb** from MaxMind (https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/ — free account required) and place it at:

```
./data/GeoLite2-City.mmdb
```

Restart the backend:

```bash
docker compose restart backend
```

Alerts will now include country and city information for detected source IPs.

---

## §11 — Troubleshooting

### Kafka Not Connected

```bash
docker compose ps kafka
docker compose logs kafka --tail 50
curl -s http://localhost:8000/status | python3 -c "import sys,json; print(json.load(sys.stdin)['components']['kafka'])"
```

Fix: Ensure `zookeeper` starts before `kafka`:

```bash
docker compose up -d zookeeper
sleep 10
docker compose up -d kafka
```

### Sensor: "No such device"

```bash
ip link show               # List all interfaces
grep SENSOR_INTERFACE .env  # Check configured interface
```

Fix: Update `SENSOR_INTERFACE` in `.env` to match the actual interface name; ensure USB WiFi is attached to the VM.

### Sensor Running But `flows_flushed=0`

- Wrong interface or no traffic on that interface.
- Run: `sudo tcpdump -i wlan0 -c 10 ip`
- If using NAT instead of bridged, switch to **Bridged Adapter** in VirtualBox.

### Models Loaded But No Alerts on Live Traffic

- Live traffic may differ from CIC-IDS2017 training data (domain shift is normal).
- Lower thresholds temporarily for demo:

```env
ISOFOREST_THRESHOLD=0.55
XGBOOST_CONFIDENCE_THRESHOLD=0.60
```

- Confirm replay test works first (§8.1) — if replay works, the models are functioning correctly.

### Dashboard Empty But Replay Works

- WebSocket blocked: check browser console (F12 -> Console / Network tabs).
- Backend URL: dashboard expects `http://localhost:8000`.
- Check: `curl -s http://localhost:8000/health`

### Docker Permission Denied

```bash
sudo usermod -aG docker $USER && newgrp docker
```

### Training: `.npy` Files Are Empty / Shape Errors

The `artifacts/processed/*.npy` files are **128-byte stubs** (empty placeholders). The Google Colab notebook re-generates them from the CSVs.

If training locally on Kali:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-training.txt

# Re-run feature extraction first
python scripts/prepare_training_data.py \
  --artifacts-dir artifacts/CSVs \
  --output-dir artifacts/processed \
  --max-samples 5000

# Then train
python scripts/train_all_models.py \
  --artifacts-dir artifacts/CSVs \
  --output-dir artifacts \
  --max-samples 5000
```

---

## §12 — Final-Year Project Checklist (Aim for A Grade)

- [ ] Architecture diagram (sensor -> Kafka -> ML inference -> dashboard) in report
- [ ] Explain **managed vs monitor mode** and why you chose managed for IP-flow IDS
- [ ] CIC-IDS2017 dataset citation: Sharafaldin et al., 2018 — "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization"
- [ ] Class distribution table from training (number of samples per attack type)
- [ ] Model metrics: Isolation Forest (anomaly detection rate, FP rate) + XGBoost (accuracy, F1 per class) — printed by training scripts
- [ ] Demo video: replay attack CSV -> live dashboard alerts (screen-record)
- [ ] Live demo (viva): port scan from second machine -> dashboard alert within seconds
- [ ] False positive discussion: benign browsing during capture window
- [ ] Ethics section: lab-only testing, IDP risks, legal authorization, data privacy
- [ ] Future work: 802.11 monitor-mode module, LSTM temporal model, DNS dataset integration (BCCC-CIC-Bell-DNS2021)

---

## §13 — Quick Reference Commands

```bash
# Start full stack (infrastructure + backend + dashboard)
docker compose up -d zookeeper kafka redis timescaledb backend ai_threat_visor

# Start live capture
docker compose --profile capture up -d sensor

# Full stack + capture (rebuild images after code changes)
docker compose --profile capture up -d --build

# Logs
docker compose logs -f backend sensor kafka

# Health checks
curl http://localhost:8000/health  | python3 -m json.tool
curl http://localhost:8000/status  | python3 -m json.tool
curl http://localhost:8000/models  | python3 -m json.tool

# Pre-flight check
./scripts/kali_setup_check.sh

# Replay attacks (test detection)
python scripts/replay_network_flows.py --csv artifacts/CSVs/ddos_loit.csv   --backend http://localhost:8000 --rate 10 --limit 50
python scripts/replay_network_flows.py --csv artifacts/CSVs/portscan.csv    --backend http://localhost:8000 --rate 5  --limit 30
python scripts/replay_network_flows.py --csv artifacts/CSVs/botnet_ares.csv --backend http://localhost:8000 --rate 5  --limit 30

# Train models locally (Kali, if RAM >= 8 GB)
python scripts/train_all_models.py \
  --artifacts-dir artifacts/CSVs \
  --output-dir artifacts \
  --max-samples 10000
docker compose restart backend

# Stop everything
docker compose --profile capture down
```

---

## §14 — Division of Work: Windows Host vs Kali VM

| Task | Where to Run |
|------|--------------|
| Edit code, docs, `.env` | Windows host (shared folder, this repo in Cursor) |
| USB WiFi passthrough | VirtualBox GUI on Windows |
| Bridged networking | VirtualBox GUI on Windows |
| `docker compose --profile capture` (sensor) | **Kali Linux VM** |
| `tcpdump` / `airmon-ng` | **Kali Linux VM** |
| `iptables` IDP blocking | **Kali Linux VM** (responder container) |
| ML training (Colab recommended) | **Google Colab** -> download -> place in `artifacts/` |
| ML training (Kali, if RAM >= 8 GB) | **Kali Linux VM** |
| System health check | **Kali Linux VM** (`kali_setup_check.sh`) |
| Dashboard / API access | Any browser -> `http://localhost:3000` / `http://localhost:8000` |

After code changes on Windows, rebuild on Kali:

```bash
docker compose --profile capture up -d --build
```

---

## §15 — What Cannot Be Done from Windows

The Windows host is suitable for code editing and documentation. It **cannot**:

- Run the live network sensor (`network_mode: host` requires Linux)
- Use `tcpdump`, `airmon-ng`, or `iptables`
- Train the ML models reliably (insufficient RAM / Python environment issues)
- See the VM's WiFi adapter as `wlan0`

**Everything requiring live packet capture, training, or container operation must be done inside Kali Linux.**
