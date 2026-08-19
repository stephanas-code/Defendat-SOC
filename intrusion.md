# NIDS/NIP Intrusion & Alert Verification Manual

This guide describes how to simulate and verify network security alerts (DDoS, Port Scanning, Botnet, Web Anomalies) to test the AI NIDS detection engine, trigger alert notifications, and display real-time telemetry on the SOC dashboard.

> [!NOTE]
> **Single-Machine Testing Note:** When both the sensor/AI tool and attack traffic run on the same machine (`192.168.1.103`), traffic directed at `127.0.0.1` or `192.168.1.103` travels via the loopback interface (`lo`). Ensure your live capture sensor listens on the `lo` or `any` interface (`-i any`) to capture self-generated packets.

---

## Method 1 — Replaying Real Attack CSV Flows (Recommended for Model Testing)

The project includes pre-processed network flow datasets in the `artifacts/CSVs/` directory. You can use the replay scripts to feed these attack flows directly into the ML inference backend:

### 1. DDoS Attack Replay (HULK / LOIT)
```bash
python scripts/replay_network_flows.py \
  --csv artifacts/CSVs/ddos_loit.csv \
  --backend http://localhost:8000 \
  --rate 20 \
  --limit 200
```

### 2. Reconnaissance (Port Scanning)
```bash
python scripts/replay_network_flows.py \
  --csv artifacts/CSVs/portscan.csv \
  --backend http://localhost:8000 \
  --rate 10 \
  --limit 100
```

### 3. Web Attacks (SQL Injection / XSS)
```bash
python scripts/replay_network_flows.py \
  --csv artifacts/CSVs/web_sql_injection.csv \
  --backend http://localhost:8000 \
  --rate 5 \
  --limit 50
```

### 4. Botnet Activity (Ares)
```bash
python scripts/replay_network_flows.py \
  --csv artifacts/CSVs/botnet_ares.csv \
  --backend http://localhost:8000 \
  --rate 5 \
  --limit 50
```

---

## Method 2 — Manual Alert Ingestion & GeoIP Testing

You can post alert objects directly to the ingestion API to verify dashboard visualization, alerts stream, and GeoIP mapping.

> [!IMPORTANT]
> **GeoIP Mapping:** Private local IPs (`192.168.x.x`, `10.x.x.x`, `127.0.0.1`) are categorized as `Local Network (LAN)`. To test external country mapping (e.g., **Nigeria**), supply a public IP allocated to Nigeria (such as `102.89.33.1` or `41.203.64.1`) or explicitly pass a custom `geoip` object in the API payload.

### 1. Trigger DDoS Alert (Nigeria Origin - Public IP `102.89.33.1`)
```bash
curl -X POST http://localhost:8000/ingest/alert \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-ddos-ng-1",
    "created_at": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
    "flow_id": "flow-ddos-ng",
    "src_ip": "102.89.33.1",
    "dst_ip": "192.168.1.103",
    "src_port": 54321,
    "dst_port": 80,
    "protocol": "TCP",
    "severity": "critical",
    "label": "DDoS_LOIT",
    "confidence": 0.98,
    "signals": {
      "rule": "High-Volume HTTP Flood",
      "score": 0.98
    },
    "geoip": {
      "country_iso": "NG",
      "country_name": "Nigeria",
      "city_name": "Lagos",
      "latitude": 6.5244,
      "longitude": 3.3792
    }
  }'
```

### 2. Trigger Port Scan Alert (Local Machine `192.168.1.103`)
```bash
curl -X POST http://localhost:8000/ingest/alert \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-scan-alert-1",
    "created_at": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
    "flow_id": "flow-scan-test",
    "src_ip": "192.168.1.103",
    "dst_ip": "192.168.1.103",
    "src_port": 39482,
    "dst_port": 22,
    "protocol": "TCP",
    "severity": "high",
    "label": "Port_Scan",
    "confidence": 0.89,
    "signals": {
      "rule": "Sequential Port Probe Detection",
      "score": 0.89
    }
  }'
```

### 3. Trigger SQL Injection / Backend Probe Alert
```bash
curl -X POST http://localhost:8000/ingest/alert \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-sqli-alert-1",
    "created_at": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
    "flow_id": "flow-sqli-test",
    "src_ip": "102.89.33.1",
    "dst_ip": "192.168.1.103",
    "src_port": 50123,
    "dst_port": 8000,
    "protocol": "TCP",
    "severity": "critical",
    "label": "Web_SQL_Injection",
    "confidence": 0.96,
    "signals": {
      "rule": "Backend API Injection Probe",
      "payload_pattern": "'\' UNION SELECT username, password FROM users--",
      "target_endpoint": "/alerts"
    },
    "geoip": {
      "country_iso": "NG",
      "country_name": "Nigeria",
      "city_name": "Abuja",
      "latitude": 9.0765,
      "longitude": 7.3986
    }
  }'
```

---

## Method 3 — Local Live Traffic Testing (Same Host: `192.168.1.103`)

When running live capture sensors locally on Kali Linux (`192.168.1.103`):

### 1. Loopback Port Scan (Self-Targeting)
Scan ports on the local host using the loopback or host interface:
```bash
# Scan local open ports to trigger NIDS flow generator
sudo nmap -sS -p 1-1000 127.0.0.1
```

### 2. HTTP Endpoint Functional Verification
Verify backend health and alert retrieval endpoints:
```bash
# Query backend API status
curl http://localhost:8000/status

# Retrieve active stored alerts
curl http://localhost:8000/alerts?limit=10
```

