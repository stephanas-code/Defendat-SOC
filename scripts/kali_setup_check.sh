#!/usr/bin/env bash
# Pre-flight checks for Kali Linux live IDS deployment.
# Usage: ./scripts/kali_setup_check.sh

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAILURES=$((FAILURES + 1)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

FAILURES=0
BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"

echo "=== AI Anomaly IDS — Kali Setup Check ==="
echo

# Docker
if command -v docker >/dev/null 2>&1; then
  pass "Docker installed"
else
  fail "Docker not installed (sudo apt install docker.io)"
fi

if docker info >/dev/null 2>&1; then
  pass "Docker daemon reachable"
else
  fail "Cannot run docker (add user to docker group or use sudo)"
fi

# .env
if [[ -f .env ]]; then
  pass ".env exists"
  IFACE=$(grep -E '^SENSOR_INTERFACE=' .env | cut -d= -f2)
  if [[ -n "${IFACE}" ]]; then
    if ip link show "${IFACE}" >/dev/null 2>&1; then
      pass "SENSOR_INTERFACE=${IFACE} exists"
    else
      fail "SENSOR_INTERFACE=${IFACE} not found — run: ip -br link"
    fi
    if [[ "${IFACE}" == *mon* ]]; then
      warn "Interface looks like monitor mode (${IFACE}). Use managed wlan0 — see implementation.md"
    fi
  else
    warn "SENSOR_INTERFACE not set in .env"
  fi
else
  fail ".env missing — run: cp .env.example .env"
fi

# Model artifacts
for f in artifacts/scaler.joblib artifacts/isoforest.joblib artifacts/xgboost.json artifacts/xgboost_labels.json; do
  if [[ -f "$f" ]]; then
    pass "Found $f"
  else
    fail "Missing $f — train models (implementation.md or TRAINING_COLAB.md)"
  fi
done

# Containers
for svc in kafka backend redis timescaledb; do
  if docker compose ps --status running "$svc" 2>/dev/null | grep -q "$svc"; then
    pass "Container running: $svc"
  else
    fail "Container not running: $svc — run: docker compose up -d zookeeper kafka redis timescaledb backend ai_threat_visor"
  fi
done

if docker compose ps --status running sensor 2>/dev/null | grep -q sensor; then
  pass "Sensor container running (capture profile)"
else
  warn "Sensor not running — start with: docker compose --profile capture up -d sensor"
fi

# Backend API
if command -v curl >/dev/null 2>&1; then
  if curl -sf "${BACKEND_URL}/health" >/dev/null 2>&1; then
    pass "Backend health endpoint OK"
    MODELS=$(curl -sf "${BACKEND_URL}/health" | python3 -c "import sys,json; m=json.load(sys.stdin).get('models',{}); print(sum(1 for v in m.values() if v))" 2>/dev/null || echo "0")
    if [[ "${MODELS}" -ge 2 ]]; then
      pass "ML models loaded (${MODELS} reported)"
    else
      fail "ML models not loaded — check /health and train models"
    fi
  else
    fail "Backend not reachable at ${BACKEND_URL}"
  fi

  KAFKA_OK=$(curl -sf "${BACKEND_URL}/status" | python3 -c "import sys,json; print(json.load(sys.stdin).get('components',{}).get('kafka',{}).get('ok', False))" 2>/dev/null || echo "False")
  if [[ "${KAFKA_OK}" == "True" ]]; then
    pass "Kafka connected"
  else
    fail "Kafka not connected — ensure zookeeper+kafka containers are up"
  fi
else
  warn "curl not installed — skipping API checks"
fi

# Packet capture test (optional, needs root)
IFACE="${IFACE:-wlan0}"
if command -v timeout >/dev/null 2>&1 && command -v tcpdump >/dev/null 2>&1; then
  if ip link show "${IFACE}" >/dev/null 2>&1; then
    COUNT=$(sudo timeout 5 tcpdump -i "${IFACE}" -c 5 ip 2>/dev/null | wc -l || echo 0)
    if [[ "${COUNT}" -gt 0 ]]; then
      pass "Captured IP packets on ${IFACE} (tcpdump)"
    else
      warn "No IP packets on ${IFACE} in 5s — check bridged networking / WiFi connection"
    fi
  fi
fi

echo
if [[ "${FAILURES}" -eq 0 ]]; then
  echo -e "${GREEN}All critical checks passed.${NC}"
  echo "Next: python scripts/replay_network_flows.py --csv artifacts/CSVs/portscan.csv --backend ${BACKEND_URL} --rate 5 --limit 20"
  exit 0
else
  echo -e "${RED}${FAILURES} check(s) failed. See implementation.md for fixes.${NC}"
  exit 1
fi
