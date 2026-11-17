#!/usr/bin/env bash
# ==============================================================================
# AI IDS/IDP — Safe Phased Production Deployment Script
# Deploys monitoring first, verifies telemetry, then activates safe IDP
# ==============================================================================
set -euo pipefail

MODE="${1:-docker}" # docker | k8s

echo "=================================================================="
echo " AI IDS/IDP Phased Production Deployment (Target: $MODE)"
echo "=================================================================="

# Step 1: Run pre-deployment audit & backup
if [ -f "./scripts/pre_deploy_audit.sh" ]; then
    bash ./scripts/pre_deploy_audit.sh
fi

if [ "$MODE" = "k8s" ]; then
    echo "[Phase 1] Applying isolated namespace & least-privilege RBAC..."
    kubectl apply -f k8s/00-namespace-rbac.yaml
    kubectl apply -f k8s/01-config-secrets.yaml

    echo "[Phase 2] Deploying internal storage & event bus (TimescaleDB, Redis, Kafka)..."
    kubectl apply -f k8s/02-storage-db-redis-kafka.yaml
    kubectl rollout status statefulset/timescaledb -n ai-ids-system --timeout=120s

    echo "[Phase 3] Deploying AI IDS/IDP Backend & SOC Dashboard..."
    kubectl apply -f k8s/03-backend-dashboard.yaml
    kubectl rollout status deployment/ai-ids-backend -n ai-ids-system --timeout=120s

    echo "[Phase 4] Deploying Node-Level Sensor & Responder DaemonSet..."
    kubectl apply -f k8s/04-sensor-responder-daemonset.yaml
    kubectl apply -f k8s/05-network-policies-waf.yaml
else
    echo "[Phase 1] Starting core infrastructure (Zookeeper, Kafka, Redis, TimescaleDB)..."
    docker compose up -d zookeeper kafka redis timescaledb
    sleep 8

    echo "[Phase 2] Starting AI Inference Backend & SOC Dashboard..."
    docker compose up -d --build backend ai_threat_visor
    sleep 5

    echo "[Phase 3] Starting Host Network Sensor & IDP Responder..."
    docker compose --profile capture up -d --build sensor responder
fi

echo "[Phase 5] Running End-to-End Validation Suite..."
python3 scripts/validate_full_system.py
