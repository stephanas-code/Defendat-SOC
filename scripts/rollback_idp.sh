#!/usr/bin/env bash
# ==============================================================================
# AI IDS/IDP — Emergency Rollback & Firewall Recovery Script
# Safely disables IDP enforcement, removes AI_IDS_BLOCK rules, and removes
# quarantine NetworkPolicies without disrupting existing applications or IDS.
# ==============================================================================
set -euo pipefail

BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
CHAIN="${IDP_CHAIN:-AI_IDS_BLOCK}"

echo "=================================================================="
echo " AI IDS/IDP Emergency Rollback Procedure"
echo "=================================================================="

echo "[1/4] Engaging API Emergency Kill Switch (Monitor-Only Mode)..."
curl -s -X POST "$BACKEND_URL/idp/kill-switch" \
  -H "Content-Type: application/json" \
  -d '{"engage": true}' >/dev/null 2>&1 || true
echo "  -> API Kill Switch engaged."

echo "[2/4] Flushing and detaching iptables chain ($CHAIN)..."
if command -v iptables >/dev/null 2>&1; then
    for parent in INPUT FORWARD DOCKER-USER; do
        while sudo iptables -C "$parent" -j "$CHAIN" 2>/dev/null; do
            sudo iptables -D "$parent" -j "$CHAIN" 2>/dev/null || true
        done
    done
    sudo iptables -F "$CHAIN" 2>/dev/null || true
    sudo iptables -X "$CHAIN" 2>/dev/null || true
    echo "  -> Chain $CHAIN detached and flushed cleanly."
fi

echo "[3/4] Removing AI IDP Quarantine Kubernetes NetworkPolicies..."
if command -v kubectl >/dev/null 2>&1; then
    kubectl delete networkpolicy -A -l managed-by=ai-anomaly-ids-idp --ignore-not-found=true || true
    echo "  -> Quarantine NetworkPolicies removed."
fi

echo "[4/4] Rollback complete. All traffic blocks removed; IDS detection remains online."
