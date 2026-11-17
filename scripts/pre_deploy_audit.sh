#!/usr/bin/env bash
# ==============================================================================
# AI IDS/IDP — Pre-Deployment Cluster & Host Security Audit + Backup Script
# Non-destructive inspection of existing Linux host, firewall, CNI, and K8s state
# ==============================================================================
set -euo pipefail

BACKUP_DIR="./backups/$(date -u +"%Y%m%d_%H%M%S")"
mkdir -p "$BACKUP_DIR"

echo "=================================================================="
echo " AI IDS/IDP Pre-Deployment Audit & State Backup"
echo " Backup Directory: $BACKUP_DIR"
echo "=================================================================="

echo "[1/7] Recording Host Network Interfaces & Active Management IPs..."
ip -br addr > "$BACKUP_DIR/host_interfaces.txt" 2>&1 || true
ss -tulnp > "$BACKUP_DIR/listening_ports.txt" 2>&1 || true
who > "$BACKUP_DIR/active_admin_sessions.txt" 2>&1 || true

echo "[2/7] Backing up Existing Firewall Rules (iptables & nftables)..."
if command -v iptables-save >/dev/null 2>&1; then
    sudo iptables-save > "$BACKUP_DIR/iptables_backup.rules" 2>/dev/null || true
    echo "  -> Saved iptables rules to $BACKUP_DIR/iptables_backup.rules"
fi
if command -v nft >/dev/null 2>&1; then
    sudo nft list ruleset > "$BACKUP_DIR/nftables_backup.nft" 2>/dev/null || true
    echo "  -> Saved nftables ruleset to $BACKUP_DIR/nftables_backup.nft"
fi

echo "[3/7] Inspecting Kubernetes Cluster, CNI, and Ingress Controller..."
if command -v kubectl >/dev/null 2>&1; then
    kubectl get nodes -o wide > "$BACKUP_DIR/k8s_nodes.txt" 2>&1 || true
    kubectl get ns > "$BACKUP_DIR/k8s_namespaces.txt" 2>&1 || true
    kubectl get all -A -o wide > "$BACKUP_DIR/k8s_all_resources.txt" 2>&1 || true
    kubectl get ingress -A -o yaml > "$BACKUP_DIR/k8s_ingresses.yaml" 2>&1 || true
    kubectl get networkpolicy -A -o yaml > "$BACKUP_DIR/k8s_networkpolicies.yaml" 2>&1 || true
    echo "  -> Saved Kubernetes resource inventory to $BACKUP_DIR/"
else
    echo "  -> kubectl not found on PATH; skipping cluster CLI snapshot"
fi

echo "[4/7] Detecting CNI Plugin..."
ls -la /etc/cni/net.d/ > "$BACKUP_DIR/cni_config.txt" 2>&1 || true

echo "[5/7] Verifying ML Model Artifacts..."
for f in scaler.joblib isoforest.joblib xgboost.json xgboost_labels.json; do
    if [ -f "./artifacts/$f" ]; then
        echo "  [OK] ./artifacts/$f present"
    else
        echo "  [WARN] ./artifacts/$f missing!"
    fi
done

echo "[6/7] Checking GeoIP Database..."
if [ -f "./data/GeoLite2-City.mmdb" ]; then
    echo "  [OK] ./data/GeoLite2-City.mmdb present"
else
    echo "  [INFO] GeoLite2-City.mmdb not found (optional)"
fi

echo "[7/7] Audit & Backup Complete: $BACKUP_DIR"
