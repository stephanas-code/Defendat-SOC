# Defendat SOC — Real-Time Server & Kubernetes AI IDS/IDP Platform

Production-grade, AI-powered Network, Linux Host, Kubernetes, and Application Intrusion Detection and Prevention System (`AI-IDS/IDP`).

Designed for **real-time deployment on live Linux servers and Kubernetes clusters** with zero mockup or synthetic data—every metric, flow, alert, host socket, Kubernetes resource, WAF event, and firewall block originates strictly from live system telemetry.

---

## 1. Architecture Overview

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                      LINUX HOST & KUBERNETES CLUSTER INFRASTRUCTURE                    │
│                                                                                        │
│  ┌─────────────────────┐  ┌─────────────────────┐  ┌────────────────────────────────┐  │
│  │ Network Flow Sensor │  │ Linux Host Monitor  │  │ Kubernetes Auto-Discovery &    │  │
│  │ (Scapy / Conntrack) │  │ (/proc, FIM, Logs,  │  │ Audit (Live K8s API / Kubelet  │  │
│  │ North-South & CNI   │  │ SSH, Sudo, Sockets) │  │ Nodes, Pods, Services, RBAC)   │  │
│  └──────────┬──────────┘  └──────────┬──────────┘  └───────────────┬────────────────┘  │
│             │                        │                             │                   │
│             ▼                        ▼                             ▼                   │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │              CENTRAL AI INFERENCE, WAF & CORRELATION ENGINE (FastAPI)            │  │
│  │  • 44-Feature Flow ML: Isolation Forest + XGBoost (14 classes) + LSTM ONNX       │  │
│  │  • OWASP CRS Application WAF: SQLi, XSS, LFI, Command Injection, Brute Force     │  │
│  │  • Multi-Layer Threat Correlation Engine (Unified Incident Tracking)             │  │
│  └─────────────────────────┬───────────────────────────────────┬────────────────────┘  │
│                            │                                   │                       │
│                            ▼                                   ▼                       │
│  ┌─────────────────────────────────────────────┐  ┌─────────────────────────────────┐  │
│  │ ACTIVE INTRUSION PREVENTION (IDP RESPONDER) │  │ PERSISTENCE & SOC DASHBOARD     │  │
│  │ • Host Firewall: iptables / nftables        │  │ • TimescaleDB Hypertables       │  │
│  │   (INPUT, FORWARD, DOCKER-USER chains)      │  │ • Redis Dedup & IDP State Sync  │  │
│  │ • L7 Ingress/WAF Block & Rate Limiting      │  │ • React/TS SOC UI (:3000)       │  │
│  │ • K8s Quarantine NetworkPolicy Isolation    │  │ • Built-in Setup Guide &        │  │
│  │ • 12 Safety Guardrails + Auto-Expiry TTL    │  │   Emergency IDP Kill Switch     │  │
│  └─────────────────────────────────────────────┘  └─────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. How to Set Up on a Live Linux Server (Step-by-Step)

### Step 1 — Clone & Run Pre-Deployment Audit / Firewall Backup

On your Linux server (Ubuntu, Debian, RHEL, Rocky, or Kali), clone the repository and run the non-destructive audit script to back up your existing `iptables`/`nftables` rules and Kubernetes state before enabling active prevention:

```bash
git clone https://github.com/stephanas-code/AI-IDS-IDP-TOOL.git
cd AI-IDS-IDP-TOOL

# Inspect your network interfaces and your current SSH client IP
ip -br addr
who

# Run pre-deployment audit & backup (saved to ./backups/YYYYMMDD_HHMMSS/)
chmod +x scripts/pre_deploy_audit.sh scripts/deploy_production.sh scripts/rollback_idp.sh
./scripts/pre_deploy_audit.sh
```

### Step 2 — Configure `.env` for Your Server & Protect Your Admin IP

Copy `.env.example` to `.env` and add your administrative workstation/bastion IP to `IDP_MANAGEMENT_IPS` and `IDP_ALLOWLIST`. This guarantees the IDP responder can **never** block your SSH or Kubernetes management access:

```bash
cp .env.example .env
nano .env
```

Key settings in `.env`:

```env
# Capture across all host and CNI interfaces (eth0, cni0, flannel.1, cali+) with packet deduplication
SENSOR_INTERFACE=any
SENSOR_BPF_FILTER=ip

# CRITICAL: Add your admin workstation/bastion IP here so it is permanently protected
IDP_MANAGEMENT_IPS=127.0.0.1,<YOUR_ADMIN_PUBLIC_IP>
IDP_ALLOWLIST=127.0.0.1/32,::1/128,10.96.0.0/12,10.244.0.0/16,<YOUR_ADMIN_PUBLIC_IP>/32

# Enable IDS & IDP active prevention
IDS_ENABLED=true
IDP_ENABLED=true
IDP_ENFORCEMENT_MODE=safe_enforce
IDP_BLOCK_SECONDS=600
IDP_CONFIDENCE_THRESHOLD=0.75
IDP_AUTO_BLOCK_CRITICAL=true
IDP_AUTO_BLOCK_HIGH=true

# Enable Server-Wide, Kubernetes, Host, Log & WAF Monitoring
KUBERNETES_MONITORING_ENABLED=true
KUBERNETES_AUDIT_ENABLED=true
HOST_MONITORING_ENABLED=true
NETWORK_MONITORING_ENABLED=true
APPLICATION_MONITORING_ENABLED=true
WAF_ENABLED=true
LOG_MONITORING_ENABLED=true
THREAT_INTELLIGENCE_ENABLED=true
```

### Step 3 — Start the Live Stack (Docker Compose with Host Packet Capture & IDP)

Start the infrastructure (`zookeeper`, `kafka`, `redis`, `timescaledb`), the AI inference `backend`, the `ai_threat_visor` SOC dashboard, and the host-network `sensor` + `responder`:

```bash
# Start all services including live packet sensor and iptables/nftables responder
docker compose --profile capture up -d --build
```

Verify live status and packet capture:

```bash
# Check backend, database, Redis, Kafka, ML models, and host telemetry
curl -s http://localhost:8000/status | python3 -m json.tool

# Watch live flow extraction and IDP responder logs
docker compose logs -f sensor responder
```

---

## 3. How to Deploy on a Live Kubernetes Cluster (`k8s/`)

To deploy directly inside a production Kubernetes cluster (`kubeadm`, `k3s`, `microk8s`, or managed Kubernetes) where the backend discovers all cluster resources via the Kubernetes API and `sensor` + `responder` run as a node-level `DaemonSet` on every node:

```bash
# 1. Build container images on the node (or push to your container registry)
docker compose --profile capture build

# 2. Apply isolated namespace & least-privilege RBAC ClusterRole
kubectl apply -f k8s/00-namespace-rbac.yaml

# 3. Apply ConfigMap & Secrets (update POSTGRES_PASSWORD & IDP_MANAGEMENT_IPS first)
kubectl apply -f k8s/01-config-secrets.yaml

# 4. Deploy TimescaleDB StatefulSet, Redis, Zookeeper & Kafka
kubectl apply -f k8s/02-storage-db-redis-kafka.yaml
kubectl rollout status statefulset/timescaledb -n ai-ids-system --timeout=120s

# 5. Deploy AI Inference Backend & SOC Dashboard
kubectl apply -f k8s/03-backend-dashboard.yaml

# 6. Deploy Node-Level Sensor & Responder DaemonSet + NetworkPolicies
kubectl apply -f k8s/04-sensor-responder-daemonset.yaml
kubectl apply -f k8s/05-network-policies-waf.yaml

# 7. Verify all pods in ai-ids-system
kubectl get pods -n ai-ids-system -o wide
```

> **Connecting Docker Compose Backend to a Host Kubernetes Cluster**:
> If you run the backend via Docker Compose on a Kubernetes control-plane node and want automatic Kubernetes discovery without deploying inside a pod, mount your cluster kubeconfig into the `backend` container in `docker-compose.yml` (e.g. `- /etc/kubernetes/admin.conf:/etc/kubernetes/admin.conf:ro` or `- /etc/rancher/k3s/k3s.yaml:/etc/rancher/k3s/k3s.yaml:ro`). `KubernetesMonitor` automatically detects and authenticates using `/etc/kubernetes/admin.conf`, `/etc/rancher/k3s/k3s.yaml`, `/root/.kube/config`, or in-cluster `ServiceAccount` tokens.

---

## 4. Protecting Websites & APIs with the OWASP CRS WAF

Network-layer packet capture (`sensor`) sees encrypted TLS packets on port `443` and cannot inspect encrypted HTTP payloads. To inspect HTTP/API payloads (SQL Injection, XSS, Path Traversal, Command Injection, Brute Force, Scanner Bots) after TLS termination:

### Option A — Kubernetes NGINX Ingress External Auth Integration
Add the following annotations to any Kubernetes `Ingress` resource to validate every incoming request against the AI IDS/IDP WAF and active blocklist before it reaches your application pods:

```yaml
metadata:
  annotations:
    nginx.ingress.kubernetes.io/enable-modsecurity: "true"
    nginx.ingress.kubernetes.io/enable-owasp-core-rules: "true"
    nginx.ingress.kubernetes.io/auth-url: "http://ai-ids-backend.ai-ids-system.svc.cluster.local:8000/waf/auth-verify"
```

### Option B — Live Reverse-Proxy Log Tailing
Mount your host Nginx / Ingress / ModSecurity log directory into the `backend` container and set `WAF_LOG_PATHS=/var/log/nginx/access.log,/var/log/modsec_audit.log` in `.env`.

---

## 5. Verifying Firewall Blocks & Emergency Rollback

### Inspect Active Host Firewall Rules
```bash
sudo iptables -L AI_IDS_BLOCK -n -v
```

### Instant Emergency Kill Switch / Rollback
To immediately flush all `AI_IDS_BLOCK` firewall rules, remove any quarantine `NetworkPolicy` resources, and switch the IDP to `monitor` mode without stopping IDS detection:

```bash
# Via rollback script:
./scripts/rollback_idp.sh

# Or via REST API:
curl -X POST http://localhost:8000/idp/kill-switch \
  -H "Content-Type: application/json" \
  -d '{"engage": true}'
```

---

## 6. Accessing the SOC Dashboard & Built-In Setup Guide

- **SOC Dashboard**: `http://localhost:3000`
  - Navigate to **Settings & Setup → Live Server Setup Guide** inside the dashboard for interactive, copyable server setup commands and live policy controls.
- **Backend API**: `http://localhost:8000`
- **Live System Status**: `http://localhost:8000/status`
