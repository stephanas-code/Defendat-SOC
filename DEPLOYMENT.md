# Production Deployment, Kubernetes Integration & Security Hardening Guide

This guide covers all 15 operational and architectural areas required to deploy and manage the **AI Anomaly IDS/IDP** on a production Linux server hosting Kubernetes.

---

## 1. Production Architecture

The platform uses a hybrid **Centralized Control Plane + Node-Level Telemetry/Enforcement** architecture:
- **Central Security Management & AI Inference (`ai-ids-backend`)**: FastAPI service running the 44-feature ML ensemble (Isolation Forest, XGBoost, LSTM Autoencoder), OWASP CRS WAF engine, Kubernetes Auto-Discovery & Audit monitor, Linux Host monitor, Centralized Threat Correlation Engine, and IDP Policy Coordinator.
- **Node-Level DaemonSet / Host Agents (`sensor` + `responder`)**:
  - `sensor`: Captures north-south and east-west traffic (`SENSOR_INTERFACE=any` with veth/bridge packet deduplication) using `CAP_NET_RAW` + `CAP_NET_ADMIN` (no unrestricted `privileged: true`), reconstructs bidirectional flows, computes the 44 CICFlowMeter features, and streams compressed records to Kafka (`flows`).
  - `responder`: Subscribes to Kafka (`alerts`) and Redis (`idp:commands`) to enforce host-level `iptables`/`nftables` drops in the dedicated `AI_IDS_BLOCK` chain (`INPUT`, `FORWARD`, `DOCKER-USER`) with a 5-second background TTL expiry thread and 12 safety guardrails.
- **Internal Data Plane (`timescaledb`, `redis`, `kafka`, `zookeeper`)**: Bound strictly to `127.0.0.1` in Docker Compose or isolated via `ClusterIP` + `NetworkPolicy` in Kubernetes (`k8s/05-network-policies-waf.yaml`).
- **SOC Management Interface (`ai_threat_visor`)**: React/TypeScript operational dashboard on port `3000`.

---

## 2. Pre-Deployment Audit & Migration Safety

Before deploying on an existing production Kubernetes host, run the non-destructive audit and backup script:

```bash
chmod +x scripts/pre_deploy_audit.sh
./scripts/pre_deploy_audit.sh
```

This creates a timestamped backup directory under `./backups/YYYYMMDD_HHMMSS/` containing:
- Host network interfaces and active admin SSH sessions (`host_interfaces.txt`, `active_admin_sessions.txt`)
- Current listening ports (`listening_ports.txt`)
- Complete `iptables-save` and `nft list ruleset` backups (`iptables_backup.rules`, `nftables_backup.nft`)
- Complete Kubernetes cluster inventory (`k8s_nodes.txt`, `k8s_all_resources.txt`, `k8s_ingresses.yaml`, `k8s_networkpolicies.yaml`)
- CNI plugin configuration snapshot (`cni_config.txt`)

**Migration Safety Rules Enforced by Design**:
- Never flushes system-wide `iptables`/`nftables` tables; only manages rules inside the dedicated `AI_IDS_BLOCK` chain.
- Never deletes or restarts existing Kubernetes workloads or modifies existing service ports.

---

## 3. Server Deployment Guide (Docker Compose)

1. Review `.env` and set `IDP_MANAGEMENT_IPS` and `IDP_ALLOWLIST` to include your workstation/bastion IP and cluster CIDRs.
2. Start the stack initially in safe `monitor` or `safe_enforce` mode:

```bash
docker compose up -d zookeeper kafka redis timescaledb backend ai_threat_visor
docker compose --profile capture up -d sensor responder
```

3. Verify health and telemetry:

```bash
curl -s http://localhost:8000/status | python3 -m json.tool
```

---

## 4. Kubernetes Integration Guide (`k8s/`)

Deploy into the isolated `ai-ids-system` namespace:

```bash
kubectl apply -f k8s/00-namespace-rbac.yaml
kubectl apply -f k8s/01-config-secrets.yaml
kubectl apply -f k8s/02-storage-db-redis-kafka.yaml
kubectl apply -f k8s/03-backend-dashboard.yaml
kubectl apply -f k8s/04-sensor-responder-daemonset.yaml
kubectl apply -f k8s/05-network-policies-waf.yaml
```

Verify that applications across all namespaces are automatically discovered:

```bash
curl -s http://localhost:8000/kubernetes/applications | python3 -m json.tool
```

---

## 5. Linux Host Monitoring Setup

Configured via `.env`:
- `HOST_MONITORING_ENABLED=true`
- `LOG_MONITORING_ENABLED=true`
- `HOST_PROC_DIR=/host/proc` (or `/proc` on native Linux)
- `HOST_ETC_DIR=/host/etc`
- `HOST_LOG_DIR=/host/var/log`

The Host Monitor continuously inspects:
- `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp` for connection anomalies, SYN floods, and unexpected listening ports.
- `/proc/[pid]/cmdline` for suspicious processes (`xmrig`, reverse shells, `ncat`, `socat`, `chisel`).
- SHA-256 file integrity of `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `/etc/crontab`, `/etc/hosts`.
- `/var/log/auth.log`, `/var/log/secure`, `/var/log/syslog`, `/var/log/kern.log`, `/var/log/ufw.log` for SSH brute-force and `sudo` privilege escalation.

You can also stream log lines from `rsyslog`/`fluent-bit` to `POST /host/log`.

---

## 6. Network Monitoring Setup

Configured via `.env`:
- `NETWORK_MONITORING_ENABLED=true`
- `SENSOR_INTERFACE=any` (or comma-separated `eth0,cni0,flannel.1`)
- `SENSOR_BPF_FILTER=ip`

Why `SENSOR_INTERFACE=any` with packet signature deduplication works for Kubernetes:
- Sniffing on a single physical NIC misses east-west pod-to-pod traffic on `cni0`/`flannel.1`/`cali+`.
- Sniffing on `any` captures both north-south and east-west traffic, while `FlowTable._recent_pkt_sigs` deduplicates identical packets traversing `veth` + bridge interfaces so flow counters remain accurate.

---

## 7. Website, API & WAF Integration

Important architectural principle: **Network-flow ML classification operates on L3/L4 flow timings and packet lengths and cannot inspect TLS-encrypted HTTP payloads.**
To inspect HTTP payloads post-TLS termination, integrate the built-in OWASP CRS WAF engine with your Kubernetes NGINX Ingress Controller:

1. Enable ModSecurity & OWASP CRS on NGINX Ingress, or add the external auth subrequest annotation to any protected Ingress resource:

```yaml
metadata:
  annotations:
    nginx.ingress.kubernetes.io/enable-modsecurity: "true"
    nginx.ingress.kubernetes.io/enable-owasp-core-rules: "true"
    nginx.ingress.kubernetes.io/auth-url: "http://ai-ids-backend.ai-ids-system.svc.cluster.local:8000/waf/auth-verify"
```

2. Or forward reverse-proxy access logs / webhook payloads to `POST /waf/inspect`.

---

## 8. IDP Activation & Threat Response Policies

Configured via `.env` or dynamically via `POST /idp/policy`:

| Severity | Default Response Policy | Enforcement Layer |
|----------|-------------------------|-------------------|
| `CRITICAL` | Automatic block when `IDP_AUTO_BLOCK_CRITICAL=true` and `confidence >= IDP_CONFIDENCE_THRESHOLD` (`0.75`). | `iptables`/`nftables` (`AI_IDS_BLOCK` for `2 * IDP_BLOCK_SECONDS`) + WAF block |
| `HIGH` | Automatic block when `IDP_AUTO_BLOCK_HIGH=true` and (`confidence >= IDP_CONFIDENCE_THRESHOLD` or corroborating hits `>= 2`). | `iptables`/`nftables` (`AI_IDS_BLOCK` for `IDP_BLOCK_SECONDS`) + WAF block |
| `MEDIUM` | Monitor, correlate, and apply L7 `rate_limit` if repeated (`>= 3` events in 5m). Never blindly L3-dropped on first hit. | `rate_limit` |
| `LOW` / `BENIGN` | Record and monitor only. Never blocked. | None |

### Enforcement Modes (`IDP_ENFORCEMENT_MODE`)
- `monitor`: Evaluates all rules and records `simulated` blocks in the dashboard without modifying host firewall rules.
- `safe_enforce` (Default): Enforces temporary host firewall and WAF blocks with all 12 safety guardrails active.
- `full_enforce`: Enables host firewall + WAF blocks + Kubernetes `NetworkPolicy` pod quarantine.

---

## 9. Firewall Enforcement Architecture & Allowlist Configuration

The responder creates chain `AI_IDS_BLOCK` and inserts jump rules at the top of `INPUT`, `FORWARD`, and `DOCKER-USER` (if present). This guarantees that malicious external IPs are dropped both when targeting the Linux host (`INPUT`) and when targeting Kubernetes pods (`FORWARD`).

Manage the allowlist via `.env` (`IDP_ALLOWLIST`, `IDP_MANAGEMENT_IPS`) or live API:

```bash
# Add trusted IP or CIDR
curl -X POST http://localhost:8000/idp/allowlist \
  -H "Content-Type: application/json" \
  -d '{"ip_or_cidr": "203.0.113.10/32", "label": "Admin VPN Gateway", "is_management": true}'

# List protected IPs
curl http://localhost:8000/idp/allowlist
```

---

## 10. Dashboard Operations Guide

Open `http://localhost:3000`:
- **Dashboard**: Infrastructure status bar (Linux Host, K8s Cluster, Nodes/NS, Pods/Apps, Sockets, IDP Status, OWASP WAF, Host Memory), real-time Threat Map, Attack Vectors, Severity Distribution, Top Attacking IPs, Most Targeted Ports, and Live Threat Stream.
- **IDP & Incidents**: Emergency IDP Kill Switch, Enforcement Mode selector, Currently Blocked IPs with live TTL countdown & Manual Unblock, Manual Threat Containment form, Allowlist manager, Guardrail Audit History, and Correlated Multi-Layer Security Incidents.
- **K8s, Host & WAF**: Auto-Discovered Kubernetes Application Inventory with one-click Pod Quarantine (`NetworkPolicy`), OWASP CRS WAF telemetry & rule testers, K8s Pod Audit findings, and Linux Host & File Integrity status.

---

## 11. Production Security Hardening

- Internal ports (`5432`, `6379`, `9094`) are bound strictly to `127.0.0.1` in `docker-compose.yml` and isolated via `NetworkPolicy` in Kubernetes.
- Enable API key enforcement for administrative endpoints by setting `API_AUTH_ENABLED=true` and passing `X-API-Key: <API_KEY>`.
- `sensor` and `responder` drop all unnecessary Linux capabilities and retain only `CAP_NET_ADMIN` and `CAP_NET_RAW`.

---

## 12. Testing, Validation, Rollback & Troubleshooting

```bash
# Run full 16-test validation & latency benchmark suite
python scripts/validate_full_system.py

# Emergency rollback (disables IDP & flushes AI_IDS_BLOCK)
./scripts/rollback_idp.sh
```
