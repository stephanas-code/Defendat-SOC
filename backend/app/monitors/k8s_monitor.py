from __future__ import annotations

import base64
import json
import logging
import os
import re
import socket
import ssl
import tempfile
import threading
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from app.config import settings
from app.db import get_discovered_apps, insert_security_event, upsert_discovered_app
from app.schemas import AlertRecord, DiscoveredApplication, K8sAuditEventRequest, LayerSecurityEvent

logger = logging.getLogger(__name__)

SENSITIVE_HOST_PATHS = {
    "/",
    "/etc",
    "/proc",
    "/sys",
    "/var/run/docker.sock",
    "/var/run/containerd/containerd.sock",
    "/root",
}

KUBECONFIG_CANDIDATES = [
    os.getenv("KUBECONFIG", ""),
    "/etc/kubernetes/admin.conf",
    "/host/etc/kubernetes/admin.conf",
    "/etc/rancher/k3s/k3s.yaml",
    "/host/etc/rancher/k3s/k3s.yaml",
    "/var/snap/microk8s/current/credentials/client.config",
    "/root/.kube/config",
]


class KubernetesMonitor:
    """Real-Time Kubernetes Cluster Auto-Discovery, Workload Auditor & Live Service Inventory Engine.

    Strictly queries live Kubernetes API endpoints (via in-cluster ServiceAccount, KUBECONFIG,
    or KUBERNETES_API_URL) and real Linux /proc/net/tcp listening sockets. Zero mockup or dummy data.
    """

    def __init__(
        self,
        on_alert: Callable[[AlertRecord, str], None],
        on_node_ips: Optional[Callable[[List[str]], None]] = None,
    ) -> None:
        self._on_alert = on_alert
        self._on_node_ips = on_node_ips
        self._stop = threading.Event()
        self._lock = threading.RLock()

        self._apps: Dict[str, DiscoveredApplication] = {}
        self._isolated_workloads: List[Dict[str, Any]] = []
        self._suspicious_pods: List[Dict[str, Any]] = []
        self._audit_alerts: List[Dict[str, Any]] = []
        self._cluster_state: Dict[str, Any] = {
            "connected": False,
            "discovery_mode": "disconnected",
            "cluster_status": "disconnected",
            "nodes_count": 0,
            "namespaces_count": 0,
            "pods_count": 0,
            "deployments_count": 0,
            "services_count": 0,
            "ingresses_count": 0,
            "network_policies_count": 0,
            "applications_count": 0,
            "nodes": [],
            "namespaces": [],
            "suspicious_pods": [],
            "isolated_workloads": [],
            "audit_alerts_count": 0,
            "last_discovery_at": None,
        }
        self._emitted_pod_findings: Set[str] = set()
        self._audit_log_offset: int = 0

    def start(self) -> None:
        if not settings.kubernetes_monitoring_enabled:
            logger.info("kubernetes_monitoring_disabled")
            return
        try:
            self.discover_once()
        except Exception:
            logger.exception("initial_k8s_discovery_failed")
        threading.Thread(target=self._run_loop, daemon=True, name="k8s-monitor").start()

    def stop(self) -> None:
        self._stop.set()

    def _run_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.discover_once()
                if settings.kubernetes_audit_enabled:
                    self._tail_k8s_audit_log()
            except Exception:
                logger.exception("k8s_discovery_loop_error")
            time.sleep(max(10, settings.monitor_interval_seconds))

    def _resolve_k8s_credentials(self) -> Tuple[Optional[str], Dict[str, str], Optional[ssl.SSLContext]]:
        """Resolve real Kubernetes API URL, auth headers, and TLS context from ServiceAccount, env, or kubeconfig."""
        headers: Dict[str, str] = {"Accept": "application/json"}
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # 1. Explicit KUBERNETES_API_URL or in-cluster KUBERNETES_SERVICE_HOST
        host = os.getenv("KUBERNETES_SERVICE_HOST")
        port = os.getenv("KUBERNETES_SERVICE_PORT", "443")
        api_base = os.getenv("KUBERNETES_API_URL", "").strip()
        if not api_base and host:
            api_base = f"https://{host}:{port}"

        token = os.getenv("KUBERNETES_BEARER_TOKEN", "").strip()
        token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        if not token and os.path.exists(token_path):
            try:
                with open(token_path, "r", encoding="utf-8") as f:
                    token = f.read().strip()
            except Exception:
                pass

        ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        if os.path.exists(ca_path):
            try:
                ctx = ssl.create_default_context(cafile=ca_path)
            except Exception:
                pass

        if api_base:
            if token:
                headers["Authorization"] = f"Bearer {token}"
            return api_base, headers, ctx

        # 2. Check standard Linux kubeconfig paths (kubeadm, k3s, microk8s, ~/.kube/config)
        for kc_path in KUBECONFIG_CANDIDATES:
            if not kc_path or not os.path.exists(kc_path) or not os.path.isfile(kc_path):
                continue
            try:
                with open(kc_path, "r", encoding="utf-8", errors="ignore") as f:
                    raw = f.read()
                m_srv = re.search(r"server:\s*(https?://[^\s\"']+)", raw)
                if not m_srv:
                    continue
                server_url = m_srv.group(1).strip()

                m_tok = re.search(r"token:\s*([^\s\"']+)", raw)
                if m_tok:
                    headers["Authorization"] = f"Bearer {m_tok.group(1).strip()}"

                m_cert = re.search(r"client-certificate-data:\s*([A-Za-z0-9+/=]+)", raw)
                m_key = re.search(r"client-key-data:\s*([A-Za-z0-9+/=]+)", raw)
                if m_cert and m_key:
                    cert_bytes = base64.b64decode(m_cert.group(1))
                    key_bytes = base64.b64decode(m_key.group(1))
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as cf, tempfile.NamedTemporaryFile(
                        delete=False, suffix=".key"
                    ) as kf:
                        cf.write(cert_bytes)
                        kf.write(key_bytes)
                        cf_name, kf_name = cf.name, kf.name
                    try:
                        ctx.load_cert_chain(certfile=cf_name, keyfile=kf_name)
                    finally:
                        try:
                            os.unlink(cf_name)
                            os.unlink(kf_name)
                        except Exception:
                            pass
                return server_url, headers, ctx
            except Exception:
                continue

        return None, headers, None

    def _k8s_api_get(self, path: str) -> Optional[Dict[str, Any]]:
        api_base, headers, ctx = self._resolve_k8s_credentials()
        if not api_base:
            return None
        url = f"{api_base.rstrip('/')}/{path.lstrip('/')}"
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, context=ctx, timeout=4) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return None

    def discover_once(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        nodes_resp = self._k8s_api_get("/api/v1/nodes")

        if nodes_resp and "items" in nodes_resp:
            return self._process_live_k8s_api(nodes_resp, now)
        else:
            return self._discover_real_host_sockets(now)

    def _process_live_k8s_api(self, nodes_resp: Dict[str, Any], now: datetime) -> Dict[str, Any]:
        ns_resp = self._k8s_api_get("/api/v1/namespaces") or {"items": []}
        pods_resp = self._k8s_api_get("/api/v1/pods") or {"items": []}
        svc_resp = self._k8s_api_get("/api/v1/services") or {"items": []}
        dep_resp = self._k8s_api_get("/apis/apps/v1/deployments") or {"items": []}
        ing_resp = self._k8s_api_get("/apis/networking.k8s.io/v1/ingresses") or {"items": []}
        netpol_resp = self._k8s_api_get("/apis/networking.k8s.io/v1/networkpolicies") or {"items": []}

        node_ips: List[str] = []
        nodes_summary: List[Dict[str, Any]] = []
        for n in nodes_resp.get("items", []):
            meta = n.get("metadata", {})
            status = n.get("status", {})
            addrs = status.get("addresses", [])
            ip = next((a["address"] for a in addrs if a.get("type") == "InternalIP"), "")
            if ip:
                node_ips.append(ip)
            conds = status.get("conditions", [])
            ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in conds)
            nodes_summary.append(
                {
                    "name": meta.get("name", ""),
                    "ip": ip,
                    "status": "Ready" if ready else "NotReady",
                    "kubelet_version": status.get("nodeInfo", {}).get("kubeletVersion", ""),
                    "security_status": "secure" if ready else "warning",
                }
            )

        if self._on_node_ips and node_ips:
            self._on_node_ips(node_ips)

        namespaces = [item.get("metadata", {}).get("name", "") for item in ns_resp.get("items", []) if item.get("metadata", {}).get("name")]

        suspicious_pods: List[Dict[str, Any]] = []
        pod_counts_by_app: Dict[str, int] = {}
        for pod in pods_resp.get("items", []):
            pmeta = pod.get("metadata", {})
            pname = pmeta.get("name", "")
            pns = pmeta.get("namespace", "default")
            plabels = pmeta.get("labels", {}) or {}
            app_label = plabels.get("app") or plabels.get("app.kubernetes.io/name") or pname.rsplit("-", 2)[0]
            pod_counts_by_app[f"{pns}/{app_label}"] = pod_counts_by_app.get(f"{pns}/{app_label}", 0) + 1

            pspec = pod.get("spec", {})
            pstatus = pod.get("status", {})
            pod_ip = pstatus.get("podIP", "")

            for vol in pspec.get("volumes", []):
                hp = (vol.get("hostPath") or {}).get("path")
                if hp and any(hp == sp or hp.startswith(sp + "/") for sp in SENSITIVE_HOST_PATHS):
                    finding_key = f"{pns}/{pname}:hostpath:{hp}"
                    suspicious_pods.append(
                        {
                            "pod": pname,
                            "namespace": pns,
                            "issue": f"Sensitive hostPath mount ({hp})",
                            "severity": "high",
                            "pod_ip": pod_ip,
                        }
                    )
                    if finding_key not in self._emitted_pod_findings:
                        self._emitted_pod_findings.add(finding_key)
                        self._emit_k8s_event(
                            category="K8s_HostPath_Mount_Abuse",
                            severity="high",
                            src_ip=pod_ip or "127.0.0.1",
                            target=f"{pns}/{pname}",
                            namespace=pns,
                            summary=f"Pod {pns}/{pname} mounts sensitive hostPath '{hp}'",
                            details={"pod": pname, "host_path": hp, "confidence": 0.90},
                            trigger_alert=True,
                        )

            for c in pspec.get("containers", []):
                cname = c.get("name", "")
                sc = c.get("securityContext") or {}
                if sc.get("privileged") is True and pns not in ("kube-system", "ai-ids-system"):
                    finding_key = f"{pns}/{pname}:{cname}:privileged"
                    suspicious_pods.append(
                        {
                            "pod": pname,
                            "namespace": pns,
                            "issue": f"Privileged container ({cname})",
                            "severity": "critical",
                            "pod_ip": pod_ip,
                        }
                    )
                    if finding_key not in self._emitted_pod_findings:
                        self._emitted_pod_findings.add(finding_key)
                        self._emit_k8s_event(
                            category="K8s_Privileged_Container",
                            severity="critical",
                            src_ip=pod_ip or "127.0.0.1",
                            target=f"{pns}/{pname}",
                            namespace=pns,
                            summary=f"Privileged container '{cname}' running in pod {pns}/{pname}",
                            details={"pod": pname, "container": cname, "image": c.get("image"), "confidence": 0.94},
                            trigger_alert=True,
                        )

        ingress_by_svc: Dict[str, str] = {}
        for ing in ing_resp.get("items", []):
            imeta = ing.get("metadata", {})
            ins = imeta.get("namespace", "default")
            for rule in ing.get("spec", {}).get("rules", []):
                host = rule.get("host", "*")
                for path_item in (rule.get("http") or {}).get("paths", []):
                    svc_name = ((path_item.get("backend") or {}).get("service") or {}).get("name")
                    if svc_name:
                        ingress_by_svc[f"{ins}/{svc_name}"] = host

        discovered_now: Dict[str, DiscoveredApplication] = {}
        for svc in svc_resp.get("items", []):
            smeta = svc.get("metadata", {})
            sname = smeta.get("name", "")
            sns = smeta.get("namespace", "default")
            if not sname or sname == "kubernetes":
                continue
            sspec = svc.get("spec", {})
            ports = [int(p.get("port", 0)) for p in sspec.get("ports", []) if p.get("port")]
            selector = sspec.get("selector") or {}
            app_label = selector.get("app") or selector.get("app.kubernetes.io/name") or sname
            domain = ingress_by_svc.get(f"{sns}/{sname}", f"{sname}.{sns}.svc.cluster.local")
            pcount = pod_counts_by_app.get(f"{sns}/{app_label}", 0)
            app_id = f"{sns}:{sname}"
            app_rec = DiscoveredApplication(
                app_id=app_id,
                name=app_label,
                namespace=sns,
                service_name=sname,
                ingress_domain=domain,
                exposed_ports=ports,
                pod_count=pcount,
                monitoring_status="active",
                security_status=self._apps[app_id].security_status if app_id in self._apps else "protected",
                threat_count=self._apps[app_id].threat_count if app_id in self._apps else 0,
                waf_enabled=settings.waf_enabled,
                last_seen=now,
                recent_threats=self._apps[app_id].recent_threats if app_id in self._apps else [],
                metadata={"type": sspec.get("type", "ClusterIP"), "source": "kubernetes_api"},
            )
            discovered_now[app_id] = app_rec
            try:
                upsert_discovered_app(app_rec)
            except Exception:
                pass

        with self._lock:
            self._apps = discovered_now
            self._suspicious_pods = suspicious_pods
            self._cluster_state = {
                "connected": True,
                "discovery_mode": "kubernetes_api",
                "cluster_status": "warning" if suspicious_pods else "secure",
                "nodes_count": len(nodes_summary),
                "namespaces_count": len(namespaces),
                "pods_count": len(pods_resp.get("items", [])),
                "deployments_count": len(dep_resp.get("items", [])),
                "services_count": len(svc_resp.get("items", [])),
                "ingresses_count": len(ing_resp.get("items", [])),
                "network_policies_count": len(netpol_resp.get("items", [])),
                "applications_count": len(self._apps),
                "nodes": nodes_summary,
                "namespaces": namespaces,
                "suspicious_pods": suspicious_pods,
                "isolated_workloads": list(self._isolated_workloads),
                "audit_alerts_count": len(self._audit_alerts),
                "last_discovery_at": now.isoformat(),
            }
            return dict(self._cluster_state)

    def _discover_real_host_sockets(self, now: datetime) -> Dict[str, Any]:
        """When Kubernetes API is not connected, discover ONLY real listening TCP services from /proc/net/tcp."""
        proc_dir = settings.host_proc_dir if os.path.exists(settings.host_proc_dir) else "/proc"
        real_ports: Dict[int, str] = {}

        for tcp_rel in ["net/tcp", "net/tcp6"]:
            p = os.path.join(proc_dir, tcp_rel)
            if not os.path.exists(p):
                continue
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f.readlines()[1:]:
                        cols = line.strip().split()
                        if len(cols) < 4:
                            continue
                        state = cols[3]
                        if state != "0A":  # 0A = TCP_LISTEN
                            continue
                        local_hex = cols[1]
                        ip_hex, port_hex = local_hex.split(":")
                        port = int(port_hex, 16)
                        if port <= 0 or port >= 32768:
                            continue
                        ip_str = "0.0.0.0"
                        if len(ip_hex) == 8:
                            ip_str = socket.inet_ntoa(int(ip_hex, 16).to_bytes(4, "little"))
                        real_ports[port] = ip_str
            except Exception:
                pass

        hostname = socket.gethostname()
        discovered_now: Dict[str, DiscoveredApplication] = {}
        for port, bind_ip in sorted(real_ports.items()):
            app_id = f"host-socket:{port}"
            prev = self._apps.get(app_id)
            app_rec = DiscoveredApplication(
                app_id=app_id,
                name=f"tcp-listener-{port}",
                namespace="host-network",
                service_name=f"socket-{port}",
                ingress_domain=f"{bind_ip}:{port}",
                exposed_ports=[port],
                pod_count=1,
                monitoring_status="active",
                security_status=prev.security_status if prev else "protected",
                threat_count=prev.threat_count if prev else 0,
                waf_enabled=settings.waf_enabled and port in (80, 443, 3000, 8000, 8080),
                last_seen=now,
                recent_threats=prev.recent_threats if prev else [],
                metadata={"type": "HostSocket", "hostname": hostname, "source": "/proc/net/tcp"},
            )
            discovered_now[app_id] = app_rec
            try:
                upsert_discovered_app(app_rec)
            except Exception:
                pass

        with self._lock:
            self._apps = discovered_now
            self._cluster_state = {
                "connected": False,
                "discovery_mode": "host_sockets_only (K8s API not connected)",
                "cluster_status": "disconnected",
                "nodes_count": 0,
                "namespaces_count": 0,
                "pods_count": 0,
                "deployments_count": 0,
                "services_count": len(discovered_now),
                "ingresses_count": 0,
                "network_policies_count": len(self._isolated_workloads),
                "applications_count": len(discovered_now),
                "nodes": [],
                "namespaces": [],
                "suspicious_pods": list(self._suspicious_pods),
                "isolated_workloads": list(self._isolated_workloads),
                "audit_alerts_count": len(self._audit_alerts),
                "last_discovery_at": now.isoformat(),
            }
            return dict(self._cluster_state)

    def _tail_k8s_audit_log(self) -> None:
        """Tail real Kubernetes API audit log file if mounted from the control-plane host."""
        path = settings.kubernetes_audit_log_path
        if not path or not os.path.exists(path) or not os.path.isfile(path):
            return
        try:
            size = os.path.getsize(path)
            if self._audit_log_offset == 0:
                self._audit_log_offset = max(0, size - 65536)
            if size < self._audit_log_offset:
                self._audit_log_offset = 0
            if size == self._audit_log_offset:
                return
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self._audit_log_offset)
                lines = f.readlines()
                self._audit_log_offset = f.tell()
            for line in lines[-200:]:
                try:
                    ev = json.loads(line.strip())
                    verb = ev.get("verb", "")
                    user = (ev.get("user") or {}).get("username", "unknown")
                    obj_ref = ev.get("objectRef") or {}
                    ns = obj_ref.get("namespace", "default")
                    res = obj_ref.get("resource", "")
                    rname = obj_ref.get("name", "")
                    src_ips = ev.get("sourceIPs") or ["127.0.0.1"]
                    status_code = int((ev.get("responseStatus") or {}).get("code", 200))
                    if res in ("secrets", "clusterrolebindings", "rolebindings", "pods"):
                        self.ingest_audit_event(
                            K8sAuditEventRequest(
                                verb=verb,
                                user=user,
                                namespace=ns,
                                resource=res,
                                resource_name=rname,
                                source_ip=src_ips[0],
                                status_code=status_code,
                            )
                        )
                except Exception:
                    continue
        except Exception:
            pass

    def ingest_audit_event(self, req: K8sAuditEventRequest) -> Dict[str, Any]:
        """Inspect a Kubernetes API audit event or container runtime security event."""
        now = datetime.now(timezone.utc)
        issues: List[str] = []
        severity = "low"
        category = "K8s_API_Audit"
        conf = 0.80

        verb = req.verb.lower()
        res = req.resource.lower()

        if req.privileged:
            issues.append("Privileged container creation")
            severity = "critical"
            category = "K8s_Privileged_Container"
            conf = 0.96
        if req.host_path and any(req.host_path == sp or req.host_path.startswith(sp + "/") for sp in SENSITIVE_HOST_PATHS):
            issues.append(f"Sensitive hostPath mount ({req.host_path})")
            severity = "critical" if severity == "critical" else "high"
            category = "K8s_HostPath_Mount_Abuse"
            conf = max(conf, 0.93)
        if req.run_as_root and req.namespace not in ("kube-system", "ai-ids-system"):
            issues.append("Container running as root (UID 0)")
            if severity == "low":
                severity = "medium"
                category = "K8s_Root_Container"
        if res == "secrets" and verb in ("get", "list", "watch") and "system:" not in req.user:
            issues.append(f"Suspicious secret access by '{req.user}'")
            severity = "high" if severity != "critical" else "critical"
            category = "K8s_Secret_Access_Anomaly"
            conf = max(conf, 0.91)
        if res in ("clusterrolebindings", "rolebindings", "clusterroles") and verb in ("create", "patch", "update"):
            issues.append(f"RBAC privilege modification on {res}/{req.resource_name} by '{req.user}'")
            severity = "critical"
            category = "K8s_RBAC_Privilege_Escalation"
            conf = 0.95
        if "exec" in res or "attach" in res:
            issues.append(f"Interactive container exec into {req.namespace}/{req.resource_name}")
            severity = "high" if severity == "low" else severity
            category = "K8s_Container_Exec"
            conf = max(conf, 0.89)

        summary = (
            f"K8s Security Alert [{req.namespace}/{req.resource_name or res}]: " + "; ".join(issues)
            if issues
            else f"K8s Audit: {req.user} performed {req.verb} on {req.namespace}/{req.resource}/{req.resource_name}"
        )

        with self._lock:
            if issues and req.resource_name:
                pod_entry = {
                    "pod": req.resource_name,
                    "namespace": req.namespace,
                    "issue": "; ".join(issues),
                    "severity": severity,
                    "pod_ip": req.source_ip,
                    "timestamp": now.isoformat(),
                }
                self._suspicious_pods.insert(0, pod_entry)
                self._suspicious_pods = self._suspicious_pods[:50]
                self._cluster_state["suspicious_pods"] = list(self._suspicious_pods)
                self._cluster_state["cluster_status"] = "warning"

            audit_entry = {
                "timestamp": now.isoformat(),
                "user": req.user,
                "verb": req.verb,
                "namespace": req.namespace,
                "resource": f"{req.resource}/{req.resource_name}",
                "source_ip": req.source_ip,
                "severity": severity,
                "category": category,
                "summary": summary,
            }
            self._audit_alerts.insert(0, audit_entry)
            self._audit_alerts = self._audit_alerts[:100]
            self._cluster_state["audit_alerts_count"] = len(self._audit_alerts)

        return self._emit_k8s_event(
            category=category,
            severity=severity,
            src_ip=req.source_ip,
            target=f"{req.namespace}/{req.resource_name or req.resource}",
            namespace=req.namespace,
            summary=summary,
            details={
                "user": req.user,
                "verb": req.verb,
                "resource": req.resource,
                "resource_name": req.resource_name,
                "privileged": req.privileged,
                "run_as_root": req.run_as_root,
                "host_path": req.host_path,
                "image": req.image,
                "confidence": conf,
                **req.details,
            },
            trigger_alert=bool(issues),
        )

    def isolate_workload(self, namespace: str, workload_name: str, reason: str = "Confirmed workload compromise") -> Dict[str, Any]:
        """Generate (and enforce when connected to K8s API) a zero-trust NetworkPolicy to quarantine a compromised pod/app."""
        now = datetime.now(timezone.utc)
        policy_manifest = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": f"ai-idp-quarantine-{workload_name}",
                "namespace": namespace,
                "labels": {"managed-by": "ai-anomaly-ids-idp", "action": "quarantine"},
            },
            "spec": {
                "podSelector": {"matchLabels": {"app": workload_name}},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],
                "egress": [
                    {
                        "to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}],
                        "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}],
                    }
                ],
            },
        }

        # Attempt live POST to Kubernetes API if connected
        k8s_enforced = False
        api_base, headers, ctx = self._resolve_k8s_credentials()
        if api_base:
            try:
                url = f"{api_base.rstrip('/')}/apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies"
                headers["Content-Type"] = "application/json"
                req = urllib.request.Request(
                    url,
                    data=json.dumps(policy_manifest).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                with urllib.request.urlopen(req, context=ctx, timeout=4) as resp:
                    if resp.status in (200, 201):
                        k8s_enforced = True
            except Exception:
                pass

        entry = {
            "isolation_id": f"ISO-{str(uuid4())[:8].upper()}",
            "namespace": namespace,
            "workload": workload_name,
            "reason": reason,
            "status": "enforced_in_k8s" if k8s_enforced else "policy_generated_awaiting_k8s_api",
            "created_at": now.isoformat(),
            "network_policy": policy_manifest,
        }
        with self._lock:
            self._isolated_workloads.insert(0, entry)
            self._cluster_state["isolated_workloads"] = list(self._isolated_workloads)
            for app in self._apps.values():
                if app.name == workload_name or app.service_name == workload_name:
                    app.security_status = "isolated"
                    try:
                        upsert_discovered_app(app)
                    except Exception:
                        pass

        self._emit_k8s_event(
            category="K8s_Workload_Quarantined",
            severity="critical",
            src_ip="127.0.0.1",
            target=f"{namespace}/{workload_name}",
            namespace=namespace,
            summary=f"Quarantine NetworkPolicy {'applied' if k8s_enforced else 'generated'} for {namespace}/{workload_name}: {reason}",
            details=entry,
            trigger_alert=False,
        )
        return entry

    def _emit_k8s_event(
        self,
        category: str,
        severity: str,
        src_ip: str,
        target: str,
        namespace: str,
        summary: str,
        details: Dict[str, Any],
        trigger_alert: bool = False,
    ) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        ev = LayerSecurityEvent(
            event_id=str(uuid4()),
            created_at=now,
            layer="kubernetes",
            category=category,
            severity=severity,
            src_ip=src_ip,
            dst_ip=target,
            target=target,
            namespace=namespace,
            summary=summary,
            details=details,
        )
        try:
            insert_security_event(ev)
        except Exception:
            pass

        if trigger_alert and self._on_alert:
            alert = AlertRecord(
                alert_id=str(uuid4()),
                created_at=now,
                flow_id=f"k8s-{ev.event_id[:8]}",
                src_ip=src_ip,
                dst_ip="10.96.0.1",
                src_port=0,
                dst_port=6443,
                protocol="TCP",
                severity=severity if severity in ("critical", "high", "medium", "low") else "high",
                label=category,
                confidence=float(details.get("confidence", 0.90)),
                signals={"layer": "kubernetes", "namespace": namespace, "target_app": target, "summary": summary, **details},
                geoip=None,
            )
            try:
                self._on_alert(alert, "Kubernetes Security Audit")
            except Exception:
                logger.exception("k8s_alert_callback_failed")

        return ev.model_dump(mode="json")

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            state = dict(self._cluster_state)
            state["audit_alerts"] = list(self._audit_alerts[:50])
            return state

    def list_applications(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.model_dump(mode="json") for a in self._apps.values()]
