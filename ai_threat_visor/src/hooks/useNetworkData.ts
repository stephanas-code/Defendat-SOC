import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  CorrelatedIncident,
  DashboardStats,
  DiscoveredApp,
  IdpAllowlistEntry,
  IdpBlockEntry,
  MLModelStats,
  NetworkAlert,
  PersistenceStatus,
  SystemComponentHealth,
} from '../types';

type ApiGeo = {
  country_iso?: string | null;
  country_name?: string | null;
  city_name?: string | null;
  latitude?: number | null;
  longitude?: number | null;
};

type ApiAlert = {
  alert_id: string;
  created_at: string;
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  severity: string;
  label: string;
  confidence: number;
  signals?: Record<string, unknown> | null;
  geoip?: ApiGeo | null;
};

type ApiStatus = {
  ok: boolean;
  components?: {
    database?: { ok: boolean };
    redis?: { ok: boolean };
    kafka?: { ok: boolean };
    ids?: { ok: boolean; enabled?: boolean };
    idp?: { ok: boolean; enabled?: boolean; mode?: string; active_blocks?: number };
    waf?: { ok: boolean; enabled?: boolean; mode?: string };
    kubernetes?: { ok: boolean; status?: string };
    host?: { ok: boolean; status?: string };
  };
  models?: {
    scaler?: boolean;
    isoforest?: boolean;
    xgboost?: boolean;
    lstm_onnx?: boolean;
  };
  model_metrics?: Record<string, {
    invocations?: number;
    avg_latency_ms?: number;
    last_run?: string;
  }>;
  alerts?: {
    total: number;
    last_1h: number;
    last_24h: number;
    critical_total: number;
    last_alert_at: string | null;
    table_bytes: number;
  };
  flows?: {
    total: number;
    last_flow_at: string | null;
    table_bytes: number;
  };
  idp?: {
    enabled: boolean;
    enforcement_mode: string;
    kill_switch_engaged: boolean;
    active_blocks_count: number;
    failed_attempts_count: number;
    allowlist_count: number;
  };
  infrastructure?: {
    server_status: string;
    cluster_status: string;
    monitored_nodes: number;
    monitored_namespaces: number;
    monitored_pods: number;
    monitored_applications: number;
    active_connections: number;
    established_connections: number;
    cpu_load_pct: number;
    memory_used_pct: number;
    incidents_open: number;
  };
  waf?: {
    enabled: boolean;
    total_inspected: number;
    http_attacks_detected: number;
    blocked_requests_count: number;
    rate_limited_count: number;
  };
};

export type IdpFullStatus = {
  enabled: boolean;
  enforcement_mode: string;
  kill_switch_engaged: boolean;
  firewall_backend: string;
  chain: string;
  block_seconds: number;
  max_blocks: number;
  confidence_threshold: number;
  auto_block_critical: boolean;
  auto_block_high: boolean;
  active_blocks_count: number;
  history_blocks_count: number;
  failed_attempts_count: number;
  active_blocks: IdpBlockEntry[];
  recent_history: IdpBlockEntry[];
  allowlist: IdpAllowlistEntry[];
  system_protected_ips: string[];
};

export type K8sFullStatus = {
  connected: boolean;
  discovery_mode: string;
  cluster_status: string;
  nodes_count: number;
  namespaces_count: number;
  pods_count: number;
  deployments_count: number;
  services_count: number;
  ingresses_count: number;
  network_policies_count: number;
  applications_count: number;
  nodes: Array<{ name: string; ip: string; status: string; kubelet_version: string; security_status: string }>;
  namespaces: string[];
  suspicious_pods: Array<{ pod: string; namespace: string; issue: string; severity: string; pod_ip: string; timestamp?: string }>;
  isolated_workloads: Array<{ isolation_id: string; namespace: string; workload: string; reason: string; status: string; created_at: string }>;
  audit_alerts_count: number;
  audit_alerts?: Array<{ timestamp: string; user: string; verb: string; namespace: string; resource: string; source_ip: string; severity: string; category: string; summary: string }>;
  last_discovery_at: string | null;
};

export type HostFullStatus = {
  status: string;
  cpu_load_pct: number;
  memory_used_pct: number;
  memory_total_mb: number;
  memory_used_mb: number;
  active_connections: number;
  established_connections: number;
  listening_ports: number[];
  unexpected_ports: number[];
  running_processes: number;
  suspicious_processes: Array<{ pid: number; cmdline: string; pattern: string }>;
  file_integrity_status: string;
  monitored_files_count: number;
  modified_files: string[];
  cron_jobs_count: number;
  ssh_failed_attempts: number;
  network_rx_mb: number;
  network_tx_mb: number;
  last_scan_at: string | null;
};

export type WafFullStatus = {
  enabled: boolean;
  mode: string;
  total_inspected: number;
  http_attacks_detected: number;
  sqli_count: number;
  xss_count: number;
  path_traversal_count: number;
  command_injection_count: number;
  brute_force_count: number;
  bot_scanner_count: number;
  rate_limited_count: number;
  blocked_requests_count: number;
  recent_detections: Array<{
    detection_id: string;
    timestamp: string;
    rule_id: string;
    category: string;
    severity: string;
    confidence: number;
    src_ip: string;
    host: string;
    target_app: string;
    namespace: string;
    method: string;
    uri: string;
    user_agent: string;
    action: string;
  }>;
};

const DEFAULT_HTTP = 'http://localhost:8000';

const MODEL_DEFS = [
  { key: 'xgboost', name: 'XGBoost Classifier' },
  { key: 'isoforest', name: 'Isolation Forest' },
  { key: 'lstm_onnx', name: 'LSTM Autoencoder' },
];

const SEVERITY_MAP: Record<string, NetworkAlert['severity']> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

const normalizeHttp = (url: string) => url.replace(/\/+$/, '');

const resolveWsUrl = (httpBase: string) => {
  const wsBase = httpBase.replace(/^http/, 'ws');
  return `${wsBase}/ws/alerts`;
};

const formatBytes = (bytes?: number | null): string | null => {
  if (bytes === null || bytes === undefined || Number.isNaN(bytes)) {
    return null;
  }
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  const precision = value >= 10 || idx === 0 ? 0 : 1;
  return `${value.toFixed(precision)} ${units[idx]}`;
};

const timeAgo = (iso?: string | null) => {
  if (!iso) return null;
  const ts = Date.parse(iso);
  if (Number.isNaN(ts)) return null;
  const deltaMs = Date.now() - ts;
  if (deltaMs < 0) return 'just now';
  const seconds = Math.floor(deltaMs / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
};

const toSeverity = (raw: string): NetworkAlert['severity'] => {
  const sev = raw?.toLowerCase?.() ?? 'low';
  return SEVERITY_MAP[sev] ?? 'Low';
};

const isPrivateIp = (ip: string): boolean => {
  if (!ip) return false;
  if (ip === '127.0.0.1' || ip === 'localhost' || ip === '::1' || ip === '0.0.0.0') return true;
  const parts = ip.split('.').map(Number);
  if (parts.length === 4) {
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
  }
  return false;
};

const toAlert = (item: ApiAlert): NetworkAlert => {
  const geo = item.geoip || {};
  const signals = item.signals || {};
  const isPrivate = isPrivateIp(item.src_ip);

  let location = 'Unresolved IP';
  let coords: [number, number] | undefined = undefined;

  if (isPrivate || geo.country_iso === 'LAN' || geo.country_name === 'Local Network (LAN)') {
    location = 'Local Network (LAN)';
  } else if (geo.country_name && geo.country_name !== 'Unknown Region') {
    location = geo.city_name && geo.city_name !== 'Unknown City' ? `${geo.city_name}, ${geo.country_name}` : geo.country_name;
    if (typeof geo.latitude === 'number' && typeof geo.longitude === 'number') {
      coords = [geo.latitude, geo.longitude];
    }
  }

  return {
    id: item.alert_id,
    timestamp: item.created_at,
    sourceIp: item.src_ip,
    destIp: item.dst_ip,
    srcPort: item.src_port,
    destPort: item.dst_port,
    protocol: item.protocol,
    port: item.dst_port,
    attackType: item.label || 'Unknown',
    severity: toSeverity(item.severity),
    confidence: Number(item.confidence ?? 0),
    location,
    countryCode: isPrivate ? 'LAN' : (geo.country_iso || undefined),
    coordinates: coords,
    incidentId: typeof signals.incident_id === 'string' ? signals.incident_id : undefined,
    detectionSource: typeof signals.detection_source === 'string' ? signals.detection_source : (typeof signals.layer === 'string' ? signals.layer : 'AI Network Flow'),
    idpAction: typeof signals.idp_action === 'string' ? signals.idp_action : undefined,
  };
};

export function useNetworkData() {
  const [alerts, setAlerts] = useState<NetworkAlert[]>([]);
  const [isCapturing, setIsCapturing] = useState(true);
  const [backendStatus, setBackendStatus] = useState<ApiStatus | null>(null);
  const [idpStatus, setIdpStatus] = useState<IdpFullStatus | null>(null);
  const [incidents, setIncidents] = useState<CorrelatedIncident[]>([]);
  const [k8sStatus, setK8sStatus] = useState<K8sFullStatus | null>(null);
  const [applications, setApplications] = useState<DiscoveredApp[]>([]);
  const [hostStatus, setHostStatus] = useState<HostFullStatus | null>(null);
  const [wafStatus, setWafStatus] = useState<WafFullStatus | null>(null);
  const [wsConnected, setWsConnected] = useState(false);

  const backendHttp = useMemo(() => {
    const env = import.meta.env.VITE_BACKEND_HTTP as string | undefined;
    return normalizeHttp(env || DEFAULT_HTTP);
  }, []);

  const backendWs = useMemo(() => {
    const env = import.meta.env.VITE_BACKEND_WS as string | undefined;
    return env ? env : resolveWsUrl(backendHttp);
  }, [backendHttp]);

  const refreshAll = useCallback(async () => {
    try {
      const [statusRes, alertsRes, idpRes, incRes, k8sRes, appsRes, hostRes, wafRes] = await Promise.allSettled([
        fetch(`${backendHttp}/status`),
        fetch(`${backendHttp}/alerts?limit=200`),
        fetch(`${backendHttp}/idp/status`),
        fetch(`${backendHttp}/incidents?limit=100`),
        fetch(`${backendHttp}/kubernetes/status`),
        fetch(`${backendHttp}/kubernetes/applications`),
        fetch(`${backendHttp}/host/status`),
        fetch(`${backendHttp}/waf/status`),
      ]);

      if (statusRes.status === 'fulfilled' && statusRes.value.ok) {
        setBackendStatus((await statusRes.value.json()) as ApiStatus);
      }
      if (alertsRes.status === 'fulfilled' && alertsRes.value.ok) {
        const payload = await alertsRes.value.json();
        const items = Array.isArray(payload?.items) ? payload.items : [];
        setAlerts(items.map((item: ApiAlert) => toAlert(item)));
      }
      if (idpRes.status === 'fulfilled' && idpRes.value.ok) {
        setIdpStatus((await idpRes.value.json()) as IdpFullStatus);
      }
      if (incRes.status === 'fulfilled' && incRes.value.ok) {
        const payload = await incRes.value.json();
        setIncidents(Array.isArray(payload?.items) ? payload.items : []);
      }
      if (k8sRes.status === 'fulfilled' && k8sRes.value.ok) {
        setK8sStatus((await k8sRes.value.json()) as K8sFullStatus);
      }
      if (appsRes.status === 'fulfilled' && appsRes.value.ok) {
        const payload = await appsRes.value.json();
        setApplications(Array.isArray(payload?.items) ? payload.items : []);
      }
      if (hostRes.status === 'fulfilled' && hostRes.value.ok) {
        setHostStatus((await hostRes.value.json()) as HostFullStatus);
      }
      if (wafRes.status === 'fulfilled' && wafRes.value.ok) {
        setWafStatus((await wafRes.value.json()) as WafFullStatus);
      }
    } catch {
      // keep existing cached state on transient network error
    }
  }, [backendHttp]);

  useEffect(() => {
    refreshAll();
    const interval = window.setInterval(refreshAll, 5000);
    return () => window.clearInterval(interval);
  }, [refreshAll]);

  useEffect(() => {
    if (!isCapturing) {
      setWsConnected(false);
      return;
    }

    const ws = new WebSocket(backendWs);
    let keepAlive: number | undefined;

    ws.onopen = () => {
      setWsConnected(true);
      keepAlive = window.setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send('ping');
        }
      }, 15000);
    };

    ws.onclose = () => {
      setWsConnected(false);
      if (keepAlive) window.clearInterval(keepAlive);
    };

    ws.onerror = () => {
      setWsConnected(false);
      if (keepAlive) window.clearInterval(keepAlive);
    };

    ws.onmessage = (event) => {
      if (!isCapturing) return;
      try {
        const data = JSON.parse(event.data);
        if (data && (data.action === 'clear' || data.type === 'clear')) {
          setAlerts([]);
          return;
        }
        if (data && (data.type === 'idp_action' || data.type === 'idp_kill_switch')) {
          refreshAll();
          return;
        }
        if (data && data.alert_id) {
          const payload = data as ApiAlert;
          const mapped = toAlert(payload);
          setAlerts((prev) => [mapped, ...prev.filter((a) => a.id !== mapped.id)].slice(0, 200));
        }
      } catch {
        // ignore malformed payloads
      }
    };

    return () => {
      if (keepAlive) window.clearInterval(keepAlive);
      ws.close();
    };
  }, [backendWs, isCapturing, refreshAll]);

  const stats = useMemo<DashboardStats>(() => {
    const inf = backendStatus?.infrastructure;
    return {
      alertsTotal: backendStatus?.alerts?.total ?? null,
      alertsLastHour: backendStatus?.alerts?.last_1h ?? null,
      alertsLastDay: backendStatus?.alerts?.last_24h ?? null,
      criticalTotal: backendStatus?.alerts?.critical_total ?? null,
      lastAlertAt: backendStatus?.alerts?.last_alert_at ?? null,
      alertTableBytes: backendStatus?.alerts?.table_bytes ?? null,
      flowsTotal: backendStatus?.flows?.total ?? null,
      infrastructure: inf
        ? {
            serverStatus: inf.server_status,
            clusterStatus: inf.cluster_status,
            monitoredNodes: inf.monitored_nodes,
            monitoredNamespaces: inf.monitored_namespaces,
            monitoredPods: inf.monitored_pods,
            monitoredApplications: inf.monitored_applications,
            activeConnections: inf.active_connections,
            establishedConnections: inf.established_connections,
            cpuLoadPct: inf.cpu_load_pct,
            memoryUsedPct: inf.memory_used_pct,
            incidentsOpen: inf.incidents_open,
            idsEnabled: backendStatus?.components?.ids?.enabled ?? true,
            idpEnabled: backendStatus?.idp?.enabled ?? true,
            idpMode: backendStatus?.idp?.enforcement_mode ?? 'safe_enforce',
            idpActiveBlocks: backendStatus?.idp?.active_blocks_count ?? 0,
            wafEnabled: backendStatus?.waf?.enabled ?? true,
            wafDetected: backendStatus?.waf?.http_attacks_detected ?? 0,
            wafBlocked: backendStatus?.waf?.blocked_requests_count ?? 0,
          }
        : undefined,
    };
  }, [backendStatus]);

  const persistence = useMemo<PersistenceStatus>(() => {
    const dbOk = backendStatus?.components?.database?.ok;
    return {
      database: 'TimescaleDB',
      status: dbOk === undefined ? 'unknown' : dbOk ? 'connected' : 'error',
      totalLogs: backendStatus?.alerts?.total ?? null,
      storageUsed: formatBytes(backendStatus?.alerts?.table_bytes),
      lastEventAt: backendStatus?.alerts?.last_alert_at ?? null,
    };
  }, [backendStatus]);

  const mlModels = useMemo<MLModelStats[]>(() => {
    return MODEL_DEFS.map((model) => ({
      name: model.name,
      status: backendStatus?.models?.[model.key as keyof ApiStatus['models']] ? 'loaded' : 'offline',
      accuracy: null,
      f1Score: null,
      latency: backendStatus?.model_metrics?.[model.key]?.avg_latency_ms ?? null,
      invocations: backendStatus?.model_metrics?.[model.key]?.invocations ?? 0,
      lastRun: backendStatus?.model_metrics?.[model.key]?.last_run ?? null,
    }));
  }, [backendStatus]);

  const systemHealth = useMemo<SystemComponentHealth[]>(() => {
    const dbOk = backendStatus?.components?.database?.ok;
    const redisOk = backendStatus?.components?.redis?.ok;
    const kafkaOk = backendStatus?.components?.kafka?.ok;
    const idpOk = backendStatus?.components?.idp?.ok;
    const wafOk = backendStatus?.components?.waf?.ok;
    const k8sOk = backendStatus?.components?.kubernetes?.ok;
    const lastAlertAt = stats.lastAlertAt || (alerts[0] ? alerts[0].timestamp : null);
    const lastAlertAge = timeAgo(lastAlertAt);

    return [
      {
        component: 'Backend API',
        status: backendStatus ? 'online' : 'offline',
        detail: backendStatus ? 'reachable' : 'unreachable',
      },
      {
        component: 'IDP Enforcement',
        status: idpOk ? 'online' : 'degraded',
        detail: backendStatus?.idp ? `${backendStatus.idp.enforcement_mode} (${backendStatus.idp.active_blocks_count} blocked)` : 'standby',
      },
      {
        component: 'OWASP WAF Engine',
        status: wafOk ? 'online' : 'offline',
        detail: backendStatus?.waf ? `${backendStatus.waf.http_attacks_detected} threats caught` : 'ready',
      },
      {
        component: 'Kubernetes Monitor',
        status: k8sOk ? 'online' : 'offline',
        detail: k8sOk
          ? `${backendStatus?.infrastructure?.monitored_nodes ?? 0} nodes / ${backendStatus?.infrastructure?.monitored_pods ?? 0} pods`
          : 'K8s API not connected',
      },
      {
        component: 'Kafka Event Bus',
        status: kafkaOk === undefined ? 'unknown' : kafkaOk ? 'online' : 'offline',
        detail: kafkaOk ? 'healthy' : 'unreachable',
      },
      {
        component: 'Redis Dedup & Sync',
        status: redisOk === undefined ? 'unknown' : redisOk ? 'online' : 'offline',
        detail: redisOk ? 'healthy' : 'unreachable',
      },
      {
        component: 'TimescaleDB',
        status: dbOk === undefined ? 'unknown' : dbOk ? 'online' : 'offline',
        detail: dbOk ? 'healthy' : 'unreachable',
      },
      {
        component: 'WebSocket Stream',
        status: wsConnected ? 'online' : 'offline',
        detail: lastAlertAge ? `last alert ${lastAlertAge}` : (wsConnected ? 'connected' : 'disconnected'),
      },
    ];
  }, [alerts, backendStatus, stats.lastAlertAt, wsConnected]);

  const clearAlerts = async () => {
    try {
      await fetch(`${backendHttp}/alerts`, { method: 'DELETE' });
    } catch {
      // ignore
    }
    setAlerts([]);
    refreshAll();
  };

  return {
    alerts,
    clearAlerts,
    isCapturing,
    setIsCapturing,
    mlModels,
    persistence,
    systemHealth,
    stats,
    backendStatus,
    idpStatus,
    incidents,
    k8sStatus,
    applications,
    hostStatus,
    wafStatus,
    refreshAll,
    backendHttp,
  };
}
