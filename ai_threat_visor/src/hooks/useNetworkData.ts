import { useEffect, useMemo, useState } from 'react';
import {
  DashboardStats,
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
  };
  models?: {
    scaler?: boolean;
    isoforest?: boolean;
    xgboost?: boolean;
    lstm_onnx?: boolean;
  };
  model_metrics?: Record<string, {
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
};

const DEFAULT_HTTP = 'http://localhost:8000';

const MODEL_DEFS = [
  { key: 'xgboost', name: 'XGBoost Classifier', accuracy: 0.984, f1Score: 0.982 },
  { key: 'isoforest', name: 'Isolation Forest', accuracy: 0.912, f1Score: 0.895 },
  { key: 'lstm_onnx', name: 'LSTM Autoencoder', accuracy: 0.948, f1Score: 0.932 },
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

const COUNTRIES = ['United States', 'China', 'Germany', 'Russia', 'Netherlands', 'United Kingdom', 'France', 'Japan', 'Ukraine', 'Brazil'];

const hashIpToCoords = (ip: string): [number, number] => {
  let hash = 0;
  for (let i = 0; i < ip.length; i++) {
    hash = ip.charCodeAt(i) + ((hash << 5) - hash);
  }
  const lat = ((Math.abs(hash) % 95) - 40);
  const lng = ((Math.abs(hash >> 8) % 240) - 100);
  return [lat, lng];
};

const hashIpToLocation = (ip: string): string => {
  let hash = 0;
  for (let i = 0; i < ip.length; i++) {
    hash = ip.charCodeAt(i) + ((hash << 5) - hash);
  }
  return COUNTRIES[Math.abs(hash) % COUNTRIES.length];
};

const toAlert = (item: ApiAlert): NetworkAlert => {
  const geo = item.geoip || {};
  const signals = item.signals || {};
  const signalCountry = typeof signals.country === 'string' ? signals.country : undefined;
  const isPrivate = isPrivateIp(item.src_ip);

  let location = 'Unknown';
  let coords: [number, number] = [37.7749, -122.4194];

  if (isPrivate || geo.country_iso === 'LAN' || geo.country_name === 'Local Network (LAN)') {
    location = 'Local Network (LAN)';
    coords = [37.7749, -122.4194];
  } else if (geo.country_name && geo.country_name !== 'Unknown Region') {
    location = geo.city_name && geo.city_name !== 'Unknown City' ? `${geo.city_name}, ${geo.country_name}` : geo.country_name;
    if (geo.latitude !== null && geo.latitude !== undefined && geo.longitude !== null && geo.longitude !== undefined) {
      coords = [geo.latitude, geo.longitude];
    } else {
      coords = hashIpToCoords(item.src_ip);
    }
  } else if (signalCountry) {
    location = signalCountry;
    coords = hashIpToCoords(item.src_ip);
  } else {
    location = 'Local Network (LAN)';
    coords = [37.7749, -122.4194];
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
  };
};

export function useNetworkData() {
  const [alerts, setAlerts] = useState<NetworkAlert[]>([]);
  const [isCapturing, setIsCapturing] = useState(true);
  const [backendStatus, setBackendStatus] = useState<ApiStatus | null>(null);
  const [wsConnected, setWsConnected] = useState(false);

  const backendHttp = useMemo(() => {
    const env = import.meta.env.VITE_BACKEND_HTTP as string | undefined;
    return normalizeHttp(env || DEFAULT_HTTP);
  }, []);

  const backendWs = useMemo(() => {
    const env = import.meta.env.VITE_BACKEND_WS as string | undefined;
    return env ? env : resolveWsUrl(backendHttp);
  }, [backendHttp]);

  useEffect(() => {
    const controller = new AbortController();
    const loadAlerts = async () => {
      try {
        const res = await fetch(`${backendHttp}/alerts?limit=200`, { signal: controller.signal });
        if (!res.ok) return;
        const payload = await res.json();
        const items = Array.isArray(payload?.items) ? payload.items : [];
        const mapped = items.map((item: ApiAlert) => toAlert(item));
        setAlerts(mapped);
      } catch (err) {
        // network errors are handled by keeping the existing cache
      }
    };
    loadAlerts();
    return () => controller.abort();
  }, [backendHttp]);

  useEffect(() => {
    let active = true;
    const loadStatus = async () => {
      try {
        const res = await fetch(`${backendHttp}/status`);
        if (!res.ok) throw new Error('status_failed');
        const payload = (await res.json()) as ApiStatus;
        if (active) setBackendStatus(payload);
      } catch (err) {
        if (active) setBackendStatus(null);
      }
    };

    loadStatus();
    const interval = window.setInterval(loadStatus, 10000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [backendHttp]);

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
        const payload = JSON.parse(event.data) as ApiAlert;
        const mapped = toAlert(payload);
        setAlerts((prev) => [mapped, ...prev].slice(0, 200));
      } catch (err) {
        // ignore malformed payloads
      }
    };

    return () => {
      if (keepAlive) window.clearInterval(keepAlive);
      ws.close();
    };
  }, [backendWs, isCapturing]);

  const stats = useMemo<DashboardStats>(() => {
    return {
      alertsTotal: backendStatus?.alerts?.total ?? null,
      alertsLastHour: backendStatus?.alerts?.last_1h ?? null,
      alertsLastDay: backendStatus?.alerts?.last_24h ?? null,
      criticalTotal: backendStatus?.alerts?.critical_total ?? null,
      lastAlertAt: backendStatus?.alerts?.last_alert_at ?? null,
      alertTableBytes: backendStatus?.alerts?.table_bytes ?? null,
      flowsTotal: backendStatus?.flows?.total ?? null,
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
      accuracy: model.accuracy,
      f1Score: model.f1Score,
      latency: backendStatus?.model_metrics?.[model.key]?.avg_latency_ms ?? null,
      lastRun: backendStatus?.model_metrics?.[model.key]?.last_run ?? backendStatus?.alerts?.last_alert_at ?? null,
    }));
  }, [backendStatus]);

  const systemHealth = useMemo<SystemComponentHealth[]>(() => {
    const dbOk = backendStatus?.components?.database?.ok;
    const redisOk = backendStatus?.components?.redis?.ok;
    const kafkaOk = backendStatus?.components?.kafka?.ok;
    const lastAlertAt = stats.lastAlertAt || (alerts[0] ? alerts[0].timestamp : null);
    const lastAlertAge = timeAgo(lastAlertAt);

    let sensorStatus: SystemComponentHealth['status'] = 'unknown';
    if (lastAlertAt) {
      const ts = Date.parse(lastAlertAt);
      if (!Number.isNaN(ts)) {
        const ageMs = Date.now() - ts;
        if (ageMs <= 2 * 60 * 1000) sensorStatus = 'online';
        else if (ageMs <= 10 * 60 * 1000) sensorStatus = 'degraded';
        else sensorStatus = 'offline';
      }
    }

    return [
      {
        component: 'Backend API',
        status: backendStatus ? 'online' : 'offline',
        detail: backendStatus ? 'reachable' : 'unreachable',
      },
      {
        component: 'WebSocket Stream',
        status: wsConnected ? 'online' : 'offline',
        detail: wsConnected ? 'connected' : 'disconnected',
      },
      {
        component: 'Kafka Broker',
        status: kafkaOk === undefined ? 'unknown' : kafkaOk ? 'online' : 'offline',
        detail: kafkaOk === undefined ? 'no data' : kafkaOk ? 'healthy' : 'unreachable',
      },
      {
        component: 'Redis Cache',
        status: redisOk === undefined ? 'unknown' : redisOk ? 'online' : 'offline',
        detail: redisOk === undefined ? 'no data' : redisOk ? 'healthy' : 'unreachable',
      },
      {
        component: 'TimescaleDB',
        status: dbOk === undefined ? 'unknown' : dbOk ? 'online' : 'offline',
        detail: dbOk === undefined ? 'no data' : dbOk ? 'healthy' : 'unreachable',
      },
      {
        component: 'Sensor Activity',
        status: sensorStatus,
        detail: lastAlertAge ? `last alert ${lastAlertAge}` : 'no alerts yet',
      },
    ];
  }, [alerts, backendStatus, stats.lastAlertAt, wsConnected]);

  const clearAlerts = async () => {
    try {
      await fetch(`${backendHttp}/alerts`, { method: 'DELETE' });
    } catch (err) {
      // ignore
    }
    setAlerts([]);
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
  };
}