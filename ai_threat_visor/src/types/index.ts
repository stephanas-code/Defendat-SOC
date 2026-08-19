export interface NetworkAlert {
  id: string;
  timestamp: string;
  sourceIp: string;
  destIp: string;
  srcPort?: number;
  destPort?: number;
  protocol: string;
  port: number;
  attackType: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  confidence: number;
  location?: string;
  countryCode?: string;
  coordinates?: [number, number]; // [lat, lng]
}

export interface MLModelStats {
  name: string;
  accuracy: number | null;
  f1Score: number | null;
  latency: number | null;
  status: 'loaded' | 'active' | 'offline';
  lastRun: string | null;
}

export type HealthStatus = 'online' | 'degraded' | 'offline' | 'unknown';

export interface SystemComponentHealth {
  component: string;
  status: HealthStatus;
  detail?: string;
  uptime?: string;
  load?: number;
}

// Alias used by SystemHealth.tsx component
export type SystemHealth = SystemComponentHealth;

export interface AttackStats {
  type: string;
  count: number;
  trend: 'up' | 'down' | 'stable';
}

export interface PersistenceStatus {
  database: 'TimescaleDB' | 'PostgreSQL';
  status: 'connected' | 'error' | 'unknown';
  totalLogs: number | null;
  storageUsed: string | null;
  lastEventAt: string | null;
}

export interface DashboardStats {
  alertsTotal: number | null;
  alertsLastHour: number | null;
  alertsLastDay: number | null;
  criticalTotal: number | null;
  lastAlertAt: string | null;
  alertTableBytes: number | null;
  flowsTotal: number | null;
}