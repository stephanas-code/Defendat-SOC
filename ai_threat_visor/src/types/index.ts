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
  incidentId?: string;
  detectionSource?: string;
  idpAction?: string;
}

export interface MLModelStats {
  name: string;
  accuracy: number | null;
  f1Score: number | null;
  latency: number | null;
  invocations?: number;
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

export interface InfrastructureOverview {
  serverStatus: string;
  clusterStatus: string;
  monitoredNodes: number;
  monitoredNamespaces: number;
  monitoredPods: number;
  monitoredApplications: number;
  activeConnections: number;
  establishedConnections: number;
  cpuLoadPct: number;
  memoryUsedPct: number;
  incidentsOpen: number;
  idsEnabled: boolean;
  idpEnabled: boolean;
  idpMode: string;
  idpActiveBlocks: number;
  wafEnabled: boolean;
  wafDetected: number;
  wafBlocked: number;
}

export interface DashboardStats {
  alertsTotal: number | null;
  alertsLastHour: number | null;
  alertsLastDay: number | null;
  criticalTotal: number | null;
  lastAlertAt: string | null;
  alertTableBytes: number | null;
  flowsTotal: number | null;
  infrastructure?: InfrastructureOverview;
}

export interface IdpBlockEntry {
  block_id: string;
  ip: string;
  reason: string;
  severity: string;
  confidence: number;
  enforcement_layer: string;
  status: string;
  incident_id?: string | null;
  alert_id?: string | null;
  created_at: string;
  expires_at: string;
  remaining_seconds?: number;
  unblocked_at?: string | null;
  unblocked_by?: string | null;
  metadata?: Record<string, unknown>;
}

export interface IdpAllowlistEntry {
  entry_id: string;
  ip_or_cidr: string;
  label: string;
  is_management: boolean;
  created_at: string;
  created_by: string;
}

export interface CorrelatedIncident {
  incident_id: string;
  title: string;
  classification: string;
  severity: string;
  confidence: number;
  src_ip: string;
  dst_ip: string;
  target_app?: string | null;
  target_namespace?: string | null;
  status: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  detection_sources: string[];
  evidence: Array<Record<string, unknown>>;
  prevention_action: string;
  response_status: string;
}

export interface DiscoveredApp {
  app_id: string;
  name: string;
  namespace: string;
  service_name: string;
  ingress_domain: string;
  exposed_ports: number[];
  pod_count: number;
  monitoring_status: string;
  security_status: string;
  threat_count: number;
  waf_enabled: boolean;
  last_seen: string;
  recent_threats: Array<Record<string, unknown>>;
  metadata?: Record<string, unknown>;
}
