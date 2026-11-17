from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

import psycopg

from app.config import settings
from app.schemas import (
    AlertRecord,
    DiscoveredApplication,
    IdpAllowlistEntry,
    IdpBlockRecord,
    LayerSecurityEvent,
    SecurityIncident,
)

logger = logging.getLogger(__name__)


def dsn() -> str:
    return (
        f"host={settings.postgres_host} port={settings.postgres_port} "
        f"dbname={settings.postgres_db} user={settings.postgres_user} password={settings.postgres_password}"
    )


SCHEMA_SQL = """
CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS alerts (
  alert_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  flow_id TEXT NOT NULL,
  src_ip TEXT NOT NULL,
  dst_ip TEXT NOT NULL,
  src_port INT NOT NULL,
  dst_port INT NOT NULL,
  protocol TEXT NOT NULL,
  severity TEXT NOT NULL,
  label TEXT NOT NULL,
  confidence DOUBLE PRECISION NOT NULL,
  signals JSONB NOT NULL,
  geoip JSONB,
  PRIMARY KEY (alert_id, created_at)
);

SELECT create_hypertable('alerts', 'created_at', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS flows (
  flow_id TEXT NOT NULL,
  first_seen TIMESTAMPTZ NOT NULL,
  last_seen TIMESTAMPTZ NOT NULL,
  src_ip TEXT NOT NULL,
  dst_ip TEXT NOT NULL,
  src_port INT NOT NULL,
  dst_port INT NOT NULL,
  protocol TEXT NOT NULL,
  features JSONB NOT NULL,
  PRIMARY KEY (flow_id, first_seen)
);

SELECT create_hypertable('flows', 'first_seen', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS idp_blocks (
  block_id TEXT PRIMARY KEY,
  ip TEXT NOT NULL,
  reason TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence DOUBLE PRECISION NOT NULL,
  enforcement_layer TEXT NOT NULL DEFAULT 'iptables',
  status TEXT NOT NULL DEFAULT 'active',
  incident_id TEXT,
  alert_id TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  unblocked_at TIMESTAMPTZ,
  unblocked_by TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_idp_blocks_ip_status ON idp_blocks(ip, status);

CREATE TABLE IF NOT EXISTS idp_allowlist (
  entry_id TEXT PRIMARY KEY,
  ip_or_cidr TEXT UNIQUE NOT NULL,
  label TEXT NOT NULL,
  is_management BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL,
  created_by TEXT NOT NULL DEFAULT 'system'
);

CREATE TABLE IF NOT EXISTS incidents (
  incident_id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  classification TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence DOUBLE PRECISION NOT NULL,
  src_ip TEXT NOT NULL,
  dst_ip TEXT NOT NULL,
  target_app TEXT,
  target_namespace TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  first_seen TIMESTAMPTZ NOT NULL,
  last_seen TIMESTAMPTZ NOT NULL,
  event_count INT NOT NULL DEFAULT 1,
  detection_sources JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
  prevention_action TEXT NOT NULL DEFAULT 'Monitoring',
  response_status TEXT NOT NULL DEFAULT 'Active Monitoring'
);
CREATE INDEX IF NOT EXISTS idx_incidents_src_ip ON incidents(src_ip, last_seen DESC);

CREATE TABLE IF NOT EXISTS discovered_apps (
  app_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  namespace TEXT NOT NULL,
  service_name TEXT NOT NULL,
  ingress_domain TEXT NOT NULL,
  exposed_ports JSONB NOT NULL DEFAULT '[]'::jsonb,
  pod_count INT NOT NULL DEFAULT 1,
  monitoring_status TEXT NOT NULL DEFAULT 'active',
  security_status TEXT NOT NULL DEFAULT 'protected',
  threat_count INT NOT NULL DEFAULT 0,
  waf_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  last_seen TIMESTAMPTZ NOT NULL,
  recent_threats JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS security_events (
  event_id TEXT PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL,
  layer TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  src_ip TEXT NOT NULL,
  dst_ip TEXT NOT NULL,
  target TEXT NOT NULL,
  namespace TEXT,
  summary TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_security_events_layer_time ON security_events(layer, created_at DESC);
"""


def init_db() -> None:
    logger.info("db_init_start")
    last_err: Exception | None = None
    for _ in range(30):
        try:
            with psycopg.connect(dsn(), autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute(SCHEMA_SQL)
            logger.info("db_init_done")
            return
        except Exception as e:
            last_err = e
            time.sleep(1)
    if last_err:
        logger.exception("db_init_failed; continuing without DB (demo mode)")
        return


def insert_alert(alert: AlertRecord) -> None:
    with psycopg.connect(dsn(), autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO alerts (
                  alert_id, created_at, flow_id,
                  src_ip, dst_ip, src_port, dst_port, protocol,
                  severity, label, confidence,
                  signals, geoip
                ) VALUES (
                  %(alert_id)s, %(created_at)s, %(flow_id)s,
                  %(src_ip)s, %(dst_ip)s, %(src_port)s, %(dst_port)s, %(protocol)s,
                  %(severity)s, %(label)s, %(confidence)s,
                  %(signals)s::jsonb, %(geoip)s::jsonb
                )
                ON CONFLICT (alert_id, created_at) DO NOTHING
                """,
                {
                    "alert_id": alert.alert_id,
                    "created_at": alert.created_at,
                    "flow_id": alert.flow_id,
                    "src_ip": alert.src_ip,
                    "dst_ip": alert.dst_ip,
                    "src_port": alert.src_port,
                    "dst_port": alert.dst_port,
                    "protocol": alert.protocol,
                    "severity": alert.severity,
                    "label": alert.label,
                    "confidence": alert.confidence,
                    "signals": json.dumps(alert.model_dump()["signals"], default=str),
                    "geoip": json.dumps(alert.model_dump().get("geoip"), default=str)
                    if alert.model_dump().get("geoip") is not None
                    else None,
                },
            )


def insert_flow(
    flow_id: str,
    first_seen: datetime,
    last_seen: datetime,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
    features_json: dict,
) -> None:
    with psycopg.connect(dsn(), autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO flows (
                  flow_id, first_seen, last_seen,
                  src_ip, dst_ip, src_port, dst_port, protocol,
                  features
                ) VALUES (
                  %(flow_id)s, %(first_seen)s, %(last_seen)s,
                  %(src_ip)s, %(dst_ip)s, %(src_port)s, %(dst_port)s, %(protocol)s,
                  %(features)s::jsonb
                )
                ON CONFLICT (flow_id, first_seen) DO NOTHING
                """,
                {
                    "flow_id": flow_id,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "features": json.dumps(features_json, default=str),
                },
            )


def get_recent_alerts(limit: int = 200) -> Iterable[dict]:
    with psycopg.connect(dsn()) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT alert_id, created_at, flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
                       severity, label, confidence, signals, geoip
                FROM alerts
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()
    for row in rows:
        yield {
            "alert_id": row[0],
            "created_at": row[1].isoformat(),
            "flow_id": row[2],
            "src_ip": row[3],
            "dst_ip": row[4],
            "src_port": row[5],
            "dst_port": row[6],
            "protocol": row[7],
            "severity": row[8],
            "label": row[9],
            "confidence": float(row[10]),
            "signals": row[11],
            "geoip": row[12],
        }


def ping_db() -> bool:
    try:
        with psycopg.connect(dsn(), connect_timeout=2) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        return True
    except Exception:
        return False


def get_alert_stats() -> Dict[str, Any]:
    with psycopg.connect(dsn()) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                  COUNT(*) AS total,
                  COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '1 hour') AS last_1h,
                  COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours') AS last_24h,
                  COUNT(*) FILTER (WHERE severity = 'critical') AS critical_total,
                  MAX(created_at) AS last_alert_at
                FROM alerts
                """
            )
            row = cur.fetchone()

            cur.execute("SELECT pg_total_relation_size('alerts');")
            size_row = cur.fetchone()

    last_alert_at = row[4].isoformat() if row and row[4] else None
    return {
        "total": int(row[0]) if row else 0,
        "last_1h": int(row[1]) if row else 0,
        "last_24h": int(row[2]) if row else 0,
        "critical_total": int(row[3]) if row else 0,
        "last_alert_at": last_alert_at,
        "table_bytes": int(size_row[0]) if size_row and size_row[0] is not None else 0,
    }


def get_flow_stats() -> Dict[str, Any]:
    with psycopg.connect(dsn()) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                  COUNT(*) AS total,
                  MAX(last_seen) AS last_flow_at
                FROM flows
                """
            )
            row = cur.fetchone()

            cur.execute("SELECT pg_total_relation_size('flows');")
            size_row = cur.fetchone()

    last_flow_at = row[1].isoformat() if row and row[1] else None
    return {
        "total": int(row[0]) if row else 0,
        "last_flow_at": last_flow_at,
        "table_bytes": int(size_row[0]) if size_row and size_row[0] is not None else 0,
    }


def clear_alerts() -> None:
    with psycopg.connect(dsn(), autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("TRUNCATE TABLE alerts, flows, incidents, security_events, idp_blocks, discovered_apps CASCADE;")


# --- IDP Blocks & Allowlist ---

def insert_idp_block(block: IdpBlockRecord) -> None:
    with psycopg.connect(dsn(), autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO idp_blocks (
                  block_id, ip, reason, severity, confidence,
                  enforcement_layer, status, incident_id, alert_id,
                  created_at, expires_at, unblocked_at, unblocked_by, metadata
                ) VALUES (
                  %(block_id)s, %(ip)s, %(reason)s, %(severity)s, %(confidence)s,
                  %(enforcement_layer)s, %(status)s, %(incident_id)s, %(alert_id)s,
                  %(created_at)s, %(expires_at)s, %(unblocked_at)s, %(unblocked_by)s, %(metadata)s::jsonb
                )
                ON CONFLICT (block_id) DO UPDATE SET
                  status = EXCLUDED.status,
                  expires_at = EXCLUDED.expires_at,
                  unblocked_at = EXCLUDED.unblocked_at,
                  unblocked_by = EXCLUDED.unblocked_by,
                  metadata = EXCLUDED.metadata
                """,
                {
                    "block_id": block.block_id,
                    "ip": block.ip,
                    "reason": block.reason,
                    "severity": block.severity,
                    "confidence": block.confidence,
                    "enforcement_layer": block.enforcement_layer,
                    "status": block.status,
                    "incident_id": block.incident_id,
                    "alert_id": block.alert_id,
                    "created_at": block.created_at,
                    "expires_at": block.expires_at,
                    "unblocked_at": block.unblocked_at,
                    "unblocked_by": block.unblocked_by,
                    "metadata": json.dumps(block.metadata, default=str),
                },
            )


def update_idp_block_status(ip: str, new_status: str, unblocked_by: str = "system") -> int:
    now = datetime.now(timezone.utc)
    with psycopg.connect(dsn(), autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE idp_blocks
                SET status = %s, unblocked_at = %s, unblocked_by = %s
                WHERE ip = %s AND status IN ('active', 'simulated')
                """,
                (new_status, now, unblocked_by, ip),
            )
            return cur.rowcount


def expire_old_idp_blocks() -> List[str]:
    now = datetime.now(timezone.utc)
    with psycopg.connect(dsn(), autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE idp_blocks
                SET status = 'expired', unblocked_at = %s, unblocked_by = 'ttl_expiry'
                WHERE status IN ('active', 'simulated') AND expires_at <= %s
                RETURNING ip
                """,
                (now, now),
            )
            rows = cur.fetchall()
    return [r[0] for r in rows]


def get_idp_blocks(status_filter: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
    with psycopg.connect(dsn()) as conn:
        with conn.cursor() as cur:
            if status_filter:
                cur.execute(
                    """
                    SELECT block_id, ip, reason, severity, confidence, enforcement_layer, status,
                           incident_id, alert_id, created_at, expires_at, unblocked_at, unblocked_by, metadata
                    FROM idp_blocks
                    WHERE status = %s
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (status_filter, limit),
                )
            else:
                cur.execute(
                    """
                    SELECT block_id, ip, reason, severity, confidence, enforcement_layer, status,
                           incident_id, alert_id, created_at, expires_at, unblocked_at, unblocked_by, metadata
                    FROM idp_blocks
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
            rows = cur.fetchall()
    out = []
    now = datetime.now(timezone.utc)
    for r in rows:
        expires_at = r[10]
        remaining_s = max(0, int((expires_at - now).total_seconds())) if r[6] in ("active", "simulated") else 0
        out.append(
            {
                "block_id": r[0],
                "ip": r[1],
                "reason": r[2],
                "severity": r[3],
                "confidence": float(r[4]),
                "enforcement_layer": r[5],
                "status": r[6],
                "incident_id": r[7],
                "alert_id": r[8],
                "created_at": r[9].isoformat(),
                "expires_at": expires_at.isoformat(),
                "remaining_seconds": remaining_s,
                "unblocked_at": r[11].isoformat() if r[11] else None,
                "unblocked_by": r[12],
                "metadata": r[13] or {},
            }
        )
    return out


def upsert_allowlist_entry(entry: IdpAllowlistEntry) -> None:
    with psycopg.connect(dsn(), autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO idp_allowlist (entry_id, ip_or_cidr, label, is_management, created_at, created_by)
                VALUES (%(entry_id)s, %(ip_or_cidr)s, %(label)s, %(is_management)s, %(created_at)s, %(created_by)s)
                ON CONFLICT (ip_or_cidr) DO UPDATE SET
                  label = EXCLUDED.label,
                  is_management = EXCLUDED.is_management
                """,
                {
                    "entry_id": entry.entry_id,
                    "ip_or_cidr": entry.ip_or_cidr,
                    "label": entry.label,
                    "is_management": entry.is_management,
                    "created_at": entry.created_at,
                    "created_by": entry.created_by,
                },
            )


def delete_allowlist_entry(ip_or_cidr: str) -> bool:
    with psycopg.connect(dsn(), autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM idp_allowlist WHERE ip_or_cidr = %s OR entry_id = %s", (ip_or_cidr, ip_or_cidr))
            return cur.rowcount > 0


def get_allowlist_entries() -> List[Dict[str, Any]]:
    with psycopg.connect(dsn()) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT entry_id, ip_or_cidr, label, is_management, created_at, created_by
                FROM idp_allowlist
                ORDER BY is_management DESC, created_at ASC
                """
            )
            rows = cur.fetchall()
    return [
        {
            "entry_id": r[0],
            "ip_or_cidr": r[1],
            "label": r[2],
            "is_management": bool(r[3]),
            "created_at": r[4].isoformat(),
            "created_by": r[5],
        }
        for r in rows
    ]


# --- Incidents (Centralized Threat Intelligence Correlation) ---

def upsert_incident(inc: SecurityIncident) -> None:
    with psycopg.connect(dsn(), autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO incidents (
                  incident_id, title, classification, severity, confidence,
                  src_ip, dst_ip, target_app, target_namespace, status,
                  first_seen, last_seen, event_count, detection_sources,
                  evidence, prevention_action, response_status
                ) VALUES (
                  %(incident_id)s, %(title)s, %(classification)s, %(severity)s, %(confidence)s,
                  %(src_ip)s, %(dst_ip)s, %(target_app)s, %(target_namespace)s, %(status)s,
                  %(first_seen)s, %(last_seen)s, %(event_count)s, %(detection_sources)s::jsonb,
                  %(evidence)s::jsonb, %(prevention_action)s, %(response_status)s
                )
                ON CONFLICT (incident_id) DO UPDATE SET
                  title = EXCLUDED.title,
                  classification = EXCLUDED.classification,
                  severity = EXCLUDED.severity,
                  confidence = EXCLUDED.confidence,
                  target_app = COALESCE(EXCLUDED.target_app, incidents.target_app),
                  target_namespace = COALESCE(EXCLUDED.target_namespace, incidents.target_namespace),
                  status = EXCLUDED.status,
                  last_seen = EXCLUDED.last_seen,
                  event_count = EXCLUDED.event_count,
                  detection_sources = EXCLUDED.detection_sources,
                  evidence = EXCLUDED.evidence,
                  prevention_action = EXCLUDED.prevention_action,
                  response_status = EXCLUDED.response_status
                """,
                {
                    "incident_id": inc.incident_id,
                    "title": inc.title,
                    "classification": inc.classification,
                    "severity": inc.severity,
                    "confidence": inc.confidence,
                    "src_ip": inc.src_ip,
                    "dst_ip": inc.dst_ip,
                    "target_app": inc.target_app,
                    "target_namespace": inc.target_namespace,
                    "status": inc.status,
                    "first_seen": inc.first_seen,
                    "last_seen": inc.last_seen,
                    "event_count": inc.event_count,
                    "detection_sources": json.dumps(inc.detection_sources, default=str),
                    "evidence": json.dumps(inc.evidence, default=str),
                    "prevention_action": inc.prevention_action,
                    "response_status": inc.response_status,
                },
            )


def get_incidents(limit: int = 100) -> List[Dict[str, Any]]:
    with psycopg.connect(dsn()) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT incident_id, title, classification, severity, confidence,
                       src_ip, dst_ip, target_app, target_namespace, status,
                       first_seen, last_seen, event_count, detection_sources,
                       evidence, prevention_action, response_status
                FROM incidents
                ORDER BY last_seen DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()
    return [
        {
            "incident_id": r[0],
            "title": r[1],
            "classification": r[2],
            "severity": r[3],
            "confidence": float(r[4]),
            "src_ip": r[5],
            "dst_ip": r[6],
            "target_app": r[7],
            "target_namespace": r[8],
            "status": r[9],
            "first_seen": r[10].isoformat(),
            "last_seen": r[11].isoformat(),
            "event_count": int(r[12]),
            "detection_sources": r[13] or [],
            "evidence": r[14] or [],
            "prevention_action": r[15],
            "response_status": r[16],
        }
        for r in rows
    ]


# --- Discovered Applications ---

def upsert_discovered_app(app_rec: DiscoveredApplication) -> None:
    with psycopg.connect(dsn(), autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO discovered_apps (
                  app_id, name, namespace, service_name, ingress_domain,
                  exposed_ports, pod_count, monitoring_status, security_status,
                  threat_count, waf_enabled, last_seen, recent_threats, metadata
                ) VALUES (
                  %(app_id)s, %(name)s, %(namespace)s, %(service_name)s, %(ingress_domain)s,
                  %(exposed_ports)s::jsonb, %(pod_count)s, %(monitoring_status)s, %(security_status)s,
                  %(threat_count)s, %(waf_enabled)s, %(last_seen)s, %(recent_threats)s::jsonb, %(metadata)s::jsonb
                )
                ON CONFLICT (app_id) DO UPDATE SET
                  service_name = EXCLUDED.service_name,
                  ingress_domain = EXCLUDED.ingress_domain,
                  exposed_ports = EXCLUDED.exposed_ports,
                  pod_count = EXCLUDED.pod_count,
                  monitoring_status = EXCLUDED.monitoring_status,
                  waf_enabled = EXCLUDED.waf_enabled,
                  last_seen = EXCLUDED.last_seen,
                  metadata = EXCLUDED.metadata
                """,
                {
                    "app_id": app_rec.app_id,
                    "name": app_rec.name,
                    "namespace": app_rec.namespace,
                    "service_name": app_rec.service_name,
                    "ingress_domain": app_rec.ingress_domain,
                    "exposed_ports": json.dumps(app_rec.exposed_ports),
                    "pod_count": app_rec.pod_count,
                    "monitoring_status": app_rec.monitoring_status,
                    "security_status": app_rec.security_status,
                    "threat_count": app_rec.threat_count,
                    "waf_enabled": app_rec.waf_enabled,
                    "last_seen": app_rec.last_seen,
                    "recent_threats": json.dumps(app_rec.recent_threats, default=str),
                    "metadata": json.dumps(app_rec.metadata, default=str),
                },
            )


def record_app_threat(app_name_or_port: str | int, threat_entry: Dict[str, Any]) -> None:
    with psycopg.connect(dsn(), autocommit=True) as conn:
        with conn.cursor() as cur:
            if isinstance(app_name_or_port, int):
                cur.execute(
                    """
                    SELECT app_id, threat_count, recent_threats
                    FROM discovered_apps
                    WHERE exposed_ports @> %s::jsonb
                    LIMIT 1
                    """,
                    (json.dumps([app_name_or_port]),),
                )
            else:
                cur.execute(
                    """
                    SELECT app_id, threat_count, recent_threats
                    FROM discovered_apps
                    WHERE name = %s OR service_name = %s OR ingress_domain = %s OR app_id = %s
                    LIMIT 1
                    """,
                    (str(app_name_or_port), str(app_name_or_port), str(app_name_or_port), str(app_name_or_port)),
                )
            row = cur.fetchone()
            if not row:
                return
            app_id, count, threats = row[0], int(row[1] or 0), list(row[2] or [])
            threats.insert(0, threat_entry)
            threats = threats[:25]
            sev = (threat_entry.get("severity") or "").lower()
            sec_status = "under_attack" if sev in ("critical", "high") else "warning"
            cur.execute(
                """
                UPDATE discovered_apps
                SET threat_count = %s, recent_threats = %s::jsonb, security_status = %s, last_seen = NOW()
                WHERE app_id = %s
                """,
                (count + 1, json.dumps(threats, default=str), sec_status, app_id),
            )


def get_discovered_apps() -> List[Dict[str, Any]]:
    with psycopg.connect(dsn()) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT app_id, name, namespace, service_name, ingress_domain,
                       exposed_ports, pod_count, monitoring_status, security_status,
                       threat_count, waf_enabled, last_seen, recent_threats, metadata
                FROM discovered_apps
                ORDER BY threat_count DESC, namespace ASC, name ASC
                """
            )
            rows = cur.fetchall()
    return [
        {
            "app_id": r[0],
            "name": r[1],
            "namespace": r[2],
            "service_name": r[3],
            "ingress_domain": r[4],
            "exposed_ports": r[5] or [],
            "pod_count": int(r[6]),
            "monitoring_status": r[7],
            "security_status": r[8],
            "threat_count": int(r[9]),
            "waf_enabled": bool(r[10]),
            "last_seen": r[11].isoformat(),
            "recent_threats": r[12] or [],
            "metadata": r[13] or {},
        }
        for r in rows
    ]


# --- Layer Security Events ---

def insert_security_event(ev: LayerSecurityEvent) -> None:
    with psycopg.connect(dsn(), autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO security_events (
                  event_id, created_at, layer, category, severity,
                  src_ip, dst_ip, target, namespace, summary, details
                ) VALUES (
                  %(event_id)s, %(created_at)s, %(layer)s, %(category)s, %(severity)s,
                  %(src_ip)s, %(dst_ip)s, %(target)s, %(namespace)s, %(summary)s, %(details)s::jsonb
                )
                ON CONFLICT (event_id) DO NOTHING
                """,
                {
                    "event_id": ev.event_id,
                    "created_at": ev.created_at,
                    "layer": ev.layer,
                    "category": ev.category,
                    "severity": ev.severity,
                    "src_ip": ev.src_ip,
                    "dst_ip": ev.dst_ip,
                    "target": ev.target,
                    "namespace": ev.namespace,
                    "summary": ev.summary,
                    "details": json.dumps(ev.details, default=str),
                },
            )


def get_security_events(layer: Optional[str] = None, limit: int = 150) -> List[Dict[str, Any]]:
    with psycopg.connect(dsn()) as conn:
        with conn.cursor() as cur:
            if layer:
                cur.execute(
                    """
                    SELECT event_id, created_at, layer, category, severity,
                           src_ip, dst_ip, target, namespace, summary, details
                    FROM security_events
                    WHERE layer = %s
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (layer, limit),
                )
            else:
                cur.execute(
                    """
                    SELECT event_id, created_at, layer, category, severity,
                           src_ip, dst_ip, target, namespace, summary, details
                    FROM security_events
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
            rows = cur.fetchall()
    return [
        {
            "event_id": r[0],
            "created_at": r[1].isoformat(),
            "layer": r[2],
            "category": r[3],
            "severity": r[4],
            "src_ip": r[5],
            "dst_ip": r[6],
            "target": r[7],
            "namespace": r[8],
            "summary": r[9],
            "details": r[10] or {},
        }
        for r in rows
    ]
