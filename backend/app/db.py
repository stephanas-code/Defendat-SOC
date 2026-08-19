from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from typing import Any, Dict, Iterable, Optional

import psycopg

from app.config import settings
from app.schemas import AlertRecord

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
        # Do not crash the whole application if the database is unavailable.
        # This allows demo-mode operation where backend will still accept
        # websocket clients and ingest requests (in-memory behaviour may be limited).
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
                    "signals": json.dumps(alert.model_dump()["signals"]),
                    "geoip": json.dumps(alert.model_dump().get("geoip")) if alert.model_dump().get("geoip") is not None else None,
                },
            )


def insert_flow(flow_id: str, first_seen: datetime, last_seen: datetime, src_ip: str, dst_ip: str,
                src_port: int, dst_port: int, protocol: str, features_json: dict) -> None:
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
                    "features": json.dumps(features_json),
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
            cur.execute("TRUNCATE TABLE alerts, flows CASCADE;")
