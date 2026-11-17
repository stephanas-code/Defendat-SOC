from __future__ import annotations

import ipaddress
from typing import List
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    project_name: str = "ai-anomaly-ids-idp"

    # Kafka
    kafka_brokers: str = "kafka:9092"
    kafka_topic_flows: str = "flows"
    kafka_topic_alerts: str = "alerts"
    kafka_topic_idp: str = "idp_actions"
    kafka_group_id: str = "inference"

    # Backend & API Auth
    backend_log_level: str = "info"
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    api_auth_enabled: bool = False
    api_key: str = "nids_live_ak_7a8b9c1d2e3f4g5h6i7j8k9l0m1n2o3p"

    # Core IDS / IDP Feature Flags & Policies
    ids_enabled: bool = True
    idp_enabled: bool = True
    idp_enforcement_mode: str = "safe_enforce"  # monitor | safe_enforce | full_enforce
    idp_block_seconds: int = 600
    idp_max_blocks: int = 100
    idp_confidence_threshold: float = 0.75
    idp_auto_block_critical: bool = True
    idp_auto_block_high: bool = True
    idp_allowlist: str = "127.0.0.1/32,::1/128,10.96.0.0/12,10.244.0.0/16"
    idp_management_ips: str = "127.0.0.1,192.168.1.1,10.0.0.1"
    idp_protected_cidrs: str = "127.0.0.0/8,10.96.0.0/12,10.244.0.0/16,169.254.0.0/16"
    idp_chain: str = "AI_IDS_BLOCK"
    idp_firewall_backend: str = "auto"  # auto | iptables | nftables
    idp_rate_limit_rps: int = 50

    # Server-Wide & Kubernetes Monitoring Layers
    kubernetes_monitoring_enabled: bool = True
    kubernetes_audit_enabled: bool = True
    host_monitoring_enabled: bool = True
    network_monitoring_enabled: bool = True
    application_monitoring_enabled: bool = True
    waf_enabled: bool = True
    log_monitoring_enabled: bool = True
    threat_intelligence_enabled: bool = True

    # Detection thresholds (44-feature ML models)
    isoforest_threshold: float = 0.65
    xgboost_confidence_threshold: float = 0.70
    lstm_enabled: bool = True
    lstm_seq_len: int = 10
    lstm_recon_error_threshold: float = 0.05

    # Host & Log Paths
    host_proc_dir: str = "/proc"
    host_etc_dir: str = "/etc"
    host_log_dir: str = "/var/log"
    waf_log_paths: str = "/var/log/nginx/access.log,/var/log/modsec_audit.log"
    kubernetes_audit_log_path: str = "/var/log/kubernetes/audit/audit.log"
    monitor_interval_seconds: int = 15

    # GeoIP (optional)
    geoip_mmdb_path: str = "/data/GeoLite2-City.mmdb"

    # Redis
    redis_host: str = "redis"
    redis_port: int = 6379
    alert_dedup_ttl_seconds: int = 60

    # TimescaleDB
    postgres_host: str = "timescaledb"
    postgres_port: int = 5432
    postgres_db: str = "ids"
    postgres_user: str = "ids"
    postgres_password: str = "ids"

    artifacts_dir: str = "/artifacts"

    @field_validator("idp_enforcement_mode")
    @classmethod
    def validate_enforcement_mode(cls, v: str) -> str:
        mode = (v or "safe_enforce").strip().lower()
        if mode not in {"monitor", "safe_enforce", "full_enforce", "disabled"}:
            return "safe_enforce"
        return mode

    @field_validator("idp_confidence_threshold")
    @classmethod
    def validate_conf_threshold(cls, v: float) -> float:
        return max(0.1, min(0.99, float(v)))

    @field_validator("idp_block_seconds")
    @classmethod
    def validate_block_seconds(cls, v: int) -> int:
        return max(10, min(86400 * 7, int(v)))

    def parsed_allowlist(self) -> List[str]:
        return [x.strip() for x in self.idp_allowlist.split(",") if x.strip()]

    def parsed_management_ips(self) -> List[str]:
        return [x.strip() for x in self.idp_management_ips.split(",") if x.strip()]

    def parsed_protected_cidrs(self) -> List[str]:
        return [x.strip() for x in self.idp_protected_cidrs.split(",") if x.strip()]


settings = Settings()
