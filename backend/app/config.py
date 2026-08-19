from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    project_name: str = "ai-anomaly-ids-idp"

    kafka_brokers: str = "kafka:9092"
    kafka_topic_flows: str = "flows"
    kafka_topic_alerts: str = "alerts"
    kafka_group_id: str = "inference"

    backend_log_level: str = "info"

    # Thresholds
    isoforest_threshold: float = 0.65
    xgboost_confidence_threshold: float = 0.70
    lstm_enabled: bool = False
    lstm_seq_len: int = 10
    lstm_recon_error_threshold: float = 0.05

    # GeoIP (optional)
    geoip_mmdb_path: str = "/data/GeoLite2-City.mmdb"

    # Redis
    redis_host: str = "redis"
    redis_port: int = 6379
    alert_dedup_ttl_seconds: int = 300

    # TimescaleDB
    postgres_host: str = "timescaledb"
    postgres_port: int = 5432
    postgres_db: str = "ids"
    postgres_user: str = "ids"
    postgres_password: str = "ids"

    artifacts_dir: str = "/artifacts"


settings = Settings()
