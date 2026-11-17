from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    kafka_brokers: str = "kafka:9092"
    kafka_topic_flows: str = "flows"

    sensor_interface: str = "any"
    sensor_bpf_filter: str = "ip"
    sensor_idle_timeout_seconds: int = 30
    sensor_active_timeout_seconds: int = 120
    sensor_flush_interval_seconds: int = 3
    sensor_compress_gzip: bool = True
    sensor_conntrack_enabled: bool = True
    network_monitoring_enabled: bool = True


settings = Settings()
