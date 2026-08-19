from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    kafka_brokers: str = "kafka:9092"
    kafka_topic_flows: str = "flows"

    sensor_interface: str = "eth0"
    sensor_bpf_filter: str = "ip"
    sensor_idle_timeout_seconds: int = 60
    sensor_active_timeout_seconds: int = 600
    sensor_flush_interval_seconds: int = 5
    sensor_compress_gzip: bool = True


settings = Settings()
