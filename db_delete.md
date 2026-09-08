# NIDS Data Management, Reset & Sensor Control

## 1. Why alerts and locations still appeared after truncating the DB

When you run only `TRUNCATE TABLE alerts, flows CASCADE;`, you are clearing **TimescaleDB only**. Three things cause alerts to keep appearing:

1. **Kafka Queue contains buffered flows**: Kafka is an independent streaming broker. Any flows sitting in the `flows` topic are still consumed by the backend and inserted into the database.
2. **The Sensor is actively capturing live packets**: If the `sensor` container is running (`network_mode: host`), Scapy continuously sniffs every packet on your network interface (DNS queries, OS updates, cloud telemetry, background HTTPS). The ML anomaly detector (Isolation Forest) flags unfamiliar modern flows as `Anomaly (Zero-Day)`, GeoIP attaches the remote server's country (e.g. US, Europe), and a new alert is generated immediately.
3. **Browser in-memory state**: The React dashboard holds alerts in its local state. Truncating the DB inside Docker does not notify the browser unless you reload or trigger a system-wide clear.

---

## 2. Complete System Reset (One-Liner)

To reset **everything** (TimescaleDB, Redis cache, and Kafka queues) back to 0:

```bash
# 1. Truncate database tables
sudo docker compose exec timescaledb psql -U ids -d ids -c "TRUNCATE TABLE alerts, flows CASCADE;"

# 2. Flush Redis deduplication cache
sudo docker compose exec redis redis-cli FLUSHALL

# 3. Purge & recreate Kafka topics (clears all pending messages)
sudo docker compose exec kafka kafka-topics --bootstrap-server localhost:9092 --delete --topic flows
sudo docker compose exec kafka kafka-topics --bootstrap-server localhost:9092 --delete --topic alerts

# 4. Restart backend inference to connect with clean state
sudo docker compose restart backend
```

> **Tip:** You can also click the **"Clear"** button directly on the Dashboard's **Live Alert Feed**. This automatically calls `DELETE /alerts`, truncates the database, flushes Redis, and broadcasts a real-time wipe to all connected dashboard screens.

---

## 3. How to Stop False Alerts from Idle Traffic

If you are **not currently testing an attack**, stop the background capture sensor so ordinary internet traffic is not processed:

```bash
# Stop sniffing background traffic
sudo docker compose stop sensor

# When you are ready to launch an attack test, start the sensor again:
sudo docker compose start sensor
```

Alternatively, to only capture attacks targeted at specific services (e.g. port 80 or your host IP), update `SENSOR_BPF_FILTER` in `.env`:
```env
# Only inspect traffic on port 80 and port 22
SENSOR_BPF_FILTER=tcp port 80 or tcp port 22
```

---

## 4. Backup & Restore

### Backup Database to File:
```bash
sudo docker compose exec timescaledb pg_dump -U ids ids > backup.sql
```

### Restore Database from Backup:
```bash
cat backup.sql | sudo docker compose exec -T timescaledb psql -U ids -d ids
```
