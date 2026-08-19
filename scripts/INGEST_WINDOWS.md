Using local CSV datasets on Windows with the replay script

This project includes a simple replay tool to POST demo alerts into the backend:

  scripts/replay_global_threats_csv.py

You said your data lives on:
  F:\steve\data\BCCC-CIC-Bell-DNS2021\BCCC-CIC-Bell-DNS2021
  F:\steve\data\CSVs

Quick option — run the replay locally (recommended on Windows):

1. Ensure Python 3.9+ is installed and in PATH.
2. From the workspace root, create and activate a venv (optional):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
```

3. Run the replay script pointing at your CSV file and backend URL (adjust paths):

```powershell
python .\scripts\replay_global_threats_csv.py --csv "F:\steve\data\CSVs\Global_Cybersecurity_Threats_2015-2024.csv" --backend http://localhost:8000 --rate 20
```

This will POST alerts to the backend `POST /ingest/alert` endpoint which stores and forwards them to the websocket. The UI will pick them up when connected.

Alternative — run inside Docker (bind-mount your F: path):

If you prefer Docker, you can run a temporary container that mounts your F: folder and runs the replay script. Example (PowerShell):

```powershell
docker run --rm -v "F:/steve/data/CSVs:/data/csvs:ro" -v "${PWD}:/workspace:ro" python:3.11-slim \
  bash -c "pip install --no-cache-dir -r /workspace/backend/requirements.txt && python /workspace/scripts/replay_global_threats_csv.py --csv /data/csvs/Global_Cybersecurity_Threats_2015-2024.csv --backend http://host.docker.internal:8000 --rate 20"
```

Notes:
- `host.docker.internal` allows the container to reach the host's `localhost` services on Docker Desktop for Windows.
- If `host.docker.internal` is unavailable, replace with the host IP.
- Adjust `--rate` to control alerts-per-second.

Next steps I can take now:
- Add an optional `replayer` service to `docker-compose.yml` that bind-mounts the Windows paths (I can add this but Docker path quoting sometimes needs manual tuning on Windows).
- Run `docker compose up --build` here to inspect the startup errors and fix any immediate issues.
Which would you like me to do?