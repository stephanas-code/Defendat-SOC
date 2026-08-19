# Train ML Models with Google Colab (Free)

Use this guide when your **Windows PC or Kali VM** cannot train the models locally (low RAM, slow CPU, or missing Python packages). Training takes about **5–15 minutes** on Colab free tier.

The trained files plug directly into this project — no code changes needed.

---

## What you will produce

After training, you need these files in your project's `artifacts/` folder:

| File | Purpose |
|------|---------|
| `scaler.joblib` | Normalizes flow features |
| `isoforest.joblib` | Anomaly detection (benign baseline) |
| `xgboost.json` | Attack classification (DDoS, portscan, etc.) |
| `xgboost_labels.json` | Label names for XGBoost classes |
| `lstm_autoencoder.onnx` | Sequence-based temporal anomaly detection (Optional) |

---

## Step 1 — Confirm your zip is on Google Drive

Your dataset is already uploaded to Google Drive as:

```
My Drive / IDS / artifacts.zip
```

No re-upload needed — just make sure the file is there before running the notebook.
The full path Colab will see is: `/content/drive/MyDrive/IDS/artifacts.zip`

---

## Step 2 — Open Google Colab

1. Go to [colab.research.google.com](https://colab.research.google.com).
2. Sign in with a Google account.
3. **File → New notebook**.

---

## Step 3 — Run this notebook (copy each cell in order)

### Cell 1 — Install dependencies

```python
!pip install -q numpy scikit-learn xgboost joblib torch onnx
```

### Cell 2 — Mount Google Drive

```python
from google.colab import drive
drive.mount('/content/drive')
```

Approve the permission prompt in the popup.

### Cell 3 — Set paths and extract the zip

Your zip is at `IDS/artifacts.zip` on Google Drive. This cell extracts it and locates the CSVs.

```python
import zipfile
from pathlib import Path

# Path to your zip on Google Drive
ZIP_PATH = Path("/content/drive/MyDrive/IDS/artifacts.zip")

# Where to extract everything
EXTRACT_DIR = Path("/content/ids_training/extracted")
OUT_DIR     = Path("/content/ids_training/artifacts")
PROC_DIR    = OUT_DIR / "processed"

for p in [EXTRACT_DIR, OUT_DIR, PROC_DIR]:
    p.mkdir(parents=True, exist_ok=True)

# Extract the zip (only if not already extracted)
if not any(EXTRACT_DIR.iterdir()):
    print(f"Extracting {ZIP_PATH} ...")
    with zipfile.ZipFile(ZIP_PATH, "r") as z:
        z.extractall(EXTRACT_DIR)
    print("Extraction complete.")
else:
    print("Already extracted — skipping.")

# ── DEBUG: print everything inside the extracted folder ──────────────────────
all_extracted = sorted(EXTRACT_DIR.rglob("*"))
print(f"\nTotal items extracted: {len(all_extracted)}")
print("First 40 items:")
for item in all_extracted[:40]:
    marker = "[DIR]" if item.is_dir() else f"[{item.stat().st_size // 1_048_576} MB]"
    print(f"  {marker}  {item.relative_to(EXTRACT_DIR)}")
if len(all_extracted) > 40:
    print(f"  ... and {len(all_extracted) - 40} more items")

# ── Find CSVs (case-insensitive — handles .CSV and .csv) ─────────────────────
csv_candidates = [f for f in EXTRACT_DIR.rglob("*") if f.suffix.lower() == ".csv"]
csv_parent_dirs = {f.parent for f in csv_candidates}
print(f"\nCSV directories found inside zip: {csv_parent_dirs}")

if not csv_candidates:
    raise FileNotFoundError(
        "No CSV files found after extraction.\n"
        "Check the 'First 40 items' list above — the CSVs may be inside a "
        "subfolder with a different name or extension.\n"
        "You can set CSV_DIR manually below:\n"
        "  CSV_DIR = EXTRACT_DIR / 'your' / 'actual' / 'subfolder'"
    )

# Pick the folder that contains the most CSVs
CSV_DIR = max(csv_parent_dirs, key=lambda d: len(list(d.glob("*"))))
csvs    = sorted(CSV_DIR.glob("*"))
csvs    = [f for f in csvs if f.suffix.lower() == ".csv"]

print(f"\nUsing CSV_DIR: {CSV_DIR}")
print(f"Found {len(csvs)} CSV files:")
for f in csvs:
    print(f"  {f.name}  ({f.stat().st_size // 1_048_576} MB)")
```

### Cell 4 — Feature extraction (same logic as `scripts/prepare_training_data.py`)

```python
import csv
import numpy as np
from pathlib import Path

FEATURES_44 = [
    "flow_duration_ms", "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts", "totlen_bwd_pkts",
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "flow_byts_s", "flow_pkts_s", "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_total", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fwd_header_len", "bwd_header_len", "fwd_pkts_s", "bwd_pkts_s",
    "pkt_len_min", "pkt_len_max", "pkt_len_mean", "pkt_len_std",
    "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "ack_flag_cnt",
]

CSV_TO_FEATURES = {
    "duration": "flow_duration_ms",
    "packets_count": "tot_fwd_pkts",
    "fwd_packets_count": "tot_fwd_pkts",
    "bwd_packets_count": "tot_bwd_pkts",
    "fwd_total_payload_bytes": "totlen_fwd_pkts",
    "bwd_total_payload_bytes": "totlen_bwd_pkts",
    "fwd_payload_bytes_max": "fwd_pkt_len_max",
    "fwd_payload_bytes_min": "fwd_pkt_len_min",
    "fwd_payload_bytes_mean": "fwd_pkt_len_mean",
    "fwd_payload_bytes_std": "fwd_pkt_len_std",
    "bwd_payload_bytes_max": "bwd_pkt_len_max",
    "bwd_payload_bytes_min": "bwd_pkt_len_min",
    "bwd_payload_bytes_mean": "bwd_pkt_len_mean",
    "bwd_payload_bytes_std": "bwd_pkt_len_std",
    "bytes_rate": "flow_byts_s",
    "packets_rate": "flow_pkts_s",
    "packets_IAT_mean": "flow_iat_mean",
    "packet_IAT_std": "flow_iat_std",
    "packet_IAT_max": "flow_iat_max",
    "packet_IAT_min": "flow_iat_min",
    "fwd_packets_IAT_mean": "fwd_iat_mean",
    "fwd_packets_IAT_std": "fwd_iat_std",
    "fwd_packets_IAT_max": "fwd_iat_max",
    "fwd_packets_IAT_min": "fwd_iat_min",
    "bwd_packets_IAT_mean": "bwd_iat_mean",
    "bwd_packets_IAT_std": "bwd_iat_std",
    "bwd_packets_IAT_max": "bwd_iat_max",
    "bwd_packets_IAT_min": "bwd_iat_min",
    "fwd_packets_rate": "fwd_pkts_s",
    "bwd_packets_rate": "bwd_pkts_s",
    "syn_flag_counts": "syn_flag_cnt",
    "ack_flag_counts": "ack_flag_cnt",
    "rst_flag_counts": "rst_flag_cnt",
    "fin_flag_counts": "fin_flag_cnt",
    "fwd_psh_flag_counts": "fwd_psh_flags",
    "bwd_psh_flag_counts": "bwd_psh_flags",
    "fwd_urg_flag_counts": "fwd_urg_flags",
    "bwd_urg_flag_counts": "bwd_urg_flags",
    "fwd_total_header_bytes": "fwd_header_len",
    "bwd_total_header_bytes": "bwd_header_len",
}

def extract_features(row):
    features = np.zeros(len(FEATURES_44), dtype=np.float32)
    for i, name in enumerate(FEATURES_44):
        val = 0.0
        for csv_col, mapped in CSV_TO_FEATURES.items():
            if mapped == name and csv_col in row:
                try:
                    val = float(row[csv_col])
                    if "variance" in csv_col.lower() and val > 0:
                        val = np.sqrt(val)
                    break
                except (ValueError, TypeError):
                    pass
        if name == "pkt_len_mean" and val == 0:
            fm = float(row.get("fwd_payload_bytes_mean") or 0)
            bm = float(row.get("bwd_payload_bytes_mean") or 0)
            if fm or bm:
                val = (fm + bm) / 2
        if name == "pkt_len_max" and val == 0:
            val = max(float(row.get("fwd_payload_bytes_max") or 0),
                      float(row.get("bwd_payload_bytes_max") or 0))
        features[i] = val
    return features

def process_file(path, label_filter=None, max_samples=10000):
    X, labels = [], []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if max_samples and len(X) >= max_samples:
                break
            label = row.get("label", "Unknown")
            if label_filter and label_filter.lower() not in label.lower():
                continue
            X.append(extract_features(row))
            labels.append(label)
    return np.array(X, dtype=np.float32), labels

MAX = 10000  # reduce to 5000 if Colab runs out of RAM

benign_files = [f for f in CSV_DIR.glob("*.csv") if "benign" in f.name.lower()]
attack_files = [f for f in CSV_DIR.glob("*.csv") if "benign" not in f.name.lower()]

benign_parts = []
for bf in benign_files:
    x, _ = process_file(bf, label_filter="Benign", max_samples=MAX)
    benign_parts.append(x)
    print(f"Benign {bf.name}: {len(x)}")

benign_X = np.vstack(benign_parts)
np.save(PROC_DIR / "benign_features.npy", benign_X)
print("Total benign:", benign_X.shape)

all_X, all_labels = [], []
label_map = {}

for bf in benign_files[:2]:
    x, labs = process_file(bf, max_samples=MAX // 2)
    all_X.append(x)
    all_labels.extend(labs)

for af in attack_files:
    x, labs = process_file(af, max_samples=MAX)
    all_X.append(x)
    all_labels.extend(labs)
    print(f"Attack {af.name}: {len(x)}")

for lab in all_labels:
    if lab not in label_map:
        label_map[lab] = len(label_map)

X_train = np.vstack(all_X)
y_train = np.array([label_map[l] for l in all_labels], dtype=np.int64)

np.save(PROC_DIR / "xgboost_features.npy", X_train)
np.save(PROC_DIR / "xgboost_labels.npy", y_train)
rev = {v: k for k, v in label_map.items()}
with open(PROC_DIR / "xgboost_label_names.txt", "w") as f:
    for i in range(len(rev)):
        f.write(rev[i] + "\n")

print("Classes:", label_map)
print("X_train:", X_train.shape)
```

### Cell 5 — Train Isolation Forest + XGBoost

```python
import json
import joblib
import xgboost as xgb
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Isolation Forest (benign only)
scaler = StandardScaler()
benign_scaled = scaler.fit_transform(benign_X)
iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
iso.fit(benign_scaled)

joblib.dump(scaler, OUT_DIR / "scaler.joblib")
joblib.dump(iso, OUT_DIR / "isoforest.joblib")
print("Saved scaler + isoforest")

# XGBoost (multi-class)
labels = [rev[i] for i in range(len(rev))]
dtrain = xgb.DMatrix(X_train, label=y_train)
params = {
    "objective": "multi:softprob",
    "num_class": len(labels),
    "max_depth": 6,
    "eta": 0.1,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "eval_metric": "mlogloss",
}
booster = xgb.train(params, dtrain, num_boost_round=200)
booster.save_model(str(OUT_DIR / "xgboost.json"))
with open(OUT_DIR / "xgboost_labels.json", "w") as f:
    json.dump(labels, f)
print("Saved xgboost + labels:", labels)
```

### Cell 5b — Train LSTM Autoencoder (Optional)

```python
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

# We train on benign features scaled using our existing scaler
benign_scaled = scaler.transform(benign_X)

# Create sequences of length 10 (matching LSTM_SEQ_LEN in .env)
seq_len = 10
def create_sequences(data, seq_len):
    if len(data) < seq_len:
        return np.empty((0, seq_len, data.shape[1]), dtype=np.float32)
    sequences = []
    for i in range(len(data) - seq_len + 1):
        sequences.append(data[i : i + seq_len])
    return np.array(sequences, dtype=np.float32)

lstm_sequences = create_sequences(benign_scaled, seq_len)
print(f"LSTM sequence data shape: {lstm_sequences.shape}")

# Define the LSTM Autoencoder
class LSTMAutoencoder(nn.Module):
    def __init__(self, n_features=45, hidden_dim=64, num_layers=2, seq_len=10):
        super().__init__()
        self.n_features = n_features
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.seq_len = seq_len

        self.encoder = nn.LSTM(
            input_size=n_features,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.1
        )
        self.decoder = nn.LSTM(
            input_size=hidden_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.1
        )
        self.output_layer = nn.Linear(hidden_dim, n_features)

    def forward(self, x):
        _, (hidden, cell) = self.encoder(x)
        decoder_input = hidden[-1].unsqueeze(1).repeat(1, self.seq_len, 1)
        decoder_output, _ = self.decoder(decoder_input, (hidden, cell))
        reconstruction = self.output_layer(decoder_output)
        return reconstruction

n_features = benign_scaled.shape[1]  # should be 45
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Training LSTM on: {device} with {n_features} features")
model = LSTMAutoencoder(n_features=n_features).to(device)

# Prepare dataset
tensor_data = torch.from_numpy(lstm_sequences)
dataset = TensorDataset(tensor_data, tensor_data)
train_loader = DataLoader(dataset, batch_size=64, shuffle=True)

# Train
optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
criterion = nn.MSELoss()

model.train()
for epoch in range(1, 31): # 30 epochs is generally enough for benign profile learning
    epoch_loss = 0.0
    for batch_x, batch_y in train_loader:
        batch_x, batch_y = batch_x.to(device), batch_y.to(device)
        optimizer.zero_grad()
        output = model(batch_x)
        loss = criterion(output, batch_y)
        loss.backward()
        optimizer.step()
        epoch_loss += loss.item() * len(batch_x)
    
    if epoch % 5 == 0 or epoch == 1:
        print(f"Epoch {epoch:2d}/30 loss: {epoch_loss/len(dataset):.6f}")

# Export to ONNX
model.eval()
model.to("cpu")
dummy_input = torch.randn(1, seq_len, n_features)
onnx_path = OUT_DIR / "lstm_autoencoder.onnx"

torch.onnx.export(
    model,
    dummy_input,
    str(onnx_path),
    input_names=["input"],
    output_names=["output"],
    dynamic_axes={
        "input": {0: "batch_size"},
        "output": {0: "batch_size"}
    },
    opset_version=14
)
print(f"LSTM ONNX model exported to {onnx_path}")
```

### Cell 6 — Download model files

```python
import os
from google.colab import files

# Check which files actually exist to avoid zip failures
zip_cmd = f"cd {OUT_DIR} && zip -j /content/model_artifacts.zip scaler.joblib isoforest.joblib xgboost.json xgboost_labels.json"
if 'onnx_path' in globals() and onnx_path.exists():
    zip_cmd += " lstm_autoencoder.onnx"

print(f"Creating zip with command: {zip_cmd}")
os.system(zip_cmd)
files.download("/content/model_artifacts.zip")
```

---

## Step 4 — Copy models into your project

1. Extract `model_artifacts.zip` on Windows.
2. Copy the files (including `lstm_autoencoder.onnx`) into:

```
ai-anomaly-ids-idp/artifacts/
```

Because the folder is shared with Kali, they appear automatically in the VM.

---

## Step 5 — Restart backend on Kali

```bash
cd /path/to/ai-anomaly-ids-idp
docker compose restart backend
curl -s http://localhost:8000/health | python3 -m json.tool
```

All model flags should be `true`.

Test detection:

```bash
python scripts/replay_network_flows.py \
  --csv artifacts/CSVs/ddos_loit.csv \
  --backend http://localhost:8000 \
  --rate 10 --limit 30
```

---

## Alternative free platforms

| Platform | Notes |
|----------|-------|
| **Google Colab** | Best for this guide; free GPU not required |
| **Kaggle Notebooks** | Upload dataset as Kaggle dataset; same Python cells |
| **GitHub Codespaces** | Works if repo is on GitHub; 60 hrs/month free |
| **Lightning AI / Gradient** | Free tiers with limits; same pip + scripts |

For Kaggle: replace Drive mount with `/kaggle/input/your-dataset/`.

---

## Train on Kali directly (if Colab is not an option)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-training.txt
python scripts/train_all_models.py --artifacts-dir artifacts/CSVs --output-dir artifacts
docker compose restart backend
```

Use `--max-samples 5000` if you run out of memory.

---

## For your report (methodology section)

Include:

1. **Dataset**: CIC-IDS2017-derived CSVs in `artifacts/CSVs/` (cite Sharafaldin et al.).
2. **Features**: 44 flow features (CICFlowMeter-compatible) — see `FEATURES_44.md` if present.
3. **Models**:
   - Isolation Forest: unsupervised, trained on benign traffic only, contamination=0.05.
   - XGBoost: supervised multi-class, 200 rounds, max_depth=6.
4. **Hardware**: Google Colab CPU runtime / your Kali VM specs.
5. **Inference thresholds**: `ISOFOREST_THRESHOLD=0.65`, `XGBOOST_CONFIDENCE_THRESHOLD=0.70`.

---

## Troubleshooting Colab

| Issue | Fix |
|-------|-----|
| Session crashed (RAM) | Lower `MAX` to 3000; train one attack file at a time |
| `FileNotFoundError` on ZIP_PATH | Drive path wrong — open Files panel (folder icon), browse to `/content/drive/MyDrive/IDS/`, confirm `artifacts.zip` is there, right-click → Copy path |
| `len(csvs) == 0` after extraction | Wrong structure inside zip — browse `/content/ids_training/extracted/` in Files panel to find the actual CSV folder and set `CSV_DIR` manually |
| Drive not mounted | Re-run Cell 2 and approve the permission popup before running Cell 3 |
| XGBoost install fails | `!pip install xgboost==2.0.3` |
| Models true but no alerts | Run replay test; lower thresholds in `.env` |
