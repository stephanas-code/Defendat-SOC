# Datasets

## Your current dataset

- `Global_Cybersecurity_Threats_2015-2024.csv`

This file is **incident-level tabular data** (country, year, attack type, losses, etc.).

It is useful for:

- demoing the dashboard + alert pipeline (see `scripts/replay_global_threats_csv.py`)

It is **not suitable** for training the NIDS flow models in this repo, because the sensor/inference pipeline expects **44 bidirectional flow features** per event.

## For training the NIDS models

You need a dataset that contains flow features compatible with the 44-feature schema described in `FEATURES_44.md`, e.g. NetFlow/CICFlowMeter-style datasets.
