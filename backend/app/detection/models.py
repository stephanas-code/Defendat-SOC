from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import xgboost as xgb

from app.config import settings
from app.detection.features import FEATURES_44

logger = logging.getLogger(__name__)


@dataclass
class LoadedModels:
    scaler: Optional[object]
    isoforest: Optional[object]
    xgb_model: Optional[xgb.Booster]
    xgb_labels: Optional[list[str]]
    lstm_onnx_path: Optional[str]


def has_lstm(models: LoadedModels) -> bool:
    return bool(models.lstm_onnx_path)


def _artifact_path(name: str) -> str:
    return str(Path(settings.artifacts_dir) / name)


def load_models() -> LoadedModels:
    scaler = None
    isoforest = None
    xgb_model = None
    xgb_labels = None
    lstm_onnx_path = None

    logger.info(f"Loading models from artifacts directory: {settings.artifacts_dir}")
    
    try:
        p = _artifact_path("scaler.joblib")
        if os.path.exists(p):
            scaler = joblib.load(p)
            logger.info("scaler_loaded")
        else:
            logger.warning(f"scaler.joblib not found at {p}")
    except Exception:
        logger.exception("scaler_load_failed")

    try:
        p = _artifact_path("isoforest.joblib")
        if os.path.exists(p):
            isoforest = joblib.load(p)
            logger.info("isoforest_loaded")
        else:
            logger.warning(f"isoforest.joblib not found at {p}")
    except Exception:
        logger.exception("isoforest_load_failed")

    try:
        p = _artifact_path("xgboost.json")
        if os.path.exists(p):
            xgb_model = xgb.Booster()
            xgb_model.load_model(p)
            logger.info("xgboost_loaded")
        else:
            logger.warning(f"xgboost.json not found at {p}")

        labels_path = _artifact_path("xgboost_labels.json")
        if os.path.exists(labels_path):
            with open(labels_path, "r", encoding="utf-8") as f:
                xgb_labels = json.load(f)
            logger.info(f"xgboost_labels_loaded with {len(xgb_labels)} classes")
        else:
            logger.warning(f"xgboost_labels.json not found at {labels_path}")
    except Exception:
        logger.exception("xgboost_load_failed")

    p = _artifact_path("lstm_autoencoder.onnx")
    if os.path.exists(p):
        lstm_onnx_path = p
        logger.info("lstm_onnx_path_found")
    else:
        logger.info("lstm_onnx_not_found (optional)")

    # Log overall model loading status
    loaded_count = sum([bool(scaler), bool(isoforest), bool(xgb_model)])
    logger.info(f"Model loading complete: {loaded_count}/3 core models loaded")
    
    if loaded_count == 0:
        logger.warning("No ML models loaded! System will not detect attacks without trained models.")
        logger.info("Train models using: python scripts/train_all_models.py --artifacts-dir artifacts/CSVs --output-dir artifacts")

    return LoadedModels(
        scaler=scaler,
        isoforest=isoforest,
        xgb_model=xgb_model,
        xgb_labels=xgb_labels,
        lstm_onnx_path=lstm_onnx_path,
    )


def vectorize_44(features: dict) -> np.ndarray:
    return np.array([float(features.get(k, 0.0)) for k in FEATURES_44], dtype=np.float32)
