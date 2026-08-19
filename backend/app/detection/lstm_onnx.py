from __future__ import annotations

import logging
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional

import numpy as np

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class LstmScoreResult:
    recon_error: float


class TemporalLstmOnnxScorer:
    """Optional sequence-based scorer.

Assumptions for ONNX model:
- Input: float32 array shaped (1, seq_len, 44) OR (seq_len, 44)
- Output: reconstructed sequence of same shape (1, seq_len, 44) OR (seq_len, 44)

If the model does not match these assumptions, scoring returns None.
"""

    def __init__(self, onnx_path: str) -> None:
        import onnxruntime as ort

        self._seq_len = int(settings.lstm_seq_len)
        self._buffers: Dict[str, Deque[np.ndarray]] = defaultdict(lambda: deque(maxlen=self._seq_len))
        self._sess = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])
        self._input_name = self._sess.get_inputs()[0].name
        self._output_name = self._sess.get_outputs()[0].name
        logger.info("lstm_onnx_loaded", extra={"path": onnx_path, "seq_len": self._seq_len})

    def score(self, src_ip: str, x_scaled_44: np.ndarray) -> Optional[LstmScoreResult]:
        buf = self._buffers[src_ip]
        buf.append(x_scaled_44.reshape(-1).astype(np.float32))
        if len(buf) < self._seq_len:
            return None

        seq = np.stack(list(buf), axis=0).astype(np.float32)  # (seq_len, 44)
        x_in = seq.reshape(1, self._seq_len, 44)

        try:
            out = self._sess.run([self._output_name], {self._input_name: x_in})[0]
            out_arr = np.array(out, dtype=np.float32)
            if out_arr.shape == (self._seq_len, 44):
                recon = out_arr
            elif out_arr.shape == (1, self._seq_len, 44):
                recon = out_arr[0]
            else:
                return None

            mse = float(np.mean((recon - seq) ** 2))
            return LstmScoreResult(recon_error=mse)
        except Exception:
            logger.exception("lstm_onnx_score_failed")
            return None
