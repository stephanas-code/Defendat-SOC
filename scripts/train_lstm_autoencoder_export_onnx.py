"""Train LSTM Autoencoder and export to ONNX format.

This script trains an LSTM autoencoder on benign network flow features
and exports the trained model as an ONNX file for inference by the
backend detection pipeline.

Requirements (install in your training environment):
    pip install torch numpy onnx

Usage:
    python scripts/train_lstm_autoencoder_export_onnx.py \
        --input artifacts/processed/benign_features.npy \
        --scaler artifacts/scaler.joblib \
        --output artifacts \
        --seq-len 10 \
        --epochs 50

The exported file `artifacts/lstm_autoencoder.onnx` will be loaded by the
backend when LSTM_ENABLED=true in .env.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

N_FEATURES = 45


def create_sequences(data: np.ndarray, seq_len: int) -> np.ndarray:
    """Slide a window of `seq_len` over `data` to produce 3-D sequences."""
    if len(data) < seq_len:
        raise ValueError(
            f"Not enough samples ({len(data)}) to create sequences of length {seq_len}. "
            f"Need at least {seq_len} benign samples."
        )
    sequences = []
    for i in range(len(data) - seq_len + 1):
        sequences.append(data[i : i + seq_len])
    return np.array(sequences, dtype=np.float32)


def main() -> None:
    ap = argparse.ArgumentParser(description="Train LSTM Autoencoder and export to ONNX")
    ap.add_argument(
        "--input",
        default="artifacts/processed/benign_features.npy",
        help="Path to benign_features.npy (shape: N x 44)",
    )
    ap.add_argument(
        "--scaler",
        default="artifacts/scaler.joblib",
        help="Path to fitted scaler (scaler.joblib). Used to normalize features.",
    )
    ap.add_argument("--output", default="artifacts", help="Output directory for lstm_autoencoder.onnx")
    ap.add_argument("--seq-len", type=int, default=10, help="Sequence length (must match LSTM_SEQ_LEN in .env)")
    ap.add_argument("--hidden-dim", type=int, default=64, help="LSTM hidden dimension")
    ap.add_argument("--num-layers", type=int, default=2, help="Number of LSTM layers")
    ap.add_argument("--epochs", type=int, default=50, help="Training epochs")
    ap.add_argument("--batch-size", type=int, default=64, help="Training batch size")
    ap.add_argument("--lr", type=float, default=1e-3, help="Learning rate")
    args = ap.parse_args()

    # ── Check dependencies ──────────────────────────────────────────────
    try:
        import torch
        import torch.nn as nn
        from torch.utils.data import DataLoader, TensorDataset
    except ImportError:
        logger.error("PyTorch is required. Install with: pip install torch")
        sys.exit(1)

    # ── Load and prepare data ───────────────────────────────────────────
    input_path = Path(args.input)
    if not input_path.exists():
        logger.error(f"Input file not found: {input_path}")
        logger.info("Run data preparation first:")
        logger.info("  python scripts/prepare_training_data.py --artifacts-dir artifacts/CSVs --output-dir artifacts/processed")
        sys.exit(1)

    raw_features = np.load(str(input_path))
    logger.info(f"Loaded features: shape={raw_features.shape}")

    if raw_features.ndim != 2 or raw_features.shape[1] != N_FEATURES:
        logger.error(f"Expected shape (N, {N_FEATURES}), got {raw_features.shape}")
        sys.exit(1)

    # Scale features using the same scaler the backend uses
    scaler_path = Path(args.scaler)
    if scaler_path.exists():
        import joblib

        scaler = joblib.load(str(scaler_path))
        features = scaler.transform(raw_features).astype(np.float32)
        logger.info("Applied scaler normalization")
    else:
        logger.warning(f"Scaler not found at {scaler_path}, using raw features")
        features = raw_features.astype(np.float32)

    # Replace NaN/Inf that sometimes appear in network data
    features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)

    # Create sequences
    sequences = create_sequences(features, args.seq_len)
    logger.info(f"Created {len(sequences)} sequences of length {args.seq_len}")

    # ── Define LSTM Autoencoder ─────────────────────────────────────────
    class LSTMAutoencoder(nn.Module):
        def __init__(self, n_features: int, hidden_dim: int, num_layers: int, seq_len: int):
            super().__init__()
            self.n_features = n_features
            self.hidden_dim = hidden_dim
            self.num_layers = num_layers
            self.seq_len = seq_len

            # Encoder
            self.encoder = nn.LSTM(
                input_size=n_features,
                hidden_size=hidden_dim,
                num_layers=num_layers,
                batch_first=True,
                dropout=0.1 if num_layers > 1 else 0.0,
            )

            # Decoder
            self.decoder = nn.LSTM(
                input_size=hidden_dim,
                hidden_size=hidden_dim,
                num_layers=num_layers,
                batch_first=True,
                dropout=0.1 if num_layers > 1 else 0.0,
            )

            # Output projection
            self.output_layer = nn.Linear(hidden_dim, n_features)

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            # x shape: (batch, seq_len, n_features)

            # Encode
            _, (hidden, cell) = self.encoder(x)

            # Repeat the encoded representation for each time step
            # Use last hidden state as decoder input
            decoder_input = hidden[-1].unsqueeze(1).repeat(1, self.seq_len, 1)

            # Decode
            decoder_output, _ = self.decoder(decoder_input, (hidden, cell))

            # Project back to feature space
            reconstruction = self.output_layer(decoder_output)
            return reconstruction

    # ── Train ───────────────────────────────────────────────────────────
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Using device: {device}")

    model = LSTMAutoencoder(N_FEATURES, args.hidden_dim, args.num_layers, args.seq_len).to(device)
    logger.info(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}")

    tensor_data = torch.from_numpy(sequences)
    dataset = TensorDataset(tensor_data, tensor_data)  # input == target for autoencoder

    # Split 90/10 for train/val
    n_train = int(0.9 * len(dataset))
    n_val = len(dataset) - n_train
    train_ds, val_ds = torch.utils.data.random_split(dataset, [n_train, n_val])

    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=args.batch_size, shuffle=False)

    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)
    criterion = nn.MSELoss()

    best_val_loss = float("inf")
    best_state = None

    for epoch in range(1, args.epochs + 1):
        # Train
        model.train()
        train_loss = 0.0
        for batch_x, batch_y in train_loader:
            batch_x, batch_y = batch_x.to(device), batch_y.to(device)
            optimizer.zero_grad()
            output = model(batch_x)
            loss = criterion(output, batch_y)
            loss.backward()
            optimizer.step()
            train_loss += loss.item() * len(batch_x)
        train_loss /= len(train_ds)

        # Validate
        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for batch_x, batch_y in val_loader:
                batch_x, batch_y = batch_x.to(device), batch_y.to(device)
                output = model(batch_x)
                loss = criterion(output, batch_y)
                val_loss += loss.item() * len(batch_x)
        val_loss /= max(len(val_ds), 1)

        if epoch % 5 == 0 or epoch == 1:
            logger.info(f"Epoch {epoch:3d}/{args.epochs}  train_loss={train_loss:.6f}  val_loss={val_loss:.6f}")

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}

    if best_state is not None:
        model.load_state_dict(best_state)
    logger.info(f"Best validation loss: {best_val_loss:.6f}")

    # ── Export to ONNX ──────────────────────────────────────────────────
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    onnx_path = output_dir / "lstm_autoencoder.onnx"

    model.eval()
    model.to("cpu")
    dummy_input = torch.randn(1, args.seq_len, N_FEATURES)

    torch.onnx.export(
        model,
        dummy_input,
        str(onnx_path),
        input_names=["input"],
        output_names=["output"],
        dynamic_axes={
            "input": {0: "batch_size"},
            "output": {0: "batch_size"},
        },
        opset_version=14,
    )
    logger.info(f"ONNX model exported to: {onnx_path}")

    # Verify the ONNX model
    try:
        import onnx

        onnx_model = onnx.load(str(onnx_path))
        onnx.checker.check_model(onnx_model)
        logger.info("ONNX model verification passed ✓")
    except ImportError:
        logger.warning("onnx package not installed, skipping verification")
    except Exception as e:
        logger.error(f"ONNX verification failed: {e}")

    # Quick inference test with onnxruntime
    try:
        import onnxruntime as ort

        sess = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
        test_input = np.random.randn(1, args.seq_len, N_FEATURES).astype(np.float32)
        result = sess.run(None, {"input": test_input})
        logger.info(f"ONNX inference test: input={test_input.shape} -> output={result[0].shape} ✓")
    except ImportError:
        logger.warning("onnxruntime not installed, skipping inference test")

    file_size = os.path.getsize(str(onnx_path))
    logger.info(f"Model file size: {file_size / 1024:.1f} KB")
    logger.info("")
    logger.info("Next steps:")
    logger.info("  1. Set LSTM_ENABLED=true in your .env file")
    logger.info(f"  2. Ensure LSTM_SEQ_LEN={args.seq_len} in your .env file")
    logger.info("  3. Restart backend: sudo docker compose restart backend")
    logger.info("  4. Verify: curl http://localhost:8000/health")


if __name__ == "__main__":
    main()
