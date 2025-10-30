"""Utility helpers for the network module."""
from pathlib import Path
import logging
import joblib


def ensure_dirs(base_path: Path):
    (base_path / "logs").mkdir(parents=True, exist_ok=True)
    (base_path / "data").mkdir(parents=True, exist_ok=True)


def setup_logger(log_path: Path, name: str = "ids"):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger


def load_model(path: Path):
    """Load a trained model using joblib with graceful errors."""
    try:
        model = joblib.load(path)
        return model
    except Exception as e:
        raise RuntimeError(f"Failed to load model from {path}: {e}")
