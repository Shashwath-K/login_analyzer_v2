"""
ml_model/attack_classifier.py
==============================
Loads the trained RandomForestClassifier and classifies login attack patterns.

Responsibilities:
    - Load model.pkl from disk (once, using joblib, cached in memory)
    - Accept a feature dict or DataFrame row and return a predicted attack type
    - Return confidence probabilities alongside the predicted label
    - Provide a batch classifier for processing multiple IPs at once
    - Handle missing model gracefully with a helpful error message

Usage (programmatic):
    from ml_model.attack_classifier import classify_features, load_model

    model = load_model()
    result = classify_features({"failed_attempts": 15, "unique_usernames": 1,
                                 "time_window": 60, "same_password_count": 0,
                                 "request_rate": 0.25})
    print(result["attack_type"])     # e.g. "Brute Force"
    print(result["confidence"])      # e.g. 0.97
"""

import os
import sys

# Adjust path so imports work when script is run directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import joblib
except ImportError:
    raise ImportError("joblib is required. Install with: pip install joblib")

try:
    import numpy as np
except ImportError:
    raise ImportError("numpy is required. Install with: pip install numpy")

try:
    import pandas as pd
    _PANDAS_AVAILABLE = True
except ImportError:
    _PANDAS_AVAILABLE = False

from analysis.feature_extractor import get_feature_columns


# ── Model path ─────────────────────────────────────────────────────────────────

DEFAULT_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "model.pkl",
)

FEATURE_COLUMNS = get_feature_columns()

# Module-level model cache (loaded once, reused for all predictions)
_cached_model = None


# ── Model loading ──────────────────────────────────────────────────────────────

def load_model(model_path: str = DEFAULT_MODEL_PATH):
    """Load the trained model from disk. Caches the result in memory.

    If the model file does not exist, provide a clear instruction to train it first.

    Args:
        model_path: Path to the .pkl model file.

    Returns:
        Loaded scikit-learn model object.

    Raises:
        FileNotFoundError: If model.pkl does not exist.
    """
    global _cached_model

    if _cached_model is not None:
        return _cached_model

    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"Model file not found: '{model_path}'\n"
            "Train the model first by running:\n"
            "    python ml_model/train_model.py"
        )

    _cached_model = joblib.load(model_path)
    return _cached_model


def is_model_available(model_path: str = DEFAULT_MODEL_PATH) -> bool:
    """Check whether the model file exists without raising an exception.

    Args:
        model_path: Path to the .pkl model file.

    Returns:
        True if the model file exists, False otherwise.
    """
    return os.path.exists(model_path)


# ── Single prediction ──────────────────────────────────────────────────────────

def classify_features(
    features: dict,
    model_path: str = DEFAULT_MODEL_PATH,
) -> dict:
    """Classify a single set of login features and return an attack type label.

    Args:
        features:   Dict with keys matching FEATURE_COLUMNS:
                    failed_attempts, unique_usernames, time_window,
                    same_password_count, request_rate.
        model_path: Path to model.pkl (default: ml_model/model.pkl).

    Returns:
        Dict containing:
            attack_type (str)   — predicted label (e.g. 'Brute Force')
            confidence  (float) — prediction probability for the top class [0, 1]
            all_probs   (dict)  — mapping of every class → probability
    """
    model = load_model(model_path)

    # Build input vector in the same column order used during training
    input_vector = [[float(features.get(col, 0)) for col in FEATURE_COLUMNS]]

    # Predict
    predicted_label = model.predict(input_vector)[0]

    # Probability for each class
    probabilities = model.predict_proba(input_vector)[0]
    class_labels = model.classes_

    prob_map = {label: round(float(prob), 4) for label, prob in zip(class_labels, probabilities)}
    confidence = round(float(max(probabilities)), 4)

    return {
        "attack_type": predicted_label,
        "confidence": confidence,
        "all_probs": prob_map,
    }


# ── Batch prediction ───────────────────────────────────────────────────────────

def classify_batch(
    feature_df: "pd.DataFrame",
    model_path: str = DEFAULT_MODEL_PATH,
) -> "pd.DataFrame":
    """Classify a DataFrame of features (one row per IP address).

    Args:
        feature_df: DataFrame with at minimum the FEATURE_COLUMNS columns.
                    Usually the output of feature_extractor.extract_features_from_logs().
        model_path: Path to model.pkl.

    Returns:
        The input DataFrame with two additional columns:
            predicted_attack_type (str)
            confidence            (float)

    Raises:
        ImportError: If pandas is not available.
    """
    if not _PANDAS_AVAILABLE:
        raise ImportError("pandas is required for batch classification.")

    model = load_model(model_path)
    df = feature_df.copy()

    # Ensure we have all required feature columns
    missing = set(FEATURE_COLUMNS) - set(df.columns)
    if missing:
        raise ValueError(f"Feature DataFrame is missing columns: {missing}")

    X = df[FEATURE_COLUMNS].fillna(0).astype(float)

    predictions = model.predict(X)
    probabilities = model.predict_proba(X).max(axis=1)

    df["predicted_attack_type"] = predictions
    df["confidence"] = probabilities.round(4)

    return df


# ── Human-readable summary ─────────────────────────────────────────────────────

def format_classification_result(ip: str, result: dict) -> str:
    """Format a classification result as a human-readable string.

    Args:
        ip:     Source IP address.
        result: Dict returned by classify_features().

    Returns:
        Formatted multi-line string.
    """
    lines = [
        f"  IP Address   : {ip}",
        f"  Attack Type  : {result['attack_type']}",
        f"  Confidence   : {result['confidence'] * 100:.1f}%",
        f"  Probabilities:",
    ]
    for label, prob in sorted(result["all_probs"].items(), key=lambda x: x[1], reverse=True):
        bar = "▓" * int(prob * 20)
        lines.append(f"    {label:<30} {prob * 100:5.1f}%  {bar}")
    return "\n".join(lines)
