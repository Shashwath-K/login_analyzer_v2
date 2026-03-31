"""
ml_model/train_model.py
========================
Trains a RandomForestClassifier on the provided training dataset and
saves the fitted model to disk using joblib.

Responsibilities:
    - Load training_data.csv using pandas
    - Validate that all required feature columns and the target column exist
    - Split data into training and test sets
    - Train a RandomForestClassifier
    - Evaluate and print accuracy + classification report
    - Save the trained model to ml_model/model.pkl via joblib
    - Can be run directly: python ml_model/train_model.py

Usage:
    python ml_model/train_model.py
    python ml_model/train_model.py --data data/training_data.csv
    python ml_model/train_model.py --data data/training_data.csv --output ml_model/model.pkl
"""

import os
import sys
import argparse

# Adjust path so imports work when script is run directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import pandas as pd
except ImportError:
    print("[ERROR] pandas is not installed. Run: pip install pandas")
    sys.exit(1)

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report
    from sklearn.preprocessing import LabelEncoder
except ImportError:
    print("[ERROR] scikit-learn is not installed. Run: pip install scikit-learn")
    sys.exit(1)

try:
    import joblib
except ImportError:
    print("[ERROR] joblib is not installed. Run: pip install joblib")
    sys.exit(1)

from analysis.feature_extractor import get_feature_columns


# ── Constants ──────────────────────────────────────────────────────────────────

DEFAULT_DATA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "training_data.csv",
)
DEFAULT_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "model.pkl",
)

FEATURE_COLUMNS = get_feature_columns()
TARGET_COLUMN = "attack_type"

# Random Forest hyper-parameters
RF_N_ESTIMATORS = 100
RF_MAX_DEPTH = None          # grow full trees
RF_RANDOM_STATE = 42
RF_MIN_SAMPLES_LEAF = 1


# ── Data loading & validation ──────────────────────────────────────────────────

def load_training_data(filepath: str) -> pd.DataFrame:
    """Load and validate the training CSV file.

    Args:
        filepath: Path to training_data.csv.

    Returns:
        Validated pandas DataFrame.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If required columns are missing or the dataset is too small.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Training data file not found: {filepath}")

    df = pd.read_csv(filepath)
    print(f"[INFO] Loaded {len(df)} training samples from '{filepath}'.")

    # Check all required columns are present
    required = set(FEATURE_COLUMNS + [TARGET_COLUMN])
    missing = required - set(df.columns)
    if missing:
        raise ValueError(
            f"Training data is missing required columns: {missing}\n"
            f"Expected: {sorted(required)}"
        )

    # Basic sanity check
    if len(df) < 20:
        raise ValueError(
            f"Training data has only {len(df)} rows. "
            "At least 20 rows are required for reliable training."
        )

    # Drop rows with NaN in key columns
    before = len(df)
    df = df.dropna(subset=FEATURE_COLUMNS + [TARGET_COLUMN])
    dropped = before - len(df)
    if dropped:
        print(f"[WARN] Dropped {dropped} rows containing NaN values.")

    return df


# ── Training ───────────────────────────────────────────────────────────────────

def train(data_path: str, model_path: str) -> None:
    """Load data, train the model, evaluate it, and save it to disk.

    Args:
        data_path:  Path to the training CSV file.
        model_path: Destination path for the saved model (.pkl).
    """
    print("\n── Loading training data ──────────────────────────────────────")
    df = load_training_data(data_path)

    X = df[FEATURE_COLUMNS]
    y = df[TARGET_COLUMN]

    # Show class distribution
    print("\n── Class distribution ─────────────────────────────────────────")
    for label, count in y.value_counts().items():
        bar = "█" * min(count, 40)
        print(f"  {label:<25} {count:>4}  {bar}")

    # Train / test split (80 / 20, stratified to maintain class balance)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RF_RANDOM_STATE, stratify=y
    )
    print(f"\n[INFO] Training on {len(X_train)} samples, evaluating on {len(X_test)} samples.")

    # Train model
    print("\n── Training RandomForestClassifier ────────────────────────────")
    model = RandomForestClassifier(
        n_estimators=RF_N_ESTIMATORS,
        max_depth=RF_MAX_DEPTH,
        min_samples_leaf=RF_MIN_SAMPLES_LEAF,
        random_state=RF_RANDOM_STATE,
        n_jobs=-1,  # use all available CPU cores
    )
    model.fit(X_train, y_train)
    print("[OK] Model trained successfully.")

    # Evaluate
    print("\n── Evaluation Results ─────────────────────────────────────────")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"  Accuracy: {accuracy * 100:.1f}%")
    print("\n  Classification Report:")
    print(classification_report(y_test, y_pred, zero_division=0))

    # Feature importance
    print("── Feature Importances ────────────────────────────────────────")
    for feat, importance in sorted(
        zip(FEATURE_COLUMNS, model.feature_importances_),
        key=lambda x: x[1],
        reverse=True,
    ):
        bar = "▓" * int(importance * 40)
        print(f"  {feat:<30} {importance:.4f}  {bar}")

    # Save model
    print(f"\n── Saving model ───────────────────────────────────────────────")
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(model, model_path)
    print(f"[OK] Model saved to: {model_path}")


# ── CLI entry point ────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train the login attack pattern classifier.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--data", default=DEFAULT_DATA_PATH,
        help="Path to training_data.csv",
    )
    parser.add_argument(
        "--output", default=DEFAULT_MODEL_PATH,
        help="Path to save the trained model (.pkl)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    try:
        train(args.data, args.output)
    except (FileNotFoundError, ValueError) as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
