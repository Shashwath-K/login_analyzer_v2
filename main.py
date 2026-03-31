"""
main.py
=======
Entry point for the Login Attack Pattern Analyzer.

This script runs the complete ML-based analysis pipeline on login_logs.csv:

    1. Read login logs from data/login_logs.csv
    2. Extract ML features per source IP
    3. Classify each IP using the trained RandomForestClassifier
    4. Explain each classification in plain English
    5. Generate mitigation recommendations
    6. Print the full report to console
    7. Generate visualisation charts (if matplotlib is available)
    8. Optionally launch the web dashboard (python_project.py style server)

Usage:
    python main.py                      # ML pipeline only
    python main.py --web                # ML pipeline + launch web dashboard
    python main.py --train              # Train the model first, then run pipeline
    python main.py --plots              # Also generate charts (saved to output/plots/)
    python main.py --web --port 9090    # Launch web server on custom port

Prerequisites:
    pip install pandas scikit-learn matplotlib joblib
"""

import os
import sys
import argparse

# ── Ensure root of project is on the import path ───────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)


# ── Argument parsing ───────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Login Attack Pattern Analyzer — ML-based CLI pipeline",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--data", default=os.path.join(PROJECT_ROOT, "data", "login_logs.csv"),
        help="Path to login_logs.csv",
    )
    parser.add_argument(
        "--training-data", default=os.path.join(PROJECT_ROOT, "data", "training_data.csv"),
        help="Path to training_data.csv",
    )
    parser.add_argument(
        "--model", default=os.path.join(PROJECT_ROOT, "ml_model", "model.pkl"),
        help="Path to the trained model file (model.pkl)",
    )
    parser.add_argument(
        "--train", action="store_true",
        help="Train the model before running the analysis pipeline",
    )
    parser.add_argument(
        "--plots", action="store_true",
        help="Generate matplotlib visualisation charts",
    )
    parser.add_argument(
        "--plots-dir", default=os.path.join(PROJECT_ROOT, "output", "plots"),
        help="Directory to save generated charts",
    )
    parser.add_argument(
        "--web", action="store_true",
        help="Launch the web dashboard after running the ML pipeline",
    )
    parser.add_argument(
        "--port", type=int, default=8080,
        help="Port for the web dashboard (used with --web)",
    )
    parser.add_argument(
        "--report", action="store_true",
        help="Print full SOC-style incident report to console",
    )
    parser.add_argument(
        "--firewall", action="store_true",
        help="Print auto-generated firewall rules to console",
    )
    return parser.parse_args()


# ── Pipeline steps ─────────────────────────────────────────────────────────────

def step_train_model(training_data_path: str, model_path: str) -> None:
    """Step 0 (optional): Train and save the RandomForestClassifier."""
    from ml_model.train_model import train
    print("\n" + "═" * 60)
    print("  STEP 0 — Training ML Model")
    print("═" * 60)
    train(training_data_path, model_path)


def step_read_logs(data_path: str) -> list[dict]:
    """Step 1: Read and validate login_logs.csv."""
    from analysis.log_reader import read_login_logs_csv
    print("\n── Step 1: Reading login logs ─────────────────────────────────")
    log_rows = read_login_logs_csv(data_path)
    successes = sum(1 for r in log_rows if r.get("status", "").lower() == "success")
    failures  = sum(1 for r in log_rows if r.get("status", "").lower() == "failure")
    print(f"[OK] Loaded {len(log_rows)} events — {successes} successes / {failures} failures")
    return log_rows


def step_extract_features(log_rows: list[dict]):
    """Step 2: Extract ML feature vectors per source IP."""
    from analysis.feature_extractor import extract_features_from_logs
    print("\n── Step 2: Extracting features ────────────────────────────────")
    feature_df = extract_features_from_logs(log_rows)
    print(f"[OK] Features computed for {len(feature_df)} unique source IP(s)")
    return feature_df


def step_classify(feature_df, model_path: str):
    """Step 3: Classify each IP using the trained ML model."""
    from ml_model.attack_classifier import classify_batch, is_model_available

    print("\n── Step 3: Classifying attack types ───────────────────────────")

    if not is_model_available(model_path):
        print(f"[WARN] Model not found at '{model_path}'.")
        print("       Run with --train to train the model first, or:")
        print("       python ml_model/train_model.py")
        return None

    classified_df = classify_batch(feature_df, model_path)
    attack_counts = classified_df["predicted_attack_type"].value_counts()
    for attack_type, count in attack_counts.items():
        print(f"  {attack_type:<30} {count} IP(s)")
    return classified_df


def step_explain(classified_df, feature_df) -> list[dict]:
    """Step 4: Generate plain-English explanations for each classification."""
    from explanation.explain_attack import explain_attack, format_explanation

    print("\n── Step 4: Generating explanations ────────────────────────────")

    if classified_df is None:
        print("[SKIP] No classifications to explain.")
        return []

    explanations = []
    for _, row in classified_df.iterrows():
        features = {
            "failed_attempts": row["failed_attempts"],
            "unique_usernames": row["unique_usernames"],
            "time_window": row["time_window"],
            "same_password_count": row["same_password_count"],
            "request_rate": row["request_rate"],
        }
        classification = {
            "attack_type": row["predicted_attack_type"],
            "confidence": row["confidence"],
            "all_probs": {},
        }
        explanation = explain_attack(row["ip_address"], features, classification)
        explanations.append(explanation)
        # Print non-normal classifications only
        if explanation["attack_type"] != "Normal":
            print(format_explanation(explanation))

    normal_count = sum(1 for e in explanations if e["attack_type"] == "Normal")
    attack_count = len(explanations) - normal_count
    print(f"\n[OK] {attack_count} attacker IP(s), {normal_count} normal IP(s) identified.")
    return explanations


def step_recommendations(explanations: list[dict], summary: dict) -> None:
    """Step 5: Print per-attack-type recommendations and threat narrative."""
    from explanation.explain_attack import generate_threat_narrative
    from insights.recommendation_engine import format_recommendation

    print("\n── Step 5: Recommendations ────────────────────────────────────")

    # Per-attack-type mitigations (deduplicated)
    seen = set()
    for e in explanations:
        if e["attack_type"] != "Normal" and e["attack_type"] not in seen:
            seen.add(e["attack_type"])
            print(format_recommendation(e["attack_type"]))

    print("\n── AI Threat Narrative ─────────────────────────────────────────")
    print(generate_threat_narrative(explanations, summary))


def step_report(explanations: list[dict], summary: dict) -> None:
    """Optional: Print the full SOC incident report."""
    from insights.recommendation_engine import generate_full_report
    print("\n── Full SOC Incident Report ────────────────────────────────────")
    print(generate_full_report(explanations, summary))


def step_firewall(explanations: list[dict]) -> None:
    """Optional: Print auto-generated firewall rules."""
    from insights.recommendation_engine import generate_firewall_rules
    print("\n── Firewall Rules ──────────────────────────────────────────────")
    print(generate_firewall_rules(explanations))


def step_visualize(log_rows: list[dict], explanations: list[dict], plots_dir: str) -> None:
    """Optional: Generate and save all matplotlib charts."""
    try:
        from visualization.plots import generate_all_plots
        print(f"\n── Step 6: Generating charts → {plots_dir} ────────────────────")
        generate_all_plots(log_rows, explanations, save_dir=plots_dir, show=False)
    except ImportError as e:
        print(f"[WARN] Could not generate charts: {e}")


def step_launch_web(port: int) -> None:
    """Optional: Launch the NetSentinel web dashboard (original web server)."""
    import subprocess
    server_path = os.path.join(PROJECT_ROOT, "python_project.py")
    if not os.path.exists(server_path):
        print(f"[ERROR] Web server file not found: {server_path}")
        return

    print(f"\n── Launching Web Dashboard on port {port} ──────────────────────")
    print(f"    URL: http://localhost:{port}")
    print("    Press Ctrl+C to stop the server.\n")
    try:
        subprocess.run([sys.executable, server_path, "-p", str(port)], check=False)
    except KeyboardInterrupt:
        print("\n[INFO] Web server stopped.")


# ── Main pipeline ──────────────────────────────────────────────────────────────

def main() -> None:
    """Run the complete Login Attack Pattern Analyzer pipeline."""
    args = parse_args()

    print("\n" + "═" * 60)
    print("  LOGIN ATTACK PATTERN ANALYZER")
    print("  ML-Based Authentication Threat Detection")
    print("═" * 60)

    # Step 0 (optional): Train the model
    if args.train:
        step_train_model(args.training_data, args.model)

    # Step 1: Read logs
    try:
        log_rows = step_read_logs(args.data)
    except FileNotFoundError as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)

    # Step 2: Extract features
    try:
        feature_df = step_extract_features(log_rows)
    except ImportError as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)

    # Step 3: Classify
    classified_df = step_classify(feature_df, args.model)

    # Step 4: Explain
    explanations = step_explain(classified_df, feature_df)

    # Build aggregate summary for reporting
    from analysis.log_reader import login_logs_to_tuples
    from analysis.pattern_detector import detect_patterns
    tuples = login_logs_to_tuples(log_rows)
    _, summary = detect_patterns(tuples)

    # Step 5: Recommendations + threat narrative
    step_recommendations(explanations, summary)

    # Optional extras
    if args.report:
        step_report(explanations, summary)

    if args.firewall:
        step_firewall(explanations)

    if args.plots:
        step_visualize(log_rows, explanations, args.plots_dir)

    print("\n" + "═" * 60)
    print("  Analysis Complete.")
    print("═" * 60)

    # Optional: Launch web dashboard (blocks until Ctrl+C)
    if args.web:
        step_launch_web(args.port)


if __name__ == "__main__":
    main()
