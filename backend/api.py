"""
backend/api.py
==============
FastAPI REST API — bridges the React web application and the ML pipeline.

Endpoints:
    GET  /api/status          → check model availability
    GET  /api/sample-data     → load sample login logs and run ML pipeline
    POST /api/analyze         → upload a CSV and run full ML analysis
    POST /api/train           → train (or retrain) the model
    GET  /api/training-status → check if model.pkl exists
    POST /api/simulate        → generate attack simulation data

Run from project root:
    uvicorn backend.api:app --reload --port 8000

Run from backend directory:
    uvicorn api:app --reload --port 8000
"""

import os
import sys
import io
import csv
import json
from typing import Optional

# Ensure the project root is on sys.path so we can import project modules
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

try:
    from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel
except ImportError:
    raise ImportError("FastAPI is required. Run: pip install fastapi uvicorn python-multipart")

# ── Import ML pipeline modules ─────────────────────────────────────────────────
from analysis.log_reader import read_login_logs_csv, login_logs_to_tuples, parse_raw_login_log
from analysis.pattern_detector import detect_patterns
from analysis.feature_extractor import extract_features_from_logs
from ml_model.attack_classifier import classify_batch, is_model_available
from explanation.explain_attack import explain_attack, generate_threat_narrative
from insights.recommendation_engine import (
    generate_full_report, generate_firewall_rules, generate_alert_emails, get_recommendation
)
from utils.helpers import build_summary

# ── Paths ──────────────────────────────────────────────────────────────────────
DATA_PATH     = os.path.join(PROJECT_ROOT, "data", "login_logs.csv")
TRAINING_PATH = os.path.join(PROJECT_ROOT, "data", "training_data.csv")
MODEL_PATH    = os.path.join(PROJECT_ROOT, "ml_model", "model.pkl")

# ── FastAPI app ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="LogCentric Attack Pattern Analyzer API",
    description="ML-based authentication threat detection REST API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://localhost:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Shared pipeline runner ─────────────────────────────────────────────────────

def _run_pipeline(log_rows: list[dict]) -> dict:
    """Run the full ML analysis pipeline on log rows and return serializable results."""

    # Rule-based pattern detection (for network event analysis)
    tuples = login_logs_to_tuples(log_rows)
    rule_results, rule_summary = detect_patterns(tuples)

    # ML feature extraction
    feature_df = extract_features_from_logs(log_rows)

    # ML classification
    if not is_model_available(MODEL_PATH):
        ml_available = False
        explanations = []
        classified_data = []
    else:
        ml_available = True
        classified_df = classify_batch(feature_df, MODEL_PATH)

        explanations = []
        classified_data = []
        for _, row in classified_df.iterrows():
            features = {
                "failed_attempts": float(row["failed_attempts"]),
                "unique_usernames": float(row["unique_usernames"]),
                "time_window": float(row["time_window"]),
                "same_password_count": float(row["same_password_count"]),
                "request_rate": float(row["request_rate"]),
            }
            classification = {
                "attack_type": row["predicted_attack_type"],
                "confidence": float(row["confidence"]),
                "all_probs": {},
            }
            explanation = explain_attack(row["ip_address"], features, classification)
            explanations.append(explanation)

            rec = get_recommendation(explanation["attack_type"])
            classified_data.append({
                "ip": row["ip_address"],
                "attack_type": row["predicted_attack_type"],
                "confidence": round(float(row["confidence"]) * 100, 1),
                "severity": explanation["severity"],
                "failed_attempts": int(row["failed_attempts"]),
                "unique_usernames": int(row["unique_usernames"]),
                "time_window": round(float(row["time_window"]), 1),
                "same_password_count": int(row["same_password_count"]),
                "request_rate": round(float(row["request_rate"]), 4),
                "summary": explanation["summary"],
                "reasons": explanation["reasons"],
                "recommendation_steps": rec["steps"],
            })

    # Summary stats
    successes = sum(1 for r in log_rows if r.get("status", "").lower() == "success")
    failures  = sum(1 for r in log_rows if r.get("status", "").lower() == "failure")

    # Per-IP breakdown for time chart
    from collections import Counter
    import datetime as dt
    time_buckets: dict[str, dict] = {}
    for r in log_rows:
        try:
            ts = dt.datetime.strptime(str(r.get("timestamp", "")).strip(), "%Y-%m-%d %H:%M:%S")
            bucket = ts.replace(minute=(ts.minute // 30) * 30, second=0, microsecond=0)
            key = bucket.strftime("%Y-%m-%d %H:%M")
            if key not in time_buckets:
                time_buckets[key] = {"time": key, "failures": 0, "successes": 0}
            if r.get("status", "").lower() == "failure":
                time_buckets[key]["failures"] += 1
            else:
                time_buckets[key]["successes"] += 1
        except (ValueError, TypeError):
            continue

    ip_failure_counts = Counter(
        r.get("ip_address", "0.0.0.0")
        for r in log_rows if r.get("status", "").lower() == "failure"
    )
    top_ips = [{"ip": ip, "count": count} for ip, count in ip_failure_counts.most_common(10)]

    attack_distribution = Counter(e["attack_type"] for e in explanations) if explanations else {}

    return {
        "ml_available": ml_available,
        "total_events": len(log_rows),
        "successes": successes,
        "failures": failures,
        "unique_ips": len(set(r.get("ip_address") for r in log_rows)),
        "classified_ips": classified_data,
        "attack_distribution": [
            {"type": k, "count": v} for k, v in attack_distribution.items()
        ],
        "top_ips": top_ips,
        "time_series": sorted(time_buckets.values(), key=lambda x: x["time"]),
        "threat_narrative": generate_threat_narrative(explanations, rule_summary) if explanations else "",
        "soc_report": generate_full_report(explanations, rule_summary) if explanations else "",
        "firewall_rules": generate_firewall_rules(explanations) if explanations else "",
        "alert_emails": generate_alert_emails(explanations, rule_summary) if explanations else "",
    }


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/api/status")
def status():
    """Check API readiness and model availability."""
    return {
        "status": "ok",
        "model_available": is_model_available(MODEL_PATH),
        "data_available": os.path.exists(DATA_PATH),
    }


@app.get("/api/sample")
def analyze_sample():
    """Run ML pipeline on the built-in sample login_logs.csv."""
    if not os.path.exists(DATA_PATH):
        raise HTTPException(status_code=404, detail=f"Sample data not found: {DATA_PATH}")
    try:
        log_rows = read_login_logs_csv(DATA_PATH)
        return _run_pipeline(log_rows)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/analyze")
async def analyze_uploaded(file: UploadFile = File(...)):
    """Upload a login log CSV or RAW file and run the full ML analysis pipeline."""
    allowed_raw = (".raw", ".txt", ".log")
    
    is_csv = file.filename.endswith(".csv")
    is_raw = any(file.filename.endswith(ext) for ext in allowed_raw)
    
    if not (is_csv or is_raw):
        raise HTTPException(status_code=400, detail="Only CSV, RAW, TXT, or LOG files are accepted.")
    try:
        content = await file.read()
        text = content.decode("utf-8", errors="replace")
        
        if is_csv:
            reader = csv.DictReader(io.StringIO(text))
            log_rows = [row for row in reader]
        else:
            log_rows = parse_raw_login_log(text)

        if not log_rows:
            raise HTTPException(status_code=400, detail="File is empty or has no valid structural data rows.")
        return _run_pipeline(log_rows)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/train")
def train_model():
    """Train (or retrain) the RandomForestClassifier and save model.pkl."""
    try:
        from ml_model.train_model import train
        train(TRAINING_PATH, MODEL_PATH)
        return {"status": "ok", "message": "Model trained and saved successfully.", "model_path": MODEL_PATH}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/simulate/{attack_type}")
def simulate_attack(attack_type: str, count: int = 20):
    """Generate synthetic attack log entries and return analysis results."""
    valid = {"brute_force", "credential_stuffing", "dictionary", "normal"}
    if attack_type not in valid:
        raise HTTPException(status_code=400, detail=f"Invalid attack type. Choose from: {valid}")

    import datetime, random
    rows = []
    base = datetime.datetime.now()

    if attack_type == "brute_force":
        for i in range(count):
            rows.append({
                "timestamp": (base + datetime.timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S"),
                "username": "admin", "ip_address": "10.99.0.1",
                "status": "failure", "password_used": f"pass{i}", "device": "Unknown", "location": "Unknown"
            })
    elif attack_type == "credential_stuffing":
        users = [f"user{i}" for i in range(count)]
        pwds  = [f"pwd{i}"  for i in range(count)]
        for i in range(count):
            rows.append({
                "timestamp": (base + datetime.timedelta(seconds=i*3)).strftime("%Y-%m-%d %H:%M:%S"),
                "username": users[i], "ip_address": "10.99.0.2",
                "status": "failure", "password_used": pwds[i], "device": "Unknown", "location": "Unknown"
            })
    elif attack_type == "dictionary":
        words = ["summer", "winter", "spring", "batman", "superman", "dragon", "master", "shadow",
                 "monkey", "cheese", "pepper", "google", "ranger", "thunder", "dallas", "cheese",
                 "tigger", "buster", "access", "hockey", "baseball", "football", "soccer", "starwars"]
        for i in range(min(count, len(words))):
            rows.append({
                "timestamp": (base + datetime.timedelta(seconds=i*6)).strftime("%Y-%m-%d %H:%M:%S"),
                "username": "root", "ip_address": "10.99.0.3",
                "status": "failure", "password_used": words[i], "device": "Unknown", "location": "Unknown"
            })
    else:  # normal
        users = ["alice", "bob", "carol", "dave", "eve"]
        ips   = ["192.168.1.10", "192.168.1.11", "10.0.0.5", "192.168.1.20", "172.16.0.10"]
        for i in range(count):
            u = users[i % len(users)]
            rows.append({
                "timestamp": (base + datetime.timedelta(minutes=i*15)).strftime("%Y-%m-%d %H:%M:%S"),
                "username": u, "ip_address": ips[i % len(ips)],
                "status": "success", "password_used": f"SecurePass!{i}", "device": "Windows", "location": "Office"
            })

    return _run_pipeline(rows)

# ── Frontend Integration ───────────────────────────────────────────────────────

# Path to the React production build
DIST_PATH = os.path.join(PROJECT_ROOT, "webapp", "dist")

# 1. Mount the assets folder (CSS, JS, Images) if it exists
if os.path.exists(os.path.join(DIST_PATH, "assets")):
    app.mount("/assets", StaticFiles(directory=os.path.join(DIST_PATH, "assets")), name="assets")

# 2. Catch-all route to serve index.html for SPA (React Router) support
@app.get("/{full_path:path}")
async def serve_spa_or_static(full_path: str):
    # Skip handling if the request is for an API endpoint (should be handled by @app.get above)
    if full_path.startswith("api"):
        raise HTTPException(status_code=404, detail="API endpoint not found")

    # If the file exists in dist/ (e.g., favicon.ico, logo.png), serve it directly
    file_path = os.path.join(DIST_PATH, full_path)
    if os.path.isfile(file_path):
        return FileResponse(file_path)

    # Otherwise, check for index.html (SPA routing)
    index_path = os.path.join(DIST_PATH, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)

    # If build directory is missing entirely, show a friendly developer message
    if not os.path.exists(DIST_PATH):
        return HTMLResponse(content=f"""
            <div style="font-family: sans-serif; text-align: center; padding: 50px;">
                <h1 style="color: #ff2d6b;">📝 Frontend Build Missing</h1>
                <p>The backend is running, but the React build was not found at:</p>
                <code style="background: #eee; padding: 5px;">{DIST_PATH}</code>
                <p>Please run the following command in your terminal to build the UI:</p>
                <div style="background: #000; color: #00f0c8; padding: 15px; display: inline-block; border-radius: 8px;">
                    <code>cd webapp ; npm install ; npm run build</code>
                </div>
                <p style="margin-top: 20px; color: #666;">Once built, refresh this page.</p>
                <p><a href="/api/status" style="color: #00f0c8;">Check API Status</a> | <a href="/docs" style="color: #00f0c8;">API Docs</a></p>
            </div>
        """, status_code=404)

    # Final fallback for missing index.html inside dist/
    raise HTTPException(status_code=404, detail="Frontend entry point not found in build directory.")
