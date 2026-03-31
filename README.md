<div align="center">

<h1>🔐 Login Attack Pattern Analyzer</h1>
<p><strong>ML-Based Authentication Threat Detection System</strong></p>

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-RandomForest-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://reactjs.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-REST%20API-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)

</div>

---

## 📌 Project Objectives

This project was built to address three core academic and industry objectives in cybersecurity analytics:

### Objective 1 — Detect Suspicious Authentication Behavior
Analyze structured login log data (`login_logs.csv`) to identify anomalous patterns across source IP addresses. The system detects rate anomalies, username diversity, password repetition, and timing patterns — all of which are key indicators of automated login attacks.

### Objective 2 — Classify Attack Types Using Machine Learning
Apply supervised machine learning (scikit-learn `RandomForestClassifier`) to classify observed login behavior into one of five categories:
- **Brute Force** — rapid, single-target, high-volume password guessing
- **Credential Stuffing** — leaked (username, password) pairs from external breaches
- **Dictionary Attack** — wordlist-based password exhaustion against one account
- **Password Spray** — one common password tried across many accounts
- **Normal** — legitimate user login activity

### Objective 3 — Explain and Provide Actionable Insights
For every classified attack, the system generates:
1. **Feature-driven plain-English explanations** — why the ML model classified it as such
2. **Prioritized mitigation recommendations** — what security controls to apply
3. **SOC-style incident reports** — formatted for security team escalation
4. **Auto-generated firewall rules** — iptables (Linux) and PowerShell (Windows)

---

## 🏗 Architecture Overview

```
Login Attack Pattern Analyzer
│
├── ML Pipeline (main.py)          ← CLI entry point for analysis
│   ├── log_reader.py              ← Read/validate CSV, PCAP, text logs
│   ├── feature_extractor.py       ← Extract 5 ML features per source IP
│   ├── attack_classifier.py       ← Predict attack type using trained model
│   ├── explain_attack.py          ← Generate plain-English reasoning
│   └── recommendation_engine.py   ← Produce mitigation steps + reports
│
├── Web Dashboard (python_project.py) ← Rule-based NetSentinel web UI
│   └── 30+ regex rules → API → embedded HTML/JS SPA
│
└── Web Application (webapp/ + backend/) ← React + FastAPI modern UI
    ├── FastAPI REST backend        ← bridge between React and ML pipeline
    └── React + Vite frontend       ← interactive cybersecurity dashboard
```

### Data Flow

```
login_logs.csv
    │
    ▼
[log_reader.py]  ──parse──▶  raw log rows
    │
    ▼
[feature_extractor.py]  ──group by IP──▶  feature vectors
    │  failed_attempts, unique_usernames,
    │  time_window, same_password_count,
    │  request_rate
    ▼
[attack_classifier.py]  ──predict──▶  attack_type + confidence
    │                    (RandomForestClassifier)
    ▼
[explain_attack.py]  ──reason──▶  plain-English explanation
    │
    ▼
[recommendation_engine.py]  ──mitigate──▶  SOC report + firewall rules
```

---

## 🧱 Technology Stack

### Backend / ML Pipeline

| Layer | Technology | Purpose |
|---|---|---|
| Language | Python 3.10+ | Core runtime |
| ML Framework | `scikit-learn` | RandomForestClassifier, train/test split |
| Data Processing | `pandas` | CSV reading, DataFrame feature extraction |
| Model Persistence | `joblib` | Save/load model.pkl |
| Visualization | `matplotlib` | 4-panel login attack charts |
| Web Framework | `FastAPI` | REST API backend for React frontend |
| ASGI Server | `uvicorn` | Production-grade Python ASGI server |
| Web Server (legacy) | `http.server` | Built-in NetSentinel web dashboard |
| Data Source | CSV files | login_logs.csv, training_data.csv |

### Frontend (Web Application)

| Layer | Technology | Purpose |
|---|---|---|
| Framework | React 18 + Vite | Fast SPA with hot module replacement |
| Charts | Recharts | Interactive attack visualisation charts |
| HTTP Client | Axios | API calls to FastAPI backend |
| Styling | CSS Modules | Dark cybersecurity theme |
| Routing | React Router v6 | Multi-page navigation |

### ML Model Details

| Parameter | Value |
|---|---|
| Algorithm | `RandomForestClassifier` |
| Estimators | 100 decision trees |
| Train/Test Split | 80% / 20% (stratified) |
| Features | 5 numeric (see below) |
| Classes | 5 attack types |
| Serialization | joblib `.pkl` |

**Feature Definitions:**

| Feature | Description |
|---|---|
| `failed_attempts` | Total failed logins from this source IP |
| `unique_usernames` | Number of distinct usernames tried |
| `time_window` | Seconds between first and last attempt |
| `same_password_count` | Most-repeated password count |
| `request_rate` | Failed attempts per second |

---

## 📁 Project Structure

```
Login_analyzer_tracer/
│
├── 📂 data/
│   ├── login_logs.csv          # Login event logs (timestamp, ip, user, status, ...)
│   └── training_data.csv       # Labelled ML training data (120 samples, 5 classes)
│
├── 📂 analysis/
│   ├── log_reader.py           # CSV + PCAP + text log parsing
│   ├── pattern_detector.py     # 30+ regex rule engine (from NetSentinel)
│   └── feature_extractor.py   # log rows → feature vectors per source IP
│
├── 📂 ml_model/
│   ├── train_model.py          # Train + evaluate + save RandomForestClassifier
│   ├── attack_classifier.py    # Load model, single + batch prediction
│   └── model.pkl               # Saved model (generated after training)
│
├── 📂 explanation/
│   └── explain_attack.py       # Feature-driven NLG explanation engine
│
├── 📂 insights/
│   └── recommendation_engine.py # Mitigation steps, SOC reports, firewall rules
│
├── 📂 visualization/
│   └── plots.py                # 4 matplotlib charts (dark cybersecurity theme)
│
├── 📂 simulations/
│   ├── brute_force_test.py     # Generate brute-force attack test data
│   ├── credential_stuffing_test.py # Generate credential stuffing test data
│   ├── dictionary_attack_test.py   # Generate dictionary attack test data
│   └── normal_login_test.py    # Generate normal login baseline data
│
├── 📂 utils/
│   └── helpers.py              # Shared utilities (severity, risk scoring, export)
│
├── 📂 backend/
│   └── api.py                  # FastAPI REST API (bridges ML pipeline ↔ React)
│
├── 📂 webapp/                  # React + Vite web application
│   ├── src/
│   │   ├── components/         # Reusable UI components
│   │   ├── pages/              # Dashboard, Analysis, Report pages
│   │   └── App.jsx
│   └── package.json
│
├── main.py                     # CLI entry point — full ML analysis pipeline
├── python_project.py           # NetSentinel web dashboard (rule-based, legacy)
└── README.md                   # This file
```

---

## 🚀 Quick Start

### Prerequisites

```bash
# Python 3.10 or higher required
python --version

# Node.js 18+ required (for web app only)
node --version
```

### 1. Install Python Dependencies

```bash
# From the project root:
pip install -r requirements.txt
```

### 2. Train the ML Model

```bash
# From the project root:
python ml_model/train_model.py
```

Expected output:
```
── Loading training data ─────────────────────────────────────
[INFO] Loaded 120 training samples from 'data/training_data.csv'.

── Class distribution ────────────────────────────────────────
  Brute Force               30  ██████████████████████████████
  Credential Stuffing       25  █████████████████████████
  Dictionary Attack         25  █████████████████████████
  Normal                    20  ████████████████████
  Password Spray            20  ████████████████████

[INFO] Training on 96 samples, evaluating on 24 samples.
── Training RandomForestClassifier ────────────────────────────
[OK] Model trained successfully.

── Evaluation Results ─────────────────────────────────────────
  Accuracy: 100.0%
[OK] Model saved to: ml_model/model.pkl
```

### 3. Run the ML Pipeline (CLI)

```bash
# Basic analysis
python main.py

# With all outputs
python main.py --report --firewall --plots

# Train model first, then run everything
python main.py --train --report --firewall --plots

# Launch web dashboard after ML pipeline
python main.py --web --port 8765
```

### 4. Run the Web Application

**Terminal 1 — Start FastAPI backend:**
```bash
cd backend
uvicorn api:app --reload --port 8000
```

**Terminal 2 — Start React frontend:**
```bash
cd webapp
npm install
npm run dev
# Opens at http://localhost:5173
```

### 5. Run the Legacy NetSentinel Dashboard (Optional)

```bash
python python_project.py
# Opens at http://localhost:8765
# Credentials: admin / admin123  |  analyst / analyst2024
```

---

## 🔬 How It Works

### Step 1 — Log Ingestion
`analysis/log_reader.py` reads `data/login_logs.csv` and validates required columns (`timestamp`, `username`, `ip_address`, `status`, `password_used`, `device`, `location`). Supports CSV, plain text, and binary PCAP formats.

### Step 2 — Feature Extraction
`analysis/feature_extractor.py` groups all log rows by source IP address and computes 5 numeric features per IP. These features are specifically chosen to discriminate between attack patterns without needing deep packet inspection.

### Step 3 — ML Classification
`ml_model/attack_classifier.py` loads the pre-trained `model.pkl` and applies it to the feature matrix. For each source IP, it returns a predicted attack type and a confidence score (probability from the Random Forest ensemble).

### Step 4 — Explanation
`explanation/explain_attack.py` maps the feature values back to plain-English sentences:
> *"15 failed login attempts detected. All 15 attempts targeted a single username, which is characteristic of a brute-force password guessing attack. The request rate was 0.250 attempts/second — this is an automated attack speed."*

### Step 5 — Recommendations
`insights/recommendation_engine.py` maps each attack type to a prioritized list of mitigations (e.g., MFA, fail2ban, account lockout), generates a full SOC incident report, and produces ready-to-apply firewall rules.

### Step 6 — Visualization
`visualization/plots.py` generates 4 charts:
1. **Success vs. Failure** — bar chart of login outcome distribution
2. **Attempts per IP** — horizontal bar chart of top attacking sources
3. **Attempts over Time** — time-series line chart with 30-min buckets
4. **Attack Type Distribution** — pie chart of ML classification results

---

## 🎯 Testing with Simulations

Generate synthetic attack data for testing:

```bash
# Generate a brute-force attack (20 attempts, automated speed)
python simulations/brute_force_test.py --attempts 20 --ip 10.0.99.1 --user admin

# Generate credential stuffing (30 leaked credential pairs)
python simulations/credential_stuffing_test.py --pairs 30 --ip 45.33.32.200

# Generate dictionary attack (slow wordlist, single target)
python simulations/dictionary_attack_test.py --words 40 --ip 178.128.99.10 --user root

# Generate normal login baseline (50 legitimate logins, 92% success rate)
python simulations/normal_login_test.py --events 50 --success-rate 0.92

# Re-run analysis after adding simulation data
python main.py --report --plots
```

---

## 📊 Output Examples

### Console Output (`python main.py`)

```
── Step 1: Reading login logs ─────────────────────────────────
[OK] Loaded 230 events — 65 successes / 165 failures

── Step 2: Extracting features ────────────────────────────────
[OK] Features computed for 18 unique source IP(s)

── Step 3: Classifying attack types ───────────────────────────
  Brute Force              4 IP(s)
  Credential Stuffing      3 IP(s)
  Dictionary Attack        2 IP(s)
  Password Spray           2 IP(s)
  Normal                   7 IP(s)

── Step 5: Recommendations ────────────────────────────────────
  Recommended Actions for: Brute Force
  Severity Level: CRITICAL
  1. Block the source IP immediately at the firewall level.
  2. Enable account lockout after 5 consecutive failed attempts.
  3. Deploy fail2ban or equivalent intrusion prevention.
  ...
```

### Generated Charts

Charts are saved to `output/plots/` when using `--plots`:
- `01_success_vs_failure.png`
- `02_attempts_per_ip.png`
- `03_attempts_over_time.png`
- `04_attack_distribution.png`

---

## 🔧 Configuration Reference

### `main.py` CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--data` | `data/login_logs.csv` | Path to login logs |
| `--training-data` | `data/training_data.csv` | Path to training data |
| `--model` | `ml_model/model.pkl` | Path to model file |
| `--train` | `False` | Train the model before analysis |
| `--plots` | `False` | Generate matplotlib charts |
| `--plots-dir` | `output/plots` | Chart output directory |
| `--report` | `False` | Print full SOC incident report |
| `--firewall` | `False` | Print firewall block rules |
| `--web` | `False` | Launch web dashboard after pipeline |
| `--port` | `8765` | Port for web dashboard |

### `login_logs.csv` Schema

| Column | Type | Required | Description |
|---|---|---|---|
| `timestamp` | `YYYY-MM-DD HH:MM:SS` | ✅ | Event timestamp |
| `username` | string | ✅ | Login username attempted |
| `ip_address` | IPv4 | ✅ | Source IP address |
| `status` | `success` / `failure` | ✅ | Login outcome |
| `password_used` | string | ✅ | Password attempted |
| `device` | string | — | Client device type |
| `location` | string | — | Geographic location |

### `training_data.csv` Schema

| Column | Type | Description |
|---|---|---|
| `failed_attempts` | int | Total failed login count |
| `unique_usernames` | int | Distinct usernames tried |
| `time_window` | float | Seconds between first and last attempt |
| `same_password_count` | int | Most-repeated password count |
| `request_rate` | float | Failed attempts per second |
| `attack_type` | string | Ground truth label |

---

## 🤝 Academic Context

This project was developed as an academic cybersecurity analytics project demonstrating:
- **Supervised learning** applied to authentication log analysis
- **Separation of concerns** in Python modular architecture
- **Explainable AI** — bridging ML predictions and human-readable reasoning
- **Full-stack cybersecurity tooling** — from raw log ingestion to actionable SOC reports

The rule-based NetSentinel dashboard (`python_project.py`) preserves the original system that was refactored into this modular architecture, demonstrating a before/after comparison of software engineering quality.

---

## 📜 License

This project is for academic purposes. All synthetic data is computer-generated and does not represent any real individuals or organizations.
