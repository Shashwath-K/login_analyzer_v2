"""
visualization/plots.py
=======================
Generates matplotlib-based visualizations for login attack analysis results.

Responsibilities:
    - Plot login success vs. failure counts (bar chart)
    - Plot login attempts per source IP (horizontal bar chart)
    - Plot login attempts over time (time-series line chart)
    - Plot attack type distribution (pie chart)
    - Apply a consistent dark cybersecurity aesthetic across all charts
    - Save charts to the output directory or display them interactively

Usage:
    from visualization.plots import generate_all_plots
    generate_all_plots(log_rows, explanations, save_dir="output/plots")
"""

import os
import sys
import datetime
from collections import Counter, defaultdict

# Adjust path for direct execution
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import matplotlib
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from matplotlib.ticker import MaxNLocator
    _MATPLOTLIB_AVAILABLE = True
except ImportError:
    _MATPLOTLIB_AVAILABLE = False

try:
    import pandas as pd
    _PANDAS_AVAILABLE = True
except ImportError:
    _PANDAS_AVAILABLE = False


# ── Chart styling ──────────────────────────────────────────────────────────────

DARK_BG = "#030508"
PANEL_BG = "#0b0e18"
ACCENT_GREEN = "#00f0c8"
ACCENT_RED = "#ff2d6b"
ACCENT_ORANGE = "#f5a623"
ACCENT_BLUE = "#3d8eff"
ACCENT_PURPLE = "#c084fc"
TEXT_COLOR = "#b0c4de"
GRID_COLOR = "#141d32"

ATTACK_COLORS = {
    "Brute Force": ACCENT_RED,
    "Credential Stuffing": ACCENT_ORANGE,
    "Dictionary Attack": ACCENT_PURPLE,
    "Password Spray": ACCENT_BLUE,
    "Normal": ACCENT_GREEN,
    "Unknown": "#666666",
}


def _apply_dark_style(ax, title: str, xlabel: str = "", ylabel: str = "") -> None:
    """Apply the dark cybersecurity aesthetic to a matplotlib Axes object.

    Args:
        ax:     The matplotlib Axes to style.
        title:  Chart title text.
        xlabel: X-axis label (optional).
        ylabel: Y-axis label (optional).
    """
    ax.set_facecolor(PANEL_BG)
    ax.figure.patch.set_facecolor(DARK_BG)
    ax.set_title(title, color=ACCENT_GREEN, fontsize=13, fontweight="bold", pad=14)
    if xlabel:
        ax.set_xlabel(xlabel, color=TEXT_COLOR, fontsize=10)
    if ylabel:
        ax.set_ylabel(ylabel, color=TEXT_COLOR, fontsize=10)
    ax.tick_params(colors=TEXT_COLOR, labelsize=8)
    ax.spines["bottom"].set_color(GRID_COLOR)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color(GRID_COLOR)
    ax.yaxis.grid(True, color=GRID_COLOR, linestyle="--", linewidth=0.5, alpha=0.5)
    ax.set_axisbelow(True)


def _check_matplotlib() -> None:
    """Raise an ImportError if matplotlib is not installed."""
    if not _MATPLOTLIB_AVAILABLE:
        raise ImportError("matplotlib is required for plots. Install with: pip install matplotlib")


# ── Chart 1: Login success vs. failure ────────────────────────────────────────

def plot_success_vs_failure(log_rows: list[dict], save_path: str | None = None) -> None:
    """Plot a bar chart comparing login successes and failures.

    Args:
        log_rows:  List of login log dicts from log_reader.read_login_logs_csv().
        save_path: File path to save the chart. If None, chart is displayed.
    """
    _check_matplotlib()

    success_count = sum(1 for r in log_rows if r.get("status", "").lower() == "success")
    failure_count = sum(1 for r in log_rows if r.get("status", "").lower() == "failure")
    total = success_count + failure_count

    fig, ax = plt.subplots(figsize=(7, 5))
    bars = ax.bar(
        ["Successful Logins", "Failed Logins"],
        [success_count, failure_count],
        color=[ACCENT_GREEN, ACCENT_RED],
        width=0.5,
        edgecolor=DARK_BG,
        linewidth=1.2,
    )

    # Value labels on bars
    for bar, val in zip(bars, [success_count, failure_count]):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(total * 0.01, 1),
            str(val),
            ha="center", va="bottom",
            color=TEXT_COLOR, fontsize=11, fontweight="bold",
        )

    _apply_dark_style(ax, "Login Success vs. Failure", ylabel="Number of Attempts")
    ax.set_ylim(0, max(success_count, failure_count) * 1.18)

    # Subtitle
    ax.text(
        0.5, -0.12,
        f"Total: {total} events  |  Failure rate: {failure_count / total * 100:.1f}%" if total else "",
        ha="center", va="top", transform=ax.transAxes,
        color=TEXT_COLOR, fontsize=8,
    )

    plt.tight_layout()
    _save_or_show(fig, save_path)


# ── Chart 2: Attempts per IP ───────────────────────────────────────────────────

def plot_attempts_per_ip(
    log_rows: list[dict],
    top_n: int = 10,
    save_path: str | None = None,
) -> None:
    """Plot a horizontal bar chart of login attempt counts per source IP.

    Args:
        log_rows:  List of login log dicts.
        top_n:     Number of top IPs to show (default: 10).
        save_path: File path to save the chart. If None, displayed interactively.
    """
    _check_matplotlib()

    # Count failures per IP
    ip_counts = Counter(
        r.get("ip_address", "0.0.0.0")
        for r in log_rows
        if r.get("status", "").lower() == "failure"
    )
    top_ips = ip_counts.most_common(top_n)

    if not top_ips:
        print("[WARN] No failed login attempts found — skipping attempts-per-IP chart.")
        return

    ips, counts = zip(*top_ips)
    colors = [ACCENT_RED if c >= 10 else ACCENT_ORANGE if c >= 5 else ACCENT_BLUE for c in counts]

    fig, ax = plt.subplots(figsize=(9, max(4, len(ips) * 0.5 + 2)))
    bars = ax.barh(
        list(reversed(ips)),
        list(reversed(counts)),
        color=list(reversed(colors)),
        edgecolor=DARK_BG,
        linewidth=0.8,
        height=0.6,
    )

    # Value labels
    for bar, val in zip(bars, reversed(counts)):
        ax.text(
            bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
            str(val), va="center", color=TEXT_COLOR, fontsize=9,
        )

    _apply_dark_style(ax, f"Failed Login Attempts per IP (Top {len(ips)})",
                      xlabel="Number of Failed Attempts")
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.set_xlim(0, max(counts) * 1.18)

    plt.tight_layout()
    _save_or_show(fig, save_path)


# ── Chart 3: Attempts over time ────────────────────────────────────────────────

def plot_attempts_over_time(
    log_rows: list[dict],
    bucket_minutes: int = 30,
    save_path: str | None = None,
) -> None:
    """Plot a line chart of login attempt counts bucketed over time.

    Args:
        log_rows:       List of login log dicts.
        bucket_minutes: Time bucket size in minutes for aggregation (default: 30).
        save_path:      File path to save the chart. If None, displayed.
    """
    _check_matplotlib()

    # Bucket attempts by time
    failure_buckets: Counter = Counter()
    success_buckets: Counter = Counter()

    for r in log_rows:
        try:
            ts = datetime.datetime.strptime(
                str(r.get("timestamp", "")).strip(), "%Y-%m-%d %H:%M:%S"
            )
            bucket = ts.replace(
                minute=(ts.minute // bucket_minutes) * bucket_minutes,
                second=0, microsecond=0,
            )
        except ValueError:
            continue

        if r.get("status", "").lower() == "failure":
            failure_buckets[bucket] += 1
        else:
            success_buckets[bucket] += 1

    if not failure_buckets and not success_buckets:
        print("[WARN] No valid timestamps found — skipping time chart.")
        return

    all_times = sorted(set(list(failure_buckets.keys()) + list(success_buckets.keys())))

    fig, ax = plt.subplots(figsize=(11, 5))
    ax.plot(
        all_times,
        [failure_buckets.get(t, 0) for t in all_times],
        color=ACCENT_RED, linewidth=2, marker="o", markersize=4,
        label="Failed Logins",
    )
    ax.plot(
        all_times,
        [success_buckets.get(t, 0) for t in all_times],
        color=ACCENT_GREEN, linewidth=2, marker="s", markersize=4,
        linestyle="--", label="Successful Logins",
    )

    ax.fill_between(
        all_times,
        [failure_buckets.get(t, 0) for t in all_times],
        alpha=0.15, color=ACCENT_RED,
    )

    _apply_dark_style(ax, f"Login Attempts Over Time ({bucket_minutes}-min buckets)",
                      xlabel="Time", ylabel="Attempts")

    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    ax.xaxis.set_major_locator(mdates.AutoDateLocator())
    plt.setp(ax.xaxis.get_majorticklabels(), rotation=35, ha="right")

    legend = ax.legend(
        facecolor=PANEL_BG, edgecolor=GRID_COLOR, labelcolor=TEXT_COLOR, fontsize=9
    )

    plt.tight_layout()
    _save_or_show(fig, save_path)


# ── Chart 4: Attack type distribution ─────────────────────────────────────────

def plot_attack_type_distribution(
    explanations: list[dict],
    save_path: str | None = None,
) -> None:
    """Plot a pie chart of predicted attack type distribution.

    Args:
        explanations: List of explanation dicts from explain_attack.explain_attack().
        save_path:    File path to save the chart. If None, displayed interactively.
    """
    _check_matplotlib()

    attack_counts = Counter(e["attack_type"] for e in explanations)
    if not attack_counts:
        print("[WARN] No classification results found — skipping attack distribution chart.")
        return

    labels = list(attack_counts.keys())
    sizes = list(attack_counts.values())
    colors = [ATTACK_COLORS.get(label, "#888888") for label in labels]
    explode = [0.04 if label != "Normal" else 0.0 for label in labels]

    fig, ax = plt.subplots(figsize=(8, 6))
    wedges, texts, autotexts = ax.pie(
        sizes,
        labels=labels,
        colors=colors,
        autopct="%1.1f%%",
        startangle=90,
        explode=explode,
        wedgeprops={"edgecolor": DARK_BG, "linewidth": 1.5},
        textprops={"color": TEXT_COLOR, "fontsize": 9},
    )
    for autotext in autotexts:
        autotext.set_color(DARK_BG)
        autotext.set_fontweight("bold")
        autotext.set_fontsize(9)

    ax.set_title(
        "Attack Type Distribution (ML Classification)",
        color=ACCENT_GREEN, fontsize=13, fontweight="bold", pad=16,
    )
    fig.patch.set_facecolor(DARK_BG)
    ax.set_facecolor(DARK_BG)

    plt.tight_layout()
    _save_or_show(fig, save_path)


# ── Batch plot generator ───────────────────────────────────────────────────────

def generate_all_plots(
    log_rows: list[dict],
    explanations: list[dict],
    save_dir: str | None = None,
    show: bool = True,
) -> None:
    """Generate all 4 analysis charts in sequence.

    Args:
        log_rows:     Login log dicts from log_reader.read_login_logs_csv().
        explanations: Explanation dicts from explain_attack.explain_attack().
        save_dir:     Directory to save PNG files. If None, charts are shown interactively.
        show:         If True and save_dir is set, still call plt.show() after saving.
    """
    _check_matplotlib()

    def _path(filename: str) -> str | None:
        if save_dir:
            os.makedirs(save_dir, exist_ok=True)
            return os.path.join(save_dir, filename)
        return None

    print("[INFO] Generating chart 1/4: Login Success vs. Failure...")
    plot_success_vs_failure(log_rows, save_path=_path("01_success_vs_failure.png"))

    print("[INFO] Generating chart 2/4: Attempts per IP...")
    plot_attempts_per_ip(log_rows, save_path=_path("02_attempts_per_ip.png"))

    print("[INFO] Generating chart 3/4: Attempts over Time...")
    plot_attempts_over_time(log_rows, save_path=_path("03_attempts_over_time.png"))

    print("[INFO] Generating chart 4/4: Attack Type Distribution...")
    plot_attack_type_distribution(explanations, save_path=_path("04_attack_distribution.png"))

    if save_dir:
        print(f"[OK] All charts saved to: {save_dir}")
    if show and save_dir:
        plt.show()


# ── Internal helper ────────────────────────────────────────────────────────────

def _save_or_show(fig, save_path: str | None) -> None:
    """Save figure to file or display it interactively.

    Args:
        fig:       matplotlib Figure object.
        save_path: File path or None.
    """
    if save_path:
        fig.savefig(save_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close(fig)
    else:
        plt.show()


# ── Direct execution ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    from analysis.log_reader import read_login_logs_csv
    from analysis.feature_extractor import extract_features_from_logs, features_to_dict_list
    from ml_model.attack_classifier import classify_batch, is_model_available
    from explanation.explain_attack import explain_attack

    DATA_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "login_logs.csv")
    MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ml_model", "model.pkl")
    OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output", "plots")

    print("Loading log data...")
    log_rows = read_login_logs_csv(DATA_PATH)

    explanations = []
    if is_model_available(MODEL_PATH):
        feature_df = extract_features_from_logs(log_rows)
        classified = classify_batch(feature_df, MODEL_PATH)
        for _, row in classified.iterrows():
            features = row[["failed_attempts", "unique_usernames", "time_window",
                            "same_password_count", "request_rate"]].to_dict()
            result = {"attack_type": row["predicted_attack_type"],
                      "confidence": row["confidence"], "all_probs": {}}
            explanations.append(explain_attack(row["ip_address"], features, result))
    else:
        print("[WARN] Model not trained yet — attack distribution chart will be empty. Run train_model.py first.")

    generate_all_plots(log_rows, explanations, save_dir=OUTPUT_DIR, show=True)
