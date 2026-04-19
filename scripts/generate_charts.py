from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_FILE = BASE_DIR / "results" / "attack_results.csv"
CHARTS_DIR = BASE_DIR / "results" / "charts"


def grouped_bar(ax, x, labels, series: dict, colors=None):
    n = len(series)
    width = 0.8 / n
    offsets = np.linspace(-(n - 1) / 2, (n - 1) / 2, n) * width
    for (label, values), offset, color in zip(series.items(), offsets, colors or plt.rcParams["axes.prop_cycle"].by_key()["color"]):
        ax.bar(x + offset, values, width, label=label, color=color)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=20, ha="right")


def main():
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(RESULTS_FILE)
    algos = df["algorithm"].tolist()
    x = np.arange(len(algos))

    # --- Chart 1: success rate (%) ---
    fig, ax = plt.subplots(figsize=(10, 5))
    grouped_bar(ax, x, algos, {
        "Dictionary": df["dictionary_success_pct"].tolist(),
        "Brute-force": df["bruteforce_success_pct"].tolist(),
    }, colors=["#4C72B0", "#DD8452"])
    ax.set_ylabel("Skutecznosc (%)")
    ax.set_title("Porownanie skutecznosci atakow")
    ax.set_ylim(0, 100)
    ax.legend()
    fig.tight_layout()
    fig.savefig(CHARTS_DIR / "success_comparison.png", dpi=150)
    plt.close(fig)

    # --- Chart 2: attack time — log scale ---
    fig, ax = plt.subplots(figsize=(10, 5))
    grouped_bar(ax, x, algos, {
        "Dictionary": df["dictionary_time_s"].tolist(),
        "Brute-force": df["bruteforce_time_s"].tolist(),
    }, colors=["#4C72B0", "#DD8452"])
    ax.set_ylabel("Czas (s) — skala logarytmiczna")
    ax.set_title("Porownanie czasu atakow")
    ax.set_yscale("log")
    ax.legend()
    fig.tight_layout()
    fig.savefig(CHARTS_DIR / "time_comparison.png", dpi=150)
    plt.close(fig)

    print(f"Charts saved in: {CHARTS_DIR}")


if __name__ == "__main__":
    main()
