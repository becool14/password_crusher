from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_FILE = BASE_DIR / "results" / "attack_results.csv"
CHARTS_DIR = BASE_DIR / "results" / "charts"


def main():
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(RESULTS_FILE)

    plt.figure(figsize=(8, 5))
    plt.bar(df["algorithm"], df["dictionary_success_pct"], label="Dictionary")
    plt.bar(df["algorithm"], df["bruteforce_success_pct"], alpha=0.7, label="Brute force")
    plt.ylabel("Skutecznosc (%)")
    plt.title("Porownanie skutecznosci atakow")
    plt.legend()
    plt.tight_layout()
    plt.savefig(CHARTS_DIR / "success_comparison.png", dpi=150)
    plt.close()

    plt.figure(figsize=(8, 5))
    plt.bar(df["algorithm"], df["dictionary_time_s"], label="Dictionary")
    plt.bar(df["algorithm"], df["bruteforce_time_s"], alpha=0.7, label="Brute force")
    plt.ylabel("Czas (s)")
    plt.title("Porownanie czasu atakow")
    plt.legend()
    plt.tight_layout()
    plt.savefig(CHARTS_DIR / "time_comparison.png", dpi=150)
    plt.close()

    print(f"Charts saved in: {CHARTS_DIR}")


if __name__ == "__main__":
    main()
