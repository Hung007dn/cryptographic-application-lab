import argparse
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt


def load_csv(path):
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")
    return pd.read_csv(path)


def make_comparison(windows_csv, linux_csv, out_csv):
    win = load_csv(windows_csv)
    lin = load_csv(linux_csv)

    win["os"] = "Windows"
    lin["os"] = "Linux"

    data = pd.concat([win, lin], ignore_index=True)

    required = ["Mode", "DataSizeBytes", "ModeType", "IsAEAD", "metric", "mean", "median", "stddev", "ci95", "runs"]
    for col in required:
        if col not in data.columns:
            raise ValueError(f"Missing required column: {col}")

    pivot = data.pivot_table(
        index=["Mode", "DataSizeBytes", "ModeType", "IsAEAD", "metric"],
        columns="os",
        values=["mean", "median", "stddev", "ci95", "runs"],
        aggfunc="first"
    )

    pivot.columns = [f"{stat}_{os_name}" for stat, os_name in pivot.columns]
    pivot = pivot.reset_index()

    if "mean_Windows" in pivot.columns and "mean_Linux" in pivot.columns:
        pivot["Windows_vs_Linux_ratio"] = pivot["mean_Windows"] / pivot["mean_Linux"]
        pivot["Linux_vs_Windows_ratio"] = pivot["mean_Linux"] / pivot["mean_Windows"]

    out_csv = Path(out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    pivot.to_csv(out_csv, index=False)

    print(f"[+] Saved OS comparison CSV: {out_csv}")
    return pivot


def plot_metric(comparison, metric_name, value_col, out_dir):
    data = comparison[comparison["metric"] == metric_name].copy()
    if data.empty:
        print(f"[!] No data for metric: {metric_name}")
        return

    # Use large payloads for cleaner throughput/latency comparison.
    preferred_sizes = [1048576, 8388608]
    data = data[data["DataSizeBytes"].isin(preferred_sizes)]

    if data.empty:
        print(f"[!] No preferred sizes found for metric: {metric_name}")
        return

    for size in sorted(data["DataSizeBytes"].unique()):
        subset = data[data["DataSizeBytes"] == size].copy()
        subset = subset.sort_values("Mode")

        labels = subset["Mode"].tolist()
        x = range(len(labels))

        win_col = f"{value_col}_Windows"
        lin_col = f"{value_col}_Linux"

        if win_col not in subset.columns or lin_col not in subset.columns:
            print(f"[!] Missing OS columns for {metric_name}")
            return

        width = 0.38

        plt.figure(figsize=(12, 6))
        plt.bar([i - width / 2 for i in x], subset[win_col], width=width, label="Windows")
        plt.bar([i + width / 2 for i in x], subset[lin_col], width=width, label="Linux")

        size_name = "1 MiB" if size == 1048576 else "8 MiB" if size == 8388608 else f"{size} bytes"

        plt.title(f"Windows vs Linux - {metric_name} - {size_name}")
        plt.xlabel("AES mode")
        plt.ylabel(value_col)
        plt.xticks(list(x), labels, rotation=30, ha="right")
        plt.legend()
        plt.grid(True, alpha=0.3, axis="y")
        plt.tight_layout()

        out_file = Path(out_dir) / f"os_comparison_{metric_name}_{size}.png"
        plt.savefig(out_file, dpi=150)
        plt.close()

        print(f"[+] Saved chart: {out_file}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--windows", default="results/windows_benchmark_stats.csv")
    parser.add_argument("--linux", default="results/linux_benchmark_stats.csv")
    parser.add_argument("--out", default="results/os_comparison_benchmark_stats.csv")
    parser.add_argument("--charts", default="results/charts")
    args = parser.parse_args()

    comparison = make_comparison(args.windows, args.linux, args.out)

    charts_dir = Path(args.charts)
    charts_dir.mkdir(parents=True, exist_ok=True)

    plot_metric(comparison, "EncryptTimeMS", "mean", charts_dir)
    plot_metric(comparison, "DecryptTimeMS", "mean", charts_dir)
    plot_metric(comparison, "ThroughputMBps", "mean", charts_dir)

    print("[+] OS comparison complete.")


if __name__ == "__main__":
    main()