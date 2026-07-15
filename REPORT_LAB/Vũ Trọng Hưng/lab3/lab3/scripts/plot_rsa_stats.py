# scripts/plot_rsa_stats.py
import argparse
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt


def safe_filename(text: str) -> str:
    return text.strip().lower().replace(" ", "_").replace("/", "_").replace("\\", "_")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stats", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    stats_path = Path(args.stats)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(stats_path)

    if "OS" in df.columns and len(df["OS"].dropna().unique()) > 0:
        os_name = str(df["OS"].dropna().unique()[0])
    else:
        os_name = stats_path.stem.replace("_benchmark_stats", "")

    prefix = safe_filename(os_name)

    df["Label"] = df["Test Name"] + " " + df["Key Bits"].astype(str)

    # =========================
    # Plot 1: Latency mean with CI95
    # =========================
    latency_df = df[df["latency_mean_ms"] > 0].copy()

    plt.figure(figsize=(13, 6))
    plt.bar(
        latency_df["Label"],
        latency_df["latency_mean_ms"],
        yerr=latency_df["latency_CI95_ms"],
        capsize=4
    )
    plt.yscale("log")
    plt.xticks(rotation=45, ha="right")
    plt.ylabel("Mean latency (ms, log scale)")
    plt.title(f"{os_name} RSA and Hybrid Encryption Latency with 95% CI")
    plt.tight_layout()

    latency_file = out_dir / f"{prefix}_latency_ci95.png"
    plt.savefig(latency_file, dpi=200)
    plt.close()

    # =========================
    # Plot 2: Hybrid throughput mean with CI95
    # =========================
    throughput_df = df[
        (df["throughput_mean_MBps"] > 0) &
        (df["Test Name"].str.contains("Hybrid", case=False, na=False))
    ].copy()

    throughput_df["Short Label"] = throughput_df["Test Name"].str.replace(
        "Hybrid ",
        "",
        regex=False
    )

    plt.figure(figsize=(10, 6))
    plt.bar(
        throughput_df["Short Label"],
        throughput_df["throughput_mean_MBps"],
        yerr=throughput_df["throughput_CI95_MBps"],
        capsize=4
    )
    plt.xticks(rotation=30, ha="right")
    plt.ylabel("Mean throughput (MB/s)")
    plt.title(f"{os_name} Hybrid AES-256-GCM Throughput with 95% CI")
    plt.tight_layout()

    throughput_file = out_dir / f"{prefix}_hybrid_throughput_ci95.png"
    plt.savefig(throughput_file, dpi=200)
    plt.close()

    print("Plots created:")
    print(f" - {latency_file}")
    print(f" - {throughput_file}")


if __name__ == "__main__":
    main()