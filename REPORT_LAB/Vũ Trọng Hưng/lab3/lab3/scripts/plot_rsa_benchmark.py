import sys
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt


def main():
    if len(sys.argv) < 2:
        print("Usage: python plot_rsa_benchmark.py rsa_benchmark_results.csv")
        sys.exit(1)

    csv_path = Path(sys.argv[1])

    if not csv_path.exists():
        print(f"CSV file not found: {csv_path}")
        sys.exit(1)

    df = pd.read_csv(csv_path)
    out_dir = csv_path.parent

    # =========================
    # Plot 1: Latency, log scale
    # =========================
    latency_df = df[df["Time (ms)"] > 0].copy()
    latency_df["Label"] = latency_df["Test Name"] + " " + latency_df["Key Bits"].astype(str)

    plt.figure(figsize=(13, 6))
    plt.bar(latency_df["Label"], latency_df["Time (ms)"])
    plt.yscale("log")
    plt.xticks(rotation=45, ha="right")
    plt.ylabel("Latency (ms, log scale)")
    plt.title("RSA and Hybrid Encryption Latency")
    plt.tight_layout()

    latency_plot = out_dir / "rsa_latency_plot.png"
    plt.savefig(latency_plot, dpi=200)
    plt.close()

    # =========================
    # Plot 2: Hybrid throughput only
    # =========================
    throughput_df = df[
        (df["Throughput (MB/s)"] > 0) &
        (df["Test Name"].str.contains("Hybrid", case=False, na=False))
    ].copy()

    throughput_df["Label"] = throughput_df["Test Name"].str.replace("Hybrid ", "", regex=False)

    plt.figure(figsize=(10, 6))
    plt.bar(throughput_df["Label"], throughput_df["Throughput (MB/s)"])
    plt.xticks(rotation=30, ha="right")
    plt.ylabel("Throughput (MB/s)")
    plt.title("Hybrid AES-256-GCM Throughput")
    plt.tight_layout()

    throughput_plot = out_dir / "hybrid_throughput_plot.png"
    plt.savefig(throughput_plot, dpi=200)
    plt.close()

    print("Plots created:")
    print(f" - {latency_plot}")
    print(f" - {throughput_plot}")


if __name__ == "__main__":
    main()