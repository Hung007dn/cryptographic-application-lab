# scripts/plot_os_comparison.py
# Compare Windows vs Linux benchmark statistics with fixed label order and 95% CI.

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


LATENCY_ORDER = [
    "RSA Encrypt 3072",
    "RSA Encrypt 4096",
    "RSA Decrypt 3072",
    "RSA Decrypt 4096",
    "Key Generation 3072",
    "Key Generation 4096",
    "Hybrid Encrypt (1 KB) 3072",
    "Hybrid Decrypt (1 KB) 3072",
    "Hybrid Encrypt (1 MB) 3072",
    "Hybrid Decrypt (1 MB) 3072",
    "Hybrid Encrypt (100 MB) 3072",
    "Hybrid Decrypt (100 MB) 3072",
]

THROUGHPUT_ORDER = [
    "Encrypt (1 KB)",
    "Decrypt (1 KB)",
    "Encrypt (1 MB)",
    "Decrypt (1 MB)",
    "Encrypt (100 MB)",
    "Decrypt (100 MB)",
]


def load_stats(path):
    df = pd.read_csv(path)

    required = [
        "OS",
        "Test Name",
        "Key Bits",
        "Data Size (bytes)",
        "latency_mean_ms",
        "latency_CI95_ms",
        "throughput_mean_MBps",
        "throughput_CI95_MBps",
    ]

    for col in required:
        if col not in df.columns:
            raise SystemExit(f"Missing column {col} in {path}")

    return df


def grouped_bar_with_ci(
    df,
    labels,
    value_col,
    ci_col,
    title,
    ylabel,
    output_path,
    log_scale=False,
):
    os_list = ["Linux", "Windows"]
    x = np.arange(len(labels))
    width = 0.38

    fig, ax = plt.subplots(figsize=(15, 7))

    for idx, os_name in enumerate(os_list):
        means = []
        cis = []

        for label in labels:
            row = df[(df["Label"] == label) & (df["OS"] == os_name)]

            if row.empty:
                means.append(0)
                cis.append(0)
            else:
                means.append(float(row[value_col].iloc[0]))
                cis.append(float(row[ci_col].iloc[0]))

        offset = (idx - 0.5) * width

        ax.bar(
            x + offset,
            means,
            width,
            yerr=cis,
            capsize=4,
            label=os_name,
        )

    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=40, ha="right")

    if log_scale:
        ax.set_yscale("log")

    ax.legend(title="OS")
    ax.grid(axis="y", alpha=0.25)

    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()

    print(f"Created: {output_path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--windows", required=True)
    parser.add_argument("--linux", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    win = load_stats(args.windows)
    lin = load_stats(args.linux)

    df = pd.concat([win, lin], ignore_index=True)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # =========================
    # Latency comparison
    # =========================
    df["Label"] = df["Test Name"] + " " + df["Key Bits"].astype(str)

    latency_df = df[df["Label"].isin(LATENCY_ORDER)].copy()

    grouped_bar_with_ci(
        latency_df,
        LATENCY_ORDER,
        "latency_mean_ms",
        "latency_CI95_ms",
        "Windows vs Linux RSA and Hybrid Latency",
        "Mean latency (ms, log scale)",
        out_dir / "windows_vs_linux_latency_ci95.png",
        log_scale=True,
    )

    # =========================
    # Hybrid throughput comparison
    # =========================
    throughput_df = df[
        (df["throughput_mean_MBps"] > 0)
        & (df["Test Name"].str.contains("Hybrid", case=False, na=False))
    ].copy()

    throughput_df["Label"] = throughput_df["Test Name"].str.replace(
        "Hybrid ",
        "",
        regex=False,
    )

    throughput_df = throughput_df[throughput_df["Label"].isin(THROUGHPUT_ORDER)].copy()

    grouped_bar_with_ci(
        throughput_df,
        THROUGHPUT_ORDER,
        "throughput_mean_MBps",
        "throughput_CI95_MBps",
        "Windows vs Linux Hybrid AES-256-GCM Throughput",
        "Mean throughput (MB/s)",
        out_dir / "windows_vs_linux_hybrid_throughput_ci95.png",
        log_scale=False,
    )


if __name__ == "__main__":
    main()