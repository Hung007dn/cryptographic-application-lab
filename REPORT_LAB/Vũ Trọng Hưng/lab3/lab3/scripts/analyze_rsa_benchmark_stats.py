import argparse
import math
from pathlib import Path

import pandas as pd


def ci95(stddev, n):
    if n <= 1:
        return 0.0
    return 1.96 * stddev / math.sqrt(n)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--os-name", required=True)
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    csv_files = sorted(input_dir.glob("*.csv"))

    if not csv_files:
        raise SystemExit(f"No CSV files found in {input_dir}")

    frames = []

    for idx, file in enumerate(csv_files, start=1):
        df = pd.read_csv(file)
        df["Run"] = idx
        df["OS"] = args.os_name
        frames.append(df)

    all_df = pd.concat(frames, ignore_index=True)

    required_cols = [
        "Test Name",
        "Key Bits",
        "Time (ms)",
        "Throughput (MB/s)",
        "Data Size (bytes)"
    ]

    for col in required_cols:
        if col not in all_df.columns:
            raise SystemExit(f"Missing column: {col}. Detected: {list(all_df.columns)}")

    grouped = all_df.groupby(
        ["OS", "Test Name", "Key Bits", "Data Size (bytes)"],
        dropna=False
    )

    stats = grouped.agg(
        runs=("Run", "count"),
        latency_mean_ms=("Time (ms)", "mean"),
        latency_median_ms=("Time (ms)", "median"),
        latency_stddev_ms=("Time (ms)", "std"),
        throughput_mean_MBps=("Throughput (MB/s)", "mean"),
        throughput_median_MBps=("Throughput (MB/s)", "median"),
        throughput_stddev_MBps=("Throughput (MB/s)", "std")
    ).reset_index()

    stats["latency_stddev_ms"] = stats["latency_stddev_ms"].fillna(0)
    stats["throughput_stddev_MBps"] = stats["throughput_stddev_MBps"].fillna(0)

    stats["latency_CI95_ms"] = stats.apply(
        lambda r: ci95(r["latency_stddev_ms"], r["runs"]),
        axis=1
    )

    stats["throughput_CI95_MBps"] = stats.apply(
        lambda r: ci95(r["throughput_stddev_MBps"], r["runs"]),
        axis=1
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    stats.to_csv(out_path, index=False)

    print(f"Loaded {len(csv_files)} CSV files")
    print(f"Statistics written to: {out_path}")
    print(stats)


if __name__ == "__main__":
    main()