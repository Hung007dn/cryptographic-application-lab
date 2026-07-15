from pathlib import Path
import argparse
import platform

import pandas as pd
import matplotlib.pyplot as plt

RESULTS_DIR = Path("results")
CHART_DIR = RESULTS_DIR / "charts"


def current_os_name():
    system = platform.system().lower()

    if "windows" in system:
        return "windows"

    if "linux" in system:
        return "linux"

    return system


def load_stats(os_name):
    stats_file = RESULTS_DIR / f"{os_name}_hash_benchmark_stats.csv"

    if not stats_file.exists():
        raise SystemExit(f"Missing stats file: {stats_file}")

    df = pd.read_csv(stats_file)

    if "OS" in df.columns:
        df = df[df["OS"].str.lower() == os_name.lower()]

    if df.empty:
        raise SystemExit(f"No rows found for OS: {os_name}")

    return df, stats_file


def plot_all_sizes(df, os_name):
    df = df.copy()

    df["Label"] = (
        df["Algorithm"].astype(str)
        + " / "
        + df["SizeName"].astype(str)
    )

    throughput_file = CHART_DIR / f"{os_name}_hash_throughput.png"
    latency_file = CHART_DIR / f"{os_name}_hash_latency.png"
    ci95_file = CHART_DIR / f"{os_name}_hash_throughput_ci95.png"

    plt.figure(figsize=(12, 6))
    plt.bar(df["Label"], df["MeanThroughputMBps"])
    plt.ylabel("Mean throughput (MB/s)")
    plt.title(f"{os_name.capitalize()} Hash Function Throughput")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(throughput_file, dpi=200)
    plt.close()

    plt.figure(figsize=(12, 6))
    plt.bar(df["Label"], df["MeanTimeSeconds"])
    plt.ylabel("Mean time (seconds)")
    plt.title(f"{os_name.capitalize()} Hash Function Latency")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(latency_file, dpi=200)
    plt.close()

    plt.figure(figsize=(12, 6))
    plt.bar(
        df["Label"],
        df["MeanThroughputMBps"],
        yerr=df["CI95ThroughputMBps"],
        capsize=4
    )
    plt.ylabel("Mean throughput (MB/s)")
    plt.title(f"{os_name.capitalize()} Hash Throughput with 95% Confidence Interval")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(ci95_file, dpi=200)
    plt.close()

    print(f"[+] Saved: {throughput_file}")
    print(f"[+] Saved: {latency_file}")
    print(f"[+] Saved: {ci95_file}")


def plot_by_size(df, os_name):
    for size_name in sorted(df["SizeName"].unique()):
        subset = df[df["SizeName"] == size_name].copy()
        subset = subset.sort_values("Algorithm")

        throughput_file = CHART_DIR / f"{os_name}_hash_throughput_{size_name}.png"
        latency_file = CHART_DIR / f"{os_name}_hash_latency_{size_name}.png"
        ci95_file = CHART_DIR / f"{os_name}_hash_throughput_ci95_{size_name}.png"

        plt.figure(figsize=(9, 5))
        plt.bar(subset["Algorithm"], subset["MeanThroughputMBps"])
        plt.ylabel("Mean throughput (MB/s)")
        plt.title(f"{os_name.capitalize()} Hash Throughput ({size_name})")
        plt.xticks(rotation=0)
        plt.tight_layout()
        plt.savefig(throughput_file, dpi=200)
        plt.close()

        plt.figure(figsize=(9, 5))
        plt.bar(subset["Algorithm"], subset["MeanTimeSeconds"])
        plt.ylabel("Mean time (seconds)")
        plt.title(f"{os_name.capitalize()} Hash Latency ({size_name})")
        plt.xticks(rotation=0)
        plt.tight_layout()
        plt.savefig(latency_file, dpi=200)
        plt.close()

        plt.figure(figsize=(9, 5))
        plt.bar(
            subset["Algorithm"],
            subset["MeanThroughputMBps"],
            yerr=subset["CI95ThroughputMBps"],
            capsize=4
        )
        plt.ylabel("Mean throughput (MB/s)")
        plt.title(f"{os_name.capitalize()} Hash Throughput 95% CI ({size_name})")
        plt.xticks(rotation=0)
        plt.tight_layout()
        plt.savefig(ci95_file, dpi=200)
        plt.close()

        print(f"[+] Saved: {throughput_file}")
        print(f"[+] Saved: {latency_file}")
        print(f"[+] Saved: {ci95_file}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--os",
        choices=["windows", "linux"],
        default=current_os_name(),
        help="OS stats to plot. Default: current operating system."
    )
    parser.add_argument(
        "--split-by-size",
        action="store_true",
        help="Also create separate charts for 1MiB and 100MiB."
    )

    args = parser.parse_args()

    os_name = args.os.lower()

    CHART_DIR.mkdir(parents=True, exist_ok=True)

    df, stats_file = load_stats(os_name)

    print(f"[+] Using stats file: {stats_file}")
    print(f"[+] Plot OS: {os_name}")

    plot_all_sizes(df, os_name)

    if args.split_by_size:
        plot_by_size(df, os_name)


if __name__ == "__main__":
    main()