from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt

RESULTS_DIR = Path("results")
CHART_DIR = RESULTS_DIR / "charts"

WINDOWS_STATS = RESULTS_DIR / "windows_hash_benchmark_stats.csv"
LINUX_STATS = RESULTS_DIR / "linux_hash_benchmark_stats.csv"


def main():
    if not WINDOWS_STATS.exists() or not LINUX_STATS.exists():
        raise SystemExit("Missing Windows or Linux stats CSV.")

    CHART_DIR.mkdir(parents=True, exist_ok=True)

    win = pd.read_csv(WINDOWS_STATS)
    lin = pd.read_csv(LINUX_STATS)

    df = pd.concat([win, lin], ignore_index=True)

    for size_name in sorted(df["SizeName"].unique()):
        subset = df[df["SizeName"] == size_name]

        pivot = subset.pivot(
            index="Algorithm",
            columns="OS",
            values="MeanThroughputMBps"
        )

        pivot.plot(kind="bar", figsize=(10, 6))
        plt.ylabel("Mean throughput (MB/s)")
        plt.title(f"Windows vs Linux Throughput ({size_name})")
        plt.xticks(rotation=0)
        plt.tight_layout()

        output = CHART_DIR / f"os_comparison_{size_name}.png"
        plt.savefig(output, dpi=200)
        plt.close()

        print(f"[+] Saved: {output}")


if __name__ == "__main__":
    main()