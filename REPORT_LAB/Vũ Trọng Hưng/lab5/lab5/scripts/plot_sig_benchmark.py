from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "results"
CHARTS_DIR = RESULTS_DIR / "charts"

STATS_FILE = RESULTS_DIR / "combined_signature_benchmark_stats.csv"

def load_stats():
    if not STATS_FILE.exists():
        raise FileNotFoundError(
            f"{STATS_FILE} not found. Run analyze_sig_benchmark_stats.py first."
        )
    return pd.read_csv(STATS_FILE)

def save_chart(path):
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"[+] Saved: {path}")

def plot_keygen_latency(df):
    data = df[df["Operation"] == "keygen"].copy()
    if data.empty:
        return

    for os_name in sorted(data["OS"].unique()):
        subset = data[data["OS"] == os_name]
        labels = subset["Algorithm"].tolist()
        values = subset["MeanTimeMS"].tolist()

        plt.figure(figsize=(10, 6))
        plt.bar(labels, values)
        plt.ylabel("Mean time (ms)")
        plt.xlabel("Algorithm")
        plt.title(f"{os_name} key generation latency")
        plt.xticks(rotation=20, ha="right")

        save_chart(CHARTS_DIR / f"{os_name.lower()}_keygen_latency.png")

def plot_sign_verify_latency(df):
    data = df[
        (df["Operation"].isin(["sign", "verify"])) &
        (df["MessageSizeBytes"] == 1024)
    ].copy()

    if data.empty:
        return

    for os_name in sorted(data["OS"].unique()):
        for operation in ["sign", "verify"]:
            subset = data[
                (data["OS"] == os_name) &
                (data["Operation"] == operation)
            ]

            if subset.empty:
                continue

            labels = subset["Algorithm"].tolist()
            values = subset["MeanTimeMS"].tolist()

            plt.figure(figsize=(10, 6))
            plt.bar(labels, values)
            plt.ylabel("Mean time (ms)")
            plt.xlabel("Algorithm")
            plt.title(f"{os_name} {operation} latency, 1 KiB message")
            plt.xticks(rotation=20, ha="right")

            save_chart(CHARTS_DIR / f"{os_name.lower()}_{operation}_latency_1kib.png")

def plot_throughput(df):
    data = df[
        (df["Operation"].isin(["sign", "verify"])) &
        (df["MessageSizeBytes"] == 1024)
    ].copy()

    if data.empty:
        return

    for os_name in sorted(data["OS"].unique()):
        for operation in ["sign", "verify"]:
            subset = data[
                (data["OS"] == os_name) &
                (data["Operation"] == operation)
            ]

            if subset.empty:
                continue

            labels = subset["Algorithm"].tolist()
            values = subset["MeanThroughputOpsPerSec"].tolist()

            plt.figure(figsize=(10, 6))
            plt.bar(labels, values)
            plt.ylabel("Mean throughput (ops/sec)")
            plt.xlabel("Algorithm")
            plt.title(f"{os_name} {operation} throughput, 1 KiB message")
            plt.xticks(rotation=20, ha="right")

            save_chart(CHARTS_DIR / f"{os_name.lower()}_{operation}_throughput_1kib.png")

def plot_message_size_impact(df):
    data = df[df["Operation"].isin(["sign", "verify"])].copy()

    if data.empty:
        return

    for os_name in sorted(data["OS"].unique()):
        for operation in ["sign", "verify"]:
            subset = data[
                (data["OS"] == os_name) &
                (data["Operation"] == operation)
            ]

            if subset.empty:
                continue

            plt.figure(figsize=(10, 6))

            for algo in sorted(subset["Algorithm"].unique()):
                algo_data = subset[subset["Algorithm"] == algo].sort_values("MessageSizeBytes")
                x = algo_data["MessageSizeBytes"] / 1024
                y = algo_data["MeanTimeMS"]
                plt.plot(x, y, marker="o", label=algo)

            plt.xlabel("Message size (KiB)")
            plt.ylabel("Mean time (ms)")
            plt.title(f"{os_name} {operation} latency vs message size")
            plt.legend()
            plt.grid(True, alpha=0.3)

            save_chart(CHARTS_DIR / f"{os_name.lower()}_{operation}_latency_vs_size.png")

def plot_os_comparison(df):
    systems = sorted(df["OS"].unique())
    if len(systems) < 2:
        print("[!] Only one OS present. Skipping OS comparison chart.")
        return

    data = df[
        (df["Operation"].isin(["sign", "verify"])) &
        (df["MessageSizeBytes"] == 1024)
    ].copy()

    for operation in ["sign", "verify"]:
        subset = data[data["Operation"] == operation]
        if subset.empty:
            continue

        pivot = subset.pivot_table(
            index="Algorithm",
            columns="OS",
            values="MeanTimeMS",
            aggfunc="first"
        )

        pivot.plot(kind="bar", figsize=(10, 6))
        plt.ylabel("Mean time (ms)")
        plt.xlabel("Algorithm")
        plt.title(f"Windows vs Linux {operation} latency, 1 KiB message")
        plt.xticks(rotation=20, ha="right")
        plt.grid(True, alpha=0.3, axis="y")

        save_chart(CHARTS_DIR / f"os_comparison_{operation}_latency_1kib.png")

def main():
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)

    df = load_stats()

    plot_keygen_latency(df)
    plot_sign_verify_latency(df)
    plot_throughput(df)
    plot_message_size_impact(df)
    plot_os_comparison(df)

    print("[+] All signature benchmark charts generated.")

if __name__ == "__main__":
    main()