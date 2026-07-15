import argparse
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt


def size_label(bytes_value: int) -> str:
    if bytes_value == 1024:
        return "1 KB"
    if bytes_value == 4 * 1024:
        return "4 KB"
    if bytes_value == 16 * 1024:
        return "16 KB"
    if bytes_value == 256 * 1024:
        return "256 KB"
    if bytes_value == 1024 * 1024:
        return "1 MB"
    if bytes_value == 8 * 1024 * 1024:
        return "8 MB"
    return str(bytes_value)


def load_summary(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)

    # Hỗ trợ cả header kiểu lowercase và uppercase
    rename_map = {
        "os": "OS",
        "metric": "Metric",
        "mean": "Mean",
        "median": "Median",
        "stddev": "StdDev",
        "ci95": "CI95",
        "runs": "Runs",
    }
    df = df.rename(columns=rename_map)

    required = ["OS", "Mode", "DataSizeBytes", "ModeType", "IsAEAD", "Runs", "Metric", "Mean", "Median", "StdDev", "CI95"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"CSV thiếu cột: {missing}")

    df["SizeLabel"] = df["DataSizeBytes"].apply(lambda x: size_label(int(x)))
    return df


def plot_8mb_throughput(df: pd.DataFrame, out_dir: Path, os_name: str) -> None:
    data = df[
        (df["Metric"] == "ThroughputMBps")
        & (df["DataSizeBytes"] == 8 * 1024 * 1024)
    ].copy()

    data = data.sort_values("Mean", ascending=False)

    plt.figure(figsize=(9, 5))
    plt.bar(data["Mode"], data["Mean"])
    plt.errorbar(data["Mode"], data["Mean"], yerr=data["CI95"], fmt="none", capsize=5)
    plt.title(f"{os_name}: 8 MB Throughput by AES Mode")
    plt.xlabel("AES Mode")
    plt.ylabel("Mean Throughput (MB/s)")
    plt.xticks(rotation=20)
    plt.tight_layout()

    output = out_dir / f"{os_name.lower()}_8mb_throughput_by_mode.png"
    plt.savefig(output, dpi=180)
    plt.close()
    print(f"Saved: {output}")


def plot_all_throughput_by_size(df: pd.DataFrame, out_dir: Path, os_name: str) -> None:
    data = df[df["Metric"] == "ThroughputMBps"].copy()
    order = [1024, 4096, 16384, 262144, 1048576, 8388608]

    plt.figure(figsize=(10, 5))

    for mode in sorted(data["Mode"].unique()):
        mode_df = data[data["Mode"] == mode].copy()
        mode_df["order"] = mode_df["DataSizeBytes"].apply(lambda x: order.index(int(x)) if int(x) in order else 999)
        mode_df = mode_df.sort_values("order")
        plt.plot(mode_df["SizeLabel"], mode_df["Mean"], marker="o", label=mode)

    plt.title(f"{os_name}: Throughput by Payload Size")
    plt.xlabel("Payload Size")
    plt.ylabel("Mean Throughput (MB/s)")
    plt.legend()
    plt.tight_layout()

    output = out_dir / f"{os_name.lower()}_throughput_by_size.png"
    plt.savefig(output, dpi=180)
    plt.close()
    print(f"Saved: {output}")


def plot_stream_vs_block(df: pd.DataFrame, out_dir: Path, os_name: str) -> None:
    data = df[
        (df["Metric"].isin(["EncryptTimeMS", "DecryptTimeMS"]))
        & (df["Mode"].isin(["AES-256-CTR", "AES-256-CBC"]))
    ].copy()

    pivot = data.pivot_table(
        index=["DataSizeBytes", "SizeLabel", "Mode"],
        columns="Metric",
        values="Mean",
        aggfunc="mean"
    ).reset_index()

    pivot["TotalLatencyMS"] = pivot["EncryptTimeMS"] + pivot["DecryptTimeMS"]
    pivot["Group"] = pivot["Mode"].replace({
        "AES-256-CTR": "Stream-like mode, CTR",
        "AES-256-CBC": "Block mode, CBC",
    })

    order = [1024, 4096, 16384, 262144, 1048576, 8388608]

    plt.figure(figsize=(10, 5))

    for group in ["Stream-like mode, CTR", "Block mode, CBC"]:
        g = pivot[pivot["Group"] == group].copy()
        g["order"] = g["DataSizeBytes"].apply(lambda x: order.index(int(x)) if int(x) in order else 999)
        g = g.sort_values("order")
        plt.plot(g["SizeLabel"], g["TotalLatencyMS"], marker="o", label=group)

    plt.title(f"{os_name}: Stream vs Block Total Latency")
    plt.xlabel("Payload Size")
    plt.ylabel("Mean Encrypt + Decrypt Latency (ms)")
    plt.legend()
    plt.tight_layout()

    output = out_dir / f"{os_name.lower()}_stream_vs_block_latency.png"
    plt.savefig(output, dpi=180)
    plt.close()
    print(f"Saved: {output}")


def plot_aead_vs_nonaead(df: pd.DataFrame, out_dir: Path, os_name: str) -> None:
    data = df[
        (df["Metric"].isin(["EncryptTimeMS", "DecryptTimeMS"]))
        & (df["Mode"].isin(["AES-256-GCM", "AES-256-CBC"]))
    ].copy()

    pivot = data.pivot_table(
        index=["DataSizeBytes", "SizeLabel", "Mode"],
        columns="Metric",
        values="Mean",
        aggfunc="mean"
    ).reset_index()

    pivot["TotalLatencyMS"] = pivot["EncryptTimeMS"] + pivot["DecryptTimeMS"]
    pivot["Group"] = pivot["Mode"].replace({
        "AES-256-GCM": "AEAD mode, GCM",
        "AES-256-CBC": "Non-AEAD mode, CBC",
    })

    order = [1024, 4096, 16384, 262144, 1048576, 8388608]

    plt.figure(figsize=(10, 5))

    for group in ["AEAD mode, GCM", "Non-AEAD mode, CBC"]:
        g = pivot[pivot["Group"] == group].copy()
        g["order"] = g["DataSizeBytes"].apply(lambda x: order.index(int(x)) if int(x) in order else 999)
        g = g.sort_values("order")
        plt.plot(g["SizeLabel"], g["TotalLatencyMS"], marker="o", label=group)

    plt.title(f"{os_name}: AEAD vs Non-AEAD Total Latency")
    plt.xlabel("Payload Size")
    plt.ylabel("Mean Encrypt + Decrypt Latency (ms)")
    plt.legend()
    plt.tight_layout()

    output = out_dir / f"{os_name.lower()}_aead_vs_nonaead_latency.png"
    plt.savefig(output, dpi=180)
    plt.close()
    print(f"Saved: {output}")


def plot_gcm_vs_ccm(df: pd.DataFrame, out_dir: Path, os_name: str) -> None:
    data = df[
        (df["Metric"].isin(["EncryptTimeMS", "DecryptTimeMS"]))
        & (df["Mode"].isin(["AES-256-GCM", "AES-256-CCM"]))
    ].copy()

    pivot = data.pivot_table(
        index=["DataSizeBytes", "SizeLabel", "Mode"],
        columns="Metric",
        values="Mean",
        aggfunc="mean"
    ).reset_index()

    pivot["TotalLatencyMS"] = pivot["EncryptTimeMS"] + pivot["DecryptTimeMS"]

    order = [1024, 4096, 16384, 262144, 1048576, 8388608]

    plt.figure(figsize=(10, 5))

    for mode in ["AES-256-GCM", "AES-256-CCM"]:
        g = pivot[pivot["Mode"] == mode].copy()
        g["order"] = g["DataSizeBytes"].apply(lambda x: order.index(int(x)) if int(x) in order else 999)
        g = g.sort_values("order")
        plt.plot(g["SizeLabel"], g["TotalLatencyMS"], marker="o", label=mode)

    plt.title(f"{os_name}: GCM vs CCM Total Latency")
    plt.xlabel("Payload Size")
    plt.ylabel("Mean Encrypt + Decrypt Latency (ms)")
    plt.legend()
    plt.tight_layout()

    output = out_dir / f"{os_name.lower()}_gcm_vs_ccm_latency.png"
    plt.savefig(output, dpi=180)
    plt.close()
    print(f"Saved: {output}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="benchmark stats CSV, e.g. results/linux_benchmark_stats.csv")
    parser.add_argument("--out-dir", default="results/charts", help="output chart directory")
    parser.add_argument("--os-name", required=True, help="Windows or Linux")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = load_summary(args.input)

    plot_8mb_throughput(df, out_dir, args.os_name)
    plot_all_throughput_by_size(df, out_dir, args.os_name)
    plot_stream_vs_block(df, out_dir, args.os_name)
    plot_aead_vs_nonaead(df, out_dir, args.os_name)
    plot_gcm_vs_ccm(df, out_dir, args.os_name)

    print("\nDone. Charts are in:", out_dir)


if __name__ == "__main__":
    main()