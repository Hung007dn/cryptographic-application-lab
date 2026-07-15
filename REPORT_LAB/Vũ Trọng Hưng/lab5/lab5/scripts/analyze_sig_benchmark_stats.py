import math
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "results"
WINDOWS_RUNS = RESULTS_DIR / "windows_runs"
LINUX_RUNS = RESULTS_DIR / "linux_runs"

def load_runs(folder: Path):
    files = sorted(folder.glob("*.csv"))
    if not files:
        return pd.DataFrame()

    frames = []
    for file in files:
        df = pd.read_csv(file)
        frames.append(df)

    return pd.concat(frames, ignore_index=True)

def ci95(std, n):
    if n <= 1:
        return 0.0
    return 1.96 * std / math.sqrt(n)

def analyze(df: pd.DataFrame, output_file: Path):
    if df.empty:
        print(f"[!] No data for {output_file}")
        return

    required = [
        "OS",
        "Algorithm",
        "Operation",
        "MessageSizeBytes",
        "TimeMS",
        "ThroughputOpsPerSec"
    ]

    for col in required:
        if col not in df.columns:
            raise ValueError(f"Missing required column: {col}")

    group_cols = ["OS", "Algorithm", "Operation", "MessageSizeBytes"]

    rows = []

    for keys, group in df.groupby(group_cols):
        os_name, algo, operation, size_bytes = keys

        times = group["TimeMS"].astype(float)
        throughput = group["ThroughputOpsPerSec"].astype(float)

        n = len(group)

        time_mean = times.mean()
        time_median = times.median()
        time_std = times.std(ddof=1) if n > 1 else 0.0
        time_ci95 = ci95(time_std, n)

        thr_mean = throughput.mean()
        thr_median = throughput.median()
        thr_std = throughput.std(ddof=1) if n > 1 else 0.0
        thr_ci95 = ci95(thr_std, n)

        rows.append({
            "OS": os_name,
            "Algorithm": algo,
            "Operation": operation,
            "MessageSizeBytes": size_bytes,
            "Runs": n,
            "MeanTimeMS": time_mean,
            "MedianTimeMS": time_median,
            "StdDevTimeMS": time_std,
            "CI95TimeMS": time_ci95,
            "MeanThroughputOpsPerSec": thr_mean,
            "MedianThroughputOpsPerSec": thr_median,
            "StdDevThroughputOpsPerSec": thr_std,
            "CI95ThroughputOpsPerSec": thr_ci95
        })

    out = pd.DataFrame(rows)
    out = out.sort_values(["OS", "Algorithm", "Operation", "MessageSizeBytes"])
    out.to_csv(output_file, index=False)

    print(f"[+] Saved stats: {output_file}")
    print(out.head(20).to_string(index=False))

def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    windows_df = load_runs(WINDOWS_RUNS)
    linux_df = load_runs(LINUX_RUNS)

    if not windows_df.empty:
        analyze(windows_df, RESULTS_DIR / "windows_signature_benchmark_stats.csv")

    if not linux_df.empty:
        analyze(linux_df, RESULTS_DIR / "linux_signature_benchmark_stats.csv")

    combined = pd.concat(
        [df for df in [windows_df, linux_df] if not df.empty],
        ignore_index=True
    ) if (not windows_df.empty or not linux_df.empty) else pd.DataFrame()

    if not combined.empty:
        analyze(combined, RESULTS_DIR / "combined_signature_benchmark_stats.csv")

if __name__ == "__main__":
    main()