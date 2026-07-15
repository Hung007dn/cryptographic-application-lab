import argparse
import glob
import math
import os
import pandas as pd

def ci95(values):
    n = len(values)
    if n <= 1:
        return 0.0
    std = values.std(ddof=1)
    return 1.96 * std / math.sqrt(n)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Folder containing benchmark CSV files")
    parser.add_argument("--out", required=True, help="Output summary CSV file")
    parser.add_argument("--os-name", required=True, help="Windows or Linux")
    args = parser.parse_args()

    files = sorted(glob.glob(os.path.join(args.input, "*.csv")))
    if not files:
        raise SystemExit(f"No CSV files found in {args.input}")

    frames = []
    for run_id, path in enumerate(files, start=1):
        df = pd.read_csv(path)
        df["run"] = run_id
        df["os"] = args.os_name
        frames.append(df)

    data = pd.concat(frames, ignore_index=True)

    print("Detected columns:")
    print(list(data.columns))

    # Expected columns from benchmark export.
    # Adjust here if your CSV header names are different.
    possible_group_cols = [
    "os",
    "Mode",
    "DataSizeBytes",
    "ModeType",
    "IsAEAD"
    ]

    group_cols = [c for c in possible_group_cols if c in data.columns]

    numeric_candidates = [
    "EncryptTimeMS",
    "DecryptTimeMS",
    "ThroughputMBps"
    ]

    metric_cols = [c for c in numeric_candidates if c in data.columns]

    if not group_cols:
        raise SystemExit("No grouping columns found. Please check CSV header.")
    if not metric_cols:
        raise SystemExit("No metric columns found. Please check CSV header.")

    summaries = []

    grouped = data.groupby(group_cols, dropna=False)

    for keys, group in grouped:
        if not isinstance(keys, tuple):
            keys = (keys,)

        base = dict(zip(group_cols, keys))
        base["runs"] = group["run"].nunique()

        for metric in metric_cols:
            values = pd.to_numeric(group[metric], errors="coerce").dropna()

            if len(values) == 0:
                continue

            row = base.copy()
            row["metric"] = metric
            row["mean"] = values.mean()
            row["median"] = values.median()
            row["stddev"] = values.std(ddof=1) if len(values) > 1 else 0.0
            row["ci95"] = ci95(values)
            row["min"] = values.min()
            row["max"] = values.max()
            summaries.append(row)

    summary_df = pd.DataFrame(summaries)
    summary_df.to_csv(args.out, index=False)

    print(f"Saved summary to {args.out}")

if __name__ == "__main__":
    main()