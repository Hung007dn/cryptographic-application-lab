import csv
import math
import statistics
from pathlib import Path

RESULTS_DIR = Path("results")

INPUT_DIRS = [
    RESULTS_DIR / "windows_runs",
    RESULTS_DIR / "linux_runs",
]


def mean(values):
    return statistics.mean(values)


def median(values):
    return statistics.median(values)


def stddev(values):
    if len(values) < 2:
        return 0.0
    return statistics.stdev(values)


def ci95(values):
    if len(values) < 2:
        return 0.0
    return 1.96 * stddev(values) / math.sqrt(len(values))


def read_rows(csv_path):
    with open(csv_path, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_stats(os_name, rows):
    grouped = {}

    for row in rows:
        key = (
            row["OS"],
            row["Algorithm"],
            row["SizeName"],
            row["FileSizeBytes"],
            row["Mode"]
        )
        grouped.setdefault(key, []).append(row)

    stats_rows = []

    for key, group in grouped.items():
        os_value, algo, size_name, size_bytes, mode = key

        times = [float(r["TimeSeconds"]) for r in group]
        throughputs = [float(r["ThroughputMBps"]) for r in group]

        stats_rows.append({
            "OS": os_value,
            "Algorithm": algo,
            "SizeName": size_name,
            "FileSizeBytes": size_bytes,
            "Mode": mode,
            "Runs": len(group),

            "MeanTimeSeconds": mean(times),
            "MedianTimeSeconds": median(times),
            "StdDevTimeSeconds": stddev(times),
            "CI95TimeSeconds": ci95(times),

            "MeanThroughputMBps": mean(throughputs),
            "MedianThroughputMBps": median(throughputs),
            "StdDevThroughputMBps": stddev(throughputs),
            "CI95ThroughputMBps": ci95(throughputs)
        })

    output = RESULTS_DIR / f"{os_name.lower()}_hash_benchmark_stats.csv"

    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=stats_rows[0].keys())
        writer.writeheader()
        writer.writerows(stats_rows)

    print(f"[+] Saved: {output}")


def main():
    for input_dir in INPUT_DIRS:
        if not input_dir.exists():
            print(f"[WARN] Missing directory: {input_dir}")
            continue

        all_rows = []

        for csv_file in input_dir.glob("*.csv"):
            if csv_file.name.startswith("windows_") or csv_file.name.startswith("linux_"):
                all_rows.extend(read_rows(csv_file))

        if not all_rows:
            print(f"[WARN] No CSV rows found in {input_dir}")
            continue

        os_name = all_rows[0]["OS"]
        write_stats(os_name, all_rows)


if __name__ == "__main__":
    main()