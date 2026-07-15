#!/usr/bin/env python3
"""Create benchmark plots from performance_report.csv.
Usage: python plot_benchmarks.py performance_report.csv
"""
import csv
import sys
from collections import defaultdict
import matplotlib.pyplot as plt

csv_file = sys.argv[1] if len(sys.argv) > 1 else "performance_report.csv"
rows = []
with open(csv_file, newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        rows.append(row)

if not rows:
    raise SystemExit("No rows found in CSV")

# Accept common column names from Benchmarker exports.
def get(row, *names, default=""):
    for n in names:
        if n in row and row[n] != "":
            return row[n]
    return default

by_mode = defaultdict(list)
for r in rows:
    mode = get(r, "mode", "Mode")
    size = float(get(r, "data_size_bytes", "size_bytes", "DataSizeBytes", default="0"))
    th = float(get(r, "throughput_mbps", "throughput_MBps", "ThroughputMBps", default="0"))
    enc = float(get(r, "encrypt_time_ms", "latency_ms", "EncryptMs", default="0"))
    by_mode[mode].append((size, th, enc))

for mode, vals in by_mode.items():
    vals.sort()
    x = [v[0] for v in vals]
    y = [v[1] for v in vals]
    plt.figure()
    plt.plot(x, y, marker="o")
    plt.xscale("log")
    plt.xlabel("Payload size (bytes, log scale)")
    plt.ylabel("Throughput (MB/s)")
    plt.title(f"Throughput - {mode}")
    plt.grid(True)
    plt.savefig(f"throughput_{mode}.png", dpi=160, bbox_inches="tight")

plt.figure()
for mode, vals in by_mode.items():
    vals.sort()
    x = [v[0] for v in vals]
    y = [v[2] for v in vals]
    plt.plot(x, y, marker="o", label=mode)
plt.xscale("log")
plt.xlabel("Payload size (bytes, log scale)")
plt.ylabel("Encryption latency (ms)")
plt.title("Encryption latency by mode")
plt.grid(True)
plt.legend()
plt.savefig("latency_comparison.png", dpi=160, bbox_inches="tight")
print("Plots created: throughput_<mode>.png and latency_comparison.png")
