import csv
import os
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / "build_linux"
SIGTOOL = BUILD_DIR / "sigtool"

RESULTS_DIR = ROOT / "results"
RUNS_DIR = RESULTS_DIR / "linux_runs"
RAW_CSV = BUILD_DIR / "signature_benchmark_results.csv"

RUNS = 30
WARMUP_SECONDS = 2


def run_cmd(cmd, cwd):
    print(" ".join(str(x) for x in cmd))
    result = subprocess.run(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    print(result.stdout)

    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(str(x) for x in cmd)}")


def add_metadata_to_csv(input_csv, output_csv, run_id):
    with open(input_csv, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = ["OS", "Run"] + reader.fieldnames

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for row in rows:
            out = {"OS": "Linux", "Run": run_id}
            out.update(row)
            writer.writerow(out)


def main():
    if not SIGTOOL.exists():
        raise FileNotFoundError(f"sigtool not found: {SIGTOOL}")

    if not os.access(SIGTOOL, os.X_OK):
        os.chmod(SIGTOOL, 0o755)

    RUNS_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("Lab 5 Linux Signature Benchmark Runner")
    print("=" * 60)
    print(f"Root: {ROOT}")
    print(f"sigtool: {SIGTOOL}")
    print(f"Runs: {RUNS}")
    print(f"Warm-up: {WARMUP_SECONDS} seconds")
    print()

    print("[*] Warm-up run")
    if RAW_CSV.exists():
        RAW_CSV.unlink()

    run_cmd([str(SIGTOOL), "--benchmark"], BUILD_DIR)
    time.sleep(WARMUP_SECONDS)

    for i in range(1, RUNS + 1):
        print()
        print("=" * 60)
        print(f"Benchmark run {i}/{RUNS}")
        print("=" * 60)

        if RAW_CSV.exists():
            RAW_CSV.unlink()

        run_cmd([str(SIGTOOL), "--benchmark"], BUILD_DIR)

        if not RAW_CSV.exists():
            raise FileNotFoundError(f"Expected CSV not found: {RAW_CSV}")

        out_csv = RUNS_DIR / f"linux_signature_benchmark_run_{i:02d}.csv"
        add_metadata_to_csv(RAW_CSV, out_csv, i)
        print(f"[+] Saved: {out_csv}")

    print()
    print("[+] Linux benchmark runs complete.")


if __name__ == "__main__":
    main()

