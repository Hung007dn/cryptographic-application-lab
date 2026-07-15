import argparse
import os
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / "build_linux"
EXE = BUILD_DIR / "encrypt_tool"

RESULTS_DIR = ROOT / "results"
RUNS_DIR = RESULTS_DIR / "linux_runs"

RUNS_DEFAULT = 30
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
        raise RuntimeError(f"Command failed with code {result.returncode}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=RUNS_DEFAULT)
    args = parser.parse_args()

    if not EXE.exists():
        raise FileNotFoundError(f"Cannot find encrypt_tool: {EXE}")

    if not os.access(EXE, os.X_OK):
        os.chmod(EXE, 0o755)

    RUNS_DIR.mkdir(parents=True, exist_ok=True)

    raw_csv = BUILD_DIR / "performance_report.csv"

    print("=" * 70)
    print("Lab 1 Linux AES Benchmark Runner")
    print("=" * 70)
    print(f"Root:      {ROOT}")
    print(f"Build dir: {BUILD_DIR}")
    print(f"Exe:       {EXE}")
    print(f"Runs:      {args.runs}")
    print("=" * 70)

    print("\n[*] Warm-up run")
    if raw_csv.exists():
        raw_csv.unlink()

    run_cmd([str(EXE), "--compare"], BUILD_DIR)
    time.sleep(WARMUP_SECONDS)

    for i in range(1, args.runs + 1):
        print()
        print("=" * 70)
        print(f"Benchmark run {i}/{args.runs}")
        print("=" * 70)

        if raw_csv.exists():
            raw_csv.unlink()

        run_cmd([str(EXE), "--compare"], BUILD_DIR)

        if not raw_csv.exists():
            raise FileNotFoundError(f"Expected CSV not found: {raw_csv}")

        out_csv = RUNS_DIR / f"performance_report_linux_run_{i:02d}.csv"
        shutil.copy2(raw_csv, out_csv)

        print(f"[+] Saved: {out_csv}")

    print("\n[+] Linux benchmark complete.")
    print(f"[+] Results saved in: {RUNS_DIR}")

if __name__ == "__main__":
    main()