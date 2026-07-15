# scripts/run_linux_benchmarks.py
# Run repeated RSA benchmark on Linux and save CSV results only.

import subprocess
import shutil
import sys
from pathlib import Path


def main():
    project_root = Path(__file__).resolve().parent.parent
    build_dir = project_root / "build_linux"
    exe_path = build_dir / "rsatool"
    out_dir = project_root / "results" / "linux_runs"

    runs = 30

    if not exe_path.exists():
        print(f"ERROR: rsatool not found at: {exe_path}")
        print("Please build first:")
        print("  cmake -S . -B build_linux")
        print("  cmake --build build_linux -j$(nproc)")
        sys.exit(1)

    out_dir.mkdir(parents=True, exist_ok=True)

    print("Warm-up run...")
    subprocess.run(
        [str(exe_path), "--benchmark"],
        cwd=build_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True
    )

    for i in range(1, runs + 1):
        print(f"Running benchmark {i}/{runs}...")

        result = subprocess.run(
            [str(exe_path), "--benchmark"],
            cwd=build_dir,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )

        if result.returncode != 0:
            print(f"ERROR: benchmark run {i} failed")
            print(result.stdout)
            sys.exit(1)

        csv_path = build_dir / "rsa_benchmark_results.csv"
        out_csv_path = out_dir / f"linux_run_{i}.csv"

        if not csv_path.exists():
            print(f"ERROR: CSV not found after run {i}: {csv_path}")
            sys.exit(1)

        shutil.copy2(csv_path, out_csv_path)

    print()
    print("Done.")
    print(f"CSV results saved to: {out_dir}")
    print(f"Total CSV files: {len(list(out_dir.glob('linux_run_*.csv')))}")


if __name__ == "__main__":
    main()