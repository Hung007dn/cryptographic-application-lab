
# run_windows_benchmarks.py
# Run repeated RSA benchmark on Windows and save CSV results only.
#
# Expected project structure:
# lab2/
# ├── build/
# │   └── rsatool.exe
# ├── results/
# └── run_windows_benchmarks.py

import subprocess
import shutil
import sys
from pathlib import Path


def main():
    project_root = Path(__file__).resolve().parent.parent
    build_dir = project_root / "build"
    exe_path = build_dir / "rsatool.exe"
    out_dir = project_root / "results" / "windows_runs"

    runs = 30

    if not exe_path.exists():
        print(f"ERROR: rsatool.exe not found at: {exe_path}")
        print("Please build first:")
        print("  cmake --build build")
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
        out_csv_path = out_dir / f"windows_run_{i}.csv"

        if not csv_path.exists():
            print(f"ERROR: CSV not found after run {i}: {csv_path}")
            sys.exit(1)

        shutil.copy2(csv_path, out_csv_path)

    print()
    print("Done.")
    print(f"CSV results saved to: {out_dir}")
    print(f"Total CSV files: {len(list(out_dir.glob('windows_run_*.csv')))}")


if __name__ == "__main__":
    main()

