import csv
import os
import subprocess
import time
from pathlib import Path

TOOL = Path("build_linux") / "hashtool"
RESULT_DIR = Path("results") / "linux_runs"

ALGORITHMS = ["sha256", "sha512", "sha3-256", "sha3-512"]
SIZES = [
    ("1MiB", 1 * 1024 * 1024),
    ("100MiB", 100 * 1024 * 1024),
]

RUNS = 30


def create_test_file(path: Path, size: int):
    if path.exists() and path.stat().st_size == size:
        return

    print(f"[+] Creating {path} ({size} bytes)")

    block = bytes([i % 256 for i in range(1024 * 1024)])
    remaining = size

    with open(path, "wb") as f:
        while remaining > 0:
            chunk = min(remaining, len(block))
            f.write(block[:chunk])
            remaining -= chunk


def run_hash(algo: str, input_file: Path):
    start = time.perf_counter()

    result = subprocess.run(
        [str(TOOL), "--algo", algo, "--in", str(input_file), "--stream"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    end = time.perf_counter()

    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {algo} {input_file}\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )

    digest = result.stdout.strip().splitlines()[-1].strip()
    return end - start, digest


def main():
    if not TOOL.exists():
        raise SystemExit(f"Tool not found: {TOOL}")

    RESULT_DIR.mkdir(parents=True, exist_ok=True)

    input_dir = RESULT_DIR / "inputs"
    input_dir.mkdir(exist_ok=True)

    for size_name, size_bytes in SIZES:
        input_file = input_dir / f"input_{size_name}.bin"
        create_test_file(input_file, size_bytes)

        for algo in ALGORITHMS:
            output_csv = RESULT_DIR / f"linux_{algo}_{size_name}.csv"

            print(f"\n[+] Linux benchmark: {algo} / {size_name}")

            rows = []

            print("[+] Warm-up...")
            run_hash(algo, input_file)

            for run in range(1, RUNS + 1):
                elapsed, digest = run_hash(algo, input_file)
                throughput = (size_bytes / (1024 * 1024)) / elapsed

                print(f"Run {run:02d}: {elapsed:.6f}s, {throughput:.2f} MB/s")

                rows.append({
                    "OS": "Linux",
                    "Algorithm": algo,
                    "SizeName": size_name,
                    "FileSizeBytes": size_bytes,
                    "Run": run,
                    "TimeSeconds": elapsed,
                    "ThroughputMBps": throughput,
                    "Mode": "streaming",
                    "Digest": digest
                })

            with open(output_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)

            print(f"[+] Saved: {output_csv}")


if __name__ == "__main__":
    main()