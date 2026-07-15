
from pathlib import Path
import math
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "results"
WINDOWS_RUNS = RESULTS_DIR / "windows_runs"
LINUX_RUNS = RESULTS_DIR / "linux_runs"

def load_runs(folder: Path) -> pd.DataFrame:
    files = sorted(folder.glob("*.csv"))
    if not files:
        return pd.DataFrame()
    return pd.concat([pd.read_csv(f) for f in files], ignore_index=True)

def ci95(std: float, n: int) -> float:
    return 0.0 if n <= 1 else 1.96 * std / math.sqrt(n)

def mode_or_first(s: pd.Series):
    m = s.mode()
    return m.iloc[0] if not m.empty else s.iloc[0]

def analyze(df: pd.DataFrame, output: Path):
    if df.empty:
        print(f"[!] no data for {output}")
        return
    group_cols = ["OS","Algorithm","Operation","MessageSizeBytes"]
    rows = []
    for keys,g in df.groupby(group_cols):
        os_name, algo, op, size = keys
        times = g["TimeMS"].astype(float)
        thr = g["ThroughputOpsPerSec"].astype(float)
        n = len(g)
        rows.append({
            "OS": os_name,
            "Algorithm": algo,
            "Operation": op,
            "MessageSizeName": mode_or_first(g["MessageSizeName"]),
            "MessageSizeBytes": size,
            "Runs": n,
            "MeanTimeMS": times.mean(),
            "MedianTimeMS": times.median(),
            "StdDevTimeMS": times.std(ddof=1) if n > 1 else 0.0,
            "CI95TimeMS": ci95(times.std(ddof=1) if n > 1 else 0.0, n),
            "MeanThroughputOpsPerSec": thr.mean(),
            "MedianThroughputOpsPerSec": thr.median(),
            "StdDevThroughputOpsPerSec": thr.std(ddof=1) if n > 1 else 0.0,
            "CI95ThroughputOpsPerSec": ci95(thr.std(ddof=1) if n > 1 else 0.0, n),
            "MeanPublicKeyBytes": g["PublicKeyBytes"].astype(float).mean(),
            "MeanPrivateKeyBytes": g["PrivateKeyBytes"].astype(float).mean(),
            "MeanSignatureBytes": g["SignatureBytes"].astype(float).mean(),
            "MeanCiphertextBytes": g["CiphertextBytes"].astype(float).mean(),
            "MeanSharedSecretBytes": g["SharedSecretBytes"].astype(float).mean(),
        })
    out = pd.DataFrame(rows).sort_values(["OS","Algorithm","Operation","MessageSizeBytes"])
    output.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(output, index=False)
    print(f"[+] saved {output}")
    print(out.head(30).to_string(index=False))

def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    win = load_runs(WINDOWS_RUNS)
    lin = load_runs(LINUX_RUNS)
    if not win.empty:
        analyze(win, RESULTS_DIR / "windows_pq_benchmark_stats.csv")
    if not lin.empty:
        analyze(lin, RESULTS_DIR / "linux_pq_benchmark_stats.csv")
    frames = [x for x in [win,lin] if not x.empty]
    if frames:
        analyze(pd.concat(frames, ignore_index=True), RESULTS_DIR / "combined_pq_benchmark_stats.csv")
    else:
        print("[!] no benchmark data found")

if __name__ == "__main__":
    main()
