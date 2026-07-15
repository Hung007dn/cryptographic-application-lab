
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "results"
CHARTS_DIR = RESULTS_DIR / "charts"
STATS = RESULTS_DIR / "combined_pq_benchmark_stats.csv"

def load_stats():
    if not STATS.exists():
        raise FileNotFoundError(f"{STATS} not found. Run analyze_pq_benchmark_stats.py first.")
    return pd.read_csv(STATS)

def save(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"[+] saved {path}")

def keygen(df):
    d = df[df.Operation == "keygen"]
    for os_name in sorted(d.OS.unique()):
        s = d[d.OS == os_name]
        plt.figure(figsize=(10,6))
        plt.bar(s.Algorithm, s.MeanTimeMS)
        plt.ylabel("Mean time (ms)")
        plt.xlabel("Algorithm")
        plt.title(f"{os_name} PQ key generation latency")
        plt.xticks(rotation=20, ha="right")
        save(CHARTS_DIR / f"{os_name.lower()}_pq_keygen_latency.png")

def mldsa_latency(df, op):
    d = df[(df.Algorithm.isin(["mldsa-44","mldsa-65"])) & (df.Operation == op) & (df.MessageSizeBytes > 0)]
    for os_name in sorted(d.OS.unique()):
        s = d[d.OS == os_name]
        plt.figure(figsize=(10,6))
        for algo in sorted(s.Algorithm.unique()):
            a = s[s.Algorithm == algo].sort_values("MessageSizeBytes")
            plt.plot(a.MessageSizeBytes/1024, a.MeanTimeMS, marker="o", label=algo)
        plt.xlabel("Message size (KiB)")
        plt.ylabel("Mean time (ms)")
        plt.title(f"{os_name} ML-DSA {op} latency vs message size")
        plt.legend()
        plt.grid(True, alpha=0.3)
        save(CHARTS_DIR / f"{os_name.lower()}_mldsa_{op}_latency_vs_size.png")

def mldsa_throughput(df, op):
    d = df[(df.Algorithm.isin(["mldsa-44","mldsa-65"])) & (df.Operation == op) & (df.MessageSizeBytes == 1024)]
    for os_name in sorted(d.OS.unique()):
        s = d[d.OS == os_name]
        plt.figure(figsize=(10,6))
        plt.bar(s.Algorithm, s.MeanThroughputOpsPerSec)
        plt.ylabel("Mean throughput (ops/sec)")
        plt.xlabel("Algorithm")
        plt.title(f"{os_name} ML-DSA {op} throughput, 1 KiB")
        save(CHARTS_DIR / f"{os_name.lower()}_mldsa_{op}_throughput_1kib.png")

def kem_latency(df):
    d = df[(df.Algorithm.isin(["mlkem-512","mlkem-768","mlkem-1024"])) & (df.Operation.isin(["encaps","decaps","batch_decaps"]))]
    for os_name in sorted(d.OS.unique()):
        s = d[d.OS == os_name]
        pivot = s.pivot_table(index="Algorithm", columns="Operation", values="MeanTimeMS", aggfunc="first")
        pivot.plot(kind="bar", figsize=(10,6))
        plt.ylabel("Mean time (ms)")
        plt.xlabel("Algorithm")
        plt.title(f"{os_name} ML-KEM latency")
        plt.xticks(rotation=20, ha="right")
        plt.grid(True, alpha=0.3, axis="y")
        save(CHARTS_DIR / f"{os_name.lower()}_mlkem_latency.png")

def kem_throughput(df):
    d = df[(df.Algorithm.isin(["mlkem-512","mlkem-768","mlkem-1024"])) & (df.Operation.isin(["encaps","decaps","batch_decaps"]))]
    for os_name in sorted(d.OS.unique()):
        s = d[d.OS == os_name]
        pivot = s.pivot_table(index="Algorithm", columns="Operation", values="MeanThroughputOpsPerSec", aggfunc="first")
        pivot.plot(kind="bar", figsize=(10,6))
        plt.ylabel("Mean throughput (ops/sec)")
        plt.xlabel("Algorithm")
        plt.title(f"{os_name} ML-KEM shared-secret throughput")
        plt.xticks(rotation=20, ha="right")
        plt.grid(True, alpha=0.3, axis="y")
        save(CHARTS_DIR / f"{os_name.lower()}_mlkem_throughput.png")

def size_overhead(df):
    k = df[df.Operation=="keygen"].drop_duplicates("Algorithm")
    if not k.empty:
        x = list(range(len(k)))
        width = 0.35
        plt.figure(figsize=(10,6))
        plt.bar([i-width/2 for i in x], k.MeanPublicKeyBytes, width=width, label="Public key")
        plt.bar([i+width/2 for i in x], k.MeanPrivateKeyBytes, width=width, label="Private key")
        plt.ylabel("Mean size (bytes)")
        plt.xlabel("Algorithm")
        plt.title("PQC key size overhead")
        plt.xticks(x, k.Algorithm, rotation=20, ha="right")
        plt.legend()
        save(CHARTS_DIR / "pq_key_size_overhead.png")
    s = df[(df.Operation=="sign") & (df.MessageSizeBytes==1024) & (df.MeanSignatureBytes>0)].drop_duplicates("Algorithm")
    if not s.empty:
        plt.figure(figsize=(10,6))
        plt.bar(s.Algorithm, s.MeanSignatureBytes)
        plt.ylabel("Signature size (bytes)")
        plt.xlabel("Algorithm")
        plt.title("ML-DSA signature size overhead")
        save(CHARTS_DIR / "mldsa_signature_size_overhead.png")
    c = df[(df.Operation=="encaps") & (df.MeanCiphertextBytes>0)].drop_duplicates("Algorithm")
    if not c.empty:
        plt.figure(figsize=(10,6))
        plt.bar(c.Algorithm, c.MeanCiphertextBytes)
        plt.ylabel("Ciphertext size (bytes)")
        plt.xlabel("Algorithm")
        plt.title("ML-KEM ciphertext size overhead")
        save(CHARTS_DIR / "mlkem_ciphertext_size_overhead.png")

def os_compare(df):
    if len(df.OS.unique()) < 2:
        print("[!] only one OS present; skipping OS comparison")
        return
    for op in ["sign","verify"]:
        d = df[(df.Operation==op) & (df.MessageSizeBytes==1024) & (df.Algorithm.isin(["mldsa-44","mldsa-65"]))]
        if not d.empty:
            d.pivot_table(index="Algorithm", columns="OS", values="MeanTimeMS", aggfunc="first").plot(kind="bar", figsize=(10,6))
            plt.ylabel("Mean time (ms)")
            plt.title(f"Windows vs Linux ML-DSA {op}, 1 KiB")
            plt.xticks(rotation=20, ha="right")
            save(CHARTS_DIR / f"os_comparison_mldsa_{op}_latency_1kib.png")

def main():
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    df = load_stats()
    keygen(df)
    mldsa_latency(df,"sign")
    mldsa_latency(df,"verify")
    mldsa_throughput(df,"sign")
    mldsa_throughput(df,"verify")
    kem_latency(df)
    kem_throughput(df)
    size_overhead(df)
    os_compare(df)
    print("[+] all charts generated")

if __name__ == "__main__":
    main()
