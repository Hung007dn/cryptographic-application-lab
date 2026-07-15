
from __future__ import annotations
import argparse, csv, os, re, shutil, subprocess, time
from pathlib import Path

SIGNATURE_ALGOS = ["mldsa-44", "mldsa-65"]
KEM_ALGOS = ["mlkem-512"]
MESSAGE_SIZES = [("1 KiB",1024),("16 KiB",16384),("1 MiB",1048576),("8 MiB",8388608)]
DEFAULT_RUNS = 30
BATCH_COUNT = 1000

def find_pqtool(root: Path, os_name: str) -> Path:
    candidates = []
    if os_name.lower() == "windows":
        candidates = [root/"build"/"pqtool.exe", root/"build_windows"/"pqtool.exe", root/"bin"/"windows"/"pqtool.exe"]
    else:
        candidates = [root/"build_linux"/"pqtool", root/"build"/"pqtool", root/"bin"/"linux"/"pqtool"]
    for p in candidates:
        if p.exists(): return p
    raise FileNotFoundError("pqtool not found. Tried:\n" + "\n".join(map(str,candidates)))

def copy_liboqs_dll(root: Path, pqtool: Path):
    if os.name != "nt": return
    target = pqtool.parent / "liboqs.dll"
    if target.exists(): return
    libroot = root.parent / "liboqs" / "build"
    if libroot.exists():
        dlls = list(libroot.rglob("liboqs.dll"))
        if dlls:
            shutil.copy2(dlls[0], target)
            print(f"[+] copied {dlls[0]} -> {target}")

def run_cmd(cmd, cwd, check=True):
    r = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if check and r.returncode != 0:
        print(r.stdout)
        raise RuntimeError("Command failed: " + " ".join(map(str,cmd)))
    return r

def timed(cmd, cwd, check=True):
    t0 = time.perf_counter()
    r = run_cmd(cmd, cwd, check)
    return (time.perf_counter()-t0)*1000.0, r

def write_msg(path: Path, n: int):
    block = bytes((i % 251 for i in range(4096)))
    with open(path, "wb") as f:
        left = n
        while left:
            b = block[:min(left, len(block))]
            f.write(b)
            left -= len(b)

def size(p: Path) -> int:
    return p.stat().st_size if p.exists() else 0

def thr(ms: float) -> float:
    return 0.0 if ms <= 0 else 1000.0 / ms

def parse_thr(text: str):
    m = re.search(r"Throughput:\s*([0-9.]+)", text)
    return float(m.group(1)) if m else None

def row(os_name, run, algo, op, msg_name, msg_bytes, ms, pub=0, priv=0, sig=0, ct=0, ss=0, notes="", throughput=None):
    return {
        "OS": os_name, "Run": run, "Algorithm": algo, "Operation": op,
        "MessageSizeName": msg_name, "MessageSizeBytes": msg_bytes,
        "TimeMS": ms, "ThroughputOpsPerSec": thr(ms) if throughput is None else throughput,
        "PublicKeyBytes": pub, "PrivateKeyBytes": priv, "SignatureBytes": sig,
        "CiphertextBytes": ct, "SharedSecretBytes": ss, "Notes": notes,
    }

def write_csv(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["OS","Run","Algorithm","Operation","MessageSizeName","MessageSizeBytes","TimeMS",
              "ThroughputOpsPerSec","PublicKeyBytes","PrivateKeyBytes","SignatureBytes",
              "CiphertextBytes","SharedSecretBytes","Notes"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

def bench_one(os_name: str, root: Path, pqtool: Path, run_id: int, warmup=False):
    temp = root/"build"/"pq_bench_temp"/("warmup" if warmup else f"run_{run_id:02d}")
    if temp.exists(): shutil.rmtree(temp)
    temp.mkdir(parents=True, exist_ok=True)
    rows = []
    messages = {}
    for name,n in MESSAGE_SIZES:
        p = temp / f"msg_{n}.bin"
        write_msg(p,n); messages[name]=p

    for algo in SIGNATURE_ALGOS:
        pub, priv = temp/f"{algo}_pub.pem", temp/f"{algo}_priv.pem"
        ms,_ = timed([str(pqtool),"keygen","--algo",algo,"--pub",str(pub),"--priv",str(priv)], root)
        if not warmup: rows.append(row(os_name,run_id,algo,"keygen","N/A",0,ms,size(pub),size(priv)))

        for msg_name,msg_path in messages.items():
            sig = temp / f"{algo}_{size(msg_path)}.sig"
            ms,_ = timed([str(pqtool),"sign","--algo",algo,"--in",str(msg_path),"--priv",str(priv),"--out",str(sig),"--encode","raw"], root)
            if not warmup: rows.append(row(os_name,run_id,algo,"sign",msg_name,size(msg_path),ms,size(pub),size(priv),size(sig)))
            ms,_ = timed([str(pqtool),"verify","--algo",algo,"--in",str(msg_path),"--sig",str(sig),"--pub",str(pub),"--encode","raw"], root)
            if not warmup: rows.append(row(os_name,run_id,algo,"verify",msg_name,size(msg_path),ms,size(pub),size(priv),size(sig)))

        ms,r = timed([str(pqtool),"--batch-verify-demo","--algo",algo,"--count",str(BATCH_COUNT)], root)
        if not warmup: rows.append(row(os_name,run_id,algo,"batch_verify","N/A",0,ms,notes=f"batch_count={BATCH_COUNT}",throughput=BATCH_COUNT * 1000.0 / ms))

    for algo in KEM_ALGOS:
        pub, priv = temp/f"{algo}_pub.pem", temp/f"{algo}_priv.pem"
        ct, ss1, ss2 = temp/f"{algo}_ct.bin", temp/f"{algo}_ss1.bin", temp/f"{algo}_ss2.bin"
        ms,_ = timed([str(pqtool),"keygen","--algo",algo,"--pub",str(pub),"--priv",str(priv)], root)
        if not warmup: rows.append(row(os_name,run_id,algo,"keygen","N/A",0,ms,size(pub),size(priv)))
        ms,_ = timed([str(pqtool),"encaps","--algo",algo,"--pub",str(pub),"--ct",str(ct),"--ss",str(ss1)], root)
        if not warmup: rows.append(row(os_name,run_id,algo,"encaps","N/A",0,ms,size(pub),size(priv),ct=size(ct),ss=size(ss1)))
        ms,_ = timed([str(pqtool),"decaps","--algo",algo,"--priv",str(priv),"--ct",str(ct),"--ss",str(ss2)], root)
        ok = ss1.exists() and ss2.exists() and ss1.read_bytes()==ss2.read_bytes()
        if not warmup: rows.append(row(os_name,run_id,algo,"decaps","N/A",0,ms,size(pub),size(priv),ct=size(ct),ss=size(ss2),notes=f"shared_secret_match={ok}"))
        ms,r = timed([str(pqtool),"--batch-decaps-bench","--algo",algo,"--count",str(BATCH_COUNT)], root)
        if not warmup: rows.append(row(os_name,run_id,algo,"batch_decaps","N/A",0,ms,notes=f"batch_count={BATCH_COUNT}",throughput=BATCH_COUNT * 1000.0 / ms))
    return rows

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--os", choices=["Windows","Linux"], required=True)
    ap.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = ap.parse_args()
    root = Path(str(args.root))
    pqtool = find_pqtool(root,args.os)
    copy_liboqs_dll(root,pqtool)
    if os.name != "nt":
        try: pqtool.chmod(0o755)
        except OSError: pass
    runs_dir = root/"results"/("windows_runs" if args.os=="Windows" else "linux_runs")
    runs_dir.mkdir(parents=True, exist_ok=True)
    print("="*70); print(f"Lab 6 PQ benchmark runner ({args.os})"); print(f"Root: {root}"); print(f"pqtool: {pqtool}"); print(f"Runs: {args.runs}")
    print("[*] warm-up")
    bench_one(args.os,root,pqtool,0,True)
    time.sleep(2.0)
    all_rows=[]
    for i in range(1,args.runs+1):
        print(f"\nRun {i}/{args.runs}")
        rows = bench_one(args.os,root,pqtool,i,False)
        all_rows += rows
        out = runs_dir / f"{args.os.lower()}_pq_benchmark_run_{i:02d}.csv"
        write_csv(out, rows); print(f"[+] saved {out}")
    raw = root/"results"/f"{args.os.lower()}_pq_benchmark_raw.csv"
    write_csv(raw, all_rows); print(f"[+] saved {raw}")

if __name__ == "__main__":
    main()
