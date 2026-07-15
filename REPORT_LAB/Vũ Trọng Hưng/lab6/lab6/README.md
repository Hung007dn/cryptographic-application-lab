# Lab 6 - Post-Quantum Signatures and Certificates

## 1. Overview

This lab implements a post-quantum cryptography command-line tool named `pqtool`.

The tool demonstrates two NIST post-quantum cryptographic families:

- ML-DSA for detached digital signatures.
- ML-KEM for key encapsulation and shared-secret establishment.

The lab also includes a small JSON certificate mini-project where an ML-DSA CA key signs a subject public key.

## 2. Implemented Features

### ML-DSA signatures

Implemented algorithms:

```text
mldsa-44
mldsa-65
```

Supported operations:

```text
keygen
sign
verify
```

Supported signature encodings:

```text
raw
base64
```

### ML-KEM key encapsulation

Implemented algorithm:

```text
mlkem-512
```

Supported operations:

```text
keygen
encaps
decaps
```

### Post-quantum certificate demo

The certificate demo creates a simple JSON certificate structure:

```json
{
  "subject": "Alice",
  "public_key": "<base64 subject public key>",
  "issuer": "PQ-CA",
  "algorithm": "mldsa-44",
  "signature": "<base64 ML-DSA signature by CA>"
}
```

The certificate signature is verified using the CA public key. This demonstrates why ML-DSA is used for signing public-key structures while ML-KEM is used for key establishment, not signatures.

## 3. Folder Structure

Expected structure:

```text
Vũ Trọng Hưng/
├── nlohmann/
│   └── json.hpp
├── catch2/
│   └── catch.hpp
└── lab6/
    ├── liboqs/
    │   ├── build/          # Windows liboqs build
    │   └── build_linux/    # Linux liboqs build
    └── lab6/
        ├── CMakeLists.txt
        ├── main.cpp
        ├── PQConfig.cpp/.hpp
        ├── PQKeyManager.cpp/.hpp
        ├── MLDSAEngine.cpp/.hpp
        ├── MLKEMEngine.cpp/.hpp
        ├── PQCertificate.cpp/.hpp
        ├── PQNegativeTests.cpp/.hpp
        ├── PQBatchTools.cpp/.hpp
        ├── PQKAT.cpp/.hpp
        ├── test_vectors.json
        ├── tests/
        │   └── unit_tests.cpp
        ├── scripts/
        ├── results/
        └── bin/
            ├── windows/
            │   ├── pqtool.exe
            │   └── liboqs.dll
            └── linux/
                └── pqtool
```

## 4. Dependencies

### Required

```text
C++17 compiler
CMake >= 3.16
liboqs
nlohmann/json single-header library
Catch2 single-header library for unit tests
Python 3 for benchmark scripts
pandas and matplotlib for benchmark analysis and plotting
```

### Windows tested toolchain

```text
Windows 10/11
MSYS2 MinGW64 GCC
CMake
liboqs built with MinGW
```

### Linux tested toolchain

```text
Kali Linux / Ubuntu-compatible environment
GCC / G++
CMake
liboqs built for Linux
```

## 5. Build liboqs

### Windows

From:

```powershell
D:\Documents\DAIHOC\MMUD\Vũ Trọng Hưng\lab6\liboqs
```

run:

```powershell
Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue

cmake -S . -B build -G "MinGW Makefiles" `
  -DCMAKE_BUILD_TYPE=Release `
  -DBUILD_SHARED_LIBS=ON `
  -DOQS_BUILD_ONLY_LIB=ON

cmake --build build -j 4
```

The expected outputs include:

```text
build/include/oqs/oqs.h
build/lib/liboqs.dll.a
build/bin/liboqs.dll
```

### Linux

From:

```bash
~/Desktop/Vũ Trọng Hưng/lab6/liboqs
```

run:

```bash
rm -rf build_linux

cmake -S . -B build_linux \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_BUILD_ONLY_LIB=ON

cmake --build build_linux -j$(nproc)
```

The expected outputs include:

```text
build_linux/include/oqs/oqs.h
build_linux/lib/liboqs.so
```

## 6. Build pqtool

### Windows

From:

```powershell
D:\Documents\DAIHOC\MMUD\Vũ Trọng Hưng\lab6\lab6
```

run:

```powershell
Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue

cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release

cmake --build build -j 4
```

The CMake file automatically copies `liboqs.dll` next to `pqtool.exe` after build.

Run:

```powershell
.\build\pqtool.exe --help
```

### Linux

From:

```bash
~/Desktop/Vũ Trọng Hưng/lab6/lab6
```

run:

```bash
rm -rf build_linux

cmake -S . -B build_linux -DCMAKE_BUILD_TYPE=Release

cmake --build build_linux -j$(nproc)
```

Run:

```bash
LD_LIBRARY_PATH=../liboqs/build_linux/lib ./build_linux/pqtool --help
```

## 7. CLI Usage

### Key generation

```bash
pqtool keygen --algo mldsa-44 --pub mldsa44_pub.pem --priv mldsa44_priv.pem
pqtool keygen --algo mldsa-65 --pub mldsa65_pub.pem --priv mldsa65_priv.pem
pqtool keygen --algo mlkem-512 --pub mlkem512_pub.pem --priv mlkem512_priv.pem
```

### ML-DSA signing

```bash
pqtool sign --algo mldsa-44 --in msg.bin --priv mldsa44_priv.pem --out sig.bin --encode raw
```

### ML-DSA verification

```bash
pqtool verify --algo mldsa-44 --in msg.bin --sig sig.bin --pub mldsa44_pub.pem --encode raw
```

### ML-KEM encapsulation

```bash
pqtool encaps --algo mlkem-512 --pub mlkem512_pub.pem --ct ct.bin --ss ss_sender.bin
```

### ML-KEM decapsulation

```bash
pqtool decaps --algo mlkem-512 --priv mlkem512_priv.pem --ct ct.bin --ss ss_receiver.bin
```

The sender and receiver shared-secret files should match.

### Certificate demo

```bash
pqtool cert-demo --algo mldsa-44 --subject Alice --out cert.json
```

### Verbose mode

```bash
pqtool keygen --algo mldsa-44 --pub pub.pem --priv priv.pem --verbose
pqtool --kat test_vectors.json --verbose
```

## 8. Correctness Tests

### KAT / self-validation vector tests

```bash
pqtool --kat test_vectors.json
```

The KAT runner validates:

```text
ML-DSA-44 sign/verify and tamper rejection
ML-DSA-65 sign/verify and tamper rejection
ML-KEM-512 encapsulation/decapsulation shared-secret agreement
modified ciphertext shared-secret mismatch
wrong private key shared-secret mismatch
```

Because ML-DSA and ML-KEM are randomized and library-managed, these are self-validation KATs. They validate correctness and tamper rejection instead of comparing fixed signature or ciphertext byte strings.

### Negative tests

```bash
pqtool --negative-tests
```

Negative tests cover:

```text
modified ML-DSA message
modified ML-DSA signature
modified ML-DSA public key
wrong ML-DSA algorithm/key
modified ML-KEM ciphertext
wrong ML-KEM private key
```

For ML-KEM, tampered ciphertext or wrong private key may not throw an error. The correct validation condition is that the recovered shared secret must not match the original shared secret.

### Batch tests

```bash
pqtool --batch-verify-demo --algo mldsa-44 --count 20
pqtool --batch-decaps-bench --algo mlkem-512 --count 100
```

These commands demonstrate batch verification and batch decapsulation timing.

## 9. Unit Testing with CTest

The project uses Catch2 if the file exists at:

```text
Vũ Trọng Hưng/catch2/catch.hpp
```

and the test file exists at:

```text
Vũ Trọng Hưng/lab6/lab6/tests/unit_tests.cpp
```

### Windows

```powershell
cd D:\Documents\DAIHOC\MMUD\Vũ Trọng Hưng\lab6\lab6\build
ctest --output-on-failure -V
```

### Linux

```bash
cd ~/Desktop/Vũ Trọng Hưng/lab6/lab6/build_linux
LD_LIBRARY_PATH=../../liboqs/build_linux/lib ctest --output-on-failure -V
```

Expected result:

```text
100% tests passed
```

## 10. Benchmarking

Benchmark scripts are located in:

```text
scripts/
```

### Windows

```powershell
cd D:\Documents\DAIHOC\MMUD\Vũ Trọng Hưng\lab6\lab6

python scripts/run_windows_pq_benchmarks.py --runs 30
python scripts/analyze_pq_benchmark_stats.py
python scripts/plot_pq_benchmark.py
```

### Linux

```bash
cd ~/Desktop/Vũ Trọng Hưng/lab6/lab6

LD_LIBRARY_PATH=../liboqs/build_linux/lib python3 scripts/run_linux_pq_benchmarks.py --runs 30
python3 scripts/analyze_pq_benchmark_stats.py
python3 scripts/plot_pq_benchmark.py
```

Benchmark outputs:

```text
results/windows_runs/
results/linux_runs/
results/windows_pq_benchmark_raw.csv
results/linux_pq_benchmark_raw.csv
results/windows_pq_benchmark_stats.csv
results/linux_pq_benchmark_stats.csv
results/combined_pq_benchmark_stats.csv
results/charts/
```

Measured operations:

```text
ML-DSA keygen, sign, verify, batch_verify
ML-KEM keygen, encaps, decaps, batch_decaps
message sizes: 1 KiB, 16 KiB, 1 MiB, 8 MiB
mean, median, standard deviation, 95% confidence interval
throughput in operations per second
```

## 11. Security Notes

### Randomness

The production cryptographic operations are delegated to liboqs. The tool does not use `rand()` or `std::random` for cryptographic key generation, signing, or encapsulation.

### ML-DSA

ML-DSA signatures are much larger than ECDSA signatures. This is an expected post-quantum trade-off. ML-DSA does not have the same RFC 6979 nonce-reuse issue as ECDSA, but it still requires careful constant-time implementation and correct rejection sampling internally.

### ML-KEM

ML-KEM is a KEM, not a signature scheme. It should be used for shared-secret establishment. It should not be used to sign certificates or messages.

### Decapsulation failure handling

For ML-KEM, invalid ciphertexts should not reveal detailed internal failure information. In this lab, tampered ciphertexts are detected by verifying that the decapsulated shared secret does not match the original shared secret.

### Side-channel awareness

The report discusses timing attack surface, lattice leakage risks, constant-time NTT importance, input-dependent timing, and failure handling in decapsulation. The implementation uses liboqs for production cryptographic operations.

## 12. Known Limitations

- This lab uses liboqs for production ML-DSA and ML-KEM instead of implementing the full schemes from primitives.
- Formula-level internals such as NTT, modular reduction, and rejection sampling are discussed for educational purposes, not reimplemented as a full backend.
- The key files are raw liboqs key material saved with `.pem` filenames for CLI compatibility. They are not standard OpenSSL PEM/X.509 key objects.
- The KAT file is a self-validation test set, not a fixed-byte NIST KAT set.
- Benchmark scripts perform CLI-level benchmarking, so process startup and file I/O overhead are included.
- Linux runs require `LD_LIBRARY_PATH` unless `liboqs.so` is installed system-wide or copied into a loader-visible directory.

## 13. Submission Checklist

```text
source code
CMakeLists.txt
test_vectors.json
tests/unit_tests.cpp
scripts/
results/
bin/windows/pqtool.exe
bin/windows/liboqs.dll
bin/linux/pqtool
README.md
Lab6_Report.md
SELF_GRADE_CHECKLIST.md
ACADEMIC_HONESTY.md
```
