# Lab 5 — Classical Digital Signatures (`sigtool`)

**Course:** Cryptography & Applications  
**Lab:** Lab 5 — Classical Digital Signatures  
**Tool name:** `sigtool`  
**Language:** C++17  
**Build system:** CMake  
**Production crypto backend:** OpenSSL EVP  
**Educational crypto components:** Crypto++ + manual RSA-PSS / modular arithmetic modules  
**Target platforms:** Windows 10/11 and Linux  

---

## 1. Overview

This lab implements a command-line tool for classical digital signatures. The tool supports key generation, signing, verification, correctness testing, negative testing, unit testing, batch verification demonstration, and performance benchmarking.

The implementation is designed to satisfy the common requirements for the Cryptography & Applications lab series:

- C++17 implementation.
- CMake-based build system.
- Out-of-source builds.
- Windows and Linux support.
- Safe key generation and key validation.
- Fail-closed behavior for malformed input and invalid signatures.
- KAT/self-validation tests.
- Negative tests.
- Catch2 unit tests.
- Benchmarking with repeated runs, statistics, and plots.
- Security discussion covering nonce risks, RSA-PSS padding, side channels, timing behavior, and implementation limitations.

The production signing and verification paths use OpenSSL EVP. Manual RSA-PSS and modular arithmetic components are included for educational analysis and advanced-topic discussion, not as the production cryptographic backend.

---

## 2. Supported Algorithms

| Algorithm | Key size / curve | Hash | Signature formats | Notes |
|---|---:|---|---|---|
| `ecdsa-p256` | NIST P-256 / `prime256v1` | SHA-256 | DER, raw, base64 | Compact EC signature |
| `ecdsa-p384` | NIST P-384 / `secp384r1` | SHA-384 | DER, raw, base64 | Higher-security EC signature |
| `rsa-pss-3072` | 3072-bit RSA | SHA-256 | raw, base64 | RSA-PSS with PSS padding |

Expected raw signature sizes:

| Algorithm | Raw signature size |
|---|---:|
| `ecdsa-p256` | 64 bytes |
| `ecdsa-p384` | 96 bytes |
| `rsa-pss-3072` | 384 bytes |

ECDSA DER signatures are variable-length because DER encodes the two integers `r` and `s`. Raw ECDSA signatures use fixed `r || s` format. RSA-PSS signatures have fixed size equal to the RSA modulus size.

---

## 3. Expected Submission Structure

The expected structure for this lab is:

```text
Vũ Trọng Hưng/
├── openssl/
├── cryptopp/
├── nlohmann/
├── catch2/
├── lab5/
│   ├── README.md
│   ├── Lab5_Report.md
│   ├── ACADEMIC_HONESTY.md
│   ├── SELF_GRADE_CHECKLIST.md
│   └── lab5/
│       ├── CMakeLists.txt
│       ├── main.cpp
│       ├── SigConfig.cpp / SigConfig.hpp
│       ├── SigKeyManager.cpp / SigKeyManager.hpp
│       ├── ECDSAEngine.cpp / ECDSAEngine.hpp
│       ├── RSAPSSEngine.cpp / RSAPSSEngine.hpp
│       ├── ManualRSAPSS.cpp / ManualRSAPSS.hpp
│       ├── ModularArithmetic.cpp / ModularArithmetic.hpp
│       ├── NegativeTests.cpp / NegativeTests.hpp
│       ├── BatchVerifier.cpp / BatchVerifier.hpp
│       ├── SigBenchmarker.cpp / SigBenchmarker.hpp
│       ├── SigKAT.cpp / SigKAT.hpp
│       ├── test_vectors.json
│       ├── tests/
│       │   └── unit_tests.cpp
│       ├── scripts/
│       ├── results/
│       ├── build/
│       ├── build_linux/
│       └── bin/
│           ├── windows/sigtool.exe
│           └── linux/sigtool
```

Important path assumptions used by `CMakeLists.txt`:

- Source location: `Vũ Trọng Hưng/lab5/lab5`
- Bundle root: `Vũ Trọng Hưng`
- Expected bundled `nlohmann`: `Vũ Trọng Hưng/nlohmann/json.hpp`
- Expected bundled Crypto++: `Vũ Trọng Hưng/cryptopp/`
- Expected bundled Catch2: `Vũ Trọng Hưng/catch2/catch.hpp`
- Windows OpenSSL bundle: `Vũ Trọng Hưng/openssl/`

---

## 4. Dependencies

### 4.1 Required Tools

| Tool | Purpose |
|---|---|
| CMake 3.16+ | Build configuration |
| C++17 compiler | Compile the C++ source code |
| OpenSSL | Production ECDSA and RSA-PSS implementation |
| Crypto++ | Educational manual RSA-PSS and modular arithmetic support |
| nlohmann/json | JSON parsing for KAT vectors and metadata |
| Catch2 | Unit testing |
| Python 3 | Benchmark automation and plotting scripts |

### 4.2 Linux Packages

On Ubuntu/Debian-like systems:

```bash
sudo apt update
sudo apt install -y build-essential cmake libssl-dev python3 python3-pip
python3 -m pip install pandas matplotlib numpy
```

If optional legacy plotting scripts are used, install seaborn as well:

```bash
python3 -m pip install seaborn
```

### 4.3 Windows Notes

The submitted Windows build is intended for MinGW64 with bundled libraries. The package includes bundled OpenSSL, Crypto++, nlohmann-json, and Catch2 folders.

Recommended Windows tools:

- CMake
- MinGW64 / MSYS2 toolchain
- Python 3 for benchmark scripts

If building with MSVC, the dependencies must be rebuilt or provided in MSVC-compatible `.lib` format. The bundled `.a` libraries are primarily intended for MinGW64.

---

## 5. Build Instructions

### 5.1 Build on Linux

From the source directory:

```bash
cd Vũ Trọng Hưng/lab5/lab5
cmake -S . -B build_linux -DCMAKE_BUILD_TYPE=Release
cmake --build build_linux
```

Run the built executable:

```bash
./build_linux/sigtool --help
```

Or run the bundled binary:

```bash
./bin/linux/sigtool --help
```

If the bundled Linux binary does not have execute permission:

```bash
chmod +x ./bin/linux/sigtool
```

### 5.2 Build on Windows with MinGW64

From PowerShell or a MinGW64 terminal:

```powershell
cd Vũ Trọng Hưng\lab5\lab5
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Run the built executable:

```powershell
.\build\sigtool.exe --help
```

Or run the bundled binary:

```powershell
.\bin\windows\sigtool.exe --help
```

---

## 6. Command-Line Usage

General form:

```bash
sigtool <command> [options]
```

Supported commands:

```text
keygen
sign
verify
--kat
--negative-tests
--benchmark
--batch-demo
--manual-pss-demo
--help
```

Supported algorithms:

```text
ecdsa-p256
ecdsa-p384
rsa-pss-3072
```

Supported hash functions:

```text
sha256
sha384
```

Supported signature encodings:

```text
raw
der
base64
```

Note: PEM is used for key files. Ordinary signature files should use `raw`, `der`, or `base64`.

---

## 7. Basic Examples

Create a test message:

Linux:

```bash
printf "Lab 5 digital signature test message" > msg.txt
```

Windows PowerShell:

```powershell
"Lab 5 digital signature test message" | Out-File -Encoding utf8 msg.txt
```

### 7.1 ECDSA-P256 Example

Generate a P-256 key pair:

```bash
sigtool keygen --algo ecdsa-p256 --pub p256_pub.pem --priv p256_priv.pem
```

Sign using SHA-256 and DER encoding:

```bash
sigtool sign --algo ecdsa-p256 --in msg.txt --priv p256_priv.pem --out p256_sig.der --hash sha256 --encode der
```

Verify:

```bash
sigtool verify --algo ecdsa-p256 --in msg.txt --sig p256_sig.der --pub p256_pub.pem --hash sha256 --encode der
```

Expected successful output:

```text
[OK] Signature verification PASSED
```

### 7.2 ECDSA-P384 Example

Generate a P-384 key pair:

```bash
sigtool keygen --algo ecdsa-p384 --pub p384_pub.pem --priv p384_priv.pem
```

Sign using SHA-384:

```bash
sigtool sign --algo ecdsa-p384 --in msg.txt --priv p384_priv.pem --out p384_sig.der --hash sha384 --encode der
```

Verify:

```bash
sigtool verify --algo ecdsa-p384 --in msg.txt --sig p384_sig.der --pub p384_pub.pem --hash sha384 --encode der
```

### 7.3 RSA-PSS-3072 Example

Generate a 3072-bit RSA key pair:

```bash
sigtool keygen --algo rsa-pss-3072 --pub rsa_pub.pem --priv rsa_priv.pem
```

Sign using RSA-PSS and SHA-256:

```bash
sigtool sign --algo rsa-pss-3072 --in msg.txt --priv rsa_priv.pem --out rsa_sig.bin --hash sha256 --encode raw
```

Verify:

```bash
sigtool verify --algo rsa-pss-3072 --in msg.txt --sig rsa_sig.bin --pub rsa_pub.pem --hash sha256 --encode raw
```

### 7.4 Base64 Signature Example

```bash
sigtool sign --algo ecdsa-p256 --in msg.txt --priv p256_priv.pem --out p256_sig.b64 --hash sha256 --encode base64
sigtool verify --algo ecdsa-p256 --in msg.txt --sig p256_sig.b64 --pub p256_pub.pem --hash sha256 --encode base64
```

---

## 8. Correctness Testing

### 8.1 KAT / Self-Validation Tests

Run:

```bash
sigtool --kat test_vectors.json
```

Alternative form:

```bash
sigtool kat --kat test_vectors.json
```

The file `test_vectors.json` contains self-validation cases for:

- ECDSA-P256 with SHA-256
- ECDSA-P384 with SHA-384
- RSA-PSS-3072 with SHA-256

Because ECDSA and RSA-PSS may involve randomized or library-managed signing behavior, the tests validate sign/verify correctness and tamper rejection rather than comparing a fixed signature byte string.

Expected behavior:

- Original message verification passes.
- Modified message verification fails.
- Empty signatures are rejected.
- Unsupported algorithms or hash choices are rejected.

### 8.2 Negative Tests

Run:

```bash
sigtool --negative-tests
```

The negative tests check fail-closed behavior for:

- Modified message.
- Modified signature.
- Wrong public key.
- Wrong algorithm.
- Wrong hash function.
- Malformed PEM key.
- Unsupported signature encoding.

The program should reject invalid inputs safely and should not crash.

### 8.3 Unit Tests with CTest

Build first, then run from the build directory.

Linux:

```bash
cd Vũ Trọng Hưng/lab5/lab5/build_linux
ctest --output-on-failure
```

Windows:

```powershell
cd Vũ Trọng Hưng\lab5\lab5\build
ctest --output-on-failure
```

Expected CTest entries:

```text
help_test
kat_tests
negative_tests
unit_tests
```

Note: `unit_tests` is built only when `tests/unit_tests.cpp` exists in the expected source directory.

---

## 9. Benchmarking

### 9.1 Single Benchmark Run

From the build directory or any working directory containing the executable:

```bash
sigtool --benchmark
```

This produces:

```text
signature_benchmark_results.csv
```

CSV columns:

```text
Algorithm,Operation,MessageSizeName,MessageSizeBytes,TimeMS,ThroughputOpsPerSec,Iterations
```

Measured operations:

- Key generation latency.
- Signing latency.
- Verification latency.
- Signing throughput.
- Verification throughput.

Message sizes:

| Name | Size |
|---|---:|
| 1 KiB | 1,024 bytes |
| 16 KiB | 16,384 bytes |
| 1 MiB | 1,048,576 bytes |
| 8 MiB | 8,388,608 bytes |

### 9.2 Repeated Windows/Linux Benchmark Runs

From the Lab 5 source directory:

```bash
cd Vũ Trọng Hưng/lab5/lab5
```

Linux repeated benchmark:

```bash
python3 scripts/run_linux_sig_benchmarks.py
```

Windows repeated benchmark:

```powershell
python scripts\run_windows_sig_benchmarks.py
```

The scripts perform a warm-up run and then collect 30 benchmark runs. Output is stored in:

```text
results/linux_runs/
results/windows_runs/
```

### 9.3 Statistical Analysis

Run:

```bash
python3 scripts/analyze_sig_benchmark_stats.py
```

Output files:

```text
results/linux_signature_benchmark_stats.csv
results/windows_signature_benchmark_stats.csv
results/combined_signature_benchmark_stats.csv
```

The analysis includes:

- Mean.
- Median.
- Standard deviation.
- 95% confidence interval.
- Mean throughput.
- Median throughput.

### 9.4 Plot Generation

Run:

```bash
python3 scripts/plot_sig_benchmark.py
```

Expected chart outputs:

```text
results/charts/linux_keygen_latency.png
results/charts/windows_keygen_latency.png
results/charts/linux_sign_latency_1kib.png
results/charts/windows_sign_latency_1kib.png
results/charts/linux_verify_latency_1kib.png
results/charts/windows_verify_latency_1kib.png
results/charts/linux_sign_throughput_1kib.png
results/charts/windows_sign_throughput_1kib.png
results/charts/linux_verify_throughput_1kib.png
results/charts/windows_verify_throughput_1kib.png
results/charts/linux_sign_latency_vs_size.png
results/charts/windows_sign_latency_vs_size.png
results/charts/linux_verify_latency_vs_size.png
results/charts/windows_verify_latency_vs_size.png
results/charts/os_comparison_sign_latency_1kib.png
results/charts/os_comparison_verify_latency_1kib.png
```

Note: In key generation charts, the ECDSA bars may appear very small compared with RSA-PSS-3072. This is expected because RSA key generation is much more expensive than elliptic-curve key generation.

---

## 10. Security Notes

### 10.1 ECDSA Nonces

ECDSA requires a secret nonce for every signature. Reusing the same nonce, using a biased nonce, or leaking part of the nonce can reveal the ECDSA private key.

This tool does not expose nonce selection through the CLI. Production ECDSA signing is delegated to OpenSSL EVP. Deterministic RFC 6979-style ECDSA nonce generation is discussed in the report as a security requirement and future improvement/justification point.

### 10.2 RSA-PSS Instead of PKCS#1 v1.5

RSA-PSS is used instead of legacy RSA PKCS#1 v1.5 signatures. PSS is a modern probabilistic padding scheme and includes a salt and MGF1 mask generation. The production RSA-PSS implementation explicitly selects PSS padding and sets the salt length to the hash length.

### 10.3 Fail-Closed Verification

Verification succeeds only when the signature is valid for the exact message, key, algorithm, hash function, and encoding. Modified messages, modified signatures, wrong keys, malformed keys, and unsupported options are rejected.

### 10.4 Timing and Side-Channel Considerations

The production cryptographic operations use OpenSSL EVP rather than custom arithmetic. The educational code includes constant-time comparison for byte arrays, but the entire application is not claimed to be a formally verified constant-time implementation.

The benchmark framework measures performance variance, but it is not a formal side-channel analysis.

### 10.5 Educational vs Production Components

Production operations:

- ECDSA signing/verification: OpenSSL EVP.
- RSA-PSS signing/verification: OpenSSL EVP.

Educational components:

- Manual RSA-PSS padding demonstration.
- MGF1 demonstration.
- Modular arithmetic demonstration.
- Modular exponentiation and inverse demonstration.
- Constant-time byte comparison demonstration.

Manual elliptic-curve point arithmetic is not implemented. ECDSA production operations rely on OpenSSL.

---

## 11. Advanced Demonstrations

### 11.1 Batch Verification Demo

```bash
sigtool --batch-demo
```

This generates a small batch of signatures and measures batch verification behavior for demonstration purposes.

### 11.2 Manual RSA-PSS Padding Demo

```bash
sigtool --manual-pss-demo
```

Expected output includes the encoded message length and verification result.

This demo is intended to explain the formula-level structure of RSA-PSS padding. It is not the production signing backend.

---

## 12. Known Limitations

1. `sign` and `verify` currently use `--in FILE` input. Direct `--text "..."` input is not implemented for the main sign/verify commands.
2. Deterministic ECDSA nonce generation according to RFC 6979 is not manually implemented in the production code. ECDSA signing is delegated to OpenSSL EVP, and nonce handling is not exposed to users.
3. Manual RSA-PSS and modular arithmetic modules are educational and not production-grade replacements for OpenSSL.
4. Manual elliptic-curve point arithmetic is not implemented.
5. Very large files are read into memory as buffers. A streaming file design would be more memory-efficient for production use.
6. Benchmark results depend on hardware, compiler, OpenSSL build, CPU frequency scaling, operating-system load, and randomness provider.
7. The benchmark is a performance measurement framework, not a formal timing side-channel audit.
8. The Windows package is primarily configured for MinGW64 bundled libraries. MSVC requires compatible dependency libraries.
9. No GUI is included in this Lab 5 submission.

---

## 13. Troubleshooting

### 13.1 `nlohmann/json.hpp not found`

Check that this file exists:

```text
Vũ Trọng Hưng/nlohmann/json.hpp
```

The source directory should be:

```text
Vũ Trọng Hưng/lab5/lab5
```

### 13.2 Crypto++ Headers or Library Not Found

Check that these paths exist:

Linux:

```text
Vũ Trọng Hưng/cryptopp/include/cryptopp/sha.h
Vũ Trọng Hưng/cryptopp/lib/linux/libcryptopp.a
```

Windows:

```text
Vũ Trọng Hưng/cryptopp/include/cryptopp/sha.h
Vũ Trọng Hưng/cryptopp/lib/windows/libcryptopp.a
```

### 13.3 Bundled OpenSSL Not Found on Windows

Check that these paths exist:

```text
Vũ Trọng Hưng/openssl/include/openssl/evp.h
Vũ Trọng Hưng/openssl/lib64/libcrypto.a
Vũ Trọng Hưng/openssl/lib64/libssl.a
```

### 13.4 `tests/unit_tests.cpp not found`

Place the unit test file here:

```text
Vũ Trọng Hưng/lab5/lab5/tests/unit_tests.cpp
```

Then reconfigure CMake:

```bash
cmake -S . -B build_linux
cmake --build build_linux
```

### 13.5 Linux Binary Cannot Execute

Run:

```bash
chmod +x bin/linux/sigtool
```

---

## 14. Report and Submission Files

Recommended files to include for Lab 5:

```text
README.md
Lab5_Report.md
ACADEMIC_HONESTY.md
SELF_GRADE_CHECKLIST.md
lab5/lab5/CMakeLists.txt
lab5/lab5/*.cpp
lab5/lab5/*.hpp
lab5/lab5/test_vectors.json
lab5/lab5/tests/unit_tests.cpp
lab5/lab5/scripts/*.py
lab5/lab5/results/*.csv
lab5/lab5/results/charts/*.png
lab5/lab5/bin/windows/sigtool.exe
lab5/lab5/bin/linux/sigtool
```

The final all-lab submission should be compressed as one ZIP/RAR file according to the course requirement.

---

## 15. Academic Integrity

This lab should include an academic honesty statement and a self-grade checklist. Any external code, library, documentation, or AI-assisted support should be acknowledged according to the course policy.

The cryptographic production implementation uses established libraries instead of copying unknown external implementations. Educational components are included to demonstrate understanding of RSA-PSS padding and modular arithmetic.

---

## 16. Quick Command Summary

Linux:

```bash
cd Vũ Trọng Hưng/lab5/lab5
cmake -S . -B build_linux -DCMAKE_BUILD_TYPE=Release
cmake --build build_linux
./build_linux/sigtool --help
./build_linux/sigtool --kat test_vectors.json
./build_linux/sigtool --negative-tests
cd build_linux && ctest --output-on-failure
```

Windows:

```powershell
cd Vũ Trọng Hưng\lab5\lab5
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build
.\build\sigtool.exe --help
.\build\sigtool.exe --kat test_vectors.json
.\build\sigtool.exe --negative-tests
cd build
ctest --output-on-failure
```

Benchmark pipeline:

```bash
cd Vũ Trọng Hưng/lab5/lab5
python3 scripts/run_linux_sig_benchmarks.py
python3 scripts/analyze_sig_benchmark_stats.py
python3 scripts/plot_sig_benchmark.py
```

---

## 17. Conclusion

`sigtool` provides a practical classical digital signature tool for Lab 5. It supports ECDSA-P256, ECDSA-P384, and RSA-PSS-3072; includes correctness tests, negative tests, unit tests, and benchmarks; and documents important security engineering issues such as nonce misuse, RSA-PSS padding, fail-closed behavior, timing risks, and implementation limitations.

This README is intended to help instructors or reviewers build, run, test, benchmark, and inspect the Lab 5 submission quickly and reproducibly.
