# SELF_GRADE_CHECKLIST.md - Lab 5 Classical Digital Signatures

**Course:** Cryptography & Applications
**Lab:** Lab 5 - Classical Digital Signatures (ECDSA, RSA-PSS)
**Tool:** `sigtool`
**Language:** C++17
**Build system:** CMake
**Libraries:** OpenSSL EVP, Crypto++
**Platforms:** Windows and Linux

---

## 0. Status Legend

| Mark | Meaning |
|---|---|
| COMPLETE | Implemented and included in the submitted folder |
| PARTIAL / JUSTIFIED | Partially implemented, implemented through a library, or documented as a limitation |
| NOT IMPLEMENTED | Not implemented |
| N/A | Optional or not applicable to this lab |

---

## 1. Overall Self-Assessment Summary

| Category | Self-assessed status | Notes |
|---|---|---|
| Core Lab 5 implementation | COMPLETE | ECDSA-P256, ECDSA-P384, RSA-PSS-3072 are implemented through OpenSSL EVP |
| Cross-platform build | COMPLETE | CMake project with Windows and Linux build support |
| CLI workflow | COMPLETE | Key generation, signing, verification, KAT, negative tests, benchmark, batch demo |
| Correctness testing | COMPLETE | KAT/self-validation, negative tests, Catch2 unit tests, CTest integration |
| Performance evaluation | COMPLETE | Latency, throughput, message-size impact, 30-run scripts, statistics, plots |
| Security discussion | COMPLETE | Nonce risks, RSA-PSS salt, fail-closed behavior, timing and side-channel risks |
| Advanced / bonus topics | PARTIAL | Manual RSA-PSS padding and modular arithmetic implemented; EC point arithmetic not manually implemented |
| Known limitations disclosed | COMPLETE | RFC 6979, DER key support, streaming input, and formal side-channel testing limitations are documented |

**Estimated self-grade:** strong core completion, with partial advanced-topic bonus.
**Important limitation:** deterministic ECDSA RFC 6979 is discussed and justified, but not manually implemented; production ECDSA signing is delegated to OpenSSL EVP.

---

## 2. General Lab Requirements Checklist

### 2.1 Environment and Build Requirements

| Requirement | Status | Evidence / Location | Notes |
|---|---|---|---|
| Use modern C++ | COMPLETE | `.cpp/.hpp` files, `CMakeLists.txt` | Project uses C++17 |
| Use CMake | COMPLETE | `lab5/lab5/CMakeLists.txt` | Main executable: `sigtool` |
| Support out-of-source build | COMPLETE | `cmake -S . -B build`, `cmake -S . -B build_linux` | Build folders are separated from source |
| Build on Windows | COMPLETE | `build/`, `bin/windows/sigtool.exe` | Windows binary included |
| Build on Linux | COMPLETE | `build_linux/`, `bin/linux/sigtool` | Linux binary included |
| Include bundled or documented dependencies | COMPLETE | `openssl/`, `cryptopp/`, `nlohmann/`, `catch2/`, `README.md` | OpenSSL/Crypto++/JSON/Catch2 are included or expected |
| README with dependency list | COMPLETE | `lab5/README.md` | Includes dependency and build instructions |
| README with Windows/Linux build commands | COMPLETE | `lab5/README.md` | Both platforms are documented |
| README with CLI examples | COMPLETE | `lab5/README.md` | Keygen/sign/verify/test/benchmark examples included |
| README with known limitations | COMPLETE | `lab5/README.md` | Limitations are explicitly stated |

---

### 2.2 CLI and Input/Output Requirements

| Requirement | Status | Evidence / Location | Notes |
|---|---|---|---|
| Tool has command structure | COMPLETE | `main.cpp` | Supports commands and flags |
| Key generation command | COMPLETE | `sigtool keygen` | `--algo`, `--pub`, `--priv`, optional `--metadata` |
| Signing command | COMPLETE | `sigtool sign` | `--algo`, `--in`, `--priv`, `--out`, `--hash`, `--encode` |
| Verification command | COMPLETE | `sigtool verify` | `--algo`, `--in`, `--sig`, `--pub`, `--hash`, `--encode` |
| File input through `--in` | COMPLETE | `main.cpp` | Binary file input supported |
| Direct text input through `--text` | NOT IMPLEMENTED | Documented in README/report limitations | File input is used instead |
| Output to file through `--out` | COMPLETE | `main.cpp` | Signature output file supported |
| Signature encoding option | COMPLETE | `--encode raw`, `--encode der`, `--encode base64` | PEM is intentionally rejected for signature files |
| Clear error messages | COMPLETE | `SigException`, CLI checks | Missing arguments and invalid inputs are rejected |
| Safe failure on invalid data | COMPLETE | Negative tests | Tool fails closed instead of accepting invalid signatures |

---

### 2.3 Randomness and Key Management

| Requirement | Status | Evidence / Location | Notes |
|---|---|---|---|
| Use cryptographic randomness | COMPLETE | OpenSSL EVP, Crypto++ `AutoSeededRandomPool` in manual PSS | No `rand()` or `std::random` used for cryptographic operations |
| Generate secure key pairs | COMPLETE | `SigKeyManager.cpp` | EC and RSA key generation use OpenSSL EVP |
| Enforce ECDSA P-256 minimum | COMPLETE | `SigKeyManager.cpp`, `SigConfig` | P-256 and P-384 supported |
| Enforce RSA ≥ 3072 bits | COMPLETE | `SigKeyManager.cpp` | RSA keys below 3072 bits are rejected |
| Save/load public and private keys | COMPLETE | `SigKeyManager.cpp` | PEM key saving/loading implemented |
| PEM key format | COMPLETE | `PEM_write_PUBKEY`, `PEM_write_PrivateKey` | Interoperable key storage |
| DER key format | PARTIAL | `SigKeyManager.hpp` declares DER export methods | CLI primarily supports PEM keys; DER key workflow is not the main implemented path |
| Metadata output | COMPLETE | `--metadata`, `saveMetadata` | Optional key metadata JSON supported |

---

### 2.4 Testing Requirements

| Requirement | Status | Evidence / Location | Notes |
|---|---|---|---|
| KAT or self-validation tests | COMPLETE | `SigKAT.cpp`, `test_vectors.json` | Uses sign/verify/tamper-reject approach |
| JSON vector format | COMPLETE | `test_vectors.json` | Includes ECDSA-P256, ECDSA-P384, RSA-PSS-3072 |
| `--kat` command | COMPLETE | `sigtool --kat test_vectors.json` | Prints pass/fail style output |
| Negative tests | COMPLETE | `NegativeTests.cpp` | Covers common misuse/failure cases |
| Malformed key rejection | COMPLETE | `NegativeTests.cpp`, `SigKeyManager.cpp` | Malformed PEM is rejected |
| Modified message rejection | COMPLETE | `NegativeTests.cpp`, unit tests | Verification fails |
| Modified signature rejection | COMPLETE | `NegativeTests.cpp`, unit tests | Verification fails |
| Wrong public key rejection | COMPLETE | `NegativeTests.cpp`, unit tests | Verification fails |
| Wrong algorithm identifier rejection | COMPLETE | `SigConfig`, `NegativeTests.cpp` | Unsupported algorithm is rejected |
| Wrong hash function rejection | COMPLETE | `validateHashForAlgorithm`, negative tests | Hash mismatch is rejected or fails verification |
| Unit tests | COMPLETE | `tests/unit_tests.cpp` | Catch2 tests included |
| CTest integration | COMPLETE | `CMakeLists.txt` | `help_test`, `kat_tests`, `negative_tests`, `unit_tests` |
| Batch verification | COMPLETE | `BatchVerifier.cpp`, `--batch-demo` | Demonstrates verifying multiple signatures |

---

### 2.5 Performance Methodology Requirements

| Requirement | Status | Evidence / Location | Notes |
|---|---|---|---|
| Warm-up run | COMPLETE | `run_linux_sig_benchmarks.py`, `run_windows_sig_benchmarks.py` | Warm-up before measured runs |
| Around 1,000 iterations | COMPLETE | `SigBenchmarker.cpp` | Sign/verify loops use repeated iterations |
| 30 repeated runs | COMPLETE | `RUNS = 30` in benchmark runner scripts | Windows and Linux scripts included |
| Mean | COMPLETE | `analyze_sig_benchmark_stats.py` | Statistical output CSV |
| Median | COMPLETE | `analyze_sig_benchmark_stats.py` | Statistical output CSV |
| Standard deviation | COMPLETE | `analyze_sig_benchmark_stats.py` | Statistical output CSV |
| 95% confidence interval | COMPLETE | `analyze_sig_benchmark_stats.py` | CI95 computed |
| Windows vs Linux comparison | COMPLETE | `windows_runs/`, `linux_runs/`, combined stats | OS comparison chart supported |
| Graphical plots | COMPLETE | `plot_sig_benchmark.py`, `results/charts/` | Latency, throughput, size impact, OS comparison |
| Analysis beyond raw numbers | COMPLETE | `Lab5_Report.md` | Hash cost, signature size, memory, platform differences |

---

### 2.6 Report and Submission Requirements

| Requirement | Status | Evidence / Location | Notes |
|---|---|---|---|
| Lab report | COMPLETE | `Lab5_Report.md` | Technical report included |
| README | COMPLETE | `README.md` | Build and usage instructions included |
| Self-grade checklist | COMPLETE | `SELF_GRADE_CHECKLIST.md` | This file |
| Academic honesty statement | COMPLETE | `ACADEMIC_HONESTY.md` | AI use disclosed |
| Source code | COMPLETE | `lab5/lab5/*.cpp`, `*.hpp` | All source files included |
| CMake file | COMPLETE | `lab5/lab5/CMakeLists.txt` | Required build file included |
| Windows binary | COMPLETE | `lab5/lab5/bin/windows/sigtool.exe` | Included in submission structure |
| Linux binary | COMPLETE | `lab5/lab5/bin/linux/sigtool` | Included in submission structure |
| Unit test source | COMPLETE | `lab5/lab5/tests/unit_tests.cpp` | Included |
| Benchmark scripts | COMPLETE | `lab5/lab5/scripts/*.py` | Windows/Linux runners and plot scripts |
| Benchmark results/charts | COMPLETE | `lab5/lab5/results/` | CSV and charts included if generated |
| GUI | N/A | Optional | Not implemented for Lab 5 |

---

## 3. Lab 5 Specific Requirements Checklist

### 3.1 Learning Outcomes

| Learning outcome | Status | Evidence / Location | Notes |
|---|---|---|---|
| Generate public/private key pairs for ECDSA | COMPLETE | `sigtool keygen --algo ecdsa-p256`, `ecdsa-p384` | P-256 and P-384 supported |
| Generate public/private key pairs for RSA-PSS | COMPLETE | `sigtool keygen --algo rsa-pss-3072` | 3072-bit RSA supported |
| Produce detached signatures | COMPLETE | `sigtool sign` | Signature file is stored separately from message |
| Verify detached signatures | COMPLETE | `sigtool verify` | Message, signature, and public key are separate inputs |
| Select secure parameters | COMPLETE | `SigConfig`, `SigKeyManager` | P-256/P-384/RSA-3072/SHA-256/SHA-384 |
| Detect signature misuse | COMPLETE | Negative tests | Tampering, wrong key, wrong hash, malformed key rejected |
| Benchmark sign/verify | COMPLETE | `SigBenchmarker.cpp` | Latency and throughput measured |
| Compare EC vs RSA signatures | COMPLETE | `Lab5_Report.md`, charts | Signature size and performance discussion included |

---

### 3.2 ECDSA Requirements

| Requirement | Status | Evidence / Location | Notes |
|---|---|---|---|
| Implement ECDSA-P256 | COMPLETE | `ECDSAEngine.cpp`, `SigKeyManager.cpp`, `SigConfig` | Uses NIST P-256 / secp256r1 |
| Add ECDSA-P384 bonus | COMPLETE | `ECDSAEngine.cpp`, `SigKeyManager.cpp`, `SigConfig` | Uses NIST P-384 / secp384r1 |
| Use SHA-256 for P-256 | COMPLETE | `validateHashForAlgorithm`, `SigConfig` | P-256 uses SHA-256 |
| Use SHA-384 for P-384 | COMPLETE | `validateHashForAlgorithm`, `SigConfig` | P-384 uses SHA-384 |
| Discuss deterministic nonce RFC 6979 vs random nonce | COMPLETE | `Lab5_Report.md`, `README.md` | Discussion included |
| Use deterministic ECDSA RFC 6979 | PARTIAL / justified | `ECDSAEngine.cpp`, `Lab5_Report.md` | Production ECDSA uses OpenSSL EVP; manual RFC 6979 is not implemented and is documented as a limitation/future improvement |
| Prevent user-supplied nonce misuse | COMPLETE | CLI design | CLI does not expose nonce selection |
| Discuss catastrophic nonce reuse | COMPLETE | `Lab5_Report.md` | Explains private-key recovery risk |
| Compare ECDSA signature size vs RSA-PSS | COMPLETE | `Lab5_Report.md` Section on signature size | P-256: 64 bytes raw, P-384: 96 bytes raw, RSA-PSS-3072: 384 bytes |
| Discuss verification cost vs signing cost | COMPLETE | `Lab5_Report.md` benchmark discussion | Notes backend/platform-dependent behavior |

---

### 3.3 RSA-PSS Requirements

| Requirement | Status | Evidence / Location | Notes |
|---|---|---|---|
| Implement RSA-PSS-3072 | COMPLETE | `RSAPSSEngine.cpp`, `SigKeyManager.cpp` | RSA key size is 3072 bits or greater |
| Use SHA-256 | COMPLETE | `SigConfig`, `validateHashForAlgorithm` | RSA-PSS uses SHA-256 in required path |
| Use PSS padding | COMPLETE | `EVP_PKEY_CTX_set_rsa_padding(... RSA_PKCS1_PSS_PADDING)` | Explicitly configured |
| Use salt length = hashLen | COMPLETE | `EVP_PKEY_CTX_set_rsa_pss_saltlen(..., -1)` | OpenSSL `-1` means salt length equals digest length |
| Use randomized salt per signature | COMPLETE | OpenSSL EVP RSA-PSS signing | Salt generation delegated to OpenSSL |
| Discuss why RSA-PSS is preferred over PKCS#1 v1.5 | COMPLETE | `Lab5_Report.md`, `README.md` | Included in security discussion |
| Discuss role of salt | COMPLETE | `Lab5_Report.md` | Explains probabilistic signatures |
| Compare RSA-PSS signature size vs ECDSA | COMPLETE | `Lab5_Report.md` | RSA-PSS-3072 = 384 bytes |
| Discuss public exponent 65537 | COMPLETE | `Lab5_Report.md` | Discussion included |
| Explicitly set public exponent 65537 in code | PARTIAL / library default | `SigKeyManager.cpp` | OpenSSL keygen default is relied on; explicit exponent setting would be a good future hardening improvement |

---

### 3.4 CLI and Format Requirements

| Requirement | Status | Evidence / Location | Notes |
|---|---|---|---|
| `sigtool keygen --algo ecdsa-p256 --pub pub.pem --priv priv.pem` | COMPLETE | `main.cpp` | Supported |
| `sigtool keygen --algo rsa-pss-3072 --pub pub.pem --priv priv.pem` | COMPLETE | `main.cpp` | Supported |
| `sigtool sign --algo ... --in ... --out ... --hash ...` | COMPLETE | `main.cpp` | Supported with `--priv` required |
| `sigtool verify --algo ... --in ... --sig ... --pub ...` | COMPLETE | `main.cpp` | Supported |
| Key format PEM | COMPLETE | `SigKeyManager.cpp` | Main key format |
| Key format DER | PARTIAL | Header declarations exist; CLI focuses on PEM | Documented limitation |
| Signature format raw | COMPLETE | `main.cpp`, ECDSA DER/raw conversion | Supported |
| Signature format DER | COMPLETE | `main.cpp`, `ECDSAEngine` | Supported for ECDSA; RSA bytes are fixed-size raw signature bytes |
| Signature format base64 | COMPLETE | `main.cpp` | Supported |
| Validate malformed keys | COMPLETE | `SigKeyManager.cpp`, `NegativeTests.cpp` | Malformed PEM rejected |
| Validate incorrect algorithm identifiers | COMPLETE | `SigConfig.cpp`, `NegativeTests.cpp` | Unsupported names rejected |
| Validate unsupported encodings | COMPLETE | `SigConfig.cpp`, `NegativeTests.cpp` | Unsupported encoding rejected |
| Validate hash mismatch errors | COMPLETE | `validateHashForAlgorithm`, tests | Wrong hash rejected/fails verification |

---

### 3.5 Correctness and Negative Testing Requirements

| Requirement | Status | Evidence / Location | Notes |
|---|---|---|---|
| Modified message fails | COMPLETE | `NegativeTests.cpp`, unit tests | Verification fails |
| Modified signature fails | COMPLETE | `NegativeTests.cpp`, unit tests | Verification fails |
| Modified/wrong public key fails | COMPLETE | `NegativeTests.cpp`, unit tests | Verification fails |
| Wrong algorithm identifier fails | COMPLETE | `SigConfig.cpp`, `NegativeTests.cpp` | Exception/rejection |
| Wrong hash function fails | COMPLETE | `NegativeTests.cpp`, `validateHashForAlgorithm` | Rejected or verification fails |
| Automated unit tests | COMPLETE | `tests/unit_tests.cpp` | Catch2 |
| Batch verification of N signatures | COMPLETE | `BatchVerifier.cpp`, `--batch-demo` | Demonstration included |
| Clear error codes | COMPLETE | `main.cpp` | Success returns `0`; errors return non-zero |
| Clear UX messages | COMPLETE | `main.cpp`, exceptions | CLI messages included |
| Discuss constant-time verification | COMPLETE | `Lab5_Report.md` | Included in security discussion |
| Discuss improper error handling leakage | COMPLETE | `Lab5_Report.md` | Included in security discussion |

---

### 3.6 Performance Evaluation Requirements

| Requirement | Status | Evidence / Location | Notes |
|---|---|---|---|
| ECDSA key generation latency | COMPLETE | `SigBenchmarker.cpp`, charts | Measured |
| ECDSA sign latency | COMPLETE | `SigBenchmarker.cpp`, charts | Measured |
| ECDSA verify latency | COMPLETE | `SigBenchmarker.cpp`, charts | Measured |
| ECDSA throughput ops/sec | COMPLETE | `SigBenchmarker.cpp`, stats CSV | Measured |
| RSA-PSS key generation latency | COMPLETE | `SigBenchmarker.cpp`, charts | Measured |
| RSA-PSS sign latency | COMPLETE | `SigBenchmarker.cpp`, charts | Measured |
| RSA-PSS verify latency | COMPLETE | `SigBenchmarker.cpp`, charts | Measured |
| RSA-PSS throughput ops/sec | COMPLETE | `SigBenchmarker.cpp`, stats CSV | Measured |
| 1 KiB message size | COMPLETE | `SigBenchmarker.cpp` | Included |
| 16 KiB message size | COMPLETE | `SigBenchmarker.cpp` | Included |
| 1 MiB message size | COMPLETE | `SigBenchmarker.cpp` | Included |
| 8 MiB message size | COMPLETE | `SigBenchmarker.cpp` | Included |
| Hash cost dominance analysis | COMPLETE | `Lab5_Report.md` | Discussed for large messages |
| ECDSA vs RSA-PSS characteristics | COMPLETE | `Lab5_Report.md` | Discussed |
| Signature size comparison | COMPLETE | `Lab5_Report.md` | Discussed with byte sizes |
| Memory usage considerations | COMPLETE | `Lab5_Report.md` | Discussed vector-based input buffering |
| Compare against Lab 6 PQC | PARTIAL Placeholder | `Lab5_Report.md` | Comparison structure prepared; final values require Lab 6 results |
| Latency vs message size plots | COMPLETE | `plot_sig_benchmark.py`, `results/charts` | Generated when scripts are run |

---

### 3.7 Advanced Topics / Bonus Checklist

| Bonus item | Status | Evidence / Location | Notes |
|---|---|---|---|
| Elliptic curve point arithmetic from primitives | NOT IMPLEMENTED | N/A | ECDSA uses OpenSSL EVP; this is documented honestly |
| Modular inversion | PARTIAL EDUCATIONAL | `ModularArithmetic.cpp` | Implemented for formula-level explanation |
| RSA modular exponentiation | PARTIAL EDUCATIONAL | `ModularArithmetic.cpp` | Educational only, not production backend |
| PSS padding generation | COMPLETE educational | `ManualRSAPSS.cpp` | Manual PSS encode/verify structure implemented |
| Constant-time comparison | PARTIAL EDUCATIONAL | `ModularArithmetic.cpp`, `ManualRSAPSS.cpp`, unit tests | Equal-length byte comparison included |
| Explain constant-time considerations | COMPLETE | `Lab5_Report.md`, `README.md` | Discussed |
| Timing attack surface | COMPLETE | `Lab5_Report.md` | Discussed |
| Fault injection risks | COMPLETE | `Lab5_Report.md` | Discussed |
| Side-channel risks in modular exponentiation | COMPLETE | `Lab5_Report.md` | Discussed |
| Deterministic nonce protection | COMPLETE discussion / PARTIAL implementation limitation | `Lab5_Report.md` | Discussed; manual RFC 6979 not implemented |
| Basic timing variance measurement | COMPLETE | Benchmark scripts and stats | Repeated measurement with stddev and CI95 |
| Discussion of constant-time libraries | COMPLETE | `Lab5_Report.md` | OpenSSL EVP preferred for production operations |
| Exploit demonstration | N/A | Not required | No exploit demonstration included |

---

## 4. Evidence Map

| File / Folder | Purpose |
|---|---|
| `CMakeLists.txt` | CMake build and CTest integration |
| `main.cpp` | CLI parsing and command dispatch |
| `SigConfig.cpp/.hpp` | Algorithm/hash/format configuration |
| `SigKeyManager.cpp/.hpp` | Key generation, PEM save/load, key validation, metadata |
| `ECDSAEngine.cpp/.hpp` | ECDSA sign/verify through OpenSSL EVP |
| `RSAPSSEngine.cpp/.hpp` | RSA-PSS sign/verify through OpenSSL EVP |
| `ManualRSAPSS.cpp/.hpp` | Educational RSA-PSS padding implementation |
| `ModularArithmetic.cpp/.hpp` | Educational modular arithmetic and constant-time comparison |
| `NegativeTests.cpp/.hpp` | Negative tests for misuse and invalid inputs |
| `BatchVerifier.cpp/.hpp` | Batch verification demonstration |
| `SigBenchmarker.cpp/.hpp` | Benchmark implementation |
| `SigKAT.cpp/.hpp` | KAT/self-validation test runner |
| `test_vectors.json` | JSON test vectors for supported algorithms |
| `tests/unit_tests.cpp` | Catch2 unit tests |
| `scripts/run_linux_sig_benchmarks.py` | Linux 30-run benchmark runner |
| `scripts/run_windows_sig_benchmarks.py` | Windows 30-run benchmark runner |
| `scripts/analyze_sig_benchmark_stats.py` | Mean/median/stddev/CI95 analysis |
| `scripts/plot_sig_benchmark.py` | Plot generation |
| `results/` | Benchmark CSVs and generated charts |
| `README.md` | Build, usage, testing, benchmark, limitations |
| `Lab5_Report.md` | Technical report and security analysis |
| `ACADEMIC_HONESTY.md` | Academic honesty and AI-use disclosure |
| `SELF_GRADE_CHECKLIST.md` | This self-assessment file |

---

## 5. Known Partial Items and Justifications

### 5.1 Deterministic ECDSA RFC 6979

The Lab 5 requirement says students should use deterministic ECDSA RFC 6979 unless justified otherwise. This implementation delegates production ECDSA signing to OpenSSL EVP and does not manually implement RFC 6979 nonce derivation.

This is marked as **partial / justified** because custom nonce generation is dangerous if implemented incorrectly. The CLI also does not expose nonce input to users, reducing accidental nonce reuse. The report discusses RFC 6979, random nonces, and catastrophic nonce reuse, and lists deterministic ECDSA as a future improvement.

### 5.2 DER Key Format

The implemented key workflow uses PEM files for public and private keys. PEM is the primary submitted and documented key format. DER support is not exposed as a complete CLI key workflow, so it is marked as **partial**.

### 5.3 Explicit RSA Public Exponent

The report discusses the common RSA public exponent value 65537. The implementation relies on OpenSSL key generation behavior and does not explicitly set the exponent in the code. Explicitly setting the public exponent would be a future hardening improvement.

### 5.4 Elliptic Curve Point Arithmetic

Manual elliptic-curve point arithmetic is not implemented. Production ECDSA correctly uses OpenSSL EVP. The advanced formula-level implementation is therefore partial, with manual RSA-PSS padding and modular arithmetic included instead.

### 5.5 Formal Side-Channel Validation

The benchmark measures timing variance for performance analysis, but it is not a formal side-channel leakage test. A formal side-channel evaluation would require controlled hardware, many more samples, fixed CPU frequency, and specialized statistical leakage testing.

---

## 6. Final Checklist Before Submission

| Final item | Status | Notes |
|---|---|---|
| Source code included | COMPLETE | `lab5/lab5/*.cpp`, `*.hpp` |
| CMake included | COMPLETE | `lab5/lab5/CMakeLists.txt` |
| Windows binary included | COMPLETE | `bin/windows/sigtool.exe` |
| Linux binary included | COMPLETE | `bin/linux/sigtool` |
| README included | COMPLETE | `lab5/README.md` |
| Lab report included | COMPLETE | `lab5/Lab5_Report.md` |
| Academic honesty file included | COMPLETE | `lab5/ACADEMIC_HONESTY.md` |
| Self-grade checklist included | COMPLETE | `lab5/SELF_GRADE_CHECKLIST.md` |
| KAT file included | COMPLETE | `lab5/lab5/test_vectors.json` |
| Unit tests included | COMPLETE | `lab5/lab5/tests/unit_tests.cpp` |
| Scripts included | COMPLETE | `lab5/lab5/scripts/` |
| Results/charts included | COMPLETE | `lab5/lab5/results/` if generated |
| Known limitations disclosed | COMPLETE | README, report, this checklist |
| AI use disclosed | COMPLETE | `ACADEMIC_HONESTY.md` |

---

