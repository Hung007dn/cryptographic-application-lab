# SELF_GRADE_CHECKLIST.md - Lab 6 Post-Quantum Signatures and Certificates

## 1. Core Requirements

| Requirement | Status | Evidence / Notes |
|---|---|---|
| C++17 implementation | COMPLETE | Project uses C++17 in CMake. |
| CMake build system | COMPLETE | `CMakeLists.txt` builds `pqtool` and optional unit tests. |
| Out-of-source build | COMPLETE | Windows uses `build/`; Linux uses `build_linux/`. |
| Windows build | COMPLETE | MinGW build supported. |
| Linux build | COMPLETE | Linux `build_linux` supported with liboqs `build_linux`. |
| Binaries for Windows and Linux | COMPLETE | `bin/windows` and `bin/linux` folders prepared. |
| README | COMPLETE | Lab 6 README provided. |
| Report | COMPLETE | Lab 6 report provided. |
| Academic honesty statement | COMPLETE | AI use and libraries disclosed. |
| Self-grade checklist | COMPLETE | This file. |

## 2. Algorithms and Parameters

| Requirement | Status | Evidence / Notes |
|---|---|---|
| ML-DSA-44 required | COMPLETE | `mldsa-44` supported in keygen/sign/verify/KAT. |
| ML-DSA-65 optional bonus | COMPLETE | `mldsa-65` supported in keygen/sign/verify/KAT. |
| ML-DSA-87 listed | PARTIAL | Recognized in configuration but not the main tested requirement. |
| ML-KEM-512 required | COMPLETE | `mlkem-512` supported in keygen/encaps/decaps/KAT. |
| ML-KEM-768 / ML-KEM-1024 | PARTIAL | May be recognized by configuration; not primary tested requirement. |
| Secure parameter discussion | COMPLETE | Discussed in report. |
| Signature size vs security trade-off | COMPLETE | ML-DSA-44 and ML-DSA-65 sizes reported. |
| ML-KEM ciphertext and shared-secret size discussion | COMPLETE | ML-KEM-512 ciphertext and shared secret sizes reported. |

## 3. CLI and Formats

| Requirement | Status | Evidence / Notes |
|---|---|---|
| `pqtool keygen` | COMPLETE | Supports ML-DSA and ML-KEM. |
| `pqtool sign` | COMPLETE | Supports ML-DSA detached signatures. |
| `pqtool verify` | COMPLETE | Supports ML-DSA verification. |
| `pqtool encaps` | COMPLETE | Supports ML-KEM encapsulation. |
| `pqtool decaps` | COMPLETE | Supports ML-KEM decapsulation. |
| `--kat test_vectors.json` | COMPLETE | KAT/self-validation runner implemented. |
| `--negative-tests` | COMPLETE | Negative tests implemented. |
| `--verbose` | COMPLETE | Verbose mode implemented for CLI commands. |
| Raw signatures | COMPLETE | `--encode raw` supported. |
| Base64 signatures | COMPLETE | `--encode base64` supported. |
| Ciphertext binary format | COMPLETE | Ciphertexts stored as binary files. |
| PEM/DER key support | PARTIAL / JUSTIFIED | Files use raw liboqs key bytes. Lab-specific PEM export helpers exist, but saved key files are not standard OpenSSL PEM objects. |

## 4. Post-Quantum Certificate Mini-Project

| Requirement | Status | Evidence / Notes |
|---|---|---|
| Generate CA key pair | COMPLETE | `cert-demo` generates CA key pair. |
| Sign subject public key | COMPLETE | Certificate manager signs subject data with ML-DSA. |
| Verify certificate signature | COMPLETE | `cert-demo` verifies generated certificate. |
| JSON certificate structure | COMPLETE | Subject, public key, issuer, algorithm, signature included. |
| Tamper discussion | COMPLETE | Discussed in report. |
| Explain why ML-KEM is not for signing | COMPLETE | Discussed in report. |
| Hybrid certificates discussion | COMPLETE | Discussed in report. |
| PQ TLS migration path | COMPLETE | Discussed in report. |

## 5. Correctness and Negative Tests

| Requirement | Status | Evidence / Notes |
|---|---|---|
| Modified message rejected | COMPLETE | Negative tests and KAT cover this. |
| Modified signature rejected | COMPLETE | Negative tests and KAT cover this. |
| Modified public key rejected | COMPLETE | Negative tests and KAT cover this. |
| Modified ML-KEM ciphertext checked | COMPLETE | Test checks original shared secret is not recovered. |
| Wrong ML-KEM private key checked | COMPLETE | Test checks original shared secret is not recovered. |
| Batch verification | COMPLETE | `--batch-verify-demo` implemented. |
| Batch decapsulation timing | COMPLETE | `--batch-decaps-bench` implemented. |
| Clear PASS/FAIL output | COMPLETE | KAT, negative tests, and CTest produce pass/fail output. |
| Fail-closed behavior discussion | COMPLETE | Discussed in report. |
| Malformed input / invalid files | PARTIAL | File open and algorithm errors handled; full fuzzing not performed. |

## 6. KAT and Unit Testing

| Requirement | Status | Evidence / Notes |
|---|---|---|
| JSON vector file | COMPLETE | `test_vectors.json` included. |
| KAT command | COMPLETE | `pqtool --kat test_vectors.json`. |
| PASS/FAIL per test | COMPLETE | KAT runner prints per-test PASS/FAIL. |
| Summary output | COMPLETE | KAT runner prints total passed/total. |
| Catch2 unit tests | COMPLETE | `tests/unit_tests.cpp` supported when Catch2 is present. |
| CTest integration | COMPLETE | `enable_testing()` and `add_test(...)` included. |
| Windows CTest | COMPLETE | `ctest --output-on-failure -V` supported. |
| Linux CTest | COMPLETE | `LD_LIBRARY_PATH=... ctest --output-on-failure -V` supported. |

## 7. Performance Evaluation

| Requirement | Status | Evidence / Notes |
|---|---|---|
| ML-DSA keygen latency | COMPLETE | Benchmark script measures it. |
| ML-DSA sign latency | COMPLETE | 1 KiB, 16 KiB, 1 MiB, 8 MiB measured. |
| ML-DSA verify latency | COMPLETE | 1 KiB, 16 KiB, 1 MiB, 8 MiB measured. |
| ML-DSA throughput | COMPLETE | CSV includes throughput ops/sec. |
| ML-KEM keygen latency | COMPLETE | Benchmark script measures it. |
| ML-KEM encapsulation latency | COMPLETE | Benchmark script measures it. |
| ML-KEM decapsulation latency | COMPLETE | Benchmark script measures it. |
| Shared-secret throughput | COMPLETE | Batch decapsulation throughput measured. |
| 30 repeated runs | COMPLETE | `--runs 30` used. |
| Warm-up | COMPLETE | Script performs warm-up. |
| Mean, median, stddev, CI95 | COMPLETE | Analysis script computes all required statistics. |
| Charts | COMPLETE | Plot script generates PNG charts. |
| Windows vs Linux comparison | COMPLETE | Separate and combined CSV outputs supported. |
| Hardware/OS table | TO BE FILLED | Add actual CPU/RAM/OS/compiler info in final report. |
| Hardware acceleration discussion | PARTIAL | Not specifically measured; can be discussed as not applicable/not isolated. |

## 8. Required Discussion

| Requirement | Status | Evidence / Notes |
|---|---|---|
| Large signature size compared to ECDSA | COMPLETE | Discussed in report. |
| ML-DSA deterministic signing / no RFC6979 issue like ECDSA | COMPLETE | Discussed in report. |
| Rejection sampling and failure probability | COMPLETE DISCUSSION | Discussed conceptually; not reimplemented. |
| IND-CCA security | COMPLETE | Discussed in ML-KEM section. |
| Fujisaki-Okamoto transform | COMPLETE | Discussed in ML-KEM section. |
| Ciphertext size vs RSA key exchange | COMPLETE | Discussed in report. |
| Hash/message-size cost dominance | COMPLETE | Discussed through large-message benchmark interpretation. |
| Memory usage | COMPLETE | Key, signature, ciphertext, and message buffer sizes discussed. |
| Compare to ECDSA/RSA-PSS | COMPLETE | Theoretical and Lab 5 comparison included. |

## 9. Advanced Topics Bonus

| Requirement | Status | Evidence / Notes |
|---|---|---|
| NTT-based polynomial arithmetic | DISCUSSED ONLY | Not reimplemented. |
| Modular reduction | DISCUSSED ONLY | Not used as production backend. |
| Rejection sampling | DISCUSSED ONLY | Not reimplemented. |
| Constant-time coding considerations | COMPLETE DISCUSSION | Discussed. |
| Timing attack surface | COMPLETE | Discussed. |
| Lattice leakage risks | COMPLETE | Discussed. |
| Importance of constant-time NTT | COMPLETE DISCUSSION | Discussed. |
| Failure handling in decapsulation | COMPLETE | Tests and discussion included. |
| Basic timing variance measurement | COMPLETE | Stddev and CI95 measured from 30 runs. |
| Input-dependent timing discussion | COMPLETE | Discussed in benchmark/security sections. |

## 10. Known Limitations

| Limitation | Status |
|---|---|
| Full ML-DSA/ML-KEM primitive implementation from scratch | NOT IMPLEMENTED |
| Official fixed-byte NIST KAT comparison | NOT IMPLEMENTED |
| Standard OpenSSL PEM/X.509 key serialization | PARTIAL |
| Formal side-channel leakage testing | NOT IMPLEMENTED |
| Production-grade certificate validation model | NOT IMPLEMENTED |
| CLI-level benchmark includes process startup and file I/O | DOCUMENTED |

## 11. Overall Self-Assessment

The core Lab 6 requirements are completed:

```text
ML-DSA-44
ML-DSA-65 optional parameter set
ML-KEM-512
key generation
sign and verify
encapsulation and decapsulation
certificate demo
KAT/self-validation tests
negative tests
Catch2/CTest integration
batch verification
batch decapsulation timing
benchmark scripts
Windows/Linux build support
report, README, honesty statement, checklist
```

Advanced mathematical implementation from primitives is not claimed. It is discussed honestly as theory and side-channel awareness, while production cryptographic operations use liboqs.
