# Lab 4 Self-Grade Checklist

## 1. Hashing Suite

| Requirement | Status | Evidence |
|---|---:|---|
| SHA-224 | Done | `HashEngine.cpp`, OpenSSL EVP |
| SHA-256 | Done | `HashEngine.cpp`, OpenSSL EVP |
| SHA-384 | Done | `HashEngine.cpp`, OpenSSL EVP |
| SHA-512 | Done | `HashEngine.cpp`, OpenSSL EVP |
| SHA3-224 | Done | `HashEngine.cpp`, OpenSSL EVP |
| SHA3-256 | Done | `HashEngine.cpp`, OpenSSL EVP |
| SHA3-384 | Done | `HashEngine.cpp`, OpenSSL EVP |
| SHA3-512 | Done | `HashEngine.cpp`, OpenSSL EVP |
| SHAKE128 | Done | `EVP_shake128()`, `EVP_DigestFinalXOF()` |
| SHAKE256 | Done | `EVP_shake256()`, `EVP_DigestFinalXOF()` |
| SHAKE variable output | Done | `--outlen` |
| Required SHAKE command | Done | `hashtool --algo shake256 --outlen 64 --in file.bin` |
| KATs | Done | `test_vectors.json`, `--kat` |
| Streamed I/O | Done | Chunked file hashing |
| Multi-GB design | Done | Streaming; 1 GiB optional |
| Hex output | Done | Default output |
| Raw binary output | Done | `--format raw --out` |
| Required discussions | Done | Report |

## 2. CLI and Formats

| Requirement | Status | Evidence |
|---|---:|---|
| Basic hashing | Done | `--algo sha256 --in file.bin` |
| Streaming mode | Done | `--stream` |
| SHAKE output length | Done | `--outlen` |
| File input | Done | `--in` |
| Text input | Done | `--text` |
| Output file | Done | `--out` |
| Raw format | Done | `--format raw` |
| Malformed input handling | Done | Negative tests |
| Algorithm validation | Done | `HashConfig` |
| Fail-closed behavior | Done | Negative tests |

## 3. PKI and Certificate Analysis

| Requirement | Status | Evidence |
|---|---:|---|
| X.509 parsing | Done | `CertificateAnalyzer.cpp` |
| Subject | Done | `cert_report_tls.json` |
| Issuer | Done | `cert_report_tls.json` |
| SPKI algorithm and parameters | Done | Certificate report |
| Signature algorithm | Done | Certificate report |
| Validity period | Done | Certificate report |
| Key usage | Done | Certificate report |
| SANs | Done | Certificate report |
| Issuer signature verification | Done | `--issuer` |
| TBS integrity | Done | `tbs_integrity_valid` |
| Fail-closed malformed certificate | Done | Negative tests |
| Nginx TLS deployment | Done | `pki_tls_evidence/` |
| TLS 1.2 | Done | `tls12_log.txt` |
| TLS 1.3 | Done | `tls13_log.txt` |
| ECDSA certificate | Done | P-256 local certificate |
| ZeroSSL trusted root | Documented limitation | Local self-signed ECDSA certificate used when public ZeroSSL certificate was unavailable |
| Config snippet | Done | README/report |
| Trust chain discussion | Done | Report |
| CA/B and CT discussion | Done | Report |

## 4. Controlled MD5 Collision Demonstration

| Requirement | Status | Evidence |
|---|---:|---|
| HashClash/fastcoll workflow | Done | `md5_collision_evidence/hashclash_command_log.txt` |
| Two benign PNG files | Done | `md5_collision_evidence/collision1.png`, `collision2.png` |
| Files differ | Done | `file_type_log.txt` or tool output |
| Matching MD5 | Done | `md5sum_log.txt` |
| SHA-256 differs | Done | `sha256sum_log.txt` |
| Tool verification | Done | `md5_collision_verify_log.txt` |
| Explanation of why MD5 is broken | Done | Report |
| Collision vs preimage explanation | Done | Report |
| Historical incidents discussion | Done | Report |
| No live target | Done | Offline local demonstration only |

## 5. Length-Extension Attack

| Requirement | Status | Evidence |
|---|---:|---|
| `MAC = H(k || m)` | Done | `length_extension_demo_log.txt` |
| Original message shown | Done | `length_extension_demo_log.txt` |
| Original MAC shown | Done | `length_extension_demo_log.txt` |
| Key length used | Done | `length_extension_demo_log.txt` |
| SHA-256 glue padding shown | Done | `padding_diagram.txt` and demo log |
| Forged extended message | Done | `length_extension_demo_log.txt` |
| Matching forged MAC | Done | `length_extension_demo_log.txt` |
| Server-side verification | Done | `length_extension_demo_log.txt` |
| Padding diagram | Done | `padding_diagram.txt` |
| Internal state manipulation | Done | `internal_state_explanation.txt` |
| HMAC mitigation | Done | Report |
| Merkle–Damgård explanation | Done | Report |
| Prefix-free discussion | Done | Report |

## 6. Performance Evaluation

| Requirement | Status | Evidence |
|---|---:|---|
| SHA-256 benchmark | Done | CSV/charts |
| SHA-512 benchmark | Done | CSV/charts |
| SHA3-256 benchmark | Done | CSV/charts |
| SHA3-512 benchmark | Done | CSV/charts |
| 1 MiB | Done | CSV |
| 100 MiB | Done | CSV |
| 1 GiB | Optional | Run if feasible |
| Throughput MB/s | Done | Stats CSV |
| Streaming I/O | Done | Mode column |
| Memory-mapped discussion | Done | Report |
| CPU utilization | Done | `cpu_evidence/windows_cpu_counter_log.txt`, `linux_mpstat_log.txt`, `linux_pidstat_log.txt` |
| SHA-2 vs SHA-3 analysis | Done | Report |
| Cache effects | Done | Report |
| Performance plots | Done | `results/charts/` |
| Windows benchmark | Done | Windows CSV/charts |
| Linux benchmark | Done | Linux CSV/charts |
| Windows vs Linux | Done | OS comparison charts |
| 30 runs | Done | `windows_runs/`, `linux_runs/` |
| Mean/median/stddev/95% CI | Done | Stats CSV |

## 7. Advanced Bonus

| Requirement | Status | Evidence |
|---|---:|---|
| Manual SHA-256 length extension | Done | `CustomSHA256Extend.cpp` |
| Reconstruct state | Done | `reconstructState()` |
| Apply padding | Done | `generatePadding()` |
| Continue compression | Done | `compress()` |
| Explain state manipulation | Done | Log and report |
| No hashpump | Done | Manual code |

## 8. Submission Materials

| Requirement | Status | Evidence |
|---|---:|---|
| Source code | Done | Lab4 source |
| CMake | Done | `CMakeLists.txt` |
| Out-of-source build | Done | `build/`, `build_linux/` |
| README | Done | `README.md` |
| Unit tests | Done | `tests/unit_tests.cpp` |
| CTest Windows | Done | Windows log |
| CTest Linux | Done | Linux log |
| Windows binary | Done | `bin/windows/hashtool.exe` |
| Linux binary | Done | `bin/linux/hashtool` |
| Benchmark scripts | Done | `scripts/` |
| Benchmark results | Done | `results/` |
| Charts | Done | `results/charts/` |
| Report | Done | `LAB4_REPORT.md` or exported PDF/DOCX |
| Academic honesty | Done | `ACADEMIC_HONESTY.md` |
| Private keys excluded | Done | Do not submit `server.key` |
| Final folder layout documented | Done | README Project Layout section |
| Documentation stored in outer `lab4/` folder | Done | `README.md`, `LAB4_REPORT.md`, `SELF_GRADE_CHECKLIST.md`, `ACADEMIC_HONESTY.md` |
| Source/build/results stored in inner `lab4/lab4/` folder | Done | `lab4/lab4/` |
| PKI/TLS evidence | Done | `pki_tls_evidence/` |
| MD5 collision evidence | Done | `md5_collision_evidence/` |
| Length-extension evidence | Done | `length_extension_evidence/` |
| CPU evidence | Done | `lab4/lab4/cpu_evidence/` |
| Test evidence / logs | Done | CTest, KAT, and negative test logs |
| Text input CLI | Done | `hashtool --algo sha256 --text "abc"` |
| Official 30-run benchmark scripts | Done | `scripts/run_windows_hash_benchmarks.py`, `scripts/run_linux_hash_benchmarks.py` |