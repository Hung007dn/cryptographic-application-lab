# Lab 3 Self-Grade Checklist

## 1. Algorithms and Parameters

| Requirement                       | Status | Evidence                                         |
| --------------------------------- | :----: | ------------------------------------------------ |
| RSA-3072 OAEP-SHA256 implemented  |  Done  | `RSAEngine.cpp`, `RSAConfig.hpp`                 |
| RSA-4096 supported for comparison |  Done  | Key generation and benchmark support             |
| RSA-OAEP padding                  |  Done  | Crypto++ RSA-OAEP implementation                 |
| OAEP with SHA-256                 |  Done  | `RSAES<OAEP<SHA256>>`                            |
| MGF1 with SHA-256                 |  Done  | Crypto++ OAEP and manual OAEP implementation     |
| Optional OAEP label support       |  Done  | Label binding and wrong-label negative test      |
| RSA minimum size enforced         |  Done  | Unsupported key sizes are rejected               |
| Plaintext size limit discussed    |  Done  | `README.md` and `Lab3_Report.md`                 |
| Direct RSA limit handled          |  Done  | Automatic hybrid encryption for large plaintexts |
| No PKCS#1 v1.5 encryption         |  Done  | RSA-OAEP is used instead                         |

## 2. Hybrid Encryption

| Requirement                   | Status | Evidence                                               |
| ----------------------------- | :----: | ------------------------------------------------------ |
| Random AES-256 key generation |  Done  | `HybridEncryptor.cpp`                                  |
| AES-256-GCM encryption        |  Done  | `HybridEncryptor.cpp`                                  |
| 96-bit AES-GCM IV             |  Done  | `RSAConfig::GCM_IV_SIZE = 12`                          |
| RSA-OAEP wrapped AES key      |  Done  | `wrapped_key` field in envelope                        |
| JSON envelope                 |  Done  | `HybridEnvelope::toJSON()`                             |
| AES-GCM authentication tag    |  Done  | `tag` field in envelope                                |
| Authenticated decryption      |  Done  | AES-GCM tag verification                               |
| Tampered ciphertext rejected  |  Done  | Negative tests                                         |
| Tampered envelope rejected    |  Done  | Negative tests                                         |
| Fail-closed hybrid decryption |  Done  | Invalid envelope/ciphertext does not produce plaintext |

## 3. CLI and Formats

| Requirement                     | Status | Evidence                           |
| ------------------------------- | :----: | ---------------------------------- |
| Key generation CLI              |  Done  | `rsatool keygen`                   |
| Encryption CLI                  |  Done  | `rsatool encrypt`                  |
| Decryption CLI                  |  Done  | `rsatool decrypt`                  |
| RSA-3072 key generation         |  Done  | `rsatool keygen --bits 3072`       |
| RSA-4096 key generation         |  Done  | `rsatool keygen --bits 4096`       |
| PEM key support                 |  Done  | Public/private key output          |
| DER key support                 |  Done  | `pub.der`, `priv.der`              |
| Metadata JSON support           |  Done  | Key metadata output                |
| Hybrid envelope JSON            |  Done  | `ct.bin.json`                      |
| Base64 fields in envelope       |  Done  | Wrapped key, IV, tag, ciphertext   |
| Raw ciphertext output           |  Done  | CLI output file                    |
| Hex/base64/raw encoding support |  Done  | CLI encoding helpers / validation  |
| Malformed input validation      |  Done  | Negative tests                     |
| Incorrect encoding validation   |  Done  | Negative tests / parser validation |

## 4. Build, Platform, and Packaging

| Requirement                      | Status | Evidence                                           |
| -------------------------------- | :----: | -------------------------------------------------- |
| C++17                            |  Done  | `CMakeLists.txt`                                   |
| CMake build                      |  Done  | `CMakeLists.txt`                                   |
| Out-of-source build              |  Done  | `cmake -S . -B build`, `cmake -S . -B build_linux` |
| Windows build                    |  Done  | `bin/windows/rsatool.exe`                          |
| Linux build                      |  Done  | `bin/linux/rsatool`                                |
| Prebuilt Windows binary          |  Done  | `bin/windows/rsatool.exe`                          |
| Prebuilt Linux binary            |  Done  | `bin/linux/rsatool`                                |
| No vcpkg dependency during build |  Done  | Crypto++ linked from bundled static libraries      |
| Bundled Windows Crypto++ library |  Done  | `cryptopp/lib/windows/libcryptopp.a`               |
| Bundled Linux Crypto++ library   |  Done  | `cryptopp/lib/linux/libcryptopp.a`                 |
| Bundled Crypto++ headers         |  Done  | `cryptopp/include/cryptopp/`                       |
| Bundled nlohmann-json            |  Done  | `nlohmann/json.hpp`                                |
| Bundled Catch2 single-header     |  Done  | `catch2/catch.hpp`                                 |
| Lab3 command-line only           |  Done  | No GUI requirement for Lab3                        |

## 5. Testing

| Requirement                      | Status | Evidence                            |
| -------------------------------- | :----: | ----------------------------------- |
| Unit tests with Catch2           |  Done  | `tests/unit_tests.cpp`              |
| CTest registration               |  Done  | `ctest --verbose`                   |
| `ctest` on Windows               |  Done  | Windows test run / screenshot / log |
| `ctest` on Linux                 |  Done  | Linux test run / screenshot / log   |
| Wrong private key test           |  Done  | `--negative-tests`                  |
| Tampered RSA ciphertext test     |  Done  | `--negative-tests`                  |
| Tampered AES-GCM ciphertext test |  Done  | `--negative-tests`                  |
| Wrong OAEP label test            |  Done  | `--negative-tests`                  |
| Tampered envelope header test    |  Done  | `--negative-tests`                  |
| Malformed ciphertext test        |  Done  | `--negative-tests`                  |
| Invalid key size test            |  Done  | `--negative-tests`                  |
| Manual OAEP test                 |  Done  | `--manual-oaep-test`                |

Expected negative test result:

```text
Passed: 7/7
```

Expected CTest result:

```text
100% tests passed
```

## 6. Performance Evaluation

| Requirement                     | Status | Evidence                                     |
| ------------------------------- | :----: | -------------------------------------------- |
| Warm-up run                     |  Done  | Benchmark scripts                            |
| 30 repeated runs                |  Done  | `results/windows_runs`, `results/linux_runs` |
| RSA key generation time         |  Done  | Benchmark results                            |
| RSA encryption time             |  Done  | Benchmark results                            |
| RSA decryption time             |  Done  | Benchmark results                            |
| RSA-3072 vs RSA-4096 comparison |  Done  | Benchmark results and charts                 |
| Hybrid encryption benchmark     |  Done  | Benchmark results                            |
| 1 KiB hybrid test               |  Done  | Benchmark results                            |
| 1 MiB hybrid test               |  Done  | Benchmark results                            |
| 100 MiB hybrid test             |  Done  | Benchmark results                            |
| Mean                            |  Done  | Benchmark stats CSV                          |
| Median                          |  Done  | Benchmark stats CSV                          |
| Standard deviation              |  Done  | Benchmark stats CSV                          |
| 95% confidence interval         |  Done  | Benchmark stats CSV                          |
| Windows vs Linux comparison     |  Done  | OS comparison plots                          |
| Latency plots                   |  Done  | `results/charts`                             |
| Throughput plots                |  Done  | `results/charts`                             |
| Performance analysis            |  Done  | `Lab3_Report.md`                             |

## 7. Security Engineering Discussion

| Requirement                               | Status | Evidence                                                                                               |
| ----------------------------------------- | :----: | ------------------------------------------------------------------------------------------------------ |
| Threat model                              |  Done  | `Lab3_Report.md`                                                                                       |
| Misuse cases                              |  Done  | `Lab3_Report.md`                                                                                       |
| Known attacks discussion                  |  Done  | PKCS#1 v1.5 padding oracle, Bleichenbacher-style attacks, OAEP validation errors, AES-GCM nonce misuse |
| Why OAEP is secure                        |  Done  | IND-CCA2 discussion in report                                                                          |
| Why PKCS#1 v1.5 is insecure               |  Done  | Report discussion                                                                                      |
| Why RSA cannot encrypt large files        |  Done  | RSA-OAEP plaintext limit discussion                                                                    |
| Safe defaults                             |  Done  | RSA-3072 minimum, OAEP-SHA256, AES-256-GCM, 96-bit IV                                                  |
| Fail-closed behavior                      |  Done  | Negative tests and report                                                                              |
| Clear non-leaky error messages            |  Done  | Report discussion                                                                                      |
| Constant-time tag verification discussion |  Done  | Crypto++ library-backed tag verification                                                               |
| Implementation limitations                |  Done  | Known limitations section                                                                              |
| Forward secrecy limitation                |  Done  | Hybrid security analysis                                                                               |
| ECDHE / ML-KEM upgrade path               |  Done  | Bonus security analysis                                                                                |

## 8. Randomness and Cryptographic Safety

| Requirement                                              | Status | Evidence                                        |
| -------------------------------------------------------- | :----: | ----------------------------------------------- |
| Secure random generation                                 |  Done  | Crypto++ `AutoSeededRandomPool`                 |
| AES key generated securely                               |  Done  | `HybridEncryptor.cpp`                           |
| AES-GCM IV generated securely                            |  Done  | `HybridEncryptor.cpp`                           |
| OAEP seed generated securely                             |  Done  | Crypto++ OAEP / manual OAEP test                |
| No `rand()` for cryptographic values                     |  Done  | Source inspection                               |
| No `srand()` for cryptographic values                    |  Done  | Source inspection                               |
| No `std::mt19937` for cryptographic values               |  Done  | Source inspection                               |
| No `std::default_random_engine` for cryptographic values |  Done  | Source inspection                               |
| No Python `random` for cryptographic values              |  Done  | Lab3 has no GUI and no Python crypto randomness |

## 9. Advanced Topics

| Requirement                          | Status | Evidence                   |
| ------------------------------------ | :----: | -------------------------- |
| Manual OAEP encoding                 |  Done  | `ManualOAEP.cpp`           |
| Manual OAEP decoding                 |  Done  | `ManualOAEP.cpp`           |
| MGF1 implementation                  |  Done  | `ManualOAEP::MGF1()`       |
| XOR masking                          |  Done  | `xorBytes()`               |
| Padding validation                   |  Done  | `oaepDecode()`             |
| Label hash validation                |  Done  | Manual OAEP implementation |
| Constant-time comparison explanation |  Done  | `Lab3_Report.md`           |
| Manual OAEP validation test          |  Done  | `--manual-oaep-test`       |
| Hybrid security analysis             |  Done  | `Lab3_Report.md`           |
| Envelope vs direct RSA comparison    |  Done  | `Lab3_Report.md`           |
| TLS/PGP-style hybrid explanation     |  Done  | `Lab3_Report.md`           |
| Forward secrecy limitation           |  Done  | `Lab3_Report.md`           |
| ECDHE or ML-KEM upgrade path         |  Done  | `Lab3_Report.md`           |

## 10. Documentation and Academic Honesty

| Item                       | Status | Evidence                               |
| -------------------------- | :----: | -------------------------------------- |
| Source code                |  Done  | Lab3 source files                      |
| README                     |  Done  | `README.md`                            |
| Unit tests                 |  Done  | `tests/unit_tests.cpp`                 |
| Report PDF/DOCX            |  Done  | Report export                          |
| Markdown report            |  Done  | `Lab3_Report.md`                       |
| Self-grade checklist       |  Done  | `SELF_GRADE_CHECKLIST.md`              |
| Academic honesty statement |  Done  | `ACADEMIC_HONESTY.md`                  |
| Originality statement      |  Done  | `ACADEMIC_HONESTY.md`                  |
| AI/tool disclosure         |  Done  | `ACADEMIC_HONESTY.md` / report section |
| External references        |  Done  | Report references section              |
| Benchmark scripts          |  Done  | `scripts/`                             |
| Benchmark results          |  Done  | `results/`                             |
| Charts                     |  Done  | `results/charts/`                      |
| Screenshots                |  Done  | Build/test screenshots                 |
| Windows binary             |  Done  | `bin/windows/rsatool.exe`              |
| Linux binary               |  Done  | `bin/linux/rsatool`                    |

## 11. Final Submission Notes

* The final submission includes both source code and prebuilt binaries.
* Lab3 is a command-line tool and does not include a GUI.
* The project no longer depends on vcpkg during build.
* Crypto++ is bundled directly as platform-specific static libraries.
* The Windows Crypto++ library is located at `cryptopp/lib/windows/libcryptopp.a`.
* The Linux Crypto++ library is located at `cryptopp/lib/linux/libcryptopp.a`.
* The Windows executable is located at `bin/windows/rsatool.exe`.
* The Linux executable is located at `bin/linux/rsatool`.
* Benchmark statistics were generated from repeated runs and include mean, median, standard deviation, and 95% confidence interval.
* Negative testing confirms fail-closed behavior for tampered or malformed inputs.
* A Windows `.exe` file is not used as a Linux binary. Separate binaries are provided for Windows and Linux.
* All cryptographic operations are implemented using Crypto++.
