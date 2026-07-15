# Lab 1 Self-Grade Checklist

## 1. Build, Platform, and Packaging

| Requirement                                           | Status | Evidence                                                                                               |
| ----------------------------------------------------- | :----: | ------------------------------------------------------------------------------------------------------ |
| Crypto++ only for cryptographic implementation        |  Done  | Source code uses Crypto++ for AES modes and cryptographic primitives                                   |
| No OpenSSL/libsodium for cryptographic implementation |  Done  | No OpenSSL/libsodium cryptographic API is used                                                         |
| C++17                                                 |  Done  | `CMakeLists.txt`                                                                                       |
| CMake build                                           |  Done  | `CMakeLists.txt`                                                                                       |
| Out-of-source build                                   |  Done  | `cmake -S . -B build`, `cmake -S . -B build_linux`                                                     |
| Windows build                                         |  Done  | `bin/windows/encrypt_tool.exe`                                                                         |
| Linux build                                           |  Done  | `bin/linux/encrypt_tool`                                                                               |
| Prebuilt Windows CLI binary                           |  Done  | `bin/windows/encrypt_tool.exe`                                                                         |
| Prebuilt Linux CLI binary                             |  Done  | `bin/linux/encrypt_tool`                                                                               |
| No vcpkg dependency during build                      |  Done  | Crypto++ is linked from bundled static libraries under `cryptopp/lib/windows` and `cryptopp/lib/linux` |
| Bundled Windows Crypto++ library                      |  Done  | `cryptopp/lib/windows/libcryptopp.a`                                                                   |
| Bundled Linux Crypto++ library                        |  Done  | `cryptopp/lib/linux/libcryptopp.a`                                                                     |
| Bundled Crypto++ headers                              |  Done  | `cryptopp/include/cryptopp/`                                                                           |
| Bundled nlohmann-json                                 |  Done  | `nlohmann/json.hpp`                                                                                    |
| Bundled Catch2 single-header                          |  Done  | `catch2/catch.hpp`                                                                                     |

## 2. AES Modes and AEAD Support

| Requirement                     | Status | Evidence                                       |
| ------------------------------- | :----: | ---------------------------------------------- |
| AES ECB mode                    |  Done  | `--mode ecb`                                   |
| AES CBC mode                    |  Done  | `--mode cbc`                                   |
| AES OFB mode                    |  Done  | `--mode ofb`                                   |
| AES CFB mode                    |  Done  | `--mode cfb`                                   |
| AES CTR mode                    |  Done  | `--mode ctr`                                   |
| AES XTS mode                    |  Done  | `--mode xts`                                   |
| AES CCM AEAD mode               |  Done  | `--mode ccm --aead`                            |
| AES GCM AEAD mode               |  Done  | `--mode gcm --aead`                            |
| AAD file/text                   |  Done  | `--aad`, `--aad-text`                          |
| Authentication tag verification |  Done  | GCM/CCM decryption verifies authentication tag |
| Fail closed on invalid tag      |  Done  | Negative tests                                 |

## 3. Misuse Prevention and IV/Nonce Handling

| Requirement                   | Status | Evidence                                                                                                          |
| ----------------------------- | :----: | ----------------------------------------------------------------------------------------------------------------- |
| ECB warning                   |  Done  | ECB encryption output                                                                                             |
| ECB file-size restriction     |  Done  | Blocks files larger than 16 KiB unless `--allow-ecb` is provided                                                  |
| `--allow-ecb` override        |  Done  | CLI option                                                                                                        |
| IV/nonce length validation    |  Done  | CryptoConfig validation and invalid IV negative test                                                              |
| Auto IV/nonce generation      |  Done  | Crypto++ `AutoSeededRandomPool`                                                                                   |
| No insecure crypto randomness |  Done  | No `rand()`, `srand()`, `std::mt19937`, `std::default_random_engine`, or Python `random` for cryptographic values |
| GUI cryptographic randomness  |  Done  | PyQt6 GUI uses Python `secrets.token_hex()` for user-facing key and IV/nonce generation                           |
| Sidecar JSON metadata         |  Done  | Output `.json` file                                                                                               |
| Nonce reuse protection        |  Done  | `.nonce_db.json` and nonce reuse negative test                                                                    |

## 4. CLI and I/O Requirements

| Requirement                  | Status | Evidence                           |
| ---------------------------- | :----: | ---------------------------------- |
| `--key-hex`                  |  Done  | CLI option                         |
| `--key KEYFILE`              |  Done  | CLI option                         |
| Raw binary key file          |  Done  | Key file parser                    |
| Hex key file with header     |  Done  | Key file parser                    |
| `--iv`, `--nonce`            |  Done  | CLI options                        |
| `--iv-hex`, `--nonce-hex`    |  Done  | CLI options                        |
| `--in FILE`                  |  Done  | CLI option                         |
| `--text`                     |  Done  | CLI option                         |
| `--out FILE`                 |  Done  | CLI option                         |
| Screen output hex/base64/raw |  Done  | `--encode hex\|base64\|raw` option |

## 5. KAT and Negative Testing

| Requirement                       | Status | Evidence                       |
| --------------------------------- | :----: | ------------------------------ |
| KAT runner                        |  Done  | `--kat test_vectors.json`      |
| CBC KAT                           |  Done  | `test_vectors.json`            |
| CFB KAT                           |  Done  | `test_vectors.json`            |
| OFB KAT                           |  Done  | `test_vectors.json`            |
| CTR KAT                           |  Done  | `test_vectors.json`            |
| GCM KAT                           |  Done  | `test_vectors.json`            |
| CCM KAT                           |  Done  | `test_vectors.json`            |
| KAT summary output                |  Done  | Total: 6, Passed: 6, Failed: 0 |
| Negative tests                    |  Done  | `--negative-tests`             |
| Wrong key negative test           |  Done  | Negative test suite            |
| Wrong IV negative test            |  Done  | Negative test suite            |
| Tampered ciphertext negative test |  Done  | Negative test suite            |
| AEAD tampering / invalid tag test |  Done  | Negative test suite            |
| Invalid IV length test            |  Done  | Negative test suite            |
| Malformed input test              |  Done  | Negative test suite            |
| Nonce reuse detection test        |  Done  | Negative test suite            |
| Negative test summary output      |  Done  | Passed: 8/8                    |

## 6. Unit Testing and CTest

| Requirement                  | Status | Evidence                                                                       |
| ---------------------------- | :----: | ------------------------------------------------------------------------------ |
| Unit tests                   |  Done  | `tests/unit_tests.cpp` using Catch2                                            |
| Catch2 bundled single-header |  Done  | `catch2/catch.hpp`                                                             |
| CTest registration           |  Done  | `ctest --verbose`                                                              |
| Windows CTest                |  Done  | Windows CTest output screenshot/log                                            |
| Linux CTest                  |  Done  | Linux CTest output screenshot/log                                              |
| Current Windows CTest result |  Done  | `4/4 Test #4: unit_tests Passed`, `100% tests passed, 0 tests failed out of 4` |

## 7. Benchmark and Performance Evaluation

| Requirement                        | Status | Evidence                                                   |
| ---------------------------------- | :----: | ---------------------------------------------------------- |
| Benchmark                          |  Done  | `--compare`                                                |
| Benchmark payload sizes            |  Done  | 1 KB, 4 KB, 16 KB, 256 KB, 1 MB, 8 MB                      |
| Benchmark repeated runs            |  Done  | 30 repeated benchmark runs per OS                          |
| Benchmark mean                     |  Done  | `windows_benchmark_stats.csv`, `linux_benchmark_stats.csv` |
| Benchmark median                   |  Done  | `windows_benchmark_stats.csv`, `linux_benchmark_stats.csv` |
| Benchmark standard deviation       |  Done  | `windows_benchmark_stats.csv`, `linux_benchmark_stats.csv` |
| Benchmark 95% confidence interval  |  Done  | `windows_benchmark_stats.csv`, `linux_benchmark_stats.csv` |
| Benchmark plots                    |  Done  | `results/charts/*.png`                                     |
| Windows vs Linux comparison        |  Done  | Benchmark results from both OSes                           |
| Stream vs block comparison         |  Done  | CTR vs CBC benchmark tables and charts                     |
| AEAD vs non-AEAD comparison        |  Done  | GCM/CCM vs CBC/CTR benchmark tables and charts             |
| GCM vs CCM tag overhead comparison |  Done  | GCM vs CCM benchmark tables and charts                     |
| Performance analysis               |  Done  | `Lab1_Report.md` / benchmark analysis section          |

## 8. Security Engineering Discussion

| Requirement                   | Status | Evidence                                                                                  |
| ----------------------------- | :----: | ----------------------------------------------------------------------------------------- |
| Threat model                  |  Done  | `Lab1_Report.md`                                                      |
| Misuse cases                  |  Done  | `Lab1_Report.md`                                                                      |
| Known attacks discussion      |  Done  | ECB, CBC padding oracle, CTR nonce reuse, GCM nonce reuse, XTS integrity limitation       |
| Safe defaults                 |  Done  | Auto IV/nonce generation, ECB restriction, fail-closed handling                           |
| Fail-closed behavior          |  Done  | Negative tests and security discussion                                                    |
| Implementation limitations    |  Done  | Known Limitations section                                                                 |
| Proper randomness discussion  |  Done  | Crypto++ `AutoSeededRandomPool`, Python `secrets`, no insecure random APIs                |
| GUI security boundary         |  Done  | PyQt6 GUI calls compiled C++ `encrypt_tool`; it does not implement cryptography in Python |
| Bundled dependency discussion |  Done  | Crypto++ static libraries are bundled directly; vcpkg is not required during build        |

## 9. Documentation, GUI, and Academic Honesty

| Requirement                 | Status | Evidence                                           |
| --------------------------- | :----: | -------------------------------------------------- |
| README                      |  Done  | `README.md`                                        |
| Report                      |  Done  | `Lab1_Report.md`                                   |
| Security discussion         |  Done  | `Lab1_Report.md`                               |
| PyQt6 GUI source            |  Done  | `gui.py`                                           |
| GUI calls compiled tool     |  Done  | PyQt6 GUI uses `subprocess` to call `encrypt_tool` |
| Prebuilt Windows GUI binary |  Done  | `bin/windows/CryptoToolGUI.exe`                    |
| Prebuilt Linux GUI binary   |  Done  | `bin/linux/CryptoToolGUI`                          |
| Windows CLI binary          |  Done  | `bin/windows/encrypt_tool.exe`                     |
| Linux CLI binary            |  Done  | `bin/linux/encrypt_tool`                           |
| Academic honesty statement  |  Done  | `ACADEMIC_HONESTY.md`                              |
| Originality statement       |  Done  | `ACADEMIC_HONESTY.md`                              |
| AI/tool disclosure          |  Done  | `ACADEMIC_HONESTY.md` / report section             |
| External references         |  Done  | Report references section                          |

## 10. Final Submission Notes

* The final submission includes both source code and prebuilt binaries.
* The project no longer depends on vcpkg during build.
* Crypto++ is bundled directly as platform-specific static libraries.
* The Windows Crypto++ library is located at `cryptopp/lib/windows/libcryptopp.a`.
* The Linux Crypto++ library is located at `cryptopp/lib/linux/libcryptopp.a`.
* The Windows CLI executable is located at `bin/windows/encrypt_tool.exe`.
* The Linux CLI executable is located at `bin/linux/encrypt_tool`.
* The Windows PyQt6 GUI executable is located at `bin/windows/CryptoToolGUI.exe`.
* The Linux PyQt6 GUI executable is located at `bin/linux/CryptoToolGUI`.
* Benchmark statistics were generated from repeated runs and include mean, median, standard deviation, and 95% confidence interval.
* The PyQt6 GUI is a frontend that calls the compiled C++ command-line executable. It does not reimplement cryptographic logic in Python.
* A Windows `.exe` file is not used as a Linux binary. Separate binaries are provided for Windows and Linux.
