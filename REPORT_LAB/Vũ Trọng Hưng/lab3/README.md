# Lab 3 — RSA-OAEP and Hybrid Encryption

## 1. Overview

This project implements RSA-OAEP encryption/decryption using SHA-256 and hybrid envelope encryption using RSA-OAEP + AES-256-GCM.

The tool supports:

* RSA-3072 key generation
* RSA-4096 key generation for performance comparison
* RSA-OAEP with SHA-256
* MGF1 with SHA-256
* Optional OAEP label binding
* Automatic hybrid encryption for large plaintexts
* AES-256-GCM authenticated encryption
* JSON-based hybrid envelope format
* Negative tests
* Unit tests with Catch2
* Manual OAEP padding demonstration
* Performance benchmarking on Windows and Linux
* Benchmark statistics and plots
* Prebuilt binaries for Windows and Linux

Executable name:

```text
rsatool
```

This lab is a command-line tool. It does not include a GUI.

---

## 2. Algorithms and Parameters

### 2.1 RSA-OAEP

| Parameter        | Setting            |
| ---------------- | ------------------ |
| Modulus size     | RSA-3072, RSA-4096 |
| Hash function    | SHA-256            |
| Padding          | OAEP               |
| MGF              | MGF1 with SHA-256  |
| Minimum RSA size | 3072 bits          |

The theoretical RSA-OAEP plaintext limit is:

```text
mLen <= k - 2hLen - 2
```

where:

* `k` is the RSA modulus length in bytes
* `hLen` is the hash output length
* SHA-256 has `hLen = 32`

For RSA-3072:

```text
384 - 2*32 - 2 = 318 bytes
```

For RSA-4096:

```text
512 - 2*32 - 2 = 446 bytes
```

The implementation also binds the optional label by including `SHA256(label)` inside the encrypted plaintext frame. Therefore, the usable direct RSA plaintext payload is reduced by 32 bytes. Larger inputs are automatically encrypted using hybrid mode.

### 2.2 Hybrid Encryption

For plaintexts exceeding the RSA-OAEP direct limit, the tool automatically switches to hybrid encryption.

Hybrid encryption workflow:

1. Generate a random 256-bit AES key.
2. Generate a 96-bit AES-GCM IV.
3. Encrypt plaintext using AES-256-GCM.
4. Encrypt the AES key using RSA-OAEP.
5. Store all required parameters in a JSON envelope.

Hybrid envelope example:

```json
{
  "mode": "RSA-OAEP-AES-GCM",
  "rsa_modulus": 3072,
  "hash": "SHA-256",
  "wrapped_key": "<base64>",
  "iv": "<base64>",
  "tag": "<base64>",
  "ciphertext": "<base64>"
}
```

AES-GCM provides authenticated encryption. If the ciphertext, IV, authentication tag, wrapped key, label, or envelope metadata is modified, decryption fails.

---

## 3. Dependencies

This submission uses bundled third-party dependencies located at the root of `Vũ Trọng Hưng`.

No additional C++ libraries need to be downloaded if the bundled folder structure is preserved.

This project does **not** require vcpkg during build. Crypto++ is linked directly from the bundled platform-specific static libraries.

### 3.1 Bundled C++ Dependencies

| Dependency           | Location                                          | Purpose                                              |
| -------------------- | ------------------------------------------------- | ---------------------------------------------------- |
| Crypto++ for Windows | `Vũ Trọng Hưng/cryptopp/lib/windows/libcryptopp.a` | RSA-OAEP, AES-GCM, SHA-256, secure random generation |
| Crypto++ for Linux   | `Vũ Trọng Hưng/cryptopp/lib/linux/libcryptopp.a`   | Linux static Crypto++ library                        |
| Crypto++ headers     | `Vũ Trọng Hưng/cryptopp/include/cryptopp/`         | Crypto++ header files                                |
| nlohmann-json        | `Vũ Trọng Hưng/nlohmann/json.hpp`                  | JSON envelope and metadata handling                  |
| Catch2               | `Vũ Trọng Hưng/catch2/catch.hpp`                   | Unit testing                                         |

Important compatibility notes:

* The Windows Crypto++ static library must be built with the same MinGW compiler used to build this project.
* The Linux Crypto++ static library must be an ELF library built on Linux.
* Do not use a Windows/MinGW `libcryptopp.a` on Linux.
* Do not use a Linux `libcryptopp.a` on Windows.
* The project does not depend on vcpkg.

### 3.2 Required Build Tools

| Platform     | Required Tools                               |
| ------------ | -------------------------------------------- |
| Windows      | CMake, MinGW-w64 g++, mingw32-make, Python 3 |
| Linux / Kali | CMake, g++, make, Python 3                   |

### 3.3 Required Python Packages

Python packages are only required for benchmark statistics and charts.

Windows:

```powershell
pip install pandas matplotlib
```

Linux/Kali:

```bash
python3 -m pip install pandas matplotlib
```

If Linux blocks pip installation, use:

```bash
sudo apt install -y python3-pandas python3-matplotlib
```

### 3.4 Tested Environment

| Platform   | Compiler                     | CMake       | Crypto++                        | nlohmann-json               |
| ---------- | ---------------------------- | ----------- | ------------------------------- | --------------------------- |
| Windows    | g++ 16.1.0 MinGW-w64 / MSYS2 | CMake 4.3.3 | bundled Windows `libcryptopp.a` | bundled `nlohmann/json.hpp` |
| Linux/Kali | g++ 14.3.0                   | CMake 4.3.2 | bundled Linux `libcryptopp.a`   | bundled `nlohmann/json.hpp` |

Useful version check commands:

Windows:

```powershell
cmake --version
g++ --version
where g++
python --version
pip show pandas
pip show matplotlib
```

Linux/Kali:

```bash
cmake --version
g++ --version
python3 --version
python3 -c "import pandas; print(pandas.__version__)"
python3 -c "import matplotlib; print(matplotlib.__version__)"
```

---

## 4. Expected Folder Structure

The project expects this folder layout:

```text
Vũ Trọng Hưng/
├── catch2/
│   └── catch.hpp
├── nlohmann/
│   └── json.hpp
├── cryptopp/
│   ├── include/
│   │   └── cryptopp/
│   └── lib/
│       ├── windows/
│       │   └── libcryptopp.a
│       └── linux/
│           └── libcryptopp.a
├── lab1/
└── lab3/
    ├── README.md
    ├── Lab3_Report.md
    ├── SELF_GRADE_CHECKLIST.md
    ├── ACADEMIC_HONESTY.md
    └── lab3/
        ├── CMakeLists.txt
        ├── main.cpp
        ├── RSAConfig.cpp
        ├── RSAConfig.hpp
        ├── RSAKeyManager.cpp
        ├── RSAKeyManager.hpp
        ├── RSAEngine.cpp
        ├── RSAEngine.hpp
        ├── HybridEncryptor.cpp
        ├── HybridEncryptor.hpp
        ├── RSAValidator.cpp
        ├── RSAValidator.hpp
        ├── RSABenchmarker.cpp
        ├── RSABenchmarker.hpp
        ├── NegativeTests.cpp
        ├── NegativeTests.hpp
        ├── ManualOAEP.cpp
        ├── ManualOAEP.hpp
        ├── OAEPValidator.cpp
        ├── tests/
        │   └── unit_tests.cpp
        ├── scripts/
        ├── results/
        └── bin/
            ├── windows/
            │   └── rsatool.exe
            └── linux/
                └── rsatool
```

Important notes:

* The Lab3 source code is inside `Vũ Trọng Hưng/lab3/lab3`.
* Bundled libraries are placed at the root of `Vũ Trọng Hưng`.
* Windows uses the bundled Windows-built Crypto++ static library at `cryptopp/lib/windows/libcryptopp.a`.
* Linux uses the bundled Linux-built Crypto++ static library at `cryptopp/lib/linux/libcryptopp.a`.
* `nlohmann/json.hpp` is located at the root-level `nlohmann/` folder.
* Catch2 is provided through the root-level `catch2/catch.hpp` single-header file.
* The Windows Crypto++ static library must not be used on Linux.
* The Linux Crypto++ static library must not be used on Windows.
* Lab3 does not include a GUI.

---

## 5. Build Instructions

The project can be built from source using CMake. The `build/` and `build_linux/` folders are generated build folders. The `bin/` folder stores the final prebuilt binaries for submission.

### 5.1 Windows Build

From the Lab3 source directory:

```powershell
cd Vũ Trọng Hưng\lab3\lab3

Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue

cmake -S . -B build -G "MinGW Makefiles"

cmake --build build
```

Run the built executable:

```powershell
.\build\rsatool.exe --help
```

Run tests:

```powershell
cd build
ctest --verbose
```

Expected result:

```text
100% tests passed
```

Copy the Windows binary into the submission `bin/` folder:

```powershell
cd ..

mkdir bin -ErrorAction SilentlyContinue
mkdir bin\windows -ErrorAction SilentlyContinue

copy build\rsatool.exe bin\windows\rsatool.exe
```

Run the submitted Windows binary from `bin/`:

```powershell
.\bin\windows\rsatool.exe --help
```

### 5.2 Linux / Kali Build

From the Lab3 source directory:

```bash
cd ~/Desktop/Vũ Trọng Hưng/lab3/lab3

rm -rf build_linux

cmake -S . -B build_linux

cmake --build build_linux -j$(nproc)
```

Run the built executable:

```bash
./build_linux/rsatool --help
```

Run tests:

```bash
cd build_linux
ctest --verbose
```

Expected result:

```text
100% tests passed
```

If the executable has no execute permission:

```bash
chmod +x build_linux/rsatool
```

Copy the Linux binary into the submission `bin/` folder:

```bash
cd ..

mkdir -p bin/linux
cp build_linux/rsatool bin/linux/rsatool
chmod +x bin/linux/rsatool
```

Run the submitted Linux binary from `bin/`:

```bash
chmod +x bin/linux/rsatool
./bin/linux/rsatool --help
```

---

## 6. Running Prebuilt Binaries

Because the final submission includes the `bin/` folder, the examples below may use the prebuilt binaries.

From `Vũ Trọng Hưng/lab3/lab3`:

Windows:

```powershell
.\bin\windows\rsatool.exe --help
```

Linux/Kali:

```bash
chmod +x bin/linux/rsatool
./bin/linux/rsatool --help
```

Do not rename the Windows `.exe` file as a Linux binary. The Windows binary must be built on Windows, and the Linux binary must be built on Linux/Kali.

---

## 7. CLI Usage

General format:

```bash
rsatool <command> [options]
```

Supported commands:

```text
keygen
encrypt
decrypt
--kat
--test-vectors
--test-nist
--negative-tests
--manual-oaep-test
--benchmark
--help
```

### 7.1 Key Generation

Generate RSA-3072 keys:

```bash
rsatool keygen --bits 3072 --pub pub.pem --priv priv.pem
```

Generate RSA-4096 keys:

```bash
rsatool keygen --bits 4096 --pub pub4096.pem --priv priv4096.pem
```

The tool saves key material and metadata including:

```json
{
  "creation_time": "...",
  "modulus_bits": 3072,
  "hash": "SHA-256",
  "padding": "OAEP",
  "mgf": "MGF1-SHA256"
}
```

The generated files include:

```text
pub.pem
priv.pem
pub.der
priv.der
pub.pem.metadata.json
```

### 7.2 Encryption

```bash
rsatool encrypt --in msg.bin --pub pub.pem --out ct.bin --label optional
```

If plaintext exceeds the RSA-OAEP limit, the tool automatically uses hybrid encryption.

For hybrid mode, the ciphertext payload is written to the selected output file and the JSON envelope metadata is written to:

```text
ct.bin.json
```

### 7.3 Decryption

```bash
rsatool decrypt --in ct.bin --priv priv.pem --out msg_out.bin --label optional
```

The same OAEP label used during encryption must be used during decryption. If the wrong label is provided, decryption fails.

### 7.4 Supported Formats

The project supports:

| Item               | Format            |
| ------------------ | ----------------- |
| Public key         | PEM and DER       |
| Private key        | PEM and DER       |
| Metadata           | JSON              |
| Hybrid envelope    | JSON              |
| Wrapped AES key    | Base64            |
| AES-GCM IV         | Base64            |
| AES-GCM tag        | Base64            |
| Payload ciphertext | Raw binary output |

---

## 8. CLI Test Examples

The examples below assume the commands are run from:

```text
Vũ Trọng Hưng/lab3/lab3
```

### 8.1 Windows CLI Test

```powershell
Remove-Item -Recurse -Force cli_test -ErrorAction SilentlyContinue
mkdir cli_test

.\build\rsatool.exe keygen --bits 3072 --pub cli_test\pub.pem --priv cli_test\priv.pem

"Hello RSA OAEP Lab 3" | Out-File -Encoding ascii cli_test\msg.txt

.\build\rsatool.exe encrypt --in cli_test\msg.txt --pub cli_test\pub.pem --out cli_test\ct.bin --label testlabel

.\build\rsatool.exe decrypt --in cli_test\ct.bin --priv cli_test\priv.pem --out cli_test\msg_out.txt --label testlabel

Get-Content cli_test\msg_out.txt
```

Expected output:

```text
Hello RSA OAEP Lab 3
```

Wrong label test:

```powershell
.\build\rsatool.exe decrypt --in cli_test\ct.bin --priv cli_test\priv.pem --out cli_test\wrong_label.txt --label wronglabel
```

Expected result: decryption fails.

Hybrid 1 MiB test:

```powershell
fsutil file createnew cli_test\large.bin 1048576

.\build\rsatool.exe encrypt --in cli_test\large.bin --pub cli_test\pub.pem --out cli_test\large_ct.bin --label hybrid

.\build\rsatool.exe decrypt --in cli_test\large_ct.bin --priv cli_test\priv.pem --out cli_test\large_out.bin --label hybrid

Get-FileHash cli_test\large.bin
Get-FileHash cli_test\large_out.bin
```

Expected result: both hashes are identical.

### 8.2 Linux / Kali CLI Test

```bash
rm -rf cli_test
mkdir -p cli_test

./build_linux/rsatool keygen --bits 3072 --pub cli_test/pub.pem --priv cli_test/priv.pem

echo "Hello RSA OAEP Lab 3" > cli_test/msg.txt

./build_linux/rsatool encrypt --in cli_test/msg.txt --pub cli_test/pub.pem --out cli_test/ct.bin --label testlabel

./build_linux/rsatool decrypt --in cli_test/ct.bin --priv cli_test/priv.pem --out cli_test/msg_out.txt --label testlabel

cat cli_test/msg_out.txt
```

Expected output:

```text
Hello RSA OAEP Lab 3
```

Wrong label test:

```bash
./build_linux/rsatool decrypt --in cli_test/ct.bin --priv cli_test/priv.pem --out cli_test/wrong_label.txt --label wronglabel
```

Expected result: decryption fails.

Hybrid 1 MiB test:

```bash
dd if=/dev/urandom of=cli_test/large.bin bs=1M count=1

./build_linux/rsatool encrypt --in cli_test/large.bin --pub cli_test/pub.pem --out cli_test/large_ct.bin --label hybrid

./build_linux/rsatool decrypt --in cli_test/large_ct.bin --priv cli_test/priv.pem --out cli_test/large_out.bin --label hybrid

sha256sum cli_test/large.bin cli_test/large_out.bin
```

Expected result: both hashes are identical.

---

## 9. Negative Tests

Windows:

```powershell
.\build\rsatool.exe --negative-tests
```

Linux/Kali:

```bash
./build_linux/rsatool --negative-tests
```

Expected result:

```text
Passed: 7/7
```

The negative tests validate:

* altered RSA ciphertext rejection
* altered AES-GCM ciphertext rejection
* wrong private key rejection
* wrong OAEP label rejection
* tampered envelope header rejection
* invalid RSA key size rejection
* malformed ciphertext rejection

---

## 10. Manual OAEP Test

Windows:

```powershell
.\build\rsatool.exe --manual-oaep-test
```

Linux/Kali:

```bash
./build_linux/rsatool --manual-oaep-test
```

Expected output includes:

```text
Verification: PASSED
Wrong label correctly rejected
```

This demonstrates manual OAEP encoding, decoding, MGF1, XOR masking, padding validation, wrong-label rejection, and constant-time comparison.

---

## 11. Unit Testing

This project uses Catch2 single-header unit tests.

Windows:

```powershell
cd Vũ Trọng Hưng\lab3\lab3\build

ctest --verbose

.\rsatool.exe --negative-tests

.\rsatool.exe --manual-oaep-test
```

Linux/Kali:

```bash
cd ~/Desktop/Vũ Trọng Hưng/lab3/lab3/build_linux

ctest --verbose

./rsatool --negative-tests

./rsatool --manual-oaep-test
```

Expected results:

```text
100% tests passed
Passed: 7/7
```

---

## 12. Benchmarking

### 12.1 Windows Benchmark

Run from `Vũ Trọng Hưng/lab3/lab3`:

```powershell
python .\scripts\run_windows_benchmarks.py

python .\scripts\analyze_rsa_benchmark_stats.py --input-dir .\results\windows_runs --out .\results\windows_benchmark_stats.csv --os-name Windows

python .\scripts\plot_rsa_stats.py --stats .\results\windows_benchmark_stats.csv --out-dir .\results\charts
```

### 12.2 Linux Benchmark

Run from `Vũ Trọng Hưng/lab3/lab3`:

```bash
python3 scripts/run_linux_benchmarks.py

python3 scripts/analyze_rsa_benchmark_stats.py --input-dir results/linux_runs --out results/linux_benchmark_stats.csv --os-name Linux

python3 scripts/plot_rsa_stats.py --stats results/linux_benchmark_stats.csv --out-dir results/charts
```

### 12.3 Windows vs Linux Comparison

Run after both `windows_benchmark_stats.csv` and `linux_benchmark_stats.csv` exist.

Linux/Kali:

```bash
python3 scripts/plot_os_comparison.py \
  --windows results/windows_benchmark_stats.csv \
  --linux results/linux_benchmark_stats.csv \
  --out-dir results/charts
```

Windows PowerShell:

```powershell
python .\scripts\plot_os_comparison.py --windows .\results\windows_benchmark_stats.csv --linux .\results\linux_benchmark_stats.csv --out-dir .\results\charts
```

Benchmark outputs include:

* mean
* median
* standard deviation
* 95% confidence interval
* latency plots
* throughput plots
* Windows vs Linux comparison plots

---

## 13. Security Notes

The implementation validates:

* malformed ciphertext
* wrong private key
* wrong OAEP label
* tampered RSA ciphertext
* tampered AES-GCM ciphertext
* tampered envelope header
* invalid RSA key size
* malformed JSON envelope
* invalid PEM/DER key format

The program follows fail-closed behavior: invalid inputs are rejected and do not produce plaintext output.

AES-GCM authentication tag verification is handled by Crypto++.

The tool uses Crypto++ secure randomness facilities and does not use `rand()`, `srand()`, `std::mt19937`, `std::default_random_engine`, or Python `random` for cryptographic randomness.

---

## 14. Known Limitations

* The manual OAEP implementation is included for educational validation. Production encryption/decryption uses Crypto++.
* RSA-OAEP is only suitable for small messages or key wrapping.
* Hybrid encryption is required for large files.
* Windows and Linux benchmark results may differ due to compiler, OS scheduler, Crypto++ build options, VM overhead, and hardware acceleration behavior.
* Pure RSA key transport does not provide forward secrecy. A stronger real-world design should use ECDHE or ML-KEM-style key establishment.
* The implementation does not provide a full production key-management system.
* The implementation does not guarantee secure deletion of plaintext or key material from memory.
* The tool does not perform certificate-based public key identity validation.
* The implementation is suitable for controlled lab benchmarks, but a production file encryption tool should use streaming encryption for very large files.
* Lab3 is a command-line tool and does not include a GUI.

---

## 15. Binaries

Prebuilt binaries are included in:

```text
bin/
├── windows/
│   └── rsatool.exe
└── linux/
    └── rsatool
```

Run Windows binary:

```powershell
.\bin\windows\rsatool.exe --help
```

Run Linux binary:

```bash
chmod +x ./bin/linux/rsatool
./bin/linux/rsatool --help
```

Do not rename the Windows `.exe` file as a Linux binary. The Windows binary must be built on Windows, and the Linux binary must be built on Linux/Kali.

---

## 16. Submission Contents

The final submission includes source code, CMake build configuration, unit tests, scripts, benchmark results, charts, reports, academic honesty statement, self-grade checklist, and prebuilt binaries for both Windows and Linux.

```text
Vũ Trọng Hưng/
├── catch2/
│   └── catch.hpp
├── nlohmann/
│   └── json.hpp
├── cryptopp/
│   ├── include/
│   │   └── cryptopp/
│   └── lib/
│       ├── windows/
│       │   └── libcryptopp.a
│       └── linux/
│           └── libcryptopp.a
├── lab1/
└── lab3/
    ├── README.md
    ├── Lab3_Report.md
    ├── SELF_GRADE_CHECKLIST.md
    ├── ACADEMIC_HONESTY.md
    └── lab3/
        ├── CMakeLists.txt
        ├── main.cpp
        ├── RSAConfig.cpp
        ├── RSAConfig.hpp
        ├── RSAKeyManager.cpp
        ├── RSAKeyManager.hpp
        ├── RSAEngine.cpp
        ├── RSAEngine.hpp
        ├── HybridEncryptor.cpp
        ├── HybridEncryptor.hpp
        ├── RSAValidator.cpp
        ├── RSAValidator.hpp
        ├── RSABenchmarker.cpp
        ├── RSABenchmarker.hpp
        ├── NegativeTests.cpp
        ├── NegativeTests.hpp
        ├── ManualOAEP.cpp
        ├── ManualOAEP.hpp
        ├── OAEPValidator.cpp
        ├── tests/
        │   └── unit_tests.cpp
        ├── scripts/
        ├── results/
        └── bin/
            ├── windows/
            │   └── rsatool.exe
            └── linux/
                └── rsatool
```
