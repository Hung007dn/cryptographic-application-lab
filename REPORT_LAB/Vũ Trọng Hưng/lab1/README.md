# Lab 1 — Symmetric Encryption with Crypto++

## 1. Lab Name

Lab 1 — Symmetric Encryption with Crypto++

---

## 2. Objective

The objective of this lab is to implement a cross-platform AES encryption tool using Crypto++. The tool supports multiple AES modes, secure IV/nonce handling, authenticated encryption modes, known answer tests, negative tests, unit tests, benchmarking, statistical analysis, plotting, and a PyQt6 graphical user interface.

The main goals are:

* Use Crypto++ safely for symmetric encryption.
* Support multiple AES modes selected at runtime.
* Correctly handle IVs and nonces.
* Prevent common cryptographic misuse such as ECB misuse and nonce reuse.
* Validate correctness using official-style test vectors.
* Benchmark performance across different modes and payload sizes.
* Collect benchmark statistics: mean, median, standard deviation, and 95% confidence interval.
* Build and test the project on both Windows and Linux using CMake.
* Provide both command-line usage and a PyQt6 GUI frontend.

---

## 3. Dependencies

This submission uses bundled third-party dependencies located at the root of `Vũ Trọng Hưng`.

No additional C++ libraries need to be downloaded if the bundled folder structure is preserved.

Crypto++ is linked directly from bundled static libraries.

### 3.1 Bundled C++ Dependencies

| Dependency           | Location                                          | Purpose                                         |
| -------------------- | ------------------------------------------------- | ----------------------------------------------- |
| Crypto++ for Windows | `Vũ Trọng Hưng/cryptopp/lib/windows/libcryptopp.a` | AES modes, AEAD modes, secure random generation |
| Crypto++ for Linux   | `Vũ Trọng Hưng/cryptopp/lib/linux/libcryptopp.a`   | Linux static Crypto++ library                   |
| Crypto++ headers     | `Vũ Trọng Hưng/cryptopp/include/cryptopp/`         | Crypto++ header files                           |
| nlohmann-json        | `Vũ Trọng Hưng/nlohmann/json.hpp`                  | JSON sidecar files and metadata                 |
| Catch2               | `Vũ Trọng Hưng/catch2/catch.hpp`                   | Unit testing                                    |

Important compatibility notes:

* The Windows Crypto++ static library must be built with the same MinGW compiler used to build this project.
* The Linux Crypto++ static library must be an ELF library built on Linux.
* Do not use a Windows/MinGW `libcryptopp.a` on Linux.
* Do not use a Linux `libcryptopp.a` on Windows.

### 3.2 Required Build Tools

| Platform     | Required Tools                               |
| ------------ | -------------------------------------------- |
| Windows      | CMake, MinGW-w64 g++, mingw32-make, Python 3 |
| Linux / Kali | CMake, g++, make, Python 3                   |

### 3.3 Required Python Packages

Python packages are required for benchmark statistics, plotting, and the PyQt6 GUI.

Windows:

```powershell
pip install pandas matplotlib PyQt6 pyinstaller
```

Linux/Kali:

```bash
python3 -m pip install pandas matplotlib PyQt6 pyinstaller
```

If Linux blocks pip installation, use:

```bash
sudo apt install -y python3-pandas python3-matplotlib python3-pyqt6
python3 -m pip install pyinstaller --break-system-packages
```

### 3.4 Tested Environment

| Platform   | Compiler                     | CMake       | Crypto++                        | Python GUI                         |
| ---------- | ---------------------------- | ----------- | ------------------------------- | ---------------------------------- |
| Windows    | g++ 16.1.0 MinGW-w64 / MSYS2 | CMake 4.3.3 | bundled Windows `libcryptopp.a` | PyQt6 / PyInstaller GUI executable |
| Linux/Kali | g++ 14.3.0                   | CMake 4.3.2 | bundled Linux `libcryptopp.a`   | PyQt6 / PyInstaller GUI executable |

Useful version check commands:

Windows:

```powershell
cmake --version
g++ --version
where g++
python --version
pip show pandas
pip show matplotlib
pip show PyQt6
```

Linux/Kali:

```bash
cmake --version
g++ --version
python3 --version
python3 -c "import pandas; print(pandas.__version__)"
python3 -c "import matplotlib; print(matplotlib.__version__)"
python3 -c "import PyQt6; print('PyQt6 available')"
```

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
│   ├── README.md
│   ├── SELF_GRADE_CHECKLIST.md
│   ├── ACADEMIC_HONESTY.md
│   ├── Lab1_Report.md
│   └── lab1/
│       ├── CMakeLists.txt
│       ├── main.cpp
│       ├── CryptoConfig.cpp / .hpp
│       ├── FileEncryptor.cpp / .hpp
│       ├── KATRunner.cpp / .hpp
│       ├── NISTValidator.cpp / .hpp
│       ├── NegativeTests.cpp / .hpp
│       ├── Benchmarker.cpp / .hpp
│       ├── test_vectors.json
│       ├── gui.py
│       ├── requirements.txt
│       ├── plot_benchmarks.py
│       ├── tests/
│       │   └── unit_tests.cpp
│       ├── scripts/
│       │   ├── run_windows_aes_benchmarks.py
│       │   ├── run_linux_aes_benchmarks.py
│       │   ├── analyze_benchmark_stats.py
│       │   ├── plot_stats_charts.py
│       │   └── compare_os_benchmark_stats.py
│       ├── results/
│       │   ├── windows_benchmark_stats.csv
│       │   ├── linux_benchmark_stats.csv
│       │   ├── os_comparison_benchmark_stats.csv
│       │   ├── windows_runs/
│       │   │   └── performance_report_windows_run_01.csv ... performance_report_windows_run_30.csv
│       │   ├── linux_runs/
│       │   │   └── performance_report_linux_run_01.csv ... performance_report_linux_run_30.csv
│       │   └── charts/
│       │       ├── windows_*.png
│       │       ├── linux_*.png
│       │       └── os_comparison_*.png
│       └── bin/
│           ├── windows/
│           │   ├── encrypt_tool.exe
│           │   └── CryptoToolGUI.exe
│           └── linux/
│               ├── encrypt_tool
│               └── CryptoToolGUI
```

Important notes:

* The Lab1 source code is inside `Vũ Trọng Hưng/lab1/lab1`.
* Bundled libraries are placed at the root of `Vũ Trọng Hưng`.
* Windows uses the bundled Windows-built Crypto++ static library at `cryptopp/lib/windows/libcryptopp.a`.
* Linux uses the bundled Linux-built Crypto++ static library at `cryptopp/lib/linux/libcryptopp.a`.
* `nlohmann/json.hpp` is located at the root-level `nlohmann/` folder.
* Catch2 is provided through the root-level `catch2/catch.hpp` single-header file.
* The benchmark scripts are located in `scripts/` and generate repeated-run CSV files, statistics CSV files, and report-ready charts.
* The GUI source is `gui.py` and is implemented with PyQt6.
* The GUI does not implement cryptography in Python. It calls the compiled C++ `encrypt_tool` executable through `subprocess`.

---




## 5. Build Instructions

The project can be built from source using CMake. The `build/` and `build_linux/` folders are generated build folders. The `bin/` folder stores the final prebuilt binaries for submission.

### 5.1 Windows Build

From the Lab1 source directory:

```powershell
cd Vũ Trọng Hưng\lab1\lab1

Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue

cmake -S . -B build -G "MinGW Makefiles"

cmake --build build
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

Run the built executable:

```powershell
.\encrypt_tool.exe --help
```

Copy the Windows binary into the submission `bin/` folder:

```powershell
cd ..

mkdir bin -ErrorAction SilentlyContinue
mkdir bin\windows -ErrorAction SilentlyContinue

copy build\encrypt_tool.exe bin\windows\encrypt_tool.exe
```

Run the submitted Windows binary from `bin/`:

```powershell
.\bin\windows\encrypt_tool.exe --help
```

### 5.2 Linux / Kali Build

From the Lab1 source directory:

```bash
cd ~/Desktop/Vũ Trọng Hưng/lab1/lab1

rm -rf build_linux

cmake -S . -B build_linux

cmake --build build_linux -j$(nproc)
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

Run the built executable:

```bash
./encrypt_tool --help
```

Copy the Linux binary into the submission `bin/` folder:

```bash
cd ..

mkdir -p bin/linux
cp build_linux/encrypt_tool bin/linux/encrypt_tool
chmod +x bin/linux/encrypt_tool
```

Run the submitted Linux binary from `bin/`:

```bash
chmod +x bin/linux/encrypt_tool
./bin/linux/encrypt_tool --help
```

---

## 6. Running Prebuilt Binaries

Because the final submission includes the `bin/` folder, the examples below use the prebuilt binaries.

From `Vũ Trọng Hưng/lab1/lab1`:

Windows:

```powershell
.\bin\windows\encrypt_tool.exe --help
```

Linux/Kali:

```bash
chmod +x bin/linux/encrypt_tool
./bin/linux/encrypt_tool --help
```

Do not rename the Windows `.exe` file as a Linux binary. The Windows binary must be built on Windows, and the Linux binary must be built on Linux/Kali.

---

## 7. CLI Usage

General format:

```bash
encrypt_tool <command> [options]
```

Supported commands:

```bash
encrypt
decrypt
--kat
--negative-tests
--benchmark
--compare
```

Common options:

```bash
--in INFILE
--text "message"
--out OUTFILE
--key KEYFILE
--key-hex HEX
--iv IVFILE
--iv-hex HEX
--nonce NONCEFILE
--nonce-hex HEX
--mode ecb|cbc|ofb|cfb|ctr|xts|ccm|gcm
--aead
--aad FILE
--aad-text STRING
--allow-ecb
--encode hex|base64|raw
--verbose
```

---

## 8. Encryption and Decryption Examples

The examples below assume the commands are run from:

```text
Vũ Trọng Hưng/lab1/lab1
```

### 8.1 Windows AES-GCM Encryption

```powershell
.\bin\windows\encrypt_tool.exe encrypt --mode gcm --key-hex 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF --text "hello lab" --out ct.bin --aad-text "meta" --aead
```

This creates:

```text
ct.bin
ct.bin.json
```

The JSON sidecar stores IV/nonce, AAD, authentication tag, algorithm, and mode.

### 8.2 Windows AES-GCM Decryption

```powershell
.\bin\windows\encrypt_tool.exe decrypt --mode gcm --key-hex 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF --in ct.bin --out pt.txt --aead
```

Check output:

```powershell
type pt.txt
```

### 8.3 Linux/Kali AES-GCM Encryption

```bash
./bin/linux/encrypt_tool encrypt --mode gcm --key-hex 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF --text "hello lab" --out ct.bin --aad-text "meta" --aead
```

### 8.4 Linux/Kali AES-GCM Decryption

```bash
./bin/linux/encrypt_tool decrypt --mode gcm --key-hex 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF --in ct.bin --out pt.txt --aead

cat pt.txt
```

### 8.5 AES-CTR Encryption

Windows:

```powershell
.\bin\windows\encrypt_tool.exe encrypt --mode ctr --key-hex 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF --text "hello ctr" --out ctr.bin
```

Linux/Kali:

```bash
./bin/linux/encrypt_tool encrypt --mode ctr --key-hex 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF --text "hello ctr" --out ctr.bin
```

### 8.6 ECB Demonstration

ECB is insecure. The tool prints a warning when ECB is used.

Windows:

```powershell
.\bin\windows\encrypt_tool.exe encrypt --mode ecb --key-hex 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF --text "hello ecb" --out ecb.bin
```

Linux/Kali:

```bash
./bin/linux/encrypt_tool encrypt --mode ecb --key-hex 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF --text "hello ecb" --out ecb.bin
```

For files larger than 16 KiB, ECB is blocked unless `--allow-ecb` is provided.

---

## 9. KAT Testing

Run known answer tests using the submitted binaries.

Windows:

```powershell
.\bin\windows\encrypt_tool.exe --kat test_vectors.json
```

Linux/Kali:

```bash
./bin/linux/encrypt_tool --kat test_vectors.json
```

Expected output:

```text
PASS/FAIL per test case
Summary of total passed and failed tests
```

Current KAT result:

```text
Total: 6
Passed: 6
Failed: 0
Success rate: 100%
```

---

## 10. Negative Testing

Windows:

```powershell
.\bin\windows\encrypt_tool.exe --negative-tests
```

Linux/Kali:

```bash
./bin/linux/encrypt_tool --negative-tests
```

The negative tests demonstrate:

* Wrong key handling
* Wrong IV handling
* Tampered ciphertext
* Tampered AEAD ciphertext
* Invalid authentication tag
* Invalid IV length
* Malformed input handling
* Nonce reuse detection
* Fail-closed behavior

Current negative test result:

```text
Passed: 8/8
```

---

## 11. Unit Testing with Catch2 and CTest

The project includes Catch2 unit tests in:

```text
tests/unit_tests.cpp
```

CTest is configured through CMake. After building, run:

Windows:

```powershell
cd Vũ Trọng Hưng\lab1\lab1\build
ctest --verbose
```

Linux/Kali:

```bash
cd ~/Desktop/Vũ Trọng Hưng/lab1/lab1/build_linux
ctest --verbose
```

Expected result:

```text
100% tests passed
```

Current Windows CTest result:

```text
4/4 Test #4: unit_tests  Passed
100% tests passed, 0 tests failed out of 4
```

These tests verify that the CLI help works, the KAT runner passes, the negative test suite passes, and the static unit checks are valid.

---

## 12. Basic Benchmark

The project provides two benchmark commands:

```bash
encrypt_tool --benchmark
encrypt_tool --compare
```

`--benchmark` is a quick benchmark used for a single all-mode performance check. It exports:

```text
benchmark_results.csv
```

`--compare` is the benchmark command used for the standardized statistical performance evaluation. It exports:

```text
performance_report.csv
```

The `--compare` benchmark evaluates:

* AES-256-CBC
* AES-256-CTR
* AES-256-GCM
* AES-256-CCM

The benchmark payload sizes are:

* 1 KB
* 4 KB
* 16 KB
* 256 KB
* 1 MB
* 8 MB

The measured metrics are:

* Encryption latency per operation in milliseconds
* Decryption latency per operation in milliseconds
* Throughput in MB/s
* Iteration count

The standardized benchmark uses:

```text
Iterations = 1000
```

for each measured mode and payload size in `performance_report.csv`.

Run one Windows benchmark:

```powershell
cd Vũ Trọng Hưng\lab1\lab1\build

.\encrypt_tool.exe --compare
```

Run one Linux/Kali benchmark:

```bash
cd ~/Desktop/Vũ Trọng Hưng/lab1/lab1/build_linux

./encrypt_tool --compare
```

After running `--compare`, the expected CSV file is:

```text
performance_report.csv
```

A valid benchmark CSV contains columns similar to:

```text
Mode,DataSizeBytes,EncryptTimeMS,DecryptTimeMS,ThroughputMBps,Iterations,IsAEAD,ModeType
```

Example:

```text
AES-256-GCM,1048576,0.778790,0.534903,1522.43,1000,AEAD,block
```

---

## 13. Statistical Benchmark Methodology

The standardized performance methodology follows the general lab requirement:

1. A warm-up run is executed before measured runs.
2. Each measured benchmark run uses 1000 internal encryption/decryption iterations.
3. The full benchmark is repeated 30 independent times on each operating system.
4. The analysis script computes mean, median, standard deviation, 95% confidence interval, minimum, and maximum.
5. The plotting scripts generate report-ready charts.
6. Windows and Linux results are compared in a separate OS comparison CSV and chart set.

### 13.1 Run 30 Windows Benchmark Repetitions

From the Lab1 source directory:

```powershell
cd Vũ Trọng Hưng\lab1\lab1

python scripts\run_windows_aes_benchmarks.py --runs 30
```

The script runs:

```powershell
build\encrypt_tool.exe --compare
```

30 independent times and saves the CSV files into:

```text
results/windows_runs/
```

Expected output files:

```text
results/windows_runs/performance_report_windows_run_01.csv
...
results/windows_runs/performance_report_windows_run_30.csv
```

Each CSV file should contain:

```text
Iterations = 1000
```

### 13.2 Run 30 Linux/Kali Benchmark Repetitions

From the Lab1 source directory:

```bash
cd ~/Desktop/Vũ Trọng Hưng/lab1/lab1

python3 scripts/run_linux_aes_benchmarks.py --runs 30
```

The script runs:

```bash
build_linux/encrypt_tool --compare
```

30 independent times and saves the CSV files into:

```text
results/linux_runs/
```

Expected output files:

```text
results/linux_runs/performance_report_linux_run_01.csv
...
results/linux_runs/performance_report_linux_run_30.csv
```

Each CSV file should contain:

```text
Iterations = 1000
```

### 13.3 Generate Statistical CSV Files

Generate Windows statistics:

```powershell
python scripts\analyze_benchmark_stats.py --input results\windows_runs --out results\windows_benchmark_stats.csv --os-name Windows
```

Generate Linux statistics:

```bash
python3 scripts/analyze_benchmark_stats.py --input results/linux_runs --out results/linux_benchmark_stats.csv --os-name Linux
```

The statistics CSV files include:

* Mean
* Median
* Standard deviation
* 95% confidence interval
* Minimum
* Maximum
* Run count

Expected output files:

```text
results/windows_benchmark_stats.csv
results/linux_benchmark_stats.csv
```

### 13.4 Generate Charts from Statistical Results

Generate Windows charts:

```powershell
python scripts\plot_stats_charts.py --input results\windows_benchmark_stats.csv --out-dir results\charts --os-name Windows
```

Generate Linux charts:

```bash
python3 scripts/plot_stats_charts.py --input results/linux_benchmark_stats.csv --out-dir results/charts --os-name Linux
```

Generated chart examples:

```text
results/charts/windows_8mb_throughput_by_mode.png
results/charts/windows_throughput_by_size.png
results/charts/windows_stream_vs_block_latency.png
results/charts/windows_aead_vs_nonaead_latency.png
results/charts/windows_gcm_vs_ccm_latency.png
results/charts/linux_8mb_throughput_by_mode.png
results/charts/linux_throughput_by_size.png
results/charts/linux_stream_vs_block_latency.png
results/charts/linux_aead_vs_nonaead_latency.png
results/charts/linux_gcm_vs_ccm_latency.png
```

### 13.5 Generate Windows vs Linux Comparison

After both Windows and Linux statistics are available, generate the OS comparison CSV and charts:

Windows:

```powershell
python scripts\compare_os_benchmark_stats.py
```

Linux/Kali:

```bash
python3 scripts/compare_os_benchmark_stats.py
```

Expected output:

```text
results/os_comparison_benchmark_stats.csv
```

Expected OS comparison charts:

```text
results/charts/os_comparison_EncryptTimeMS_1048576.png
results/charts/os_comparison_EncryptTimeMS_8388608.png
results/charts/os_comparison_DecryptTimeMS_1048576.png
results/charts/os_comparison_DecryptTimeMS_8388608.png
results/charts/os_comparison_ThroughputMBps_1048576.png
results/charts/os_comparison_ThroughputMBps_8388608.png
```

### 13.6 Benchmark Evidence Checklist

For submission, the benchmark evidence should include:

```text
results/windows_runs/*.csv
results/linux_runs/*.csv
results/windows_benchmark_stats.csv
results/linux_benchmark_stats.csv
results/os_comparison_benchmark_stats.csv
results/charts/*.png
```

The benchmark section of the report should discuss:

* Windows vs Linux differences
* Stream-like CTR vs block-mode CBC
* AEAD modes vs non-AEAD modes
* GCM vs CCM authentication overhead
* Small-payload overhead
* Larger-payload throughput behavior
* OS scheduling and system-call overhead
* Possible effects of compiler optimization and AES hardware acceleration
---

## 14. PyQt6 GUI Usage

The project includes a PyQt6 GUI frontend in:

```text
gui.py
```

The GUI does not implement cryptography in Python. It calls the compiled C++ `encrypt_tool` executable through `subprocess`. Therefore, all cryptographic operations are still performed by the Lab1 C++ Crypto++ implementation.

### 14.1 Running GUI from Source

Before running the GUI from source, install the Python requirements:

Windows:

```powershell
pip install PyQt6
```

Linux/Kali:

```bash
python3 -m pip install PyQt6
```

Run GUI on Windows:

```powershell
cd Vũ Trọng Hưng\lab1\lab1
python gui.py
```

Run GUI on Linux/Kali:

```bash
cd ~/Desktop/Vũ Trọng Hưng/lab1/lab1
python3 gui.py
```

The GUI searches for the C++ executable in common locations, including:

```text
bin/windows/encrypt_tool.exe
bin/linux/encrypt_tool
build/encrypt_tool.exe
build_linux/encrypt_tool
```

### 14.2 Running Prebuilt GUI Binaries

Prebuilt GUI binaries are included for convenience.

Windows:

```powershell
cd Vũ Trọng Hưng\lab1\lab1\bin\windows

.\CryptoToolGUI.exe
```

The Windows GUI executable should be placed in the same folder as:

```text
encrypt_tool.exe
```

Linux/Kali:

```bash
cd ~/Desktop/Vũ Trọng Hưng/lab1/lab1/bin/linux

chmod +x CryptoToolGUI
chmod +x encrypt_tool

./CryptoToolGUI
```

The Linux GUI executable should be placed in the same folder as:

```text
encrypt_tool
```

### 14.3 Building GUI Executables

Build Windows GUI executable with PyInstaller:

```powershell
cd Vũ Trọng Hưng\lab1\lab1

pip install PyQt6 pyinstaller

pyinstaller --onefile --windowed --name CryptoToolGUI gui.py

copy dist\CryptoToolGUI.exe bin\windows\CryptoToolGUI.exe
```

Build Linux GUI executable with PyInstaller:

```bash
cd ~/Desktop/Vũ Trọng Hưng/lab1/lab1

python3 -m pip install PyQt6 pyinstaller

pyinstaller --onefile --windowed --name CryptoToolGUI gui.py

mkdir -p bin/linux
cp dist/CryptoToolGUI bin/linux/CryptoToolGUI
chmod +x bin/linux/CryptoToolGUI
```

### 14.4 GUI Features

The PyQt6 GUI supports:

* AES mode selection
* 256-bit key generation
* IV/nonce generation
* File loading
* Encryption
* Decryption
* Output saving
* Displaying ciphertext as hex
* Reusing sidecar JSON metadata in the same GUI session for AEAD decryption

---

## 15. Known Limitations

* The GUI is a PyQt6 frontend and does not expose every CLI option.
* The GUI calls the compiled `encrypt_tool` executable and does not perform cryptography itself.
* Benchmark results depend on hardware, compiler, OS scheduling, file system behavior, and CPU AES acceleration.
* XTS provides confidentiality but does not provide authentication or integrity.
* Non-AEAD modes such as CBC, CFB, OFB, CTR, ECB, and XTS do not detect tampering by themselves.
* The nonce reuse database is local to the execution directory. If it is deleted, previous nonce usage history is lost.
* Windows `.exe` binaries cannot be used as Linux binaries.
* The implementation is for educational purposes and should be reviewed before any production use.

---

## 16. Security Notes

* Keys are sensitive and must not be committed to public repositories.
* IVs/nonces are stored in sidecar JSON files when needed for decryption.
* GCM and CCM verify authentication tags during decryption.
* Invalid tags, invalid IV lengths, malformed input, and nonce reuse are rejected.
* ECB is restricted and should only be used for demonstration.
* The PyQt6 GUI is only a frontend. The C++ Crypto++ binary performs all encryption and decryption operations.

---

## 17. Binaries

Prebuilt binaries are included in:

```text
bin/
├── windows/
│   ├── encrypt_tool.exe
│   └── CryptoToolGUI.exe
└── linux/
    ├── encrypt_tool
    └── CryptoToolGUI
```

Run Windows CLI binary:

```powershell
.\bin\windows\encrypt_tool.exe --help
```

Run Windows GUI binary:

```powershell
.\bin\windows\CryptoToolGUI.exe
```

Run Linux CLI binary:

```bash
chmod +x ./bin/linux/encrypt_tool
./bin/linux/encrypt_tool --help
```

Run Linux GUI binary:

```bash
chmod +x ./bin/linux/CryptoToolGUI
./bin/linux/CryptoToolGUI
```

---
