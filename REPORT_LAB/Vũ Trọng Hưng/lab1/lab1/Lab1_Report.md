# Lab 1 Report — Symmetric Encryption with Crypto++

## 1. Objective

The objective of Lab 1 is to design and implement a symmetric encryption tool using Crypto++. The tool supports multiple AES modes, including ECB, CBC, OFB, CFB, CTR, XTS, CCM, and GCM. It also implements secure IV/nonce handling, AEAD authentication, known answer tests, negative tests, benchmarking, and a minimal Python GUI.

This lab demonstrates practical use of symmetric encryption, secure parameter handling, misuse prevention, and performance evaluation.

## 2. Environment

### Windows Environment



|         Item          |                  Value                         |
|-----------------------|------------------------------------------------|
| OS                    |                Windows 10/11                   |
| Compiler              | g++ 12.1.0 (MinGW-W64 x86_64-msvcrt-posix-seh) |
| CMake version         |                 4.3.3                          |
| Crypto++ version      | 2026-03-02, triplet x64-mingw-static           |
| nlohmann-json version | 3.12.0#2, triplet x64-mingw-static             |
| CPU                   | 11th Gen Intel(R) Core(TM) i7-11800H @ 2.30GHz |
| RAM                   |                16 GB                           |

Commands used:

```powershell
cmake --version
g++ --version
D:\vcpkg\vcpkg list | findstr cryptopp
D:\vcpkg\vcpkg list | findstr nlohmann
```

### Linux Environment


|        Item           |                     Value                      |
|-----------------------|------------------------------------------------|
|         OS            |      Kali Linux, kernel 6.12.38+kali-amd64     |
|      Compiler         |        g++ 14.3.0 (Debian 14.3.0-5)            |
|     CMake version     |             4.3.2                              |
|   Crypto++ version    |           8.9.0-2+b2                           |
| nlohmann-json version |    3.12.0.really.3.12.0.really.3.11.3-3        |
|         CPU           | 11th Gen Intel(R) Core(TM) i7-11800H @ 2.30GHz |
|        RAM            |             3.8 GiB                            |
|     Virtualization    |          VMware virtual machine                |
Commands used:

```bash
uname -a
cmake --version
g++ --version
dpkg -l | grep "libcrypto++"
dpkg -l | grep "nlohmann-json"
lscpu
free -h
```

## 3. Implementation Details

The tool is implemented in modern C++ using Crypto++ for all cryptographic primitives. OpenSSL and libsodium are not used for cryptographic operations.

The main components are:

| Component                | Purpose                                            |
| ------------------------ | -------------------------------------------------- |
| `main.cpp`               | CLI parsing and command dispatch                   |
| `CryptoConfig.cpp/.hpp`  | Configuration, mode parsing, key/IV validation     |
| `FileEncryptor.cpp/.hpp` | AES encryption and decryption implementation       |
| `KATRunner.cpp/.hpp`     | Known Answer Test runner                           |
| `NegativeTests.cpp/.hpp` | Misuse and failure test cases                      |
| `Benchmarker.cpp/.hpp`   | Performance measurement                            |
| `gui.py`                 | Minimal Python GUI calling the compiled executable |
| `plot_benchmarks.py`     | Plot generation from benchmark CSV                 |

### Supported AES modes

The tool supports the following modes selected at runtime using `--mode`:

```text
ecb, cbc, ofb, cfb, ctr, xts, ccm, gcm
```

### AEAD support

GCM and CCM are implemented as AEAD modes. The tool supports AAD through:

```text
--aad FILE
--aad-text STRING
```

During decryption, the authentication tag is verified. If verification fails, decryption fails closed and no trusted plaintext is returned.

### IV and nonce handling

For modes requiring an IV or nonce, the tool validates the required length. If the user does not provide an IV/nonce, the tool generates one securely using Crypto++ `AutoSeededRandomPool`.

The IV/nonce is stored in a sidecar JSON file together with metadata such as algorithm, mode, AAD, and authentication tag.

### Nonce reuse prevention

For CTR, CCM, and GCM, nonce reuse is dangerous. The tool records a fingerprint of the AES key and the nonce in a local database. If the same key and nonce combination is used again, the encryption operation is rejected.

### ECB misuse prevention

ECB mode is insecure because it leaks repeated plaintext patterns. The tool prints a warning when ECB is selected. It also blocks ECB encryption for files larger than 16 KiB unless the user explicitly provides:

```text
--allow-ecb
```

## 4. CLI Usage

Because this submission includes prebuilt binaries in the `bin/` folder, the commands in this report use the submitted binary paths:

```text
Windows: .\bin\windows\encrypt_tool.exe
Linux:   ./bin/linux/encrypt_tool
```

The `build/` and `build_linux/` folders are only build output folders. The submitted executable files are stored in `bin/windows/` and `bin/linux/`.

### AES-GCM encryption

```powershell
.\bin\windows\encrypt_tool.exe encrypt --mode gcm --key-hex 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF --text "hello lab" --out ct.bin --aad-text "meta" --aead
```

### AES-GCM decryption

```powershell
.\bin\windows\encrypt_tool.exe decrypt --mode gcm --key-hex 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF --in ct.bin --out pt.txt --aead
```

### KAT runner

```powershell
.\bin\windows\encrypt_tool.exe --kat test_vectors.json
```

### Negative tests

```powershell
.\bin\windows\encrypt_tool.exe --negative-tests
```

### Benchmark

```powershell
.\bin\windows\encrypt_tool.exe --compare
```

## 5. KAT Results

Run:

```powershell
.\bin\windows\encrypt_tool.exe --kat test_vectors.json
```

Linux:

```bash
./bin/linux/encrypt_tool --kat test_vectors.json
```


### Result

| Test group   | Result |
| ------------ | ------ |
| CBC          | PASS   |
| CFB          | PASS   |
| OFB          | PASS   |
| CTR          | PASS   |
| GCM          | PASS   |
| CCM          | PASS   |
| Total passed | 6      |
| Total failed | 0      |


## 6. Negative Test Results

Run:

```powershell
.\bin\windows\encrypt_tool.exe --negative-tests
```

Linux:

```bash
./bin/linux/encrypt_tool --negative-tests
```


### Result

| Negative test                 | Result |
| ----------------------------- | ------ |
| Wrong key                     | PASS   |
| Wrong IV                      | PASS   |
| Tampered ciphertext, non-AEAD | PASS   |
| Tampered ciphertext, AEAD     | PASS   |
| Invalid tag                   | PASS   |
| Invalid IV length             | PASS   |
| Malformed input               | PASS   |

Screenshot:

```text
Insert screenshot: screenshots/negative_tests_pass.png
```

## 7. Benchmark Methodology

The benchmark evaluates AES modes using payload sizes:

* 1 KB
* 4 KB
* 16 KB
* 256 KB
* 1 MB
* 8 MB

The measured metrics are:

* Encryption latency per operation
* Decryption latency per operation
* Throughput in MB/s

For a more reliable performance study, each test should include warm-up runs and repeated measurements. The report should compare:

* Windows vs Linux
* Stream-like modes vs block modes
* AEAD modes vs non-AEAD modes
* Authentication tag overhead in GCM and CCM

Commands on Windows:

```powershell
.\bin\windows\encrypt_tool.exe --compare
python plot_benchmarks.py performance_report.csv
mkdir results
copy performance_report.csv results\performance_report_windows.csv
copy latency_comparison.png results\latency_comparison_windows.png
copy throughput_*.png results\
```

Commands on Linux/Kali:

```bash
./bin/linux/encrypt_tool --compare
python3 plot_benchmarks.py performance_report.csv
mkdir -p results
cp performance_report.csv results/performance_report_linux.csv
cp latency_comparison.png results/latency_comparison_linux.png
cp throughput_*.png results/
```

## 8. Windows vs Linux Results
## Windows Benchmark Results

The Windows benchmark was executed using 300 iterations per test. The benchmark evaluated six payload sizes: 1 KB, 4 KB, 16 KB, 256 KB, 1 MB, and 8 MB.

For throughput, AES-256-CTR achieved the highest result among the tested modes. At 8 MB, AES-256-CTR reached 415.80 MB/s, followed by AES-256-CBC at 309.93 MB/s, AES-256-GCM at 284.99 MB/s, and AES-256-CCM at 166.29 MB/s. This result is expected because CTR is a stream-like mode that does not require padding, while CCM includes authentication overhead and is generally slower.

### Throughput Summary

| Mode        |        1 KB |        8 MB |
| ----------- | ----------: | ----------: |
| AES-256-CBC | 136.25 MB/s | 309.93 MB/s |
| AES-256-CTR | 174.91 MB/s | 415.80 MB/s |
| AES-256-GCM | 122.37 MB/s | 284.99 MB/s |
| AES-256-CCM |  92.84 MB/s | 166.29 MB/s |

### Stream vs Block Modes

The benchmark shows that the stream-like mode was consistently faster than the block mode for all tested payload sizes. The speedup ranged from 1.14x for 1 KB to 1.37x for 8 MB. This indicates that CTR mode can provide better throughput than CBC in this implementation.

| Size   |     Stream |      Block | Speedup |
| ------ | ---------: | ---------: | ------: |
| 1 KB   |  0.0111 ms |  0.0126 ms |   1.14x |
| 4 KB   |  0.0234 ms |  0.0287 ms |   1.23x |
| 16 KB  |  0.0751 ms |  0.0944 ms |   1.26x |
| 256 KB |  1.0469 ms |  1.4254 ms |   1.36x |
| 1 MB   |  4.4200 ms |  6.1273 ms |   1.39x |
| 8 MB   | 38.6397 ms | 52.7994 ms |   1.37x |

### AEAD vs Non-AEAD

AEAD modes provide authentication in addition to confidentiality, so some overhead is expected. The measured overhead was higher for very small payloads and lower for larger payloads. At 8 MB, AEAD overhead was 8.40%. At 256 KB, the result was -0.18%, which is close to zero and can be treated as measurement noise.

| Size   |       AEAD |   Non-AEAD | Overhead |
| ------ | ---------: | ---------: | -------: |
| 1 KB   |  0.0161 ms |  0.0127 ms |   26.94% |
| 4 KB   |  0.0328 ms |  0.0284 ms |   15.61% |
| 16 KB  |  0.1009 ms |  0.0982 ms |    2.77% |
| 256 KB |  1.4356 ms |  1.4382 ms |   -0.18% |
| 1 MB   |  6.5705 ms |  6.2878 ms |    4.49% |
| 8 MB   | 57.3155 ms | 52.8764 ms |    8.40% |

### GCM vs CCM Tag Overhead

GCM was faster than CCM for every tested payload size. The overhead of CCM compared with GCM ranged from 31.56% at 1 KB to 76.22% at 8 MB. This shows that GCM is more efficient than CCM in this benchmark environment.

| Size   |        GCM |        CCM | CCM over GCM |
| ------ | ---------: | ---------: | -----------: |
| 1 KB   |  0.0154 ms |  0.0203 ms |       31.56% |
| 4 KB   |  0.0319 ms |  0.0545 ms |       70.68% |
| 16 KB  |  0.0995 ms |  0.1828 ms |       83.58% |
| 256 KB |  1.4314 ms |  2.8601 ms |       99.81% |
| 1 MB   |  6.5221 ms | 11.9387 ms |       83.05% |
| 8 MB   | 56.5653 ms | 99.6816 ms |       76.22% |

Overall, the benchmark results show that AES-256-CTR is the fastest tested mode, AES-256-CCM is the slowest tested mode, and GCM provides better AEAD performance than CCM on Windows.

## Linux Benchmark Results

The Linux benchmark was executed on Kali Linux using 300 iterations per test.

System information:

| Item                | Value                                          |
| ------------------- | ---------------------------------------------- |
| OS                  | Linux / Kali                                   |
| CPU                 | 11th Gen Intel(R) Core(TM) i7-11800H @ 2.30GHz |
| Iterations per test | 300                                            |

### Linux Throughput Summary

| Mode        | 1 KB Throughput | 8 MB Throughput |
| ----------- | --------------: | --------------: |
| AES-256-CBC |     544.31 MB/s |    1040.79 MB/s |
| AES-256-CTR |     702.79 MB/s |    3706.34 MB/s |
| AES-256-GCM |     531.43 MB/s |    1331.14 MB/s |
| AES-256-CCM |     421.86 MB/s |     693.84 MB/s |

For the 8 MB payload, AES-256-CTR achieved the highest throughput at 3706.34 MB/s. AES-256-GCM achieved 1331.14 MB/s, AES-256-CBC achieved 1040.79 MB/s, and AES-256-CCM achieved 693.84 MB/s. CTR was the fastest mode, while CCM was the slowest tested mode.

### Stream vs Block Modes on Linux

| Size   |    Stream |      Block | Speedup |
| ------ | --------: | ---------: | ------: |
| 1 KB   | 0.0030 ms |  0.0040 ms |   1.37x |
| 4 KB   | 0.0038 ms |  0.0068 ms |   1.77x |
| 16 KB  | 0.0086 ms |  0.0194 ms |   2.25x |
| 256 KB | 0.0991 ms |  0.2665 ms |   2.69x |
| 1 MB   | 0.4290 ms |  1.0912 ms |   2.54x |
| 8 MB   | 4.5793 ms | 15.7281 ms |   3.43x |

The Linux benchmark shows that stream-like mode was consistently faster than block mode for all tested payload sizes. The difference became more visible for larger payloads. At 8 MB, stream mode was approximately 3.43x faster than block mode.

### AEAD vs Non-AEAD on Linux

| Size   |       AEAD |   Non-AEAD | Overhead |
| ------ | ---------: | ---------: | -------: |
| 1 KB   |  0.0035 ms |  0.0037 ms |   -5.18% |
| 4 KB   |  0.0050 ms |  0.0064 ms |  -21.92% |
| 16 KB  |  0.0119 ms |  0.0189 ms |  -37.35% |
| 256 KB |  0.1505 ms |  0.2621 ms |  -42.59% |
| 1 MB   |  0.6172 ms |  1.0625 ms |  -41.91% |
| 8 MB   | 12.8408 ms | 16.1552 ms |  -20.52% |

In this Linux environment, AEAD mode measured faster than the selected non-AEAD comparison mode. This produces negative overhead values. The result does not mean that authentication has no cost in general. Instead, it indicates that AES-GCM was highly optimized on this platform, while the selected non-AEAD mode had slower measured performance. This may be caused by CPU hardware acceleration, compiler optimization, Crypto++ implementation differences, memory behavior, and OS scheduling.

### GCM vs CCM Tag Overhead on Linux

| Size   |        GCM |        CCM | CCM over GCM |
| ------ | ---------: | ---------: | -----------: |
| 1 KB   |  0.0036 ms |  0.0045 ms |       23.82% |
| 4 KB   |  0.0051 ms |  0.0099 ms |       93.13% |
| 16 KB  |  0.0124 ms |  0.0328 ms |      164.78% |
| 256 KB |  0.1544 ms |  0.4981 ms |      222.67% |
| 1 MB   |  0.6984 ms |  1.9800 ms |      183.51% |
| 8 MB   | 11.7821 ms | 23.5143 ms |       99.58% |

GCM was faster than CCM for every tested payload size. At 8 MB, CCM was approximately 99.58% slower than GCM. This shows that GCM was significantly more efficient than CCM in this Linux benchmark environment.

## Windows vs Linux Comparison

The same benchmark was executed on both Windows and Linux with 300 iterations per test.

### 8 MB Throughput Comparison

| Mode        |     Windows |        Linux | Observation       |
| ----------- | ----------: | -----------: | ----------------- |
| AES-256-CBC | 309.93 MB/s | 1040.79 MB/s | Linux faster      |
| AES-256-CTR | 415.80 MB/s | 3706.34 MB/s | Linux much faster |
| AES-256-GCM | 284.99 MB/s | 1331.14 MB/s | Linux faster      |
| AES-256-CCM | 166.29 MB/s |  693.84 MB/s | Linux faster      |

The Linux benchmark produced higher throughput than Windows for all tested modes. The largest difference was observed in AES-256-CTR, where Linux reached 3706.34 MB/s compared with 415.80 MB/s on Windows.

### Cross-Platform Analysis

The benchmark results show that Linux performed faster than Windows in this test environment. Several factors may explain the difference, including compiler optimization, Crypto++ build configuration, CPU scheduling, file system behavior, memory allocation, and hardware acceleration such as AES-NI.

Stream-like modes were faster than block modes on both platforms. This is expected because CTR mode does not require padding and can be processed efficiently. AEAD modes such as GCM and CCM provide authentication in addition to confidentiality, but their performance depends heavily on implementation optimization. On Linux, GCM was highly efficient and even outperformed the selected non-AEAD comparison mode in this benchmark.

Overall, the results show that performance is platform-dependent. Therefore, cryptographic benchmarks should be run on each target operating system instead of assuming identical performance across platforms.


| OS      | Fastest mode | Slowest mode | Notes                    |
| ------- | ------------ | ------------ | ------------------------ |
| Windows | AES-256-CTR  | AES-256-CCM  | Based on 8 MB throughput |
| Linux   | AES-256-CTR  | AES-256-CCM  | Based on 8 MB throughput |


### Benchmark files

| File                                     | Description              |
| ---------------------------------------- | ------------------------ |
| `results/performance_report_windows.csv` | Windows benchmark result |
| `results/performance_report_linux.csv`   | Linux benchmark result   |
| `results/latency_comparison.png`         | Latency comparison plot  |
| `results/throughput_<mode>.png`          | Throughput plot per mode |


## 9. Security Engineering Discussion

### 9.1 Mode-Level Security

#### Why ECB is insecure

ECB encrypts each block independently with the same key. Equal plaintext blocks produce equal ciphertext blocks. This leaks patterns and makes ECB unsuitable for real-world file encryption. In this tool, ECB is restricted and produces a warning.

#### CBC padding oracle risks

CBC requires padding for messages that are not multiples of the AES block size. If a system reveals whether padding is valid or invalid, attackers may exploit a padding oracle. Therefore, decryption errors must fail closed and avoid exposing detailed information.

#### CTR nonce reuse catastrophe

CTR mode generates a keystream from the key and nonce/counter. If the same key and nonce are reused, the same keystream is reused. Attackers can XOR ciphertexts and learn relationships between plaintexts. This tool rejects repeated key and nonce combinations for CTR.

#### AEAD guarantees vs non-AEAD modes

Non-AEAD modes provide confidentiality only. They do not detect tampering. AEAD modes such as GCM and CCM provide both confidentiality and integrity by using an authentication tag. If ciphertext, AAD, IV/nonce, or tag is modified, verification fails.

#### Why GCM requires unique nonces

GCM requires a unique nonce for every encryption under the same key. Reusing a nonce can reveal plaintext relationships and may allow authentication forgery. The tool prevents GCM nonce reuse by recording used key and nonce combinations.

#### XTS limitations

XTS is designed for storage encryption. It provides confidentiality for data at rest but does not provide authentication or integrity. If ciphertext is modified, XTS alone cannot reliably detect tampering.

### 9.2 Implementation-Level Security

#### Proper randomness generation

The tool uses Crypto++ `AutoSeededRandomPool` to generate IVs and nonces when omitted by the user. This avoids insecure randomness such as `rand()` or `std::random` for cryptographic values.

#### Safe IV storage

IVs and nonces are not secret, but they must be available for decryption. The tool stores them in a sidecar JSON file. The AES key is not stored in metadata.

#### Authentication tag verification

For GCM and CCM, the tag is generated during encryption and verified during decryption. If verification fails, the program rejects the input and does not output trusted plaintext.

#### Failure handling

The tool follows the fail-closed principle. Invalid IV length, nonce reuse, invalid tag, malformed input, and AEAD authentication failures are rejected.

#### Key storage risks

AES keys are sensitive. If a key file is leaked, encrypted data can be decrypted. In real systems, keys should be protected with OS permissions, secure storage, or a key management system.

### 9.3 Cross-Platform Considerations

#### RNG differences between OSes

Windows and Linux use different OS-level entropy sources. Crypto++ abstracts these differences through `AutoSeededRandomPool`.

#### File system behavior

File caching, antivirus scanning, disk I/O, and buffering differ between Windows and Linux. These differences can affect benchmark results.

#### Performance variation causes

Performance can vary because of compiler optimization, CPU scheduling, hardware AES acceleration, memory allocation, file system caching, and system call overhead.

## 10. Limitations

* The tool is designed for educational purposes.
* The GUI is minimal and does not expose all CLI options.
* The nonce reuse database is local. If deleted, previous nonce history is lost.
* Non-AEAD modes do not detect tampering.
* XTS does not provide integrity.
* Benchmark results may vary between machines and runs.
* Real production systems should use stronger key management and audited protocols.

## 11. Conclusion

Lab 1 successfully implements a Crypto++-based AES encryption tool with multiple runtime-selectable modes, AEAD support, secure IV/nonce handling, nonce reuse detection, KAT validation, negative testing, benchmarking, and a minimal GUI. The lab demonstrates that secure symmetric encryption requires not only correct AES usage, but also careful mode selection, IV/nonce lifecycle management, authentication verification, and fail-closed error handling.
