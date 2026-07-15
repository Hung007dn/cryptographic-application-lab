# Lab 4 - Hashing, PKI, and Practical Attacks

## 1. Overview

This project implements the Lab 4 requirements for the Cryptography & Applications course. The tool is a C++17 command-line application named `hashtool`.

Lab 4 covers modern hash functions, SHAKE XOFs, Known Answer Tests, streamed file hashing, raw/hex output, X.509 certificate parsing, TLS deployment evidence, controlled MD5 collision verification, SHA-256 length-extension attack demonstration, manual SHA-256 length-extension implementation, and performance benchmarking on Windows and Linux.

The implementation uses **OpenSSL** for SHA-2, SHA-3, SHAKE, MD5/SHA-256 verification, X.509 parsing, and TLS-related operations. The SHA-256 length-extension attack is implemented manually in `CustomSHA256Extend.cpp` and does not use `hashpump`.

## 2. Project Layout

### Final Folder Layout Used for Submission

The final Lab 4 submission uses the following folder organization:

```text
Vũ Trọng Hưng/
├── openssl/
├── nlohmann/
├── catch2/
├── cryptopp/
└── lab4/
    ├── ACADEMIC_HONESTY.md
    ├── LAB4_REPORT.md
    ├── README.md
    ├── SELF_GRADE_CHECKLIST.md
    ├── length_extension_evidence/
    ├── md5_collision_evidence/
    ├── pki_tls_evidence/
    └── lab4/
        ├── CMakeLists.txt
        ├── main.cpp
        ├── *.cpp / *.hpp
        ├── test_vectors.json
        ├── bin/
        ├── build/
        ├── build_linux/
        ├── cpu_evidence/
        ├── results/
        ├── scripts/
        └── tests/
```

The documentation and high-level evidence folders are stored in `Vũ Trọng Hưng/lab4/`.

The source code, CMake project, binaries, benchmark results, scripts, tests, and CPU evidence are stored in `Vũ Trọng Hưng/lab4/lab4/`.

External libraries are stored at the root of `Vũ Trọng Hưng/`, including OpenSSL, nlohmann-json, Catch2, and Crypto++ for other labs. Lab 4 itself uses OpenSSL for hashing, X.509 parsing, and digest verification.

Private key files such as `server.key` are used only in the local TLS environment and are not included in the final submission package.


Expected binary locations:

```text
Vũ Trọng Hưng/lab4/lab4/bin/windows/hashtool.exe
Vũ Trọng Hưng/lab4/lab4/bin/linux/hashtool
```

## 3. Dependencies




Minimum / expected versions:

| Tool | Version / Note |
|---|---|
| CMake | 3.16 or newer |
| C++ | C++17 |
| OpenSSL | Bundled OpenSSL on Windows; system OpenSSL with `libssl-dev` on Linux |
| Python | Python 3.x |
| pandas | Required for benchmark statistics |
| matplotlib | Required for benchmark plots |
| Catch2 | Single-header Catch2 |
| nlohmann-json | Single-header JSON library |

Expected bundled OpenSSL files:

```text
Vũ Trọng Hưng/openssl/bin/openssl.exe
Vũ Trọng Hưng/openssl/include/openssl/x509.h
Vũ Trọng Hưng/openssl/lib64/libcrypto.a
Vũ Trọng Hưng/openssl/lib64/libssl.a
Vũ Trọng Hưng/openssl/ssl/openssl.cnf
```

### Linux

```bash
sudo apt update
sudo apt install -y build-essential cmake openssl libssl-dev python3 python3-pandas python3-matplotlib nginx sysstat
```

## 4. Build Instructions

### Windows MinGW64

```powershell
cd D:\Documents\DAIHOC\MMUD\Vũ Trọng Hưng\lab4\lab4
Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build
cd build
ctest --verbose
```

### Linux

```bash
cd ~/Desktop/Vũ Trọng Hưng/lab4/lab4
rm -rf build_linux
cmake -S . -B build_linux
cmake --build build_linux -j$(nproc)
cd build_linux
ctest --verbose
```

Expected CTest tests:

```text
help_test
kat_tests
negative_tests
unit_tests
```

## 5. CLI Usage

```bash
./hashtool --help
./hashtool --algo sha256 --in file.bin
./hashtool --algo sha256 --text "abc"
./hashtool --algo sha512 --in large.iso --stream
./hashtool --algo shake256 --outlen 64 --in file.bin
./hashtool --algo sha256 --in abc.txt --out digest.bin --format raw
```

The default output format is lowercase hexadecimal text printed to the console. Raw output requires `--out`.

## 6. Supported Algorithms

| Family | Algorithms |
|---|---|
| SHA-2 | SHA-224, SHA-256, SHA-384, SHA-512 |
| SHA-3 | SHA3-224, SHA3-256, SHA3-384, SHA3-512 |
| SHAKE | SHAKE128, SHAKE256 with variable output length |

## 7. Known Answer Tests

```bash
./hashtool --kat ../test_vectors.json
```

The KAT runner prints PASS/FAIL for each vector and a final summary. It covers SHA-2, SHA-3, and SHAKE vectors.

## 8. Negative Tests

```bash
./hashtool --negative-tests
```

Negative tests cover unsupported algorithm identifiers, missing input files, invalid SHAKE output length, raw output without an output file, malformed certificate input, and non-colliding MD5 file pairs. The tool fails closed and does not crash.

## 9. X.509 Certificate Analysis

```bash
./hashtool --cert --in test_cert.pem --out cert_report.json
./hashtool --cert --in server.crt --issuer server.crt --out cert_report_tls.json
```

Extracted fields include subject, issuer, serial number, version, validity period, public key algorithm and parameters, signature algorithm, key usage, SANs, SHA-1 and SHA-256 fingerprints, signature verification status, and TBS integrity status.

## 10. TLS Deployment Evidence

Example Nginx TLS configuration:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name localhost;
    root /var/www/lab4;
    index index.html;
    ssl_certificate     /etc/nginx/lab4_tls/server.crt;
    ssl_certificate_key /etc/nginx/lab4_tls/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers HIGH:!aNULL:!MD5:!SHA1;
    location / { try_files $uri $uri/ =404; }
}
```

Validation commands:

```bash
sudo nginx -t
sudo systemctl restart nginx
sudo systemctl status nginx --no-pager
openssl s_client -connect localhost:443 -servername localhost -tls1_2
openssl s_client -connect localhost:443 -servername localhost -tls1_3
```

## 11. MD5 Collision Verification

```bash
./hashtool --md5-collision --file1 collision1.png --file2 collision2.png
```

Expected successful properties:

- Files differ at the byte level
- MD5 digests match
- SHA-256 digests differ
- Tool prints `[+] MD5 collision confirmed.`

Recommended evidence folder:

```text
md5_collision_evidence/
├── collision1.png
├── collision2.png
├── md5sum_log.txt
├── sha256sum_log.txt
├── file_type_log.txt
└── md5_collision_verify_log.txt
```

## 12. Length-Extension Attack

```bash
./hashtool --length-extension-demo
./hashtool --length-extension-demo > length_extension_demo_log.txt 2>&1
```

The demo prints the original message, original MAC, assumed key length, SHA-256 glue padding, forged message, forged MAC, server verification, and HMAC mitigation. The implementation is manual in `CustomSHA256Extend.cpp`.

## 13. Performance Benchmarks
The CLI option `hashtool --benchmark` is intended only as a quick local benchmark. The official repeated benchmark evidence is generated by the Python scripts, which perform 30 runs and produce CSV statistics and plots.
### Windows

```powershell
python scripts\run_windows_hash_benchmarks.py
python scripts\analyze_hash_benchmark_stats.py
python scripts\plot_hash_benchmark.py --os windows --split-by-size
```

### Linux

```bash
python3 scripts/run_linux_hash_benchmarks.py
python3 scripts/analyze_hash_benchmark_stats.py
python3 scripts/plot_hash_benchmark.py --os linux --split-by-size
```

### OS comparison

```bash
python3 scripts/plot_os_comparison.py
```

Expected results:

```text
results/windows_runs/*.csv
results/linux_runs/*.csv
results/windows_hash_benchmark_stats.csv
results/linux_hash_benchmark_stats.csv
results/charts/*.png
```


## 14. CPU Utilization Evidence

CPU utilization evidence is stored in:

```text
lab4/lab4/cpu_evidence/
```


## 15. Known Limitations

* 1 GiB benchmarks are optional and may be skipped if not feasible.
* Linux benchmark numbers may be affected by VM overhead.
* The submitted benchmark evidence uses streaming I/O. Memory-mapped I/O is discussed as an alternative approach but is not implemented as a separate benchmark mode in this submission.
* A public trusted ZeroSSL certificate may not be available in the local lab environment. A local self-signed ECDSA certificate demonstrates TLS configuration and X.509 parsing but should be documented as a limitation.
* Private key files such as `server.key` are not included in the final submission package.
* MD5 chosen-prefix collision generation can be slow. The tool supports verification of prepared collision files.
