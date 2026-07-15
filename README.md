# cryptographic-application-lab
# Applied Cryptography Labs

Repository này tổng hợp các bài thực hành của học phần **Mật mã học ứng dụng**.

Các bài lab tập trung vào việc triển khai, kiểm thử, đánh giá hiệu năng và
phân tích bảo mật của các thuật toán mật mã trên hai môi trường Windows và Linux.

## Thông tin sinh viên

- Họ và tên: Vũ Trọng Hưng
- Mã số sinh viên: 24162053
- Môn học: Mật mã học ứng dụng
- Giảng viên hướng dẫn: TS. Nguyễn Ngọc Tự
- Trường: Trường Đại học Sư phạm Kỹ thuật Thành phố Hồ Chí Minh

## Danh sách bài Lab

| Lab | Nội dung | Thuật toán/Công nghệ chính | Trạng thái |
|---|---|---|---|
| Lab 1 | Symmetric Encryption | AES, CBC, CTR, GCM, CCM, XTS, Crypto++ | Hoàn thành |
| Lab 3 | RSA-OAEP và Hybrid Encryption | RSA-3072, RSA-4096, OAEP-SHA256, AES-256-GCM | Hoàn thành |
| Lab 4 | Hashing, PKI và Practical Attacks | SHA-2, SHA-3, SHAKE, X.509, TLS, MD5 Collision | Hoàn thành |
| Lab 5 | Classical Digital Signatures | RSA-PSS, ECDSA, SHA-256 | Hoàn thành |
| Lab 6 | Post-Quantum Cryptography | ML-DSA, ML-KEM, liboqs | Hoàn thành |

## Mục tiêu dự án

Dự án được thực hiện nhằm:

- Triển khai các thuật toán mật mã bằng C++.
- Xây dựng chương trình có giao diện dòng lệnh CLI.
- Hỗ trợ biên dịch trên Windows và Linux.
- Kiểm thử tính đúng đắn bằng Known Answer Tests và Unit Tests.
- Kiểm tra các trường hợp lỗi và hành vi fail-closed.
- Đánh giá hiệu năng theo latency và throughput.
- Phân tích các nguy cơ bảo mật khi sử dụng sai thuật toán.

## Công nghệ sử dụng

| Thành phần | Công nghệ |
|---|---|
| Ngôn ngữ | C++17 |
| Build system | CMake |
| Mã hóa đối xứng | Crypto++ |
| RSA, Hash và PKI | OpenSSL |
| Mật mã hậu lượng tử | liboqs |
| Unit Test | Catch2 hoặc GoogleTest |
| Benchmark | C++, Python |
| Hệ điều hành | Windows 11, Kali Linux |
| Dữ liệu kết quả | CSV, JSON, PNG |

## Cấu trúc repository

```text
Applied-Cryptography-Labs/
├── lab1-symmetric-encryption/
│   ├── src/
│   ├── include/
│   ├── tests/
│   ├── results/
│   └── CMakeLists.txt
│
├── lab3-rsa-hybrid/
│   ├── src/
│   ├── include/
│   ├── tests/
│   ├── results/
│   └── CMakeLists.txt
│
├── lab4-hashing-pki/
│   ├── src/
│   ├── certificates/
│   ├── tests/
│   ├── results/
│   └── CMakeLists.txt
│
├── lab5-digital-signatures/
│   ├── src/
│   ├── keys/
│   ├── tests/
│   ├── results/
│   └── CMakeLists.txt
│
├── lab6-post-quantum/
│   ├── src/
│   ├── tests/
│   ├── results/
│   └── CMakeLists.txt
│
├── report/
│   └── Applied_Cryptography_Lab_Report.pdf
│
└── README.md
