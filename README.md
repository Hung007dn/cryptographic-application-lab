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
Yêu cầu hệ thống

Trước khi build chương trình, cần cài đặt:

CMake phiên bản 3.20 trở lên.
Trình biên dịch hỗ trợ C++17.
Crypto++.
OpenSSL.
liboqs cho Lab 6.
Git.
Hướng dẫn clone repository
git clone https://github.com/USERNAME/REPOSITORY.git
cd REPOSITORY

Thay USERNAME và REPOSITORY bằng tên tài khoản và repository thực tế.

Build trên Windows

Ví dụ build bằng MinGW:

cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 4
Build trên Linux
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
Chạy kiểm thử
cd build
ctest --output-on-failure -V

Chương trình được thiết kế để từ chối các trường hợp không hợp lệ như:

Sai khóa.
Sai IV hoặc nonce.
Authentication tag bị thay đổi.
Chữ ký không hợp lệ.
File khóa bị lỗi.
Ciphertext bị chỉnh sửa.
Dữ liệu đầu vào sai định dạng.

Lab 1 — Symmetric Encryption
Lab 1 triển khai công cụ mã hóa đối xứng bằng AES với các mode:

ECB.
CBC.
CFB.
OFB.
CTR.
GCM.
CCM.
XTS.

Ví dụ mã hóa bằng AES-GCM:
aes_tool encrypt \
  --mode gcm \
  --in plaintext.txt \
  --out ciphertext.bin \
  --key-hex YOUR_AES_KEY

Ví dụ giải mã:
aes_tool decrypt \
  --in ciphertext.bin \
  --out recovered.txt \
  --key-hex YOUR_AES_KEY

Các cơ chế bảo mật được triển khai:
Sinh IV và nonce bằng bộ sinh số ngẫu nhiên an toàn.
Phát hiện hoặc ngăn chặn tái sử dụng nonce.
Kiểm tra authentication tag đối với GCM và CCM.
Không xuất plaintext nếu xác thực thất bại.
Cảnh báo khi người dùng lựa chọn ECB.

Lab 3 — RSA-OAEP và Hybrid Encryption
Lab 3 triển khai:
RSA-3072.
RSA-4096.
OAEP với SHA-256.
MGF1-SHA256.
Hybrid encryption sử dụng RSA-OAEP và AES-256-GCM.

Sinh cặp khóa RSA:
rsa_tool keygen \
  --bits 3072 \
  --public public.pem \
  --private private.pem
Mã hóa:
rsa_tool encrypt \
  --in message.txt \
  --public public.pem \
  --out encrypted.json
Giải mã:
rsa_tool decrypt \
  --in encrypted.json \
  --private private.pem \
  --out recovered.txt
Khi dữ liệu vượt quá giới hạn của RSA-OAEP, chương trình tự động sử dụng
hybrid encryption:
Sinh khóa AES-256.
Mã hóa dữ liệu bằng AES-GCM.
Mã hóa khóa AES bằng RSA-OAEP.
Lưu wrapped key, IV, tag và ciphertext trong envelope JSON.

Lab 4 — Hashing, PKI và Practical Attacks
Lab 4 hỗ trợ:
SHA-224.
SHA-256.
SHA-384.
SHA-512.
SHA3-224.
SHA3-256.
SHA3-384.
SHA3-512.
SHAKE128.
SHAKE256.
Phân tích chứng chỉ X.509.
Kiểm tra chuỗi tin cậy TLS.
Minh họa MD5 collision.
Minh họa length-extension attack.

Ví dụ tính SHA-256:
hash_tool hash \
  --algorithm sha256 \
  --in input.txt

Phân tích chứng chỉ:

hash_tool cert \
  --in server.crt

Các phần minh họa tấn công chỉ được thực hiện trong môi trường offline và
phục vụ mục đích học tập.

Lab 5 — Classical Digital Signatures
Lab 5 triển khai các thuật toán chữ ký số:
RSA-PSS.
ECDSA.
SHA-256.

Sinh khóa:
sig_tool keygen \
  --algorithm ecdsa \
  --public public.pem \
  --private private.pem

Ký file:
sig_tool sign \
  --algorithm ecdsa \
  --private private.pem \
  --in message.txt \
  --out signature.bin

Xác minh chữ ký:
sig_tool verify \
  --algorithm ecdsa \
  --public public.pem \
  --in message.txt \
  --signature signature.bin

Chương trình phải từ chối chữ ký nếu:
Nội dung file bị thay đổi.
Chữ ký bị chỉnh sửa.
Dùng sai public key.
Định dạng khóa không hợp lệ.
Lab 6 — Post-Quantum Cryptography

Lab 6 triển khai các cơ chế mật mã hậu lượng tử:
ML-DSA.
ML-KEM.
Chứng chỉ hậu lượng tử tối thiểu.
Thư viện liboqs.

Các chức năng chính:
pq_tool keygen
pq_tool sign
pq_tool verify
pq_tool encaps
pq_tool decaps

Lab này tập trung so sánh mật mã hậu lượng tử với RSA và ECDSA về:
Kích thước public key.
Kích thước private key.
Kích thước chữ ký.
Thời gian sinh khóa.
Thời gian ký và xác minh.
Thời gian encapsulation và decapsulation.
Phương pháp benchmark

Mỗi trường hợp benchmark được thực hiện theo quy trình
Chạy warm-up trước khi đo.
Thực hiện nhiều lần đo độc lập.
Lưu kết quả vào CSV.
Tính mean, median và standard deviation.
Tính khoảng tin cậy 95%.
Tạo biểu đồ latency và throughput.

Các kích thước dữ liệu được sử dụng tùy theo từng lab, ví dụ:
1 KiB.
4 KiB.
16 KiB.
256 KiB.
1 MiB.
8 MiB.
100 MiB.

Nguyên tắc bảo mật
Repository tuân theo các nguyên tắc:
Không sử dụng rand() để sinh khóa, IV hoặc nonce.
Không lưu private key hoặc AES key trực tiếp trong mã nguồn.
Không xuất plaintext nếu xác thực thất bại.
Không sử dụng lại nonce với cùng một khóa.
Không sử dụng ECB trong hệ thống thực tế.
Ưu tiên AEAD như AES-GCM.
RSA chỉ được sử dụng để mã hóa dữ liệu nhỏ hoặc bọc khóa.
MD5 chỉ được sử dụng để minh họa lỗ hổng.
Các demo tấn công chỉ chạy trong môi trường kiểm soát.

Kết quả tổng quát
Nội dung	          Kết quả
Build trên Windows	Thành công
Build trên Linux	  Thành công
Known Answer Tests	PASS
Negative Tests	    PASS
Unit Tests	        PASS
Benchmark	          Đã thực hiện
Phân tích bảo mật	  Đã thực hiện
