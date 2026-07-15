// RSAConfig.hpp
#pragma once
#include <string>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <stdexcept>
#include <vector>
enum class RSAKeySize {
    RSA_3072 = 3072,
    RSA_4096 = 4096
};

enum class OutputFormat {
    RAW, HEX, BASE64, PEM, DER
};

struct RSAConfig {
    RSAKeySize key_size;
    bool use_hybrid;
    std::string label;
    OutputFormat output_format;
    
    // Constants
    static constexpr int HASH_SIZE = CryptoPP::SHA256::DIGESTSIZE;  // 32 bytes
    static constexpr int GCM_IV_SIZE = 12;                          // 96 bits
    static constexpr int GCM_TAG_SIZE = 16;                         // 128 bits
    static constexpr int AES_KEY_SIZE = 32;                         // 256 bits
    
    RSAConfig() : key_size(RSAKeySize::RSA_3072), use_hybrid(true), 
                  output_format(OutputFormat::BASE64) {}
    
    // Tính toán plaintext size limit cho RSA-OAEP
    // mLen ≤ k - 2*hLen - 2
    size_t getMaxPlaintextSize() const {
        size_t k = static_cast<size_t>(key_size) / 8;  // key size in bytes
        return k - 2 * HASH_SIZE - 2;
    }
    
    static std::string keySizeToString(RSAKeySize size);
    static RSAKeySize stringToKeySize(const std::string& str);
    static std::string formatToString(OutputFormat fmt);
    static OutputFormat stringToFormat(const std::string& str);
};

class RSAException : public std::runtime_error {
public:
    explicit RSAException(const std::string& msg) : std::runtime_error(msg) {}
};