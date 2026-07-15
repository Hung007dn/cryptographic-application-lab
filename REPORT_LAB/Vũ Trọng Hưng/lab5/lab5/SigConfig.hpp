// SigConfig.hpp
#pragma once
#include <string>
#include <cstdint>
#include <stdexcept>

enum class SignatureAlgorithm {
    ECDSA_P256,
    ECDSA_P384,
    RSA_PSS_3072
};

enum class HashAlgorithm {
    SHA256,
    SHA384
};

enum class OutputFormat {
    RAW, DER, BASE64, PEM
};

struct SigConfig {
    SignatureAlgorithm algorithm;
    HashAlgorithm hash_algo;
    OutputFormat output_format;
    bool deterministic_nonce;  // RFC 6979 for ECDSA
    
    SigConfig();
    
    static SignatureAlgorithm stringToAlgorithm(const std::string& algo);
    static std::string algorithmToString(SignatureAlgorithm algo);
    static HashAlgorithm stringToHash(const std::string& hash);
    static std::string hashToString(HashAlgorithm hash);
    static OutputFormat stringToFormat(const std::string& fmt);
    static std::string formatToString(OutputFormat fmt);
    
    size_t getKeySizeBits() const;
    size_t getSignatureSize() const;
    std::string getCurveName() const;
};

class SigException : public std::runtime_error {
public:
    explicit SigException(const std::string& msg) : std::runtime_error(msg) {}
};