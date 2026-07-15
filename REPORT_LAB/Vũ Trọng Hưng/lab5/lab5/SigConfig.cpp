// SigConfig.cpp
#include "SigConfig.hpp"
#include <algorithm>
#include <cctype>

SigConfig::SigConfig()
    : algorithm(SignatureAlgorithm::ECDSA_P256)
    , hash_algo(HashAlgorithm::SHA256)
    , output_format(OutputFormat::DER)
    , deterministic_nonce(true)
{}

SignatureAlgorithm SigConfig::stringToAlgorithm(const std::string& algo) {
    std::string lower = algo;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    if (lower == "ecdsa-p256") return SignatureAlgorithm::ECDSA_P256;
    if (lower == "ecdsa-p384") return SignatureAlgorithm::ECDSA_P384;
    if (lower == "rsa-pss-3072") return SignatureAlgorithm::RSA_PSS_3072;
    
    throw SigException("Unsupported algorithm: " + algo);
}

std::string SigConfig::algorithmToString(SignatureAlgorithm algo) {
    switch (algo) {
        case SignatureAlgorithm::ECDSA_P256: return "ECDSA-P256";
        case SignatureAlgorithm::ECDSA_P384: return "ECDSA-P384";
        case SignatureAlgorithm::RSA_PSS_3072: return "RSA-PSS-3072";
        default: return "UNKNOWN";
    }
}

HashAlgorithm SigConfig::stringToHash(const std::string& hash) {
    std::string lower = hash;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower == "sha256") return HashAlgorithm::SHA256;
    if (lower == "sha384") return HashAlgorithm::SHA384;
    throw SigException("Unsupported hash: " + hash);
}

std::string SigConfig::hashToString(HashAlgorithm hash) {
    switch (hash) {
        case HashAlgorithm::SHA256: return "SHA-256";
        case HashAlgorithm::SHA384: return "SHA-384";
        default: return "UNKNOWN";
    }
}

OutputFormat SigConfig::stringToFormat(const std::string& fmt) {
    std::string lower = fmt;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower == "raw") return OutputFormat::RAW;
    if (lower == "der") return OutputFormat::DER;
    if (lower == "base64") return OutputFormat::BASE64;
    if (lower == "pem") return OutputFormat::PEM;
    throw SigException("Unsupported format: " + fmt);
}

std::string SigConfig::formatToString(OutputFormat fmt) {
    switch (fmt) {
        case OutputFormat::RAW: return "raw";
        case OutputFormat::DER: return "der";
        case OutputFormat::BASE64: return "base64";
        case OutputFormat::PEM: return "pem";
        default: return "der";
    }
}

size_t SigConfig::getKeySizeBits() const {
    switch (algorithm) {
        case SignatureAlgorithm::ECDSA_P256: return 256;
        case SignatureAlgorithm::ECDSA_P384: return 384;
        case SignatureAlgorithm::RSA_PSS_3072: return 3072;
        default: return 0;
    }
}

size_t SigConfig::getSignatureSize() const {
    switch (algorithm) {
        case SignatureAlgorithm::ECDSA_P256: return 64;  // r + s (32+32)
        case SignatureAlgorithm::ECDSA_P384: return 96;  // r + s (48+48)
        case SignatureAlgorithm::RSA_PSS_3072: return 384; // 3072 bits / 8
        default: return 0;
    }
}

std::string SigConfig::getCurveName() const {
    switch (algorithm) {
        case SignatureAlgorithm::ECDSA_P256: return "secp256r1";
        case SignatureAlgorithm::ECDSA_P384: return "secp384r1";
        default: return "";
    }
}