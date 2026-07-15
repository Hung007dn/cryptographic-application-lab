// HashConfig.cpp
#include "HashConfig.hpp"
#include <algorithm>
#include <cctype>

HashConfig::HashConfig()
    : algorithm(HashAlgorithm::SHA_256)
    , output_format(OutputFormat::HEX)
    , shake_output_length(32)
    , stream_mode(false)
{}

HashAlgorithm HashConfig::stringToAlgorithm(const std::string& algo) {
    std::string lower = algo;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    if (lower == "sha224") return HashAlgorithm::SHA_224;
    if (lower == "sha256") return HashAlgorithm::SHA_256;
    if (lower == "sha384") return HashAlgorithm::SHA_384;
    if (lower == "sha512") return HashAlgorithm::SHA_512;
    if (lower == "sha3-224" || lower == "sha3_224") return HashAlgorithm::SHA3_224;
    if (lower == "sha3-256" || lower == "sha3_256") return HashAlgorithm::SHA3_256;
    if (lower == "sha3-384" || lower == "sha3_384") return HashAlgorithm::SHA3_384;
    if (lower == "sha3-512" || lower == "sha3_512") return HashAlgorithm::SHA3_512;
    if (lower == "shake128") return HashAlgorithm::SHAKE128;
    if (lower == "shake256") return HashAlgorithm::SHAKE256;
    
    throw HashException("Unsupported algorithm: " + algo);
}

std::string HashConfig::algorithmToString(HashAlgorithm algo) {
    switch (algo) {
        case HashAlgorithm::SHA_224: return "SHA-224";
        case HashAlgorithm::SHA_256: return "SHA-256";
        case HashAlgorithm::SHA_384: return "SHA-384";
        case HashAlgorithm::SHA_512: return "SHA-512";
        case HashAlgorithm::SHA3_224: return "SHA3-224";
        case HashAlgorithm::SHA3_256: return "SHA3-256";
        case HashAlgorithm::SHA3_384: return "SHA3-384";
        case HashAlgorithm::SHA3_512: return "SHA3-512";
        case HashAlgorithm::SHAKE128: return "SHAKE128";
        case HashAlgorithm::SHAKE256: return "SHAKE256";
        default: return "UNKNOWN";
    }
}

OutputFormat HashConfig::stringToFormat(const std::string& fmt) {
    std::string lower = fmt;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower == "hex") return OutputFormat::HEX;
    if (lower == "raw") return OutputFormat::RAW;
    throw HashException("Unsupported output format: " + fmt);
}

std::string HashConfig::formatToString(OutputFormat fmt) {
    switch (fmt) {
        case OutputFormat::HEX: return "hex";
        case OutputFormat::RAW: return "raw";
        default: return "hex";
    }
}

size_t HashConfig::getDigestSize() const {
    switch (algorithm) {
        case HashAlgorithm::SHA_224: return 28;  // 224 bits
        case HashAlgorithm::SHA_256: return 32;  // 256 bits
        case HashAlgorithm::SHA_384: return 48;  // 384 bits
        case HashAlgorithm::SHA_512: return 64;  // 512 bits
        case HashAlgorithm::SHA3_224: return 28;
        case HashAlgorithm::SHA3_256: return 32;
        case HashAlgorithm::SHA3_384: return 48;
        case HashAlgorithm::SHA3_512: return 64;
        case HashAlgorithm::SHAKE128:
        case HashAlgorithm::SHAKE256:
            return shake_output_length;
        default: return 0;
    }
}

std::string HashConfig::getAlgorithmName() const {
    return algorithmToString(algorithm);
}