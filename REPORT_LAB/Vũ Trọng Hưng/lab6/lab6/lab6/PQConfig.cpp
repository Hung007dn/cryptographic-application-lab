// PQConfig.cpp
#include "PQConfig.hpp"
#include <algorithm>
#include <cctype>

PQConfig::PQConfig()
    : algorithm(PQAlgorithm::MLDSA_44)
    , output_format(OutputFormat::RAW)
{}

PQAlgorithm PQConfig::stringToAlgorithm(const std::string& algo) {
    std::string lower = algo;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    if (lower == "mldsa-44") return PQAlgorithm::MLDSA_44;
    if (lower == "mldsa-65") return PQAlgorithm::MLDSA_65;
    if (lower == "mldsa-87") return PQAlgorithm::MLDSA_87;
    if (lower == "mlkem-512") return PQAlgorithm::MLKEM_512;
    if (lower == "mlkem-768") return PQAlgorithm::MLKEM_768;
    if (lower == "mlkem-1024") return PQAlgorithm::MLKEM_1024;
    
    throw PQException("Unsupported algorithm: " + algo);
}

std::string PQConfig::algorithmToString(PQAlgorithm algo) {
    switch (algo) {
        case PQAlgorithm::MLDSA_44: return "ML-DSA-44";
        case PQAlgorithm::MLDSA_65: return "ML-DSA-65";
        case PQAlgorithm::MLDSA_87: return "ML-DSA-87";
        case PQAlgorithm::MLKEM_512: return "ML-KEM-512";
        case PQAlgorithm::MLKEM_768: return "ML-KEM-768";
        case PQAlgorithm::MLKEM_1024: return "ML-KEM-1024";
        default: return "UNKNOWN";
    }
}

OutputFormat PQConfig::stringToFormat(const std::string& fmt) {
    std::string lower = fmt;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower == "raw") return OutputFormat::RAW;
    if (lower == "base64") return OutputFormat::BASE64;
    if (lower == "pem") return OutputFormat::PEM;
    if (lower == "der") return OutputFormat::DER;
    throw PQException("Unsupported format: " + fmt);
}

std::string PQConfig::formatToString(OutputFormat fmt) {
    switch (fmt) {
        case OutputFormat::RAW: return "raw";
        case OutputFormat::BASE64: return "base64";
        case OutputFormat::PEM: return "pem";
        case OutputFormat::DER: return "der";
        default: return "raw";
    }
}

size_t PQConfig::getPublicKeySize() const {
    switch (algorithm) {
        case PQAlgorithm::MLDSA_44: return 1312;
        case PQAlgorithm::MLDSA_65: return 1952;
        case PQAlgorithm::MLDSA_87: return 2592;
        case PQAlgorithm::MLKEM_512: return 800;
        case PQAlgorithm::MLKEM_768: return 1184;
        case PQAlgorithm::MLKEM_1024: return 1568;
        default: return 0;
    }
}

size_t PQConfig::getPrivateKeySize() const {
    switch (algorithm) {
        case PQAlgorithm::MLDSA_44: return 2528;
        case PQAlgorithm::MLDSA_65: return 4032;
        case PQAlgorithm::MLDSA_87: return 4896;
        case PQAlgorithm::MLKEM_512: return 1632;
        case PQAlgorithm::MLKEM_768: return 2400;
        case PQAlgorithm::MLKEM_1024: return 3168;
        default: return 0;
    }
}

size_t PQConfig::getSignatureSize() const {
    switch (algorithm) {
        case PQAlgorithm::MLDSA_44: return 2420;
        case PQAlgorithm::MLDSA_65: return 3309;
        case PQAlgorithm::MLDSA_87: return 4627;
        default: return 0;
    }
}

size_t PQConfig::getCiphertextSize() const {
    switch (algorithm) {
        case PQAlgorithm::MLKEM_512: return 768;
        case PQAlgorithm::MLKEM_768: return 1088;
        case PQAlgorithm::MLKEM_1024: return 1568;
        default: return 0;
    }
}

size_t PQConfig::getSharedSecretSize() const {
    return 32;  // All ML-KEM variants produce 32-byte shared secret
}

std::string PQConfig::getAlgorithmName() const {
    return algorithmToString(algorithm);
}