#include "CryptoConfig.hpp"
#include <algorithm>
#include <cctype>

CryptoConfig::CryptoConfig()
    : mode(CipherMode::CBC)
    , use_aead(false)
    , allow_ecb(false)
    , is_text_input(false)
    , output_format(OutputFormat::RAW)
    , iv_generated_securely(false)
    , iv_size(0)
    , key_size(0)
{}

CipherMode CryptoConfig::stringToMode(const std::string& mode_str) {
    std::string lower = mode_str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    if (lower == "ecb") return CipherMode::ECB;
    if (lower == "cbc") return CipherMode::CBC;
    if (lower == "ofb") return CipherMode::OFB;
    if (lower == "cfb") return CipherMode::CFB;
    if (lower == "ctr") return CipherMode::CTR;
    if (lower == "xts") return CipherMode::XTS;
    if (lower == "ccm") return CipherMode::CCM;
    if (lower == "gcm") return CipherMode::GCM;
    
    throw CryptoException("Unknown mode: " + mode_str);
}

std::string CryptoConfig::modeToString(CipherMode mode) {
    switch (mode) {
        case CipherMode::ECB: return "AES-128-ECB";
        case CipherMode::CBC: return "AES-256-CBC";
        case CipherMode::OFB: return "AES-256-OFB";
        case CipherMode::CFB: return "AES-256-CFB";
        case CipherMode::CTR: return "AES-256-CTR";
        case CipherMode::XTS: return "AES-256-XTS";
        case CipherMode::CCM: return "AES-256-CCM";
        case CipherMode::GCM: return "AES-256-GCM";
        default: return "UNKNOWN";
    }
}

OutputFormat CryptoConfig::stringToFormat(const std::string& format_str) {
    std::string lower = format_str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower == "hex") return OutputFormat::HEX;
    if (lower == "base64") return OutputFormat::BASE64;
    return OutputFormat::RAW;
}

std::string CryptoConfig::formatToString(OutputFormat format) {
    switch (format) {
        case OutputFormat::RAW: return "raw";
        case OutputFormat::HEX: return "hex";
        case OutputFormat::BASE64: return "base64";
        default: return "raw";
    }
}

size_t CryptoConfig::getRequiredIVSize() const {
    using namespace CryptoPP;
    switch (mode) {
        case CipherMode::ECB: return 0;
        case CipherMode::CBC: return AES::BLOCKSIZE;
        case CipherMode::OFB: return AES::BLOCKSIZE;
        case CipherMode::CFB: return AES::BLOCKSIZE;
        case CipherMode::CTR: return AES::BLOCKSIZE;
        case CipherMode::XTS: return AES::BLOCKSIZE;
        case CipherMode::CCM: return 12;
        case CipherMode::GCM: return 12;
        default: return 0;
    }
}

size_t CryptoConfig::getNonceSize() const {
    if (mode == CipherMode::CCM || mode == CipherMode::GCM) {
        return 12;
    }
    return 0;
}

bool CryptoConfig::validateParameters() const {
    // Validate key size.
    // Normal AES modes accept 128/192/256-bit keys: 16/24/32 bytes.
    // XTS uses two AES keys, so it needs double-length material: 32/48/64 bytes.
    if (mode == CipherMode::XTS) {
        if (key.size() != 32 && key.size() != 48 && key.size() != 64) {
            throw CryptoException("Invalid XTS key size: must be 32, 48, or 64 bytes");
        }
    } else {
        if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
            throw CryptoException("Invalid AES key size: must be 16, 24, or 32 bytes");
        }
    }

    // Validate IV/nonce sizes only when the caller already supplied IV/nonce.
    // If it is omitted, FileEncryptor will generate it securely using AutoSeededRandomPool.
    size_t expected_iv = getRequiredIVSize();
    if (expected_iv > 0 && !iv.empty() && iv.size() != expected_iv) {
        throw CryptoException("Invalid IV/nonce size: expected " +
                              std::to_string(expected_iv) + " bytes, got " +
                              std::to_string(iv.size()) + " bytes");
    }

    // ECB is allowed to reach FileEncryptor, where it prints a warning and
    // blocks files larger than 16 KiB unless --allow-ecb is provided.
    return true;
}
