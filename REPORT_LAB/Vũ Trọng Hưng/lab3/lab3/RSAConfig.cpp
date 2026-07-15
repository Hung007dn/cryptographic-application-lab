// RSAConfig.cpp
#include "RSAConfig.hpp"
#include <algorithm>
#include <cctype>

std::string RSAConfig::keySizeToString(RSAKeySize size) {
    switch (size) {
        case RSAKeySize::RSA_3072: return "3072";
        case RSAKeySize::RSA_4096: return "4096";
        default: return "3072";
    }
}

RSAKeySize RSAConfig::stringToKeySize(const std::string& str) {
    if (str == "3072") return RSAKeySize::RSA_3072;
    if (str == "4096") return RSAKeySize::RSA_4096;
    throw RSAException("Unsupported key size: " + str + ". Use 3072 or 4096");
}

std::string RSAConfig::formatToString(OutputFormat fmt) {
    switch (fmt) {
        case OutputFormat::RAW: return "raw";
        case OutputFormat::HEX: return "hex";
        case OutputFormat::BASE64: return "base64";
        case OutputFormat::PEM: return "pem";
        case OutputFormat::DER: return "der";
        default: return "base64";
    }
}

OutputFormat RSAConfig::stringToFormat(const std::string& str) {
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (lower == "raw") return OutputFormat::RAW;
    if (lower == "hex") return OutputFormat::HEX;
    if (lower == "base64") return OutputFormat::BASE64;
    if (lower == "pem") return OutputFormat::PEM;
    if (lower == "der") return OutputFormat::DER;

    throw RSAException("Incorrect encoding: " + str + ". Use raw, hex, base64, pem, or der.");
}