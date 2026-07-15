#pragma once
#include <string>
#include <vector>
#include <cryptopp/secblock.h>
#include <cryptopp/aes.h>
#include <stdexcept>

enum class CipherMode {
    ECB, CBC, OFB, CFB, CTR, XTS, CCM, GCM
};

enum class OutputFormat {
    RAW, HEX, BASE64
};

struct CryptoConfig {
    CipherMode mode;
    CryptoPP::SecByteBlock key;
    CryptoPP::SecByteBlock iv;
    CryptoPP::SecByteBlock tweak_key;
    
    // AEAD specific
    bool use_aead;
    std::string aad_file;
    std::string aad_text;
    std::vector<uint8_t> aad_data;
    std::vector<uint8_t> auth_tag;  // Authentication tag for AEAD
    
    // ECB override
    bool allow_ecb;
    
    // Key handling
    std::string key_hex;
    std::string key_file;
    std::string iv_file;
    std::string nonce_file;
    
    // Input handling
    std::string text_input;  // --text "message"
    bool is_text_input;
    
    // Output format
    OutputFormat output_format;
    
    // Flags
    bool iv_generated_securely;
    size_t iv_size;
    size_t key_size;
    
    CryptoConfig();
    
    static CipherMode stringToMode(const std::string& mode_str);
    static std::string modeToString(CipherMode mode);
    static OutputFormat stringToFormat(const std::string& format_str);
    static std::string formatToString(OutputFormat format);
    
    bool validateParameters() const;
    size_t getRequiredIVSize() const;
    size_t getNonceSize() const;
    
    bool isAEADMode() const {
        return mode == CipherMode::CCM || mode == CipherMode::GCM;
    }
    
    bool requiresIV() const {
        return mode != CipherMode::ECB;
    }
};

class CryptoException : public std::runtime_error {
public:
    explicit CryptoException(const std::string& msg) : std::runtime_error(msg) {}
};