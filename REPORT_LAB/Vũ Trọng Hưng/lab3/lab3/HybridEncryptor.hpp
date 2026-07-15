
// HybridEncryptor.hpp
#pragma once

#include "RSAConfig.hpp"
#include "RSAKeyManager.hpp"
#include "RSAEngine.hpp"

#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

#include <vector>
#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

struct HybridEnvelope {
    std::string mode;
    int rsa_modulus;
    std::string hash;
    std::string wrapped_key;  // Base64 encoded RSA-encrypted AES key
    std::string iv;           // Base64 encoded IV
    std::string tag;          // Base64 encoded GCM tag
    std::vector<uint8_t> ciphertext;

    std::string toJSON() const;
    static HybridEnvelope fromJSON(const std::string& json_str);
};

class HybridEncryptor {
public:
    HybridEncryptor();
    ~HybridEncryptor();

    // Hybrid encryption for large data
    HybridEnvelope hybridEncrypt(
        const std::vector<uint8_t>& plaintext,
        CryptoPP::RSA::PublicKey& publicKey,
        const std::string& label = ""
    );

    std::vector<uint8_t> hybridDecrypt(
        const HybridEnvelope& envelope,
        CryptoPP::RSA::PrivateKey& privateKey,
        const std::string& label = ""
    );

    // Automatic mode selection
    std::vector<uint8_t> encryptAuto(
        const std::vector<uint8_t>& plaintext,
        CryptoPP::RSA::PublicKey& publicKey,
        const std::string& label = "",
        bool force_hybrid = false
    );

    std::vector<uint8_t> decryptAuto(
        const std::vector<uint8_t>& ciphertext,
        CryptoPP::RSA::PrivateKey& privateKey,
        const std::string& label = ""
    );

private:
    RSAEngine m_rsaEngine;
    CryptoPP::AutoSeededRandomPool m_rng;

    std::vector<uint8_t> generateAESKey();
    std::vector<uint8_t> generateIV();

    // AES-GCM encryption with label as AAD.
    // tag is output.
    std::vector<uint8_t> aesGCMEncrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv,
        const std::string& label,
        std::vector<uint8_t>& tag
    );

    // AES-GCM decryption with label as AAD.
    // tag is input and must verify correctly.
    std::vector<uint8_t> aesGCMDecrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& tag,
        const std::string& label
    );

    std::string base64Encode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> base64Decode(const std::string& base64);
};
