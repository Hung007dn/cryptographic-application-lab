// RSAKeyManager.hpp
#pragma once
#include "RSAConfig.hpp"
#include <string>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class RSAKeyManager {
public:
    RSAKeyManager();
    ~RSAKeyManager();
    
    // Key generation
    void generateKeyPair(RSAKeySize key_size);
    void saveKeyPair(const std::string& pub_file, const std::string& priv_file);
    void saveMetadata(const std::string& metadata_file);
    
    // Key loading
    void loadPublicKey(const std::string& pub_file);
    void loadPrivateKey(const std::string& priv_file);
    
    // Getters
    CryptoPP::RSA::PublicKey& getPublicKey() { return m_publicKey; }
    CryptoPP::RSA::PrivateKey& getPrivateKey() { return m_privateKey; }
    bool hasPublicKey() const { return m_hasPublicKey; }
    bool hasPrivateKey() const { return m_hasPrivateKey; }
    
    // Export formats
    std::string exportPublicKeyPEM();
    std::string exportPrivateKeyPEM();
    std::vector<uint8_t> exportPublicKeyDER();
    std::vector<uint8_t> exportPrivateKeyDER();
    
    // Import formats
    void importPublicKeyPEM(const std::string& pem);
    void importPrivateKeyPEM(const std::string& pem);
    void importPublicKeyDER(const std::vector<uint8_t>& der);
    void importPrivateKeyDER(const std::vector<uint8_t>& der);
    
private:
    CryptoPP::RSA::PublicKey m_publicKey;
    CryptoPP::RSA::PrivateKey m_privateKey;
    CryptoPP::AutoSeededRandomPool m_rng;
    bool m_hasPublicKey;
    bool m_hasPrivateKey;
    RSAKeySize m_currentKeySize;
    
    std::string base64Encode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> base64Decode(const std::string& base64);
    void createPEMHeader(const std::string& type, std::string& output);
};