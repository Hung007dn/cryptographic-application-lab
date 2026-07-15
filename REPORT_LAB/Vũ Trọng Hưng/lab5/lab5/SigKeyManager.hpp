// SigKeyManager.hpp
#pragma once
#include "SigConfig.hpp"
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>

class SigKeyManager {
public:
    SigKeyManager();
    ~SigKeyManager();
    
    // Key generation
    void generateKeyPair(SignatureAlgorithm algo);
    void saveKeyPair(const std::string& pub_file, const std::string& priv_file);
    void saveMetadata(const std::string& metadata_file);
    
    // Key loading
    void loadPublicKey(const std::string& pub_file, SignatureAlgorithm algo);
    void loadPrivateKey(const std::string& priv_file, SignatureAlgorithm algo);
    
    // Getters
    EVP_PKEY* getPublicKey() const { return m_pubkey; }
    EVP_PKEY* getPrivateKey() const { return m_privkey; }
    bool hasPublicKey() const { return m_pubkey != nullptr; }
    bool hasPrivateKey() const { return m_privkey != nullptr; }
    
    // Export formats
    std::string exportPublicKeyPEM();
    std::string exportPrivateKeyPEM();
    std::vector<uint8_t> exportPublicKeyDER();
    std::vector<uint8_t> exportPrivateKeyDER();
    
    // Import from memory
    void importPublicKeyPEM(const std::string& pem, SignatureAlgorithm algo);
    void importPrivateKeyPEM(const std::string& pem, SignatureAlgorithm algo);
    
private:
    EVP_PKEY* m_pubkey;
    EVP_PKEY* m_privkey;
    SignatureAlgorithm m_algorithm;
    bool m_hasPubKey;
    bool m_hasPrivKey;
    
    void cleanup();
    std::string base64Encode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> base64Decode(const std::string& base64);
};