// RSAEngine.hpp
#pragma once
#include "RSAConfig.hpp"
#include "RSAKeyManager.hpp"
#include <vector>
#include <string>

class RSAEngine {
public:
    RSAEngine();
    ~RSAEngine();
    
    // Pure RSA-OAEP encryption (for small data)
    std::vector<uint8_t> encryptOAEP(const std::vector<uint8_t>& plaintext,
                                      CryptoPP::RSA::PublicKey& publicKey,
                                      const std::string& label = "");
    
    std::vector<uint8_t> decryptOAEP(const std::vector<uint8_t>& ciphertext,
                                      CryptoPP::RSA::PrivateKey& privateKey,
                                      const std::string& label = "");
    
    // For large data: will use hybrid mode
    bool isPlaintextTooLarge(size_t plaintext_size, CryptoPP::RSA::PublicKey& publicKey);
    size_t getMaxPlaintextSize(CryptoPP::RSA::PublicKey& publicKey);
    
private:
    CryptoPP::AutoSeededRandomPool m_rng;
};