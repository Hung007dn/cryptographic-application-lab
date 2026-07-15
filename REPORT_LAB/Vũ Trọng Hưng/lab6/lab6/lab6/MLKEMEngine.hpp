// MLKEMEngine.hpp
#pragma once
#include "PQConfig.hpp"
#include "PQKeyManager.hpp"
#include <vector>
#include <string>
#include <oqs/oqs.h>

struct KEMResult {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> sharedSecret;
};

class MLKEMEngine {
public:
    MLKEMEngine();
    ~MLKEMEngine();
    
    // Encapsulate: generate shared secret and ciphertext
    KEMResult encapsulate(const std::vector<uint8_t>& publicKey,
                           PQAlgorithm algo);
    
    // Decapsulate: recover shared secret from ciphertext
    std::vector<uint8_t> decapsulate(const std::vector<uint8_t>& ciphertext,
                                      const std::vector<uint8_t>& privateKey,
                                      PQAlgorithm algo);
    
private:
    OQS_KEM* getContext(PQAlgorithm algo);
    void cleanup();
    
    OQS_KEM* m_kem;
};