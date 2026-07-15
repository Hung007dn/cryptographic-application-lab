// RSAPSSEngine.hpp
#pragma once
#include "SigConfig.hpp"
#include "SigKeyManager.hpp"
#include <vector>
#include <string>

class RSAPSSEngine {
public:
    RSAPSSEngine();
    ~RSAPSSEngine();
    
    // Sign with RSA-PSS
    std::vector<uint8_t> sign(const std::vector<uint8_t>& message,
                               EVP_PKEY* privateKey,
                               HashAlgorithm hash_algo);
    
    // Verify RSA-PSS signature
    bool verify(const std::vector<uint8_t>& message,
                const std::vector<uint8_t>& signature,
                EVP_PKEY* publicKey,
                HashAlgorithm hash_algo);
    
private:
    std::string hashToString(HashAlgorithm algo);
    int getNID(HashAlgorithm algo);
};