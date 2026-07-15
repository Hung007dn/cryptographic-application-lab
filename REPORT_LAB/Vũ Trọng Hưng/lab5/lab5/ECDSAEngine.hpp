// ECDSAEngine.hpp
#pragma once
#include "SigConfig.hpp"
#include "SigKeyManager.hpp"
#include <vector>
#include <string>

class ECDSAEngine {
public:
    ECDSAEngine();
    ~ECDSAEngine();
    
    // Sign message (supports RFC 6979 deterministic nonce)
    std::vector<uint8_t> sign(const std::vector<uint8_t>& message,
                               EVP_PKEY* privateKey,
                               HashAlgorithm hash_algo,
                               bool deterministic = true);
    
    // Verify signature
    bool verify(const std::vector<uint8_t>& message,
                const std::vector<uint8_t>& signature,
                EVP_PKEY* publicKey,
                HashAlgorithm hash_algo);
    
    // Get signature in different formats
    std::vector<uint8_t> encodeSignatureDER(const std::vector<uint8_t>& raw_sig);
    std::vector<uint8_t> decodeSignatureDER(const std::vector<uint8_t>& der_sig);
    
private:
    std::string hashToString(HashAlgorithm algo);
    int getNID(HashAlgorithm algo);
};