// MLDSAEngine.hpp
#pragma once
#include "PQConfig.hpp"
#include "PQKeyManager.hpp"
#include <vector>
#include <string>
#include <oqs/oqs.h>

class MLDSAEngine {
public:
    MLDSAEngine();
    ~MLDSAEngine();
    
    // Sign message
    std::vector<uint8_t> sign(const std::vector<uint8_t>& message,
                               const std::vector<uint8_t>& privateKey,
                               PQAlgorithm algo);
    
    // Verify signature
    bool verify(const std::vector<uint8_t>& message,
                const std::vector<uint8_t>& signature,
                const std::vector<uint8_t>& publicKey,
                PQAlgorithm algo);
    
private:
    OQS_SIG* getContext(PQAlgorithm algo);
    void cleanup();
    
    OQS_SIG* m_sig;
};