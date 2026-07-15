// BatchVerifier.hpp
#pragma once
#include "SigConfig.hpp"
#include "SigKeyManager.hpp"
#include "ECDSAEngine.hpp"
#include "RSAPSSEngine.hpp"
#include <vector>
#include <string>

struct BatchResult {
    size_t total;
    size_t valid;
    size_t invalid;
    std::vector<size_t> failed_indices;
    double total_time_ms;
};

class BatchVerifier {
public:
    BatchVerifier();
    ~BatchVerifier();
    
    // Batch verify multiple signatures
    BatchResult verifyBatch(const std::vector<std::string>& messages,
                            const std::vector<std::vector<uint8_t>>& signatures,
                            EVP_PKEY* publicKey,
                            SignatureAlgorithm algo,
                            HashAlgorithm hash_algo);
    
    // Generate test batch
    void generateTestBatch(size_t count);
    
    // Print batch results
    void printBatchResult(const BatchResult& result);
    
    // Performance test
    void runBatchPerformanceTest();
    
private:
    ECDSAEngine m_ecdsaEngine;
    RSAPSSEngine m_rsaEngine;
    SigKeyManager m_keyManager;
    
    std::vector<std::string> m_testMessages;
    std::vector<std::vector<uint8_t>> m_testSignatures;
};