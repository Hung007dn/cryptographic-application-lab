#pragma once
#include "CryptoConfig.hpp"
#include <string>
#include <vector>
#include <map>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

struct KATResult {
    std::string name;
    std::string mode;
    bool passed;
    std::string expected;
    std::string actual;
    std::string error_message;
    double execution_time_ms;
};

class KATRunner {
public:
    KATRunner();
    
    // Run KAT from JSON file
    bool runFromFile(const std::string& json_file);
    
    // Run individual test suites
    bool runNIST_SP800_38A();
    bool runNIST_GCM();
    bool runNIST_CCM();
    
    // Print results
    void printSummary();
    void exportResults(const std::string& output_file);
    
private:
    std::vector<KATResult> m_results;
    
    // Individual test functions
    bool testCBC_KAT(const json& vector);
    bool testCFB_KAT(const json& vector);
    bool testOFB_KAT(const json& vector);
    bool testCTR_KAT(const json& vector);
    bool testGCM_KAT(const json& vector);
    bool testCCM_KAT(const json& vector);
    
    // Helper functions
    std::vector<uint8_t> hexToBytes(const std::string& hex);
    std::string bytesToHex(const std::vector<uint8_t>& bytes);
    bool compareBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    
    // Mode-specific encryption
    std::vector<uint8_t> encryptCBC(const std::vector<uint8_t>& key,
                                     const std::vector<uint8_t>& iv,
                                     const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> encryptCFB(const std::vector<uint8_t>& key,
                                     const std::vector<uint8_t>& iv,
                                     const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> encryptOFB(const std::vector<uint8_t>& key,
                                     const std::vector<uint8_t>& iv,
                                     const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> encryptCTR(const std::vector<uint8_t>& key,
                                     const std::vector<uint8_t>& iv,
                                     const std::vector<uint8_t>& plaintext);
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encryptGCM(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& aad);
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encryptCCM(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& aad);
};