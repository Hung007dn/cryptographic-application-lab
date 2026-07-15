// RSAValidator.hpp
#pragma once
#include "RSAConfig.hpp"
#include "RSAKeyManager.hpp"
#include "RSAEngine.hpp"
#include <string>
#include <vector>
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

class RSAValidator {
public:
    RSAValidator();
    
    // Run KAT from JSON file
    bool runFromFile(const std::string& json_file);
    
    // Run NIST RSA test vectors
    bool runNIST_RSA_OAEP_Tests();
    
    void printSummary();
    void exportResults(const std::string& output_file);
    
private:
    std::vector<KATResult> m_results;
    RSAKeyManager m_keyManager;
    RSAEngine m_engine;
    
    // Test functions
    bool testRSA_OAEP_KAT(const json& vector);
    
    // Helper functions
    std::vector<uint8_t> hexToBytes(const std::string& hex);
    std::string bytesToHex(const std::vector<uint8_t>& bytes);
    bool compareBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    
    void printResult(const std::string& test_name, bool passed);
};