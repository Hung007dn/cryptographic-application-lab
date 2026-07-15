// HashValidator.hpp
#pragma once
#include "HashConfig.hpp"
#include "HashEngine.hpp"
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

struct KATResult {
    std::string name;
    std::string algorithm;
    bool passed;
    std::string expected;
    std::string actual;
    std::string error_message;
    double execution_time_ms;
};

class HashValidator {
public:
    HashValidator();
    
    // Run KAT from JSON file
    bool runFromFile(const std::string& json_file);
    
    // Run NIST test vectors
    bool runNISTTests();
    
    void printSummary();
    void exportResults(const std::string& output_file);
    
private:
    std::vector<KATResult> m_results;
    HashEngine m_engine;
    
    // Test functions
    bool testSHA2_KAT(const json& vector);
    bool testSHA3_KAT(const json& vector);
    bool testSHAKE_KAT(const json& vector);
    
    // Helpers
    std::vector<uint8_t> hexToBytes(const std::string& hex);
    std::string bytesToHex(const std::vector<uint8_t>& bytes);
    bool compareBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    
    void loadNISTVectors();
};