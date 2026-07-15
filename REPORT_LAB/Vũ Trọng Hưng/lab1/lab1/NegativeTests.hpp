#pragma once
#include "CryptoConfig.hpp"
#include "FileEncryptor.hpp"
#include <string>
#include <vector>

struct NegativeTestResult {
    std::string name;
    bool passed;
    std::string expected_behavior;
    std::string actual_behavior;
};

class NegativeTests {
public:
    NegativeTests();
    
    bool runAllTests();
    void printSummary();
    
private:
    std::vector<NegativeTestResult> m_results;
    
    // Negative tests
    bool testWrongKey();
    bool testWrongIV();
    bool testTamperedCiphertext_NonAEAD();
    bool testTamperedCiphertext_AEAD();
    bool testInvalidTag();
    bool testInvalidIVLength();
    bool testMalformedInput();
    bool testNonceReuse();
    
    void addResult(const std::string& name, bool passed, 
                   const std::string& expected, const std::string& actual);
};