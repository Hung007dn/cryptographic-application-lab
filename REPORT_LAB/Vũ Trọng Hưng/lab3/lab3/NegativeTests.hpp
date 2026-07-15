// NegativeTests.hpp - Thêm vào
#pragma once
#include "RSAConfig.hpp"
#include "RSAKeyManager.hpp"
#include "RSAEngine.hpp"
#include "HybridEncryptor.hpp"
#include <vector>
#include <string>

struct NegativeTestResult {
    std::string name;
    bool passed;
    std::string expected;
    std::string actual;
};

class RSANegativeTests {
public:
    RSANegativeTests();
    bool runAllTests();
    void printSummary();
    
private:
    std::vector<NegativeTestResult> m_results;
    RSAKeyManager m_keyManager;
    RSAEngine m_engine;
    HybridEncryptor m_hybrid;
    
    void addResult(const std::string& name, bool passed,
                   const std::string& expected, const std::string& actual);
    
    // Test functions
    bool testWrongPrivateKey();
    bool testTamperedRSACiphertext();
    bool testTamperedAESGCMCiphertext();
    bool testWrongOAEPLabel();
    bool testTamperedEnvelopeHeader();
    bool testInvalidKeySize();
    bool testMalformedCiphertext();
};