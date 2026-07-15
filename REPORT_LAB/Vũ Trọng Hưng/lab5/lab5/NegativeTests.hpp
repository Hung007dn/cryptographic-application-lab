// NegativeTests.hpp
#pragma once

#include "SigConfig.hpp"
#include "SigKeyManager.hpp"
#include "ECDSAEngine.hpp"
#include "RSAPSSEngine.hpp"

#include <string>
#include <vector>

struct NegativeTestResult {
    std::string name;
    bool passed;
    std::string expected;
    std::string actual;
};

class SignatureNegativeTests {
public:
    SignatureNegativeTests();

    bool runAllTests();
    void printSummary() const;

private:
    std::vector<NegativeTestResult> m_results;

    ECDSAEngine m_ecdsa;
    RSAPSSEngine m_rsa;

    void addResult(
        const std::string& name,
        bool passed,
        const std::string& expected,
        const std::string& actual
    );

    bool testModifiedMessageFails();
    bool testModifiedSignatureFails();
    bool testWrongPublicKeyFails();
    bool testWrongAlgorithmIdentifierFails();
    bool testWrongHashFunctionFails();
    bool testMalformedPublicKeyFails();
    bool testUnsupportedEncodingFails();
};