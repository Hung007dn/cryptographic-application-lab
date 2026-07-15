#pragma once

#include "HashConfig.hpp"
#include "HashEngine.hpp"

#include <string>
#include <vector>

struct NegativeTestResult {
    std::string name;
    bool passed;
    std::string expected;
    std::string actual;
};

class HashNegativeTests {
public:
    HashNegativeTests();

    bool runAllTests();
    void printSummary() const;

private:
    std::vector<NegativeTestResult> m_results;
    HashEngine m_engine;

    void addResult(const std::string& name,
                   bool passed,
                   const std::string& expected,
                   const std::string& actual);

    bool testUnsupportedAlgorithm();
    bool testUnsupportedFormat();
    bool testMissingInputFile();
    bool testInvalidShakeOutlen();
    bool testRawOutputRequiresFile();
    bool testMalformedCertificate();
    bool testNonCollidingMD5Pair();
};