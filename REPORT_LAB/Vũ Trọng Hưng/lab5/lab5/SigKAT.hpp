#pragma once

#include "SigConfig.hpp"
#include "SigKeyManager.hpp"
#include "ECDSAEngine.hpp"
#include "RSAPSSEngine.hpp"

#include <string>
#include <vector>

struct SigKATResult {
    std::string name;
    std::string algorithm;
    std::string hash;
    bool passed;
    std::string error;
};

class SigKAT {
public:
    bool runFromFile(const std::string& jsonFile);

private:
    std::vector<SigKATResult> m_results;

    static std::vector<uint8_t> stringToBytes(const std::string& text);

    bool runOneTest(
        const std::string& name,
        SignatureAlgorithm algo,
        HashAlgorithm hash,
        const std::vector<uint8_t>& message
    );

    void printSummary() const;
};