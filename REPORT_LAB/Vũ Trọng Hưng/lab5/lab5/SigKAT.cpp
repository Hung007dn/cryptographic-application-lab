#include "SigKAT.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <iostream>
#include <iomanip>

using json = nlohmann::json;

std::vector<uint8_t> SigKAT::stringToBytes(const std::string& text) {
    return std::vector<uint8_t>(text.begin(), text.end());
}

bool SigKAT::runOneTest(
    const std::string& name,
    SignatureAlgorithm algo,
    HashAlgorithm hash,
    const std::vector<uint8_t>& message
) {
    SigKATResult result;
    result.name = name;
    result.algorithm = SigConfig::algorithmToString(algo);
    result.hash = SigConfig::hashToString(hash);
    result.passed = false;

    try {
        SigKeyManager keyManager;
        keyManager.generateKeyPair(algo);

        std::vector<uint8_t> signature;
        bool verified = false;
        bool tamperRejected = false;

        if (algo == SignatureAlgorithm::ECDSA_P256 ||
            algo == SignatureAlgorithm::ECDSA_P384) {
            ECDSAEngine engine;

            signature = engine.sign(
                message,
                keyManager.getPrivateKey(),
                hash,
                true
            );

            verified = engine.verify(
                message,
                signature,
                keyManager.getPublicKey(),
                hash
            );

            std::vector<uint8_t> modified = message;
            if (!modified.empty()) {
                modified[0] ^= 0x01;
            } else {
                modified.push_back(0x01);
            }

            tamperRejected = !engine.verify(
                modified,
                signature,
                keyManager.getPublicKey(),
                hash
            );

        } else if (algo == SignatureAlgorithm::RSA_PSS_3072) {
            RSAPSSEngine engine;

            signature = engine.sign(
                message,
                keyManager.getPrivateKey(),
                hash
            );

            verified = engine.verify(
                message,
                signature,
                keyManager.getPublicKey(),
                hash
            );

            std::vector<uint8_t> modified = message;
            if (!modified.empty()) {
                modified[0] ^= 0x01;
            } else {
                modified.push_back(0x01);
            }

            tamperRejected = !engine.verify(
                modified,
                signature,
                keyManager.getPublicKey(),
                hash
            );

        } else {
            throw SigException("Unsupported algorithm in KAT");
        }

        result.passed = verified && tamperRejected && !signature.empty();

        if (!result.passed) {
            result.error = "signature verification or tamper rejection failed";
        }

    } catch (const std::exception& e) {
        result.passed = false;
        result.error = e.what();
    }

    m_results.push_back(result);
    return result.passed;
}

bool SigKAT::runFromFile(const std::string& jsonFile) {
    m_results.clear();

    std::ifstream file(jsonFile);
    if (!file.is_open()) {
        std::cerr << "Error: cannot open KAT file: " << jsonFile << std::endl;
        return false;
    }

    json data;
    try {
        file >> data;
    } catch (const std::exception& e) {
        std::cerr << "Error: invalid KAT JSON: " << e.what() << std::endl;
        return false;
    }

    if (!data.contains("tests") || !data["tests"].is_array()) {
        std::cerr << "Error: KAT JSON must contain a tests array" << std::endl;
        return false;
    }

    std::cout << "\n=== Lab 5 Signature KAT Suite ===\n" << std::endl;

    for (const auto& test : data["tests"]) {
        std::string name = test.value("name", "Unnamed KAT");
        std::string algoText = test.value("algorithm", "");
        std::string hashText = test.value("hash", "sha256");
        std::string messageText = test.value("message", "");

        try {
            SignatureAlgorithm algo = SigConfig::stringToAlgorithm(algoText);
            HashAlgorithm hash = SigConfig::stringToHash(hashText);

            bool ok = runOneTest(
                name,
                algo,
                hash,
                stringToBytes(messageText)
            );

            std::cout << (ok ? "[PASSED] " : "[FAILED] ")
                      << std::setw(40) << std::left << name
                      << " algo=" << algoText
                      << " hash=" << hashText
                      << std::endl;

        } catch (const std::exception& e) {
            SigKATResult result;
            result.name = name;
            result.algorithm = algoText;
            result.hash = hashText;
            result.passed = false;
            result.error = e.what();
            m_results.push_back(result);

            std::cout << "[FAILED] "
                      << std::setw(40) << std::left << name
                      << " error=" << e.what()
                      << std::endl;
        }
    }

    printSummary();

    for (const auto& r : m_results) {
        if (!r.passed) {
            return false;
        }
    }

    return true;
}

void SigKAT::printSummary() const {
    size_t passed = 0;

    for (const auto& r : m_results) {
        if (r.passed) {
            passed++;
        }
    }

    std::cout << "\n=== KAT Summary ===" << std::endl;
    std::cout << "Total: " << m_results.size() << std::endl;
    std::cout << "Passed: " << passed << std::endl;
    std::cout << "Failed: " << (m_results.size() - passed) << std::endl;

    if (!m_results.empty()) {
        double rate = static_cast<double>(passed) * 100.0 /
                      static_cast<double>(m_results.size());
        std::cout << "Success rate: " << rate << "%" << std::endl;
    }
}