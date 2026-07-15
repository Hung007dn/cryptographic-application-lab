// NegativeTests.cpp
#include "NegativeTests.hpp"

#include <fstream>
#include <iostream>
#include <cstdio>

SignatureNegativeTests::SignatureNegativeTests() = default;

void SignatureNegativeTests::addResult(
    const std::string& name,
    bool passed,
    const std::string& expected,
    const std::string& actual
) {
    NegativeTestResult result;
    result.name = name;
    result.passed = passed;
    result.expected = expected;
    result.actual = actual;
    m_results.push_back(result);
}

bool SignatureNegativeTests::testModifiedMessageFails() {
    try {
        SigKeyManager keyManager;
        keyManager.generateKeyPair(SignatureAlgorithm::ECDSA_P256);

        std::vector<uint8_t> message = {'h', 'e', 'l', 'l', 'o'};
        std::vector<uint8_t> modified = {'h', 'e', 'l', 'l', '0'};

        auto sig = m_ecdsa.sign(
            message,
            keyManager.getPrivateKey(),
            HashAlgorithm::SHA256,
            true
        );

        bool ok = m_ecdsa.verify(
            modified,
            sig,
            keyManager.getPublicKey(),
            HashAlgorithm::SHA256
        );

        bool passed = !ok;

        addResult(
            "Modified message verification",
            passed,
            "Verification must fail",
            passed ? "Failed as expected" : "Unexpectedly verified"
        );

        return passed;

    } catch (const std::exception& e) {
        addResult(
            "Modified message verification",
            false,
            "Verification must fail",
            e.what()
        );

        return false;
    }
}

bool SignatureNegativeTests::testModifiedSignatureFails() {
    try {
        SigKeyManager keyManager;
        keyManager.generateKeyPair(SignatureAlgorithm::ECDSA_P256);

        std::vector<uint8_t> message = {'h', 'e', 'l', 'l', 'o'};

        auto sig = m_ecdsa.sign(
            message,
            keyManager.getPrivateKey(),
            HashAlgorithm::SHA256,
            true
        );

        if (!sig.empty()) {
            sig[sig.size() / 2] ^= 0x01;
        }

        bool ok = m_ecdsa.verify(
            message,
            sig,
            keyManager.getPublicKey(),
            HashAlgorithm::SHA256
        );

        bool passed = !ok;

        addResult(
            "Modified signature verification",
            passed,
            "Verification must fail",
            passed ? "Failed as expected" : "Unexpectedly verified"
        );

        return passed;

    } catch (const std::exception& e) {
        addResult(
            "Modified signature verification",
            false,
            "Verification must fail",
            e.what()
        );

        return false;
    }
}

bool SignatureNegativeTests::testWrongPublicKeyFails() {
    try {
        SigKeyManager keyA;
        SigKeyManager keyB;

        keyA.generateKeyPair(SignatureAlgorithm::RSA_PSS_3072);
        keyB.generateKeyPair(SignatureAlgorithm::RSA_PSS_3072);

        std::vector<uint8_t> message = {'t', 'e', 's', 't'};

        auto sig = m_rsa.sign(
            message,
            keyA.getPrivateKey(),
            HashAlgorithm::SHA256
        );

        bool ok = m_rsa.verify(
            message,
            sig,
            keyB.getPublicKey(),
            HashAlgorithm::SHA256
        );

        bool passed = !ok;

        addResult(
            "Wrong public key verification",
            passed,
            "Verification must fail",
            passed ? "Failed as expected" : "Unexpectedly verified"
        );

        return passed;

    } catch (const std::exception& e) {
        addResult(
            "Wrong public key verification",
            false,
            "Verification must fail",
            e.what()
        );

        return false;
    }
}

bool SignatureNegativeTests::testWrongAlgorithmIdentifierFails() {
    try {
        (void)SigConfig::stringToAlgorithm("ecdsa-p999");

        addResult(
            "Wrong algorithm identifier",
            false,
            "Unsupported algorithm must be rejected",
            "Accepted invalid algorithm"
        );

        return false;

    } catch (const std::exception&) {
        addResult(
            "Wrong algorithm identifier",
            true,
            "Unsupported algorithm must be rejected",
            "Rejected as expected"
        );

        return true;
    }
}

bool SignatureNegativeTests::testWrongHashFunctionFails() {
    try {
        SigKeyManager keyManager;
        keyManager.generateKeyPair(SignatureAlgorithm::ECDSA_P256);

        std::vector<uint8_t> message = {'h', 'a', 's', 'h'};

        auto sig = m_ecdsa.sign(
            message,
            keyManager.getPrivateKey(),
            HashAlgorithm::SHA256,
            true
        );

        bool ok = m_ecdsa.verify(
            message,
            sig,
            keyManager.getPublicKey(),
            HashAlgorithm::SHA384
        );

        bool passed = !ok;

        addResult(
            "Wrong hash function verification",
            passed,
            "Verification must fail",
            passed ? "Failed as expected" : "Unexpectedly verified"
        );

        return passed;

    } catch (const std::exception& e) {
        addResult(
            "Wrong hash function verification",
            false,
            "Verification must fail",
            e.what()
        );

        return false;
    }
}

bool SignatureNegativeTests::testMalformedPublicKeyFails() {
    const std::string badKeyFile = "bad_public_key.pem";

    try {
        {
            std::ofstream out(badKeyFile);
            out << "-----BEGIN PUBLIC KEY-----\n";
            out << "this-is-not-a-valid-key\n";
            out << "-----END PUBLIC KEY-----\n";
        }

        SigKeyManager keyManager;
        keyManager.loadPublicKey(badKeyFile, SignatureAlgorithm::ECDSA_P256);

        std::remove(badKeyFile.c_str());

        addResult(
            "Malformed public key",
            false,
            "Malformed key must be rejected",
            "Accepted malformed key"
        );

        return false;

    } catch (const std::exception&) {
        std::remove(badKeyFile.c_str());

        addResult(
            "Malformed public key",
            true,
            "Malformed key must be rejected",
            "Rejected as expected"
        );

        return true;
    }
}

bool SignatureNegativeTests::testUnsupportedEncodingFails() {
    try {
        (void)SigConfig::stringToFormat("hexadecimal");

        addResult(
            "Unsupported signature encoding",
            false,
            "Unsupported encoding must be rejected",
            "Accepted invalid encoding"
        );

        return false;

    } catch (const std::exception&) {
        addResult(
            "Unsupported signature encoding",
            true,
            "Unsupported encoding must be rejected",
            "Rejected as expected"
        );

        return true;
    }
}

bool SignatureNegativeTests::runAllTests() {
    m_results.clear();

    std::cout << "\n=== Lab 5 Signature Negative Tests ===\n" << std::endl;

    testModifiedMessageFails();
    testModifiedSignatureFails();
    testWrongPublicKeyFails();
    testWrongAlgorithmIdentifierFails();
    testWrongHashFunctionFails();
    testMalformedPublicKeyFails();
    testUnsupportedEncodingFails();

    printSummary();

    for (const auto& result : m_results) {
        if (!result.passed) {
            return false;
        }
    }

    return true;
}

void SignatureNegativeTests::printSummary() const {
    size_t passed = 0;

    for (const auto& result : m_results) {
        std::cout << (result.passed ? "[PASSED] " : "[FAILED] ")
                  << result.name
                  << " | Expected: " << result.expected
                  << " | Actual: " << result.actual
                  << std::endl;

        if (result.passed) {
            passed++;
        }
    }

    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << "Total: " << m_results.size() << std::endl;
    std::cout << "Passed: " << passed << std::endl;
    std::cout << "Failed: " << (m_results.size() - passed) << std::endl;
}