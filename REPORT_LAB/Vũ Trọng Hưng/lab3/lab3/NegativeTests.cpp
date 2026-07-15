
// NegativeTests.cpp
#include "NegativeTests.hpp"

#include <iostream>
#include <vector>
#include <string>

using namespace std;

RSANegativeTests::RSANegativeTests() {
    m_keyManager.generateKeyPair(RSAKeySize::RSA_3072);
}

void RSANegativeTests::addResult(
    const string& name,
    bool passed,
    const string& expected,
    const string& actual
) {
    NegativeTestResult result;
    result.name = name;
    result.passed = passed;
    result.expected = expected;
    result.actual = actual;
    m_results.push_back(result);
}

// ============ TEST 1: Wrong private key ============
bool RSANegativeTests::testWrongPrivateKey() {
    cout << "[Test] Wrong Private Key..." << endl;

    try {
        RSAKeyManager keyManager1;
        RSAKeyManager keyManager2;

        keyManager1.generateKeyPair(RSAKeySize::RSA_3072);
        keyManager2.generateKeyPair(RSAKeySize::RSA_3072);

        string plaintext = "Secret message for wrong private key test";
        vector<uint8_t> plain(plaintext.begin(), plaintext.end());

        auto cipher = m_engine.encryptOAEP(
            plain,
            keyManager1.getPublicKey(),
            "lab2"
        );

        try {
            auto decrypted = m_engine.decryptOAEP(
                cipher,
                keyManager2.getPrivateKey(),
                "lab2"
            );

            (void)decrypted;
            return false;

        } catch (const RSAException&) {
            return true;
        } catch (const std::exception&) {
            return true;
        }

    } catch (...) {
        return false;
    }
}

// ============ TEST 2: Tampered RSA ciphertext ============
bool RSANegativeTests::testTamperedRSACiphertext() {
    cout << "[Test] Tampered RSA Ciphertext..." << endl;

    try {
        string plaintext = "Message to be tampered";
        vector<uint8_t> plain(plaintext.begin(), plaintext.end());

        auto cipher = m_engine.encryptOAEP(
            plain,
            m_keyManager.getPublicKey(),
            "lab2"
        );

        if (!cipher.empty()) {
            cipher[cipher.size() / 2] ^= 0xFF;
        }

        try {
            auto decrypted = m_engine.decryptOAEP(
                cipher,
                m_keyManager.getPrivateKey(),
                "lab2"
            );

            (void)decrypted;
            return false;

        } catch (const RSAException&) {
            return true;
        } catch (const std::exception&) {
            return true;
        }

    } catch (...) {
        return false;
    }
}

// ============ TEST 3: Tampered AES-GCM ciphertext ============
bool RSANegativeTests::testTamperedAESGCMCiphertext() {
    cout << "[Test] Tampered AES-GCM Ciphertext..." << endl;

    try {
        string plaintext(1024 * 10, 'A');
        vector<uint8_t> plain(plaintext.begin(), plaintext.end());

        HybridEnvelope envelope = m_hybrid.hybridEncrypt(
            plain,
            m_keyManager.getPublicKey(),
            "lab2"
        );

        if (!envelope.ciphertext.empty()) {
            envelope.ciphertext[envelope.ciphertext.size() / 2] ^= 0xFF;
        }

        try {
            auto decrypted = m_hybrid.hybridDecrypt(
                envelope,
                m_keyManager.getPrivateKey(),
                "lab2"
            );

            (void)decrypted;
            return false;

        } catch (const RSAException&) {
            return true;
        } catch (const std::exception&) {
            return true;
        }

    } catch (...) {
        return false;
    }
}

// ============ TEST 4: Wrong OAEP label ============
bool RSANegativeTests::testWrongOAEPLabel() {
    cout << "[Test] Wrong OAEP Label..." << endl;

    try {
        string plaintext = "Message with OAEP label";
        vector<uint8_t> plain(plaintext.begin(), plaintext.end());

        auto cipher = m_engine.encryptOAEP(
            plain,
            m_keyManager.getPublicKey(),
            "correct_label"
        );

        try {
            auto decrypted = m_engine.decryptOAEP(
                cipher,
                m_keyManager.getPrivateKey(),
                "wrong_label"
            );

            (void)decrypted;
            return false;

        } catch (const RSAException&) {
            return true;
        } catch (const std::exception&) {
            return true;
        }

    } catch (...) {
        return false;
    }
}

// ============ TEST 5: Tampered envelope header ============
bool RSANegativeTests::testTamperedEnvelopeHeader() {
    cout << "[Test] Tampered Envelope Header..." << endl;

    try {
        string plaintext = "Tampered envelope header test";
        vector<uint8_t> plain(plaintext.begin(), plaintext.end());

        HybridEnvelope envelope = m_hybrid.hybridEncrypt(
            plain,
            m_keyManager.getPublicKey(),
            "lab2"
        );

        // Tamper authenticated header field.
        envelope.hash = "SHA-1";

        try {
            auto decrypted = m_hybrid.hybridDecrypt(
                envelope,
                m_keyManager.getPrivateKey(),
                "lab2"
            );

            (void)decrypted;
            return false;

        } catch (const RSAException&) {
            return true;
        } catch (const std::exception&) {
            return true;
        }

    } catch (...) {
        return false;
    }
}

// ============ TEST 6: Invalid key size ============
bool RSANegativeTests::testInvalidKeySize() {
    cout << "[Test] Invalid Key Size..." << endl;

    try {
        RSAKeyManager km;

        try {
            km.generateKeyPair(static_cast<RSAKeySize>(1024));
            return false;

        } catch (const RSAException&) {
            return true;
        } catch (const std::exception&) {
            return true;
        }

    } catch (...) {
        return false;
    }
}

// ============ TEST 7: Malformed ciphertext ============
bool RSANegativeTests::testMalformedCiphertext() {
    cout << "[Test] Malformed Ciphertext..." << endl;

    try {
        vector<uint8_t> malformed(100, 0x00);

        try {
            auto decrypted = m_engine.decryptOAEP(
                malformed,
                m_keyManager.getPrivateKey(),
                "lab2"
            );

            (void)decrypted;
            return false;

        } catch (const RSAException&) {
            return true;
        } catch (const std::exception&) {
            return true;
        }

    } catch (...) {
        return false;
    }
}

// ============ RUN ALL TESTS ============
bool RSANegativeTests::runAllTests() {
    m_results.clear();

    cout << "\n========================================\n";
    cout << "     RSA NEGATIVE TESTS SUITE\n";
    cout << "========================================\n\n";

    addResult(
        "Wrong Private Key",
        testWrongPrivateKey(),
        "Decryption must fail with wrong private key",
        "Wrong private key test executed"
    );

    addResult(
        "Tampered RSA Ciphertext",
        testTamperedRSACiphertext(),
        "Altered RSA ciphertext must fail",
        "Tampered RSA ciphertext test executed"
    );

    addResult(
        "Tampered AES-GCM Ciphertext",
        testTamperedAESGCMCiphertext(),
        "Altered AES-GCM ciphertext must fail tag verification",
        "Tampered AES-GCM ciphertext test executed"
    );

    addResult(
        "Wrong OAEP Label",
        testWrongOAEPLabel(),
        "Wrong OAEP label must fail",
        "Wrong OAEP label test executed"
    );

    addResult(
        "Tampered Envelope Header",
        testTamperedEnvelopeHeader(),
        "Tampered envelope header must fail",
        "Tampered envelope header test executed"
    );

    addResult(
        "Invalid Key Size",
        testInvalidKeySize(),
        "Unsupported RSA key size must fail",
        "Invalid key size test executed"
    );

    addResult(
        "Malformed Ciphertext",
        testMalformedCiphertext(),
        "Malformed ciphertext must fail",
        "Malformed ciphertext test executed"
    );

    printSummary();

    for (const auto& result : m_results) {
        if (!result.passed) {
            return false;
        }
    }

    return true;
}

// ============ PRINT SUMMARY ============
void RSANegativeTests::printSummary() {
    cout << "\n=== Negative Tests Summary ===\n";

    int passed_count = 0;

    for (const auto& result : m_results) {
        if (result.passed) {
            cout << "  [PASSED] " << result.name << "\n";
            passed_count++;
        } else {
            cout << "  [FAILED] " << result.name << "\n";
            cout << "           Expected: " << result.expected << "\n";
            cout << "           Actual  : " << result.actual << "\n";
        }
    }

    cout << "\nPassed: " << passed_count << "/" << m_results.size() << "\n";
}

