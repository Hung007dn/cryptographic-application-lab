#include "PQNegativeTests.hpp"
#include "PQKeyManager.hpp"
#include "MLDSAEngine.hpp"
#include "MLKEMEngine.hpp"
#include "PQCertificate.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdio>

static bool report(const std::string& name, bool passed) {
    std::cout << (passed ? "[PASS] " : "[FAIL] ") << name << "\n";
    return passed;
}

static void setupMLDSAKeys(const std::string& pub, const std::string& priv) {
    PQKeyManager::mldsaKeygen(MLDSALevel::MLDSA44, pub, priv);
}

bool PQNegativeTests::testModifiedMessageFails() {
    setupMLDSAKeys("._neg_pub.pem", "._neg_priv.pem");
    std::vector<unsigned char> msg = {'H','e','l','l','o'};
    auto sig = MLDSAEngine::sign(MLDSALevel::MLDSA44, "._neg_priv.pem", msg);
    // Tamper message
    msg[0] = 'X';
    bool verifyResult = MLDSAEngine::verify(MLDSALevel::MLDSA44, "._neg_pub.pem", msg, sig);
    remove("._neg_pub.pem"); remove("._neg_priv.pem");
    // Expected: verify returns FALSE (tampered message should fail)
    return report("Modified message -> verify fails", !verifyResult);
}

bool PQNegativeTests::testModifiedSigFails() {
    setupMLDSAKeys("._neg_pub.pem", "._neg_priv.pem");
    std::vector<unsigned char> msg = {'T','e','s','t'};
    auto sig = MLDSAEngine::sign(MLDSALevel::MLDSA44, "._neg_priv.pem", msg);
    // Tamper signature
    if (!sig.empty()) sig[0] ^= 0xFF;
    bool verifyResult = MLDSAEngine::verify(MLDSALevel::MLDSA44, "._neg_pub.pem", msg, sig);
    remove("._neg_pub.pem"); remove("._neg_priv.pem");
    return report("Modified signature -> verify fails", !verifyResult);
}

bool PQNegativeTests::testWrongKeyFails() {
    // Sign with key1, verify with key2
    setupMLDSAKeys("._neg_pub1.pem", "._neg_priv1.pem");
    setupMLDSAKeys("._neg_pub2.pem", "._neg_priv2.pem");
    std::vector<unsigned char> msg = {'K','e','y'};
    auto sig = MLDSAEngine::sign(MLDSALevel::MLDSA44, "._neg_priv1.pem", msg);
    bool verifyResult = MLDSAEngine::verify(MLDSALevel::MLDSA44, "._neg_pub2.pem", msg, sig);
    remove("._neg_pub1.pem"); remove("._neg_priv1.pem");
    remove("._neg_pub2.pem"); remove("._neg_priv2.pem");
    return report("Wrong public key -> verify fails", !verifyResult);
}

bool PQNegativeTests::testModifiedKEMCiphertextFails() {
    PQKeyManager::mlkemKeygen(MLKEMLevel::MLKEM512, "._neg_kem_pub.pem", "._neg_kem_priv.pem");
    auto res = MLKEMEngine::encapsulate(MLKEMLevel::MLKEM512, "._neg_kem_pub.pem");
    // Tamper ciphertext
    auto ct = res.ciphertext;
    if (!ct.empty()) ct[0] ^= 0xFF;
    bool exceptionThrown = false;
    try {
        auto ss2 = MLKEMEngine::decapsulate(MLKEMLevel::MLKEM512, "._neg_kem_priv.pem", ct);
        // If decaps succeeds with tampered ct, ss must differ from original
        if (ss2 != res.sharedSecret) exceptionThrown = true;
    } catch (...) {
        exceptionThrown = true;
    }
    remove("._neg_kem_pub.pem"); remove("._neg_kem_priv.pem");
    return report("Modified KEM ciphertext -> shared secret mismatch or error", exceptionThrown);
}

bool PQNegativeTests::testTamperedCertFails() {
    // Setup CA keys
    PQKeyManager::mldsaKeygen(MLDSALevel::MLDSA44, "._ca_pub.pem", "._ca_priv.pem");
    // Setup subject keys (also ML-DSA for simplicity)
    PQKeyManager::mldsaKeygen(MLDSALevel::MLDSA44, "._sub_pub.pem", "._sub_priv.pem");
    // Generate cert
    PQCertificate::generate("._ca_priv.pem", "._ca_pub.pem", "TestSubject", "._sub_pub.pem", "._neg_cert.json");
    // Tamper the cert (change subject name)
    {
        std::ifstream fin("._neg_cert.json");
        std::string content((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
        // Replace subject value
        size_t pos = content.find("TestSubject");
        if (pos != std::string::npos) content.replace(pos, 11, "HackedName!");
        std::ofstream fout("._neg_cert.json");
        fout << content;
    }
    bool ok = PQCertificate::verify("._neg_cert.json", "._ca_pub.pem");
    remove("._ca_pub.pem"); remove("._ca_priv.pem");
    remove("._sub_pub.pem"); remove("._sub_priv.pem");
    remove("._neg_cert.json");
    return report("Tampered certificate -> verify fails", !ok);
}

bool PQNegativeTests::runAll() {
    std::cout << "\n========== Negative Tests ==========\n";
    bool allOk = true;
    allOk &= testModifiedMessageFails();
    allOk &= testModifiedSigFails();
    allOk &= testWrongKeyFails();
    allOk &= testModifiedKEMCiphertextFails();
    allOk &= testTamperedCertFails();
    std::cout << "=====================================\n";
    std::cout << (allOk ? "[ALL NEGATIVE TESTS PASSED]\n" : "[SOME NEGATIVE TESTS FAILED]\n");
    return allOk;
}
