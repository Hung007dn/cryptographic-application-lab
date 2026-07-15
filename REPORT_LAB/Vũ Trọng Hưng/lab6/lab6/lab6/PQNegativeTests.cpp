// PQNegativeTests.cpp
#include "PQNegativeTests.hpp"

#include "PQConfig.hpp"
#include "PQKeyManager.hpp"
#include "MLDSAEngine.hpp"
#include "MLKEMEngine.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

namespace {

std::vector<uint8_t> makeMessage(const std::string& text) {
    return std::vector<uint8_t>(text.begin(), text.end());
}

bool sameBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

void flipFirstByte(std::vector<uint8_t>& data) {
    if (!data.empty()) {
        data[0] ^= 0x01;
    }
}

void printResult(const std::string& name, bool ok) {
    std::cout << (ok ? "[PASS] " : "[FAIL] ") << name << "\n";
}

bool testModifiedMessageFails() {
    PQKeyManager km;
    km.generateKeyPair(PQAlgorithm::MLDSA_44);

    MLDSAEngine engine;
    auto message = makeMessage("Lab 6 ML-DSA negative test message");
    auto signature = engine.sign(message, km.getPrivateKey(), PQAlgorithm::MLDSA_44);

    auto modified = message;
    flipFirstByte(modified);

    return !engine.verify(modified, signature, km.getPublicKey(), PQAlgorithm::MLDSA_44);
}

bool testModifiedSignatureFails() {
    PQKeyManager km;
    km.generateKeyPair(PQAlgorithm::MLDSA_44);

    MLDSAEngine engine;
    auto message = makeMessage("Lab 6 ML-DSA modified signature test");
    auto signature = engine.sign(message, km.getPrivateKey(), PQAlgorithm::MLDSA_44);

    flipFirstByte(signature);

    return !engine.verify(message, signature, km.getPublicKey(), PQAlgorithm::MLDSA_44);
}

bool testModifiedPublicKeyFails() {
    PQKeyManager km;
    km.generateKeyPair(PQAlgorithm::MLDSA_44);

    MLDSAEngine engine;
    auto message = makeMessage("Lab 6 ML-DSA modified public key test");
    auto signature = engine.sign(message, km.getPrivateKey(), PQAlgorithm::MLDSA_44);

    auto badPublicKey = km.getPublicKey();
    flipFirstByte(badPublicKey);

    return !engine.verify(message, signature, badPublicKey, PQAlgorithm::MLDSA_44);
}

bool testWrongSignatureAlgorithmFails() {
    PQKeyManager km44;
    km44.generateKeyPair(PQAlgorithm::MLDSA_44);

    PQKeyManager km65;
    km65.generateKeyPair(PQAlgorithm::MLDSA_65);

    MLDSAEngine engine;
    auto message = makeMessage("Lab 6 wrong signature algorithm test");
    auto signature44 = engine.sign(message, km44.getPrivateKey(), PQAlgorithm::MLDSA_44);

    return !engine.verify(message, signature44, km65.getPublicKey(), PQAlgorithm::MLDSA_65);
}

bool testModifiedCiphertextDoesNotRecoverSameSecret() {
    PQKeyManager km;
    km.generateKeyPair(PQAlgorithm::MLKEM_512);

    MLKEMEngine engine;
    KEMResult result = engine.encapsulate(km.getPublicKey(), PQAlgorithm::MLKEM_512);

    auto modifiedCt = result.ciphertext;
    flipFirstByte(modifiedCt);

    try {
        auto recovered = engine.decapsulate(modifiedCt, km.getPrivateKey(), PQAlgorithm::MLKEM_512);
        return !sameBytes(recovered, result.sharedSecret);
    } catch (const std::exception&) {
        // Also acceptable: some implementations reject malformed ciphertext explicitly.
        return true;
    }
}

bool testWrongPrivateKeyDoesNotRecoverSameSecret() {
    PQKeyManager receiver;
    receiver.generateKeyPair(PQAlgorithm::MLKEM_512);

    PQKeyManager wrongReceiver;
    wrongReceiver.generateKeyPair(PQAlgorithm::MLKEM_512);

    MLKEMEngine engine;
    KEMResult result = engine.encapsulate(receiver.getPublicKey(), PQAlgorithm::MLKEM_512);

    try {
        auto recovered = engine.decapsulate(
            result.ciphertext,
            wrongReceiver.getPrivateKey(),
            PQAlgorithm::MLKEM_512
        );

        return !sameBytes(recovered, result.sharedSecret);
    } catch (const std::exception&) {
        return true;
    }
}

} // namespace

bool PQNegativeTests::runAll() {
    struct TestCase {
        const char* name;
        bool (*fn)();
    };

    const TestCase tests[] = {
        {"Modified ML-DSA message is rejected", testModifiedMessageFails},
        {"Modified ML-DSA signature is rejected", testModifiedSignatureFails},
        {"Modified ML-DSA public key is rejected", testModifiedPublicKeyFails},
        {"Wrong ML-DSA algorithm/key is rejected", testWrongSignatureAlgorithmFails},
        {"Modified ML-KEM ciphertext does not recover original shared secret", testModifiedCiphertextDoesNotRecoverSameSecret},
        {"Wrong ML-KEM private key does not recover original shared secret", testWrongPrivateKeyDoesNotRecoverSameSecret}
    };

    std::cout << "=== Lab 6 PQ negative tests ===\n";

    int passed = 0;
    int total = 0;

    for (const auto& test : tests) {
        ++total;
        bool ok = false;

        try {
            ok = test.fn();
        } catch (const std::exception& ex) {
            std::cout << "[ERROR] " << test.name << ": " << ex.what() << "\n";
            ok = false;
        }

        printResult(test.name, ok);
        if (ok) {
            ++passed;
        }
    }

    std::cout << "Summary: " << passed << "/" << total << " tests passed\n";
    return passed == total;
}
