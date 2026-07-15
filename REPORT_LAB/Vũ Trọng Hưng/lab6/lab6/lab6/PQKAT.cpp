// PQKAT.cpp
#include "PQKAT.hpp"

#include "PQConfig.hpp"
#include "PQKeyManager.hpp"
#include "MLDSAEngine.hpp"
#include "MLKEMEngine.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using json = nlohmann::json;

namespace {

std::vector<uint8_t> toBytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

bool isMLDSA(PQAlgorithm algo) {
    return algo == PQAlgorithm::MLDSA_44 ||
           algo == PQAlgorithm::MLDSA_65 ||
           algo == PQAlgorithm::MLDSA_87;
}

bool isMLKEM(PQAlgorithm algo) {
    return algo == PQAlgorithm::MLKEM_512 ||
           algo == PQAlgorithm::MLKEM_768 ||
           algo == PQAlgorithm::MLKEM_1024;
}

bool vectorsEqual(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

json loadJSON(const std::string& filename) {
    std::ifstream file(filename);

    if (!file.is_open()) {
        throw PQException("Cannot open KAT vector file: " + filename);
    }

    json j;
    file >> j;
    return j;
}

bool runMLDSATest(const json& test) {
    const std::string name = test.value("name", "unnamed ML-DSA test");
    const std::string algoStr = test.at("algorithm").get<std::string>();
    const std::string messageStr = test.value("message", "Lab 6 ML-DSA KAT message");

    PQAlgorithm algo = PQConfig::stringToAlgorithm(algoStr);

    if (!isMLDSA(algo)) {
        throw PQException("KAT test is not an ML-DSA algorithm: " + algoStr);
    }

    PQKeyManager km;
    km.generateKeyPair(algo);

    MLDSAEngine engine;
    std::vector<uint8_t> message = toBytes(messageStr);

    std::vector<uint8_t> signature = engine.sign(
        message,
        km.getPrivateKey(),
        algo
    );

    bool validOriginal = engine.verify(
        message,
        signature,
        km.getPublicKey(),
        algo
    );

    std::vector<uint8_t> modifiedMessage = message;
    if (modifiedMessage.empty()) {
        modifiedMessage.push_back(0x41);
    } else {
        modifiedMessage[0] ^= 0x01;
    }

    bool rejectModifiedMessage = !engine.verify(
        modifiedMessage,
        signature,
        km.getPublicKey(),
        algo
    );

    std::vector<uint8_t> modifiedSignature = signature;
    if (!modifiedSignature.empty()) {
        modifiedSignature[0] ^= 0x01;
    }

    bool rejectModifiedSignature = !engine.verify(
        message,
        modifiedSignature,
        km.getPublicKey(),
        algo
    );

    std::vector<uint8_t> modifiedPublicKey = km.getPublicKey();
    if (!modifiedPublicKey.empty()) {
        modifiedPublicKey[0] ^= 0x01;
    }

    bool rejectModifiedPublicKey = !engine.verify(
        message,
        signature,
        modifiedPublicKey,
        algo
    );

    bool sizeOK =
        !signature.empty() &&
        !km.getPublicKey().empty() &&
        !km.getPrivateKey().empty();

    bool pass =
        validOriginal &&
        rejectModifiedMessage &&
        rejectModifiedSignature &&
        rejectModifiedPublicKey &&
        sizeOK;

    std::cout << "[" << (pass ? "PASS" : "FAIL") << "] " << name << "\n";

    if (!pass) {
        std::cout << "    validOriginal=" << validOriginal << "\n";
        std::cout << "    rejectModifiedMessage=" << rejectModifiedMessage << "\n";
        std::cout << "    rejectModifiedSignature=" << rejectModifiedSignature << "\n";
        std::cout << "    rejectModifiedPublicKey=" << rejectModifiedPublicKey << "\n";
        std::cout << "    sizeOK=" << sizeOK << "\n";
    }

    return pass;
}

bool runMLKEMTest(const json& test) {
    const std::string name = test.value("name", "unnamed ML-KEM test");
    const std::string algoStr = test.at("algorithm").get<std::string>();

    PQAlgorithm algo = PQConfig::stringToAlgorithm(algoStr);

    if (!isMLKEM(algo)) {
        throw PQException("KAT test is not an ML-KEM algorithm: " + algoStr);
    }

    PQKeyManager km;
    km.generateKeyPair(algo);

    MLKEMEngine engine;

    KEMResult encapsulated = engine.encapsulate(
        km.getPublicKey(),
        algo
    );

    std::vector<uint8_t> decapsulated = engine.decapsulate(
        encapsulated.ciphertext,
        km.getPrivateKey(),
        algo
    );

    bool sharedSecretMatches = vectorsEqual(
        encapsulated.sharedSecret,
        decapsulated
    );

    std::vector<uint8_t> modifiedCiphertext = encapsulated.ciphertext;
    if (!modifiedCiphertext.empty()) {
        modifiedCiphertext[0] ^= 0x01;
    }

    bool modifiedCiphertextRejected = false;

    try {
        std::vector<uint8_t> tamperedSecret = engine.decapsulate(
            modifiedCiphertext,
            km.getPrivateKey(),
            algo
        );

        modifiedCiphertextRejected = !vectorsEqual(
            encapsulated.sharedSecret,
            tamperedSecret
        );
    } catch (const std::exception&) {
        modifiedCiphertextRejected = true;
    }

    PQKeyManager wrongKey;
    wrongKey.generateKeyPair(algo);

    bool wrongPrivateKeyRejected = false;

    try {
        std::vector<uint8_t> wrongSecret = engine.decapsulate(
            encapsulated.ciphertext,
            wrongKey.getPrivateKey(),
            algo
        );

        wrongPrivateKeyRejected = !vectorsEqual(
            encapsulated.sharedSecret,
            wrongSecret
        );
    } catch (const std::exception&) {
        wrongPrivateKeyRejected = true;
    }

    bool sizeOK =
        !km.getPublicKey().empty() &&
        !km.getPrivateKey().empty() &&
        !encapsulated.ciphertext.empty() &&
        !encapsulated.sharedSecret.empty();

    bool pass =
        sharedSecretMatches &&
        modifiedCiphertextRejected &&
        wrongPrivateKeyRejected &&
        sizeOK;

    std::cout << "[" << (pass ? "PASS" : "FAIL") << "] " << name << "\n";

    if (!pass) {
        std::cout << "    sharedSecretMatches=" << sharedSecretMatches << "\n";
        std::cout << "    modifiedCiphertextRejected=" << modifiedCiphertextRejected << "\n";
        std::cout << "    wrongPrivateKeyRejected=" << wrongPrivateKeyRejected << "\n";
        std::cout << "    sizeOK=" << sizeOK << "\n";
    }

    return pass;
}

} // namespace

bool PQKAT::run(const std::string& vectorFile) {
    json root = loadJSON(vectorFile);

    if (!root.contains("tests") || !root["tests"].is_array()) {
        throw PQException("KAT vector file must contain a tests array");
    }

    std::cout << "=== Lab 6 PQ KAT / self-validation tests ===\n";
    std::cout << "Vector file: " << vectorFile << "\n";

    std::size_t total = 0;
    std::size_t passed = 0;

    for (const auto& test : root["tests"]) {
        ++total;

        const std::string type = test.value("type", "");
        bool ok = false;

        try {
            if (type == "mldsa-sign-verify") {
                ok = runMLDSATest(test);
            } else if (type == "mlkem-encaps-decaps") {
                ok = runMLKEMTest(test);
            } else {
                std::cout << "[FAIL] Unsupported KAT test type: " << type << "\n";
                ok = false;
            }
        } catch (const std::exception& ex) {
            std::cout << "[FAIL] " << test.value("name", "unnamed test")
                      << " - " << ex.what() << "\n";
            ok = false;
        }

        if (ok) {
            ++passed;
        }
    }

    std::cout << "KAT summary: " << passed << "/" << total << " passed\n";

    return total > 0 && passed == total;
}
