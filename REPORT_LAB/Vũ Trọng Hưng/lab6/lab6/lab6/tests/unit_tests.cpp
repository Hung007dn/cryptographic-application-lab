#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "PQConfig.hpp"
#include "PQKeyManager.hpp"
#include "MLDSAEngine.hpp"
#include "MLKEMEngine.hpp"
#include "PQNegativeTests.hpp"
#include "PQBatchTools.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> makeMessage(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

void flipFirstByte(std::vector<uint8_t>& data) {
    if (!data.empty()) {
        data[0] ^= 0x01;
    }
}

bool sameBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

} // namespace

TEST_CASE("ML-DSA sign and verify succeeds", "[mldsa]") {
    PQKeyManager km;
    km.generateKeyPair(PQAlgorithm::MLDSA_44);

    MLDSAEngine engine;
    auto message = makeMessage("unit test message");
    auto sig = engine.sign(message, km.getPrivateKey(), PQAlgorithm::MLDSA_44);

    REQUIRE_FALSE(sig.empty());
    REQUIRE(engine.verify(message, sig, km.getPublicKey(), PQAlgorithm::MLDSA_44));
}

TEST_CASE("ML-DSA modified message fails verification", "[negative][mldsa]") {
    PQKeyManager km;
    km.generateKeyPair(PQAlgorithm::MLDSA_44);

    MLDSAEngine engine;
    auto message = makeMessage("message before tampering");
    auto sig = engine.sign(message, km.getPrivateKey(), PQAlgorithm::MLDSA_44);

    flipFirstByte(message);
    REQUIRE_FALSE(engine.verify(message, sig, km.getPublicKey(), PQAlgorithm::MLDSA_44));
}

TEST_CASE("ML-DSA modified signature fails verification", "[negative][mldsa]") {
    PQKeyManager km;
    km.generateKeyPair(PQAlgorithm::MLDSA_44);

    MLDSAEngine engine;
    auto message = makeMessage("signature tamper unit test");
    auto sig = engine.sign(message, km.getPrivateKey(), PQAlgorithm::MLDSA_44);

    flipFirstByte(sig);
    REQUIRE_FALSE(engine.verify(message, sig, km.getPublicKey(), PQAlgorithm::MLDSA_44));
}

TEST_CASE("ML-DSA modified public key fails verification", "[negative][mldsa]") {
    PQKeyManager km;
    km.generateKeyPair(PQAlgorithm::MLDSA_44);

    MLDSAEngine engine;
    auto message = makeMessage("public key tamper unit test");
    auto sig = engine.sign(message, km.getPrivateKey(), PQAlgorithm::MLDSA_44);

    auto badPub = km.getPublicKey();
    flipFirstByte(badPub);

    REQUIRE_FALSE(engine.verify(message, sig, badPub, PQAlgorithm::MLDSA_44));
}

TEST_CASE("ML-KEM encapsulation and decapsulation shared secret match", "[mlkem]") {
    PQKeyManager km;
    km.generateKeyPair(PQAlgorithm::MLKEM_512);

    MLKEMEngine engine;
    auto result = engine.encapsulate(km.getPublicKey(), PQAlgorithm::MLKEM_512);
    auto recovered = engine.decapsulate(result.ciphertext, km.getPrivateKey(), PQAlgorithm::MLKEM_512);

    REQUIRE(sameBytes(result.sharedSecret, recovered));
}

TEST_CASE("ML-KEM modified ciphertext does not recover original shared secret", "[negative][mlkem]") {
    PQKeyManager km;
    km.generateKeyPair(PQAlgorithm::MLKEM_512);

    MLKEMEngine engine;
    auto result = engine.encapsulate(km.getPublicKey(), PQAlgorithm::MLKEM_512);

    auto badCt = result.ciphertext;
    flipFirstByte(badCt);

    try {
        auto recovered = engine.decapsulate(badCt, km.getPrivateKey(), PQAlgorithm::MLKEM_512);
        REQUIRE_FALSE(sameBytes(result.sharedSecret, recovered));
    } catch (const std::exception&) {
        SUCCEED("Implementation rejected modified ciphertext explicitly");
    }
}

TEST_CASE("ML-KEM wrong private key does not recover original shared secret", "[negative][mlkem]") {
    PQKeyManager receiver;
    receiver.generateKeyPair(PQAlgorithm::MLKEM_512);

    PQKeyManager wrongReceiver;
    wrongReceiver.generateKeyPair(PQAlgorithm::MLKEM_512);

    MLKEMEngine engine;
    auto result = engine.encapsulate(receiver.getPublicKey(), PQAlgorithm::MLKEM_512);

    try {
        auto recovered = engine.decapsulate(result.ciphertext, wrongReceiver.getPrivateKey(), PQAlgorithm::MLKEM_512);
        REQUIRE_FALSE(sameBytes(result.sharedSecret, recovered));
    } catch (const std::exception&) {
        SUCCEED("Implementation rejected wrong private key explicitly");
    }
}

TEST_CASE("Negative test runner passes", "[negative]") {
    REQUIRE(PQNegativeTests::runAll());
}

TEST_CASE("Batch demos run successfully", "[batch]") {
    REQUIRE(PQBatchTools::runBatchVerifyDemo(PQAlgorithm::MLDSA_44, 3));
    REQUIRE(PQBatchTools::runBatchDecapsulationTiming(PQAlgorithm::MLKEM_512, 3));
}
