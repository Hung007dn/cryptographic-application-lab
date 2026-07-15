#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "SigConfig.hpp"
#include "SigKeyManager.hpp"
#include "ECDSAEngine.hpp"
#include "RSAPSSEngine.hpp"
#include "BatchVerifier.hpp"
#include "ManualRSAPSS.hpp"
#include "ModularArithmetic.hpp"

#include <vector>
#include <string>
#include <cstdint>

static std::vector<uint8_t> bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

TEST_CASE("SigConfig parses supported algorithms, hashes, and formats", "[config]") {
    REQUIRE(SigConfig::stringToAlgorithm("ecdsa-p256") == SignatureAlgorithm::ECDSA_P256);
    REQUIRE(SigConfig::stringToAlgorithm("ecdsa-p384") == SignatureAlgorithm::ECDSA_P384);
    REQUIRE(SigConfig::stringToAlgorithm("rsa-pss-3072") == SignatureAlgorithm::RSA_PSS_3072);

    REQUIRE(SigConfig::algorithmToString(SignatureAlgorithm::ECDSA_P256) == "ECDSA-P256");
    REQUIRE(SigConfig::algorithmToString(SignatureAlgorithm::ECDSA_P384) == "ECDSA-P384");
    REQUIRE(SigConfig::algorithmToString(SignatureAlgorithm::RSA_PSS_3072) == "RSA-PSS-3072");

    REQUIRE(SigConfig::stringToHash("sha256") == HashAlgorithm::SHA256);
    REQUIRE(SigConfig::stringToHash("sha384") == HashAlgorithm::SHA384);

    REQUIRE(SigConfig::stringToFormat("raw") == OutputFormat::RAW);
    REQUIRE(SigConfig::stringToFormat("der") == OutputFormat::DER);
    REQUIRE(SigConfig::stringToFormat("base64") == OutputFormat::BASE64);
    REQUIRE(SigConfig::stringToFormat("pem") == OutputFormat::PEM);
}

TEST_CASE("SigConfig rejects unsupported identifiers", "[config][negative]") {
    REQUIRE_THROWS_AS(SigConfig::stringToAlgorithm("ecdsa-p999"), SigException);
    REQUIRE_THROWS_AS(SigConfig::stringToAlgorithm("rsa-v15"), SigException);
    REQUIRE_THROWS_AS(SigConfig::stringToHash("sha1"), SigException);
    REQUIRE_THROWS_AS(SigConfig::stringToFormat("hexadecimal"), SigException);
}

TEST_CASE("SigConfig reports expected key and signature sizes", "[config]") {
    SigConfig cfg;

    cfg.algorithm = SignatureAlgorithm::ECDSA_P256;
    REQUIRE(cfg.getKeySizeBits() == 256);
    REQUIRE(cfg.getSignatureSize() == 64);
    REQUIRE(cfg.getCurveName() == "secp256r1");

    cfg.algorithm = SignatureAlgorithm::ECDSA_P384;
    REQUIRE(cfg.getKeySizeBits() == 384);
    REQUIRE(cfg.getSignatureSize() == 96);
    REQUIRE(cfg.getCurveName() == "secp384r1");

    cfg.algorithm = SignatureAlgorithm::RSA_PSS_3072;
    REQUIRE(cfg.getKeySizeBits() == 3072);
    REQUIRE(cfg.getSignatureSize() == 384);
}

TEST_CASE("ECDSA-P256 signs and verifies SHA-256 messages", "[ecdsa][p256]") {
    SigKeyManager km;
    km.generateKeyPair(SignatureAlgorithm::ECDSA_P256);

    ECDSAEngine engine;
    auto message = bytes("Lab 5 ECDSA-P256 unit test message");

    auto signature = engine.sign(
        message,
        km.getPrivateKey(),
        HashAlgorithm::SHA256,
        true
    );

    REQUIRE_FALSE(signature.empty());

    bool ok = engine.verify(
        message,
        signature,
        km.getPublicKey(),
        HashAlgorithm::SHA256
    );

    REQUIRE(ok);
}

TEST_CASE("ECDSA-P256 verification fails for modified message", "[ecdsa][negative]") {
    SigKeyManager km;
    km.generateKeyPair(SignatureAlgorithm::ECDSA_P256);

    ECDSAEngine engine;
    auto message = bytes("original message");
    auto modified = bytes("original messagf");

    auto signature = engine.sign(
        message,
        km.getPrivateKey(),
        HashAlgorithm::SHA256,
        true
    );

    REQUIRE_FALSE(signature.empty());

    bool ok = engine.verify(
        modified,
        signature,
        km.getPublicKey(),
        HashAlgorithm::SHA256
    );

    REQUIRE_FALSE(ok);
}

TEST_CASE("ECDSA-P256 verification fails for modified signature", "[ecdsa][negative]") {
    SigKeyManager km;
    km.generateKeyPair(SignatureAlgorithm::ECDSA_P256);

    ECDSAEngine engine;
    auto message = bytes("message for signature tamper test");

    auto signature = engine.sign(
        message,
        km.getPrivateKey(),
        HashAlgorithm::SHA256,
        true
    );

    REQUIRE_FALSE(signature.empty());

    signature[signature.size() / 2] ^= 0x01;

    bool ok = engine.verify(
        message,
        signature,
        km.getPublicKey(),
        HashAlgorithm::SHA256
    );

    REQUIRE_FALSE(ok);
}

TEST_CASE("ECDSA-P384 signs and verifies SHA-384 messages", "[ecdsa][p384]") {
    SigKeyManager km;
    km.generateKeyPair(SignatureAlgorithm::ECDSA_P384);

    ECDSAEngine engine;
    auto message = bytes("Lab 5 ECDSA-P384 unit test message");

    auto signature = engine.sign(
        message,
        km.getPrivateKey(),
        HashAlgorithm::SHA384,
        true
    );

    REQUIRE_FALSE(signature.empty());

    bool ok = engine.verify(
        message,
        signature,
        km.getPublicKey(),
        HashAlgorithm::SHA384
    );

    REQUIRE(ok);
}

TEST_CASE("RSA-PSS-3072 signs and verifies SHA-256 messages", "[rsa-pss]") {
    SigKeyManager km;
    km.generateKeyPair(SignatureAlgorithm::RSA_PSS_3072);

    RSAPSSEngine engine;
    auto message = bytes("Lab 5 RSA-PSS-3072 unit test message");

    auto signature = engine.sign(
        message,
        km.getPrivateKey(),
        HashAlgorithm::SHA256
    );

    REQUIRE(signature.size() == 384);

    bool ok = engine.verify(
        message,
        signature,
        km.getPublicKey(),
        HashAlgorithm::SHA256
    );

    REQUIRE(ok);
}

TEST_CASE("RSA-PSS verification fails for modified signature", "[rsa-pss][negative]") {
    SigKeyManager km;
    km.generateKeyPair(SignatureAlgorithm::RSA_PSS_3072);

    RSAPSSEngine engine;
    auto message = bytes("RSA-PSS tamper test");

    auto signature = engine.sign(
        message,
        km.getPrivateKey(),
        HashAlgorithm::SHA256
    );

    REQUIRE(signature.size() == 384);

    signature[signature.size() / 2] ^= 0x01;

    bool ok = engine.verify(
        message,
        signature,
        km.getPublicKey(),
        HashAlgorithm::SHA256
    );

    REQUIRE_FALSE(ok);
}

TEST_CASE("Wrong public key fails verification", "[negative]") {
    SigKeyManager keyA;
    SigKeyManager keyB;

    keyA.generateKeyPair(SignatureAlgorithm::ECDSA_P256);
    keyB.generateKeyPair(SignatureAlgorithm::ECDSA_P256);

    ECDSAEngine engine;
    auto message = bytes("wrong public key test");

    auto signature = engine.sign(
        message,
        keyA.getPrivateKey(),
        HashAlgorithm::SHA256,
        true
    );

    bool ok = engine.verify(
        message,
        signature,
        keyB.getPublicKey(),
        HashAlgorithm::SHA256
    );

    REQUIRE_FALSE(ok);
}

TEST_CASE("Batch verification counts valid and invalid signatures", "[batch]") {
    SigKeyManager km;
    km.generateKeyPair(SignatureAlgorithm::ECDSA_P256);

    ECDSAEngine engine;

    std::vector<std::string> messages = {
        "batch message 1",
        "batch message 2",
        "batch message 3"
    };

    std::vector<std::vector<uint8_t>> signatures;

    for (const auto& msg : messages) {
        auto msgBytes = bytes(msg);
        signatures.push_back(
            engine.sign(
                msgBytes,
                km.getPrivateKey(),
                HashAlgorithm::SHA256,
                true
            )
        );
    }

    BatchVerifier verifier;

    auto result = verifier.verifyBatch(
        messages,
        signatures,
        km.getPublicKey(),
        SignatureAlgorithm::ECDSA_P256,
        HashAlgorithm::SHA256
    );

    REQUIRE(result.total == 3);
    REQUIRE(result.valid == 3);
    REQUIRE(result.invalid == 0);
    REQUIRE(result.failed_indices.empty());

    messages[1][0] ^= 0x01;

    auto tamperedResult = verifier.verifyBatch(
        messages,
        signatures,
        km.getPublicKey(),
        SignatureAlgorithm::ECDSA_P256,
        HashAlgorithm::SHA256
    );

    REQUIRE(tamperedResult.total == 3);
    REQUIRE(tamperedResult.valid == 2);
    REQUIRE(tamperedResult.invalid == 1);
    REQUIRE(tamperedResult.failed_indices.size() == 1);
    REQUIRE(tamperedResult.failed_indices[0] == 1);
}

TEST_CASE("Batch verification rejects mismatched input sizes", "[batch][negative]") {
    SigKeyManager km;
    km.generateKeyPair(SignatureAlgorithm::ECDSA_P256);

    BatchVerifier verifier;

    std::vector<std::string> messages = {
        "message 1",
        "message 2"
    };

    std::vector<std::vector<uint8_t>> signatures = {
        {0x30, 0x00}
    };

    REQUIRE_THROWS_AS(
        verifier.verifyBatch(
            messages,
            signatures,
            km.getPublicKey(),
            SignatureAlgorithm::ECDSA_P256,
            HashAlgorithm::SHA256
        ),
        SigException
    );
}

TEST_CASE("Manual RSA-PSS MGF1 returns requested length", "[manual-pss]") {
    auto seed = bytes("mgf1 seed");

    auto mask32 = ManualRSAPSS::mgf1(seed, 32);
    auto mask64 = ManualRSAPSS::mgf1(seed, 64);

    REQUIRE(mask32.size() == 32);
    REQUIRE(mask64.size() == 64);
    REQUIRE(mask32 != std::vector<uint8_t>(32, 0x00));
}

TEST_CASE("Manual RSA-PSS encode and verify round trip", "[manual-pss]") {
    std::vector<uint8_t> messageHash(ManualRSAPSS::HASH_SIZE, 0x11);
    std::vector<uint8_t> salt(ManualRSAPSS::HASH_SIZE, 0x22);

    auto encoded = ManualRSAPSS::encodePSS(
        messageHash,
        3071,
        salt
    );

    REQUIRE_FALSE(encoded.empty());
    REQUIRE(encoded.back() == 0xBC);

    bool ok = ManualRSAPSS::verifyPSS(
        messageHash,
        encoded,
        3071,
        salt
    );

    REQUIRE(ok);

    encoded[0] ^= 0x01;

    bool tampered = ManualRSAPSS::verifyPSS(
        messageHash,
        encoded,
        3071,
        salt
    );

    REQUIRE_FALSE(tampered);
}

TEST_CASE("ModularArithmetic constant-time compare works", "[manual][constant-time]") {
    std::vector<uint8_t> a = {0x01, 0x02, 0x03};
    std::vector<uint8_t> b = {0x01, 0x02, 0x03};
    std::vector<uint8_t> c = {0x01, 0x02, 0x04};
    std::vector<uint8_t> d = {0x01, 0x02};

    REQUIRE(ModularArithmetic::constantTimeCompare(a, b));
    REQUIRE_FALSE(ModularArithmetic::constantTimeCompare(a, c));
    REQUIRE_FALSE(ModularArithmetic::constantTimeCompare(a, d));
}