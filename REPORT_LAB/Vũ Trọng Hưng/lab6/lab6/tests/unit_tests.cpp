#define CATCH_CONFIG_MAIN
#include <catch.hpp>

#include "PQKeyManager.hpp"
#include "MLDSAEngine.hpp"
#include "MLKEMEngine.hpp"
#include "PQCertificate.hpp"
#include <vector>
#include <cstdio>
#include <fstream>

// ── helpers ───────────────────────────────────────────────────────────────────
static void removeIfExists(const std::string& f) { remove(f.c_str()); }

// ═══════════════════════════════════════════════════════════════════════════════
// ML-DSA TESTS
// ═══════════════════════════════════════════════════════════════════════════════
TEST_CASE("ML-DSA-44 keygen writes key files", "[mldsa44][keygen]") {
    PQKeyManager::mldsaKeygen(MLDSALevel::MLDSA44, "test_pub44.pem", "test_priv44.pem");
    std::ifstream pub("test_pub44.pem"), priv("test_priv44.pem");
    REQUIRE(pub.good());
    REQUIRE(priv.good());
    removeIfExists("test_pub44.pem");
    removeIfExists("test_priv44.pem");
}

TEST_CASE("ML-DSA-44 sign and verify roundtrip", "[mldsa44][sign][verify]") {
    PQKeyManager::mldsaKeygen(MLDSALevel::MLDSA44, "test_pub44.pem", "test_priv44.pem");
    std::vector<unsigned char> msg = {'H','e','l','l','o',' ','L','a','b',' ','6'};
    auto sig = MLDSAEngine::sign(MLDSALevel::MLDSA44, "test_priv44.pem", msg);
    REQUIRE(!sig.empty());
    bool ok = MLDSAEngine::verify(MLDSALevel::MLDSA44, "test_pub44.pem", msg, sig);
    REQUIRE(ok == true);
    removeIfExists("test_pub44.pem");
    removeIfExists("test_priv44.pem");
}

TEST_CASE("ML-DSA-44 tampered message fails verify", "[mldsa44][negative]") {
    PQKeyManager::mldsaKeygen(MLDSALevel::MLDSA44, "test_pub44.pem", "test_priv44.pem");
    std::vector<unsigned char> msg = {'S','e','c','r','e','t'};
    auto sig = MLDSAEngine::sign(MLDSALevel::MLDSA44, "test_priv44.pem", msg);
    msg[0] ^= 0xFF;
    bool ok = MLDSAEngine::verify(MLDSALevel::MLDSA44, "test_pub44.pem", msg, sig);
    REQUIRE(ok == false);
    removeIfExists("test_pub44.pem");
    removeIfExists("test_priv44.pem");
}

TEST_CASE("ML-DSA-44 tampered signature fails verify", "[mldsa44][negative]") {
    PQKeyManager::mldsaKeygen(MLDSALevel::MLDSA44, "test_pub44.pem", "test_priv44.pem");
    std::vector<unsigned char> msg = {'D','a','t','a'};
    auto sig = MLDSAEngine::sign(MLDSALevel::MLDSA44, "test_priv44.pem", msg);
    if (!sig.empty()) sig[0] ^= 0xFF;
    bool ok = MLDSAEngine::verify(MLDSALevel::MLDSA44, "test_pub44.pem", msg, sig);
    REQUIRE(ok == false);
    removeIfExists("test_pub44.pem");
    removeIfExists("test_priv44.pem");
}

TEST_CASE("ML-DSA-44 wrong key fails verify", "[mldsa44][negative]") {
    PQKeyManager::mldsaKeygen(MLDSALevel::MLDSA44, "test_pub44a.pem", "test_priv44a.pem");
    PQKeyManager::mldsaKeygen(MLDSALevel::MLDSA44, "test_pub44b.pem", "test_priv44b.pem");
    std::vector<unsigned char> msg = {'K','e','y'};
    auto sig = MLDSAEngine::sign(MLDSALevel::MLDSA44, "test_priv44a.pem", msg);
    bool ok = MLDSAEngine::verify(MLDSALevel::MLDSA44, "test_pub44b.pem", msg, sig);
    REQUIRE(ok == false);
    removeIfExists("test_pub44a.pem"); removeIfExists("test_priv44a.pem");
    removeIfExists("test_pub44b.pem"); removeIfExists("test_priv44b.pem");
}

TEST_CASE("ML-DSA-65 sign and verify roundtrip", "[mldsa65]") {
    PQKeyManager::mldsaKeygen(MLDSALevel::MLDSA65, "test_pub65.pem", "test_priv65.pem");
    std::vector<unsigned char> msg = {'M','L','D','S','A','6','5'};
    auto sig = MLDSAEngine::sign(MLDSALevel::MLDSA65, "test_priv65.pem", msg);
    REQUIRE(!sig.empty());
    bool ok = MLDSAEngine::verify(MLDSALevel::MLDSA65, "test_pub65.pem", msg, sig);
    REQUIRE(ok == true);
    removeIfExists("test_pub65.pem");
    removeIfExists("test_priv65.pem");
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML-KEM TESTS
// ═══════════════════════════════════════════════════════════════════════════════
TEST_CASE("ML-KEM-512 keygen writes key files", "[mlkem512][keygen]") {
    PQKeyManager::mlkemKeygen(MLKEMLevel::MLKEM512, "test_kem_pub.pem", "test_kem_priv.pem");
    std::ifstream pub("test_kem_pub.pem"), priv("test_kem_priv.pem");
    REQUIRE(pub.good());
    REQUIRE(priv.good());
    removeIfExists("test_kem_pub.pem");
    removeIfExists("test_kem_priv.pem");
}

TEST_CASE("ML-KEM-512 encaps + decaps shared secret matches", "[mlkem512][encaps][decaps]") {
    PQKeyManager::mlkemKeygen(MLKEMLevel::MLKEM512, "test_kem_pub.pem", "test_kem_priv.pem");
    auto res = MLKEMEngine::encapsulate(MLKEMLevel::MLKEM512, "test_kem_pub.pem");
    REQUIRE(!res.ciphertext.empty());
    REQUIRE(!res.sharedSecret.empty());
    auto ss2 = MLKEMEngine::decapsulate(MLKEMLevel::MLKEM512, "test_kem_priv.pem", res.ciphertext);
    REQUIRE(ss2 == res.sharedSecret);
    removeIfExists("test_kem_pub.pem");
    removeIfExists("test_kem_priv.pem");
}

TEST_CASE("ML-KEM-512 tampered ciphertext produces different shared secret", "[mlkem512][negative]") {
    PQKeyManager::mlkemKeygen(MLKEMLevel::MLKEM512, "test_kem_pub.pem", "test_kem_priv.pem");
    auto res = MLKEMEngine::encapsulate(MLKEMLevel::MLKEM512, "test_kem_pub.pem");
    auto ct  = res.ciphertext;
    if (!ct.empty()) ct[0] ^= 0xFF;
    bool failed = false;
    try {
        auto ss2 = MLKEMEngine::decapsulate(MLKEMLevel::MLKEM512, "test_kem_priv.pem", ct);
        failed = (ss2 != res.sharedSecret);
    } catch (...) { failed = true; }
    REQUIRE(failed == true);
    removeIfExists("test_kem_pub.pem");
    removeIfExists("test_kem_priv.pem");
}

// ═══════════════════════════════════════════════════════════════════════════════
// PQ CERTIFICATE TESTS
// ═══════════════════════════════════════════════════════════════════════════════
TEST_CASE("PQ Certificate generate and verify", "[cert]") {
    PQKeyManager::mldsaKeygen(MLDSALevel::MLDSA44, "test_ca_pub.pem", "test_ca_priv.pem");
    PQKeyManager::mldsaKeygen(MLDSALevel::MLDSA44, "test_sub_pub.pem", "test_sub_priv.pem");
    PQCertificate::generate("test_ca_priv.pem", "test_ca_pub.pem",
                            "TestSubject", "test_sub_pub.pem", "test_cert.json");
    bool ok = PQCertificate::verify("test_cert.json", "test_ca_pub.pem");
    REQUIRE(ok == true);
    removeIfExists("test_ca_pub.pem"); removeIfExists("test_ca_priv.pem");
    removeIfExists("test_sub_pub.pem"); removeIfExists("test_sub_priv.pem");
    removeIfExists("test_cert.json");
}

TEST_CASE("PQ Certificate tampered fails verify", "[cert][negative]") {
    PQKeyManager::mldsaKeygen(MLDSALevel::MLDSA44, "test_ca_pub.pem", "test_ca_priv.pem");
    PQKeyManager::mldsaKeygen(MLDSALevel::MLDSA44, "test_sub_pub.pem", "test_sub_priv.pem");
    PQCertificate::generate("test_ca_priv.pem", "test_ca_pub.pem",
                            "TestSubject", "test_sub_pub.pem", "test_cert.json");
    // Tamper the cert
    {
        std::ifstream fin("test_cert.json");
        std::string content((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
        size_t pos = content.find("TestSubject");
        if (pos != std::string::npos) content.replace(pos, 11, "HackedUser!");
        std::ofstream fout("test_cert.json");
        fout << content;
    }
    bool ok = PQCertificate::verify("test_cert.json", "test_ca_pub.pem");
    REQUIRE(ok == false);
    removeIfExists("test_ca_pub.pem"); removeIfExists("test_ca_priv.pem");
    removeIfExists("test_sub_pub.pem"); removeIfExists("test_sub_priv.pem");
    removeIfExists("test_cert.json");
}
