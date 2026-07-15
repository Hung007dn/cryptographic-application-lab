#define CATCH_CONFIG_MAIN

#include <catch2/catch.hpp>

#include "../RSAConfig.hpp"
#include "../RSAKeyManager.hpp"
#include "../RSAEngine.hpp"
#include "../HybridEncryptor.hpp"
#include "../RSAValidator.hpp"
#include "../RSABenchmarker.hpp"
#include "../NegativeTests.hpp"
#include "../ManualOAEP.hpp"
using namespace std;

TEST_CASE("RSA Key Generation", "[rsa]") {
    RSAKeyManager km;
    
    SECTION("Generate RSA-3072 key") {
        REQUIRE_NOTHROW(km.generateKeyPair(RSAKeySize::RSA_3072));
        REQUIRE(km.hasPublicKey() == true);
        REQUIRE(km.hasPrivateKey() == true);
    }
    
    SECTION("Generate RSA-4096 key") {
        REQUIRE_NOTHROW(km.generateKeyPair(RSAKeySize::RSA_4096));
        REQUIRE(km.hasPublicKey() == true);
        REQUIRE(km.hasPrivateKey() == true);
    }
    
    SECTION("Invalid key size should throw") {
        REQUIRE_THROWS_AS(km.generateKeyPair(static_cast<RSAKeySize>(1024)), RSAException);
    }
}

TEST_CASE("RSA-OAEP Encryption/Decryption", "[rsa][oaep]") {
    RSAKeyManager km;
    km.generateKeyPair(RSAKeySize::RSA_3072);
    RSAEngine engine;
    
    SECTION("Encrypt and decrypt small message") {
        string plaintext = "Hello RSA-OAEP!";
        vector<uint8_t> plain(plaintext.begin(), plaintext.end());
        
        auto cipher = engine.encryptOAEP(plain, km.getPublicKey(), "");
        auto decrypted = engine.decryptOAEP(cipher, km.getPrivateKey(), "");
        
        vector<uint8_t> expected(plaintext.begin(), plaintext.end());
        REQUIRE(decrypted == expected);
    }
    
    SECTION("Encrypt with label and decrypt with same label") {
        string plaintext = "Message with label";
        vector<uint8_t> plain(plaintext.begin(), plaintext.end());
        string label = "my_secret_label";
        
        auto cipher = engine.encryptOAEP(plain, km.getPublicKey(), label);
        auto decrypted = engine.decryptOAEP(cipher, km.getPrivateKey(), label);
        
        vector<uint8_t> expected(plaintext.begin(), plaintext.end());
        REQUIRE(decrypted == expected);
    }
    
    SECTION("Decrypt with wrong label should fail") {
        string plaintext = "Secret message";
        vector<uint8_t> plain(plaintext.begin(), plaintext.end());
        
        auto cipher = engine.encryptOAEP(plain, km.getPublicKey(), "correct_label");
        
        REQUIRE_THROWS_AS(engine.decryptOAEP(cipher, km.getPrivateKey(), "wrong_label"), 
                          RSAException);
    }
    
    SECTION("Plaintext too large should throw") {
        string large_text(500, 'A');  // > max size for RSA-3072
        vector<uint8_t> plain(large_text.begin(), large_text.end());
        
        REQUIRE_THROWS_AS(engine.encryptOAEP(plain, km.getPublicKey(), ""), RSAException);
    }
}

TEST_CASE("RSA Max Plaintext Size", "[rsa]") {
    RSAKeyManager km;
    RSAEngine engine;
    
    SECTION("RSA-3072 max size calculation") {
        km.generateKeyPair(RSAKeySize::RSA_3072);
        size_t max_size = engine.getMaxPlaintextSize(km.getPublicKey());
        // k = 384 bytes, 2*32 - 2 = 62, 384 - 62 = 322
        REQUIRE(max_size == 384 - 2 * 32 - 2);  // 384 - 64 - 2 = 318
    }
    
    SECTION("RSA-4096 max size calculation") {
        km.generateKeyPair(RSAKeySize::RSA_4096);
        size_t max_size = engine.getMaxPlaintextSize(km.getPublicKey());
        // k = 512 bytes, 512 - 64 - 2 = 446
        REQUIRE(max_size == 512 - 2 * 32 - 2);  // 512 - 64 - 2 = 446
    }
}

TEST_CASE("Hybrid Encryption", "[hybrid]") {
    RSAKeyManager km;
    km.generateKeyPair(RSAKeySize::RSA_3072);
    HybridEncryptor hybrid;
    
    SECTION("Encrypt large file with hybrid mode") {
        string large_text(1024 * 100, 'A');  // 100KB
        vector<uint8_t> plain(large_text.begin(), large_text.end());
        
        auto envelope = hybrid.hybridEncrypt(plain, km.getPublicKey(), "");
        auto decrypted = hybrid.hybridDecrypt(envelope, km.getPrivateKey(), "");
        
        REQUIRE(decrypted == plain);
    }
    
    SECTION("Tampered ciphertext should fail authentication") {
        string plaintext(1024, 'B');
        vector<uint8_t> plain(plaintext.begin(), plaintext.end());
        
        auto envelope = hybrid.hybridEncrypt(plain, km.getPublicKey(), "");
        
        // Tamper ciphertext
        if (!envelope.ciphertext.empty()) {
            envelope.ciphertext[10] ^= 0xFF;
        }
        
        REQUIRE_THROWS_AS(hybrid.hybridDecrypt(envelope, km.getPrivateKey(), ""), 
                          RSAException);
    }
}

TEST_CASE("Key Serialization", "[keys]") {
    RSAKeyManager km;
    km.generateKeyPair(RSAKeySize::RSA_3072);
    
    SECTION("Export to PEM format") {
    RSAKeyManager km;
    km.generateKeyPair(RSAKeySize::RSA_3072);

    std::string pub_pem = km.exportPublicKeyPEM();
    std::string priv_pem = km.exportPrivateKeyPEM();

    REQUIRE(pub_pem.find("BEGIN PUBLIC KEY") != std::string::npos);
    REQUIRE(pub_pem.find("END PUBLIC KEY") != std::string::npos);

    REQUIRE(priv_pem.find("BEGIN RSA PRIVATE KEY") != std::string::npos);
    REQUIRE(priv_pem.find("END RSA PRIVATE KEY") != std::string::npos);
}
    SECTION("Export to DER format") {
        auto pub_der = km.exportPublicKeyDER();
        auto priv_der = km.exportPrivateKeyDER();
        
        REQUIRE(pub_der.size() > 0);
        REQUIRE(priv_der.size() > 0);
    }
}

TEST_CASE("Negative Tests", "[negative]") {
    RSAKeyManager km;
    km.generateKeyPair(RSAKeySize::RSA_3072);
    RSAEngine engine;
    
    SECTION("Wrong private key should fail") {
        RSAKeyManager km2;
        km2.generateKeyPair(RSAKeySize::RSA_3072);
        
        string plaintext = "Secret";
        vector<uint8_t> plain(plaintext.begin(), plaintext.end());
        
        auto cipher = engine.encryptOAEP(plain, km.getPublicKey(), "");
        
        REQUIRE_THROWS_AS(engine.decryptOAEP(cipher, km2.getPrivateKey(), ""), 
                          RSAException);
    }
    
    SECTION("Malformed ciphertext should fail") {
        vector<uint8_t> malformed(100, 0x00);
        
        REQUIRE_THROWS_AS(engine.decryptOAEP(malformed, km.getPrivateKey(), ""), 
                          RSAException);
    }
}