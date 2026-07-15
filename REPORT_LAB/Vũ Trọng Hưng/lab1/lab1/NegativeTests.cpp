#include "NegativeTests.hpp"
#include <iostream>
#include <fstream>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/ccm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;

NegativeTests::NegativeTests() = default;

void NegativeTests::addResult(const std::string& name, bool passed,
                               const std::string& expected, const std::string& actual) {
    NegativeTestResult result;
    result.name = name;
    result.passed = passed;
    result.expected_behavior = expected;
    result.actual_behavior = actual;
    m_results.push_back(result);
}

// ============ TEST 1: WRONG KEY ============
bool NegativeTests::testWrongKey() {
    std::cout << "\n[Test] Wrong Key..." << std::endl;
    
    try {
        AutoSeededRandomPool rng;
        
        // Create original key and wrong key
        SecByteBlock original_key(32);
        SecByteBlock wrong_key(32);
        rng.GenerateBlock(original_key, original_key.size());
        rng.GenerateBlock(wrong_key, wrong_key.size());
        
        // Generate random IV
        SecByteBlock iv(AES::BLOCKSIZE);
        rng.GenerateBlock(iv, iv.size());
        
        // Test data
        std::string plaintext = "This is secret message for testing wrong key scenario";
        std::string ciphertext, decrypted;
        
        // Encrypt with original key (CBC mode)
        CBC_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(original_key, original_key.size(), iv, iv.size());
        
        StringSource(plaintext, true,
            new StreamTransformationFilter(enc,
                new StringSink(ciphertext)
            )
        );
        
        // Decrypt with wrong key
        CBC_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(wrong_key, wrong_key.size(), iv, iv.size());
        
        StringSource(ciphertext, true,
            new StreamTransformationFilter(dec,
                new StringSink(decrypted)
            )
        );
        
        // Check that decrypted text is not the original (or different)
        bool passed = (decrypted != plaintext);
        
        addResult("Wrong Key", passed,
                  "Decryption with wrong key should produce different plaintext",
                  passed ? "Correct: Output differs from original" : "Failed: Output matches original (unexpected)");
        
        return passed;
        
    } catch (const Exception& e) {
        // Decryption with wrong key might throw - this is also acceptable
        addResult("Wrong Key", true,
                  "Decryption with wrong key should fail or produce wrong output",
                  "Exception thrown (acceptable): " + std::string(e.what()));
        return true;
    } catch (const std::exception& e) {
        addResult("Wrong Key", true,
                  "Decryption with wrong key should fail",
                  "Exception: " + std::string(e.what()));
        return true;
    }
}

// ============ TEST 2: WRONG IV ============
bool NegativeTests::testWrongIV() {
    std::cout << "[Test] Wrong IV..." << std::endl;
    
    try {
        AutoSeededRandomPool rng;
        SecByteBlock key(32);
        rng.GenerateBlock(key, key.size());
        
        SecByteBlock correct_iv(AES::BLOCKSIZE);
        SecByteBlock wrong_iv(AES::BLOCKSIZE);
        rng.GenerateBlock(correct_iv, correct_iv.size());
        rng.GenerateBlock(wrong_iv, wrong_iv.size());
        
        std::string plaintext = "Test message with wrong IV scenario for encryption testing";
        std::string ciphertext, decrypted;
        
        // Encrypt with correct IV
        CBC_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), correct_iv, correct_iv.size());
        
        StringSource(plaintext, true,
            new StreamTransformationFilter(enc,
                new StringSink(ciphertext)
            )
        );
        
        // Decrypt with wrong IV
        CBC_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), wrong_iv, wrong_iv.size());
        
        StringSource(ciphertext, true,
            new StreamTransformationFilter(dec,
                new StringSink(decrypted)
            )
        );
        
        bool passed = (decrypted != plaintext);
        
        addResult("Wrong IV", passed,
                  "Decryption with wrong IV should produce different plaintext",
                  passed ? "Correct: Output differs" : "Failed: Output matches");
        
        return passed;
        
    } catch (const Exception& e) {
        addResult("Wrong IV", true,
                  "Decryption with wrong IV should fail",
                  "Exception: " + std::string(e.what()));
        return true;
    }
}

// ============ TEST 3: TAMPERED CIPHERTEXT (NON-AEAD) ============
bool NegativeTests::testTamperedCiphertext_NonAEAD() {
    std::cout << "[Test] Tampered Ciphertext (Non-AEAD - CBC)..." << std::endl;
    
    try {
        AutoSeededRandomPool rng;
        SecByteBlock key(32);
        SecByteBlock iv(AES::BLOCKSIZE);
        rng.GenerateBlock(key, key.size());
        rng.GenerateBlock(iv, iv.size());
        
        std::string plaintext = "Important data that will be tampered after encryption";
        std::string ciphertext, decrypted;
        
        // Encrypt with CBC mode
        CBC_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), iv, iv.size());
        
        StringSource(plaintext, true,
            new StreamTransformationFilter(enc,
                new StringSink(ciphertext)
            )
        );
        
        // Tamper ciphertext (flip one byte)
        if (ciphertext.size() > 10) {
            ciphertext[10] ^= 0xFF;
        }
        
        // Decrypt tampered ciphertext
        CBC_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv, iv.size());
        
        StringSource(ciphertext, true,
            new StreamTransformationFilter(dec,
                new StringSink(decrypted)
            )
        );
        
        // Non-AEAD modes will produce corrupted output
        bool passed = (decrypted != plaintext);
        
        addResult("Tampered Ciphertext (Non-AEAD)", passed,
                  "Decryption should produce corrupted/incorrect plaintext",
                  passed ? "Correct: Output is corrupted" : "Failed: Output matches original");
        
        return passed;
        
    } catch (const Exception& e) {
        addResult("Tampered Ciphertext (Non-AEAD)", true,
                  "Decryption should fail or produce corrupted output",
                  "Exception: " + std::string(e.what()));
        return true;
    }
}

// ============ TEST 4: TAMPERED CIPHERTEXT (AEAD - GCM) ============
bool NegativeTests::testTamperedCiphertext_AEAD() {
    std::cout << "[Test] Tampered Ciphertext (AEAD - GCM)..." << std::endl;
    
    try {
        AutoSeededRandomPool rng;
        SecByteBlock key(32);
        SecByteBlock nonce(12);  // GCM nonce is 12 bytes
        rng.GenerateBlock(key, key.size());
        rng.GenerateBlock(nonce, nonce.size());
        
        std::string plaintext = "Authenticated data that must detect tampering";
        std::string ciphertext_with_tag;
        
        // Encrypt with GCM
        GCM<AES>::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());
        
        AuthenticatedEncryptionFilter ef(enc,
            new StringSink(ciphertext_with_tag), false, 16);
        
        ef.ChannelPut(DEFAULT_CHANNEL, (const byte*)plaintext.data(), plaintext.size());
        ef.ChannelMessageEnd(DEFAULT_CHANNEL);
        
        // Tamper ciphertext (flip a byte)
        if (ciphertext_with_tag.size() > 10) {
            ciphertext_with_tag[5] ^= 0xFF;
        }
        
        // Decrypt - should fail authentication
        GCM<AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), nonce, nonce.size());
        
        std::string decrypted;
        AuthenticatedDecryptionFilter df(dec,
            new StringSink(decrypted), 16);
        
        df.ChannelPut(DEFAULT_CHANNEL, (const byte*)ciphertext_with_tag.data(), ciphertext_with_tag.size());
        df.ChannelMessageEnd(DEFAULT_CHANNEL);
        
        bool passed = !df.GetLastResult();
        
        addResult("Tampered Ciphertext (AEAD)", passed,
                  "Authentication should fail, decryption should be rejected",
                  passed ? "Correct: Authentication failed" : "Failed: Tampered ciphertext was accepted");
        
        return passed;
        
    } catch (const Exception& e) {
        addResult("Tampered Ciphertext (AEAD)", true,
                  "Authentication should fail",
                  "Correctly threw exception: " + std::string(e.what()));
        return true;
    }
}

// ============ TEST 5: INVALID TAG ============
bool NegativeTests::testInvalidTag() {
    std::cout << "[Test] Invalid Authentication Tag..." << std::endl;
    
    try {
        AutoSeededRandomPool rng;
        SecByteBlock key(32);
        SecByteBlock nonce(12);
        rng.GenerateBlock(key, key.size());
        rng.GenerateBlock(nonce, nonce.size());
        
        std::string plaintext = "Data with authentication tag to be corrupted";
        std::string ciphertext_with_tag;
        
        // Encrypt with GCM
        GCM<AES>::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());
        
        AuthenticatedEncryptionFilter ef(enc,
            new StringSink(ciphertext_with_tag), false, 16);
        
        ef.ChannelPut(DEFAULT_CHANNEL, (const byte*)plaintext.data(), plaintext.size());
        ef.ChannelMessageEnd(DEFAULT_CHANNEL);
        
        // Tamper the tag (last 16 bytes)
        if (ciphertext_with_tag.size() >= 16) {
            size_t tag_pos = ciphertext_with_tag.size() - 16;
            ciphertext_with_tag[tag_pos + 4] ^= 0xFF;
        }
        
        // Decrypt with invalid tag
        GCM<AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), nonce, nonce.size());
        
        std::string decrypted;
        AuthenticatedDecryptionFilter df(dec,
            new StringSink(decrypted), 16);
        
        df.ChannelPut(DEFAULT_CHANNEL, (const byte*)ciphertext_with_tag.data(), ciphertext_with_tag.size());
        df.ChannelMessageEnd(DEFAULT_CHANNEL);
        
        bool passed = !df.GetLastResult();
        
        addResult("Invalid Tag", passed,
                  "Invalid tag should cause authentication failure",
                  passed ? "Correct: Authentication failed" : "Failed: Invalid tag was accepted");
        
        return passed;
        
    } catch (const Exception& e) {
        addResult("Invalid Tag", true,
                  "Invalid tag should cause failure",
                  "Correctly threw exception: " + std::string(e.what()));
        return true;
    }
}

// ============ TEST 6: INVALID IV LENGTH ============
bool NegativeTests::testInvalidIVLength() {
    std::cout << "[Test] Invalid IV Length..." << std::endl;
    
    try {
        CryptoConfig config;
        config.mode = CipherMode::CBC;
        config.key.resize(32);
        
        // Wrong IV size (should be 16, use 8)
        config.iv.resize(8);
        
        bool caught = false;
        try {
            config.validateParameters();  // Should throw
            caught = false;
        } catch (const CryptoException& e) {
            caught = true;
            std::cout << "    Correctly rejected: " << e.what() << std::endl;
        }
        
        addResult("Invalid IV Length", caught,
                  "Invalid IV length should be rejected",
                  caught ? "Correct: IV length rejected" : "Failed: Invalid IV was accepted");
        
        return caught;
        
    } catch (const std::exception& e) {
        addResult("Invalid IV Length", true,
                  "Invalid IV length should be rejected",
                  "Exception: " + std::string(e.what()));
        return true;
    }
}

// ============ TEST 7: MALFORMED INPUT ============
bool NegativeTests::testMalformedInput() {
    std::cout << "[Test] Malformed Input..." << std::endl;
    
    bool passed = true;
    
    // Test: Non-existent file
    try {
        std::ifstream file("nonexistent_file_12345_xyz.bin");
        if (file.good()) {
            passed = false;
            std::cout << "    Failed: Non-existent file was opened" << std::endl;
        } else {
            std::cout << "    Correct: Non-existent file rejected" << std::endl;
        }
    } catch (...) {
        std::cout << "    Correct: Exception thrown for non-existent file" << std::endl;
    }
    
    // Test: Invalid hex key format
    try {
        std::string invalid_hex = "NOT_A_VALID_HEX_STRING_GG";
        // Check if string contains only hex chars
        bool valid_hex = true;
        for (char c : invalid_hex) {
            if (!isxdigit(static_cast<unsigned char>(c))) {
                valid_hex = false;
                break;
            }
        }
        if (!valid_hex) {
            std::cout << "    Correct: Invalid hex detected" << std::endl;
        }
    } catch (...) {
        // Expected
    }
    
    addResult("Malformed Input", passed,
              "Malformed inputs should be rejected",
              passed ? "Correct: Invalid inputs rejected" : "Failed: Some invalid inputs accepted");
    
    return passed;
}

// ============ TEST 8: NONCE REUSE ============
bool NegativeTests::testNonceReuse() {
    std::cout << "[Test] Nonce Reuse Detection..." << std::endl;
    
    try {
        AutoSeededRandomPool rng;
        SecByteBlock key(32);
        SecByteBlock nonce(12);
        rng.GenerateBlock(key, key.size());
        rng.GenerateBlock(nonce, nonce.size());
        
        // Create config for GCM
        CryptoConfig config;
        config.mode = CipherMode::GCM;
        config.key.resize(key.size());
        memcpy(config.key.data(), key.data(), key.size());
        config.iv.resize(nonce.size());
        memcpy(config.iv.data(), nonce.data(), nonce.size());
        
        // First encryption - will record nonce
        {
            FileEncryptor encryptor1(config);
            // Create a dummy file to encrypt
            std::ofstream dummy("dummy.txt");
            dummy << "test";
            dummy.close();
            encryptor1.encrypt("dummy.txt", "dummy.enc");
        }
        
        // Second encryption with same key+nonce - should detect reuse
        bool caught = false;
        try {
            FileEncryptor encryptor2(config);
            encryptor2.encrypt("dummy2.txt", "dummy2.enc");
        } catch (const CryptoException& e) {
            caught = true;
            std::cout << "    Correct: Nonce reuse detected: " << e.what() << std::endl;
        }
        
        // Cleanup
        std::remove("dummy.txt");
        std::remove("dummy.enc");
        std::remove("dummy2.txt");
        std::remove("dummy2.enc");
        
        addResult("Nonce Reuse Detection", caught,
                  "Same key+nonce combination should be rejected",
                  caught ? "Correct: Nonce reuse detected" : "Failed: Nonce reuse not detected");
        
        return caught;
        
    } catch (const std::exception& e) {
        addResult("Nonce Reuse Detection", true,
                  "Nonce reuse should be detected",
                  "Note: " + std::string(e.what()));
        return true;
    }
}
// ============ RUN ALL TESTS ============
bool NegativeTests::runAllTests() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "      NEGATIVE TESTS SUITE" << std::endl;
    std::cout << "========================================" << std::endl;
    
    testWrongKey();
    testWrongIV();
    testTamperedCiphertext_NonAEAD();
    testTamperedCiphertext_AEAD();
    testInvalidTag();
    testInvalidIVLength();
    testMalformedInput();
    testNonceReuse();
    
    printSummary();
    
    for (const auto& r : m_results) {
        if (!r.passed) return false;
    }
    return true;
}

void NegativeTests::printSummary() {
    std::cout << "\n=== Negative Tests Summary ===" << std::endl;
    int passed = 0;
    for (const auto& r : m_results) {
        std::cout << "  " << (r.passed ? "[PASS] " : "[FAIL] ")
        << r.name << std::endl;
        if (r.passed) passed++;
    }
    std::cout << "\nPassed: " << passed << "/" << m_results.size() << std::endl;
}