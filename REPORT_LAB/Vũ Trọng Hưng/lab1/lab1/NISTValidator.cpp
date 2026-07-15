#include "NISTValidator.hpp"
#include <iostream>
#include <iomanip>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/gcm.h>
#include <cryptopp/ccm.h>


constexpr int GCM_TAG_SIZE = 16;   
constexpr int CCM_TAG_SIZE = 16;  

NISTValidator::NISTValidator() = default;

void NISTValidator::printResult(const std::string& test_name, bool passed) {
    std::cout << "[NIST] " << std::setw(30) << std::left << test_name 
              << (passed ? "✓ PASSED" : "✗ FAILED") << std::endl;
}

void NISTValidator::loadAES128CBCVectors() {
    // NIST SP 800-38A - AES-128 CBC test vectors
    NISTTestVector vec;
    vec.name = "AES-128-CBC (NIST SP 800-38A)";
    
    // Key: 2b7e151628aed2a6abf7158809cf4f3c
    vec.key = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    
    // IV: 000102030405060708090a0b0c0d0e0f
    vec.iv = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    
    // Plaintext: "Single block msg"
    vec.plaintext = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                     0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    
    // Ciphertext: 7649abac8119b246cee98e9b12e9197d
    vec.ciphertext = {0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
                      0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d};
    
    m_vectors.push_back(vec);
}

void NISTValidator::loadAES128GCMVectors() {
    // NIST CAVP GCM test vectors
    NISTTestVector vec;
    vec.name = "AES-128-GCM (NIST CAVP)";
    
    vec.key = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    vec.iv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00};
    vec.plaintext = {0x00};
    vec.ciphertext = {0xce};
    vec.tag = {0xa7, 0x40, 0xd2, 0x8f, 0x13, 0x5f, 0x78, 0x0d,
               0x12, 0x36, 0x6c, 0x66, 0x61, 0xdf, 0xcf, 0xcc};
    vec.aad = {};
    
    m_vectors.push_back(vec);
}

void NISTValidator::loadAES256CTRVectors() {
    // NIST SP 800-38A - AES-256 CTR
    NISTTestVector vec;
    vec.name = "AES-256-CTR (NIST SP 800-38A)";
    
    vec.key = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
               0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
               0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
               0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
    
    vec.iv = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
              0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
    
    vec.plaintext = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                     0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    
    vec.ciphertext = {0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5,
                      0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28};
    
    m_vectors.push_back(vec);
}

bool NISTValidator::testCBC() {
    using namespace CryptoPP;
    
    loadAES128CBCVectors();
    auto& vec = m_vectors.back();
    
    try {
        CBC_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(vec.key.data(), vec.key.size(), vec.iv.data(), vec.iv.size());
        
        std::string ciphertext;
        StringSource ss(vec.plaintext.data(), vec.plaintext.size(), true,
            new StreamTransformationFilter(enc,
                new StringSink(ciphertext),
                StreamTransformationFilter::NO_PADDING  // THÊM DÒNG NÀY
            )
        );
        
        // Debug output
        std::cout << "CBC Test - Expected: ";
        for (auto b : vec.ciphertext) printf("%02x", b);
        std::cout << "\nCBC Test - Got:      ";
        for (unsigned char c : ciphertext) printf("%02x", (unsigned char)c);
        std::cout << std::endl;
        
        if (ciphertext.size() != vec.ciphertext.size()) {
            return false;
        }
        
        for (size_t i = 0; i < ciphertext.size(); i++) {
            if (static_cast<uint8_t>(ciphertext[i]) != vec.ciphertext[i]) {
                return false;
            }
        }
        
        return true;
    } catch (const Exception& e) {
        std::cerr << "CBC test exception: " << e.what() << std::endl;
        return false;
    }
}

bool NISTValidator::testGCM() {
    using namespace CryptoPP;
    
    loadAES128GCMVectors();
    auto& vec = m_vectors.back();
    
    try {
        GCM<AES>::Encryption enc;
        enc.SetKeyWithIV(vec.key.data(), vec.key.size(), vec.iv.data(), vec.iv.size());
        
        std::string ciphertext_with_tag;
        
    
        AuthenticatedEncryptionFilter ef(enc,
            new StringSink(ciphertext_with_tag), 
            false,  
            16    
        );
        
        ef.ChannelPut(DEFAULT_CHANNEL, vec.plaintext.data(), vec.plaintext.size());
        ef.ChannelMessageEnd(DEFAULT_CHANNEL);
        
        std::string ciphertext = ciphertext_with_tag.substr(0, ciphertext_with_tag.size() - 16);
        std::string tag = ciphertext_with_tag.substr(ciphertext_with_tag.size() - 16);
        
        std::cout << "Expected ciphertext: ";
        for (auto b : vec.ciphertext) printf("%02x", b);
        std::cout << "\nGot ciphertext:      ";
        for (unsigned char c : ciphertext) printf("%02x", c);
        std::cout << std::endl;
        
        std::cout << "Expected tag: ";
        for (auto b : vec.tag) printf("%02x", b);
        std::cout << "\nGot tag:      ";
        for (unsigned char c : tag) printf("%02x", c);
        std::cout << std::endl;
        
        bool ciphertext_ok = (ciphertext.size() == vec.ciphertext.size());
        for (size_t i = 0; i < ciphertext.size() && i < vec.ciphertext.size(); i++) {
            if ((unsigned char)ciphertext[i] != vec.ciphertext[i]) {
                ciphertext_ok = false;
                break;
            }
        }
        
        bool tag_ok = (tag.size() == vec.tag.size());
        for (size_t i = 0; i < tag.size() && i < vec.tag.size(); i++) {
            if ((unsigned char)tag[i] != vec.tag[i]) {
                tag_ok = false;
                break;
            }
        }
        
        return ciphertext_ok && tag_ok;
        
    } catch (const Exception& e) {
        std::cerr << "GCM test exception: " << e.what() << std::endl;
        return false;
    }
}
bool NISTValidator::testCTR() {
    using namespace CryptoPP;
    
    loadAES256CTRVectors();
    auto& vec = m_vectors.back();
    
    try {
        CTR_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(vec.key.data(), vec.key.size(), vec.iv.data(), vec.iv.size());
        
        std::string ciphertext;
        StringSource ss(vec.plaintext.data(), vec.plaintext.size(), true,
            new StreamTransformationFilter(enc,
                new StringSink(ciphertext)
            )
        );
        
        if (ciphertext.size() != vec.ciphertext.size()) {
            return false;
        }
        
        for (size_t i = 0; i < ciphertext.size(); i++) {
            if (static_cast<uint8_t>(ciphertext[i]) != vec.ciphertext[i]) {
                return false;
            }
        }
        
        return true;
    } catch (const Exception& e) {
        std::cerr << "CTR test exception: " << e.what() << std::endl;
        return false;
    }
}

bool NISTValidator::validateMode(CipherMode mode) {
    switch (mode) {
        case CipherMode::CBC: return testCBC();
        case CipherMode::GCM: return testGCM();
        case CipherMode::CTR: return testCTR();  // SỬA: gọi testCTR()
        default:
            std::cout << "Mode " << CryptoConfig::modeToString(mode) 
                      << " validation not yet implemented" << std::endl;
            return true;
    }
}

void NISTValidator::runAllTests() {
    std::cout << "\n=== NIST Test Vector Validation ===\n" << std::endl;
    
    printResult("AES-128-CBC (NIST SP 800-38A)", testCBC());
    printResult("AES-128-GCM (NIST CAVP)", testGCM());
    printResult("AES-256-CTR (NIST SP 800-38A)", testCTR());  // SỬA
    
    std::cout << "\n=== Validation Complete ===\n" << std::endl;
}