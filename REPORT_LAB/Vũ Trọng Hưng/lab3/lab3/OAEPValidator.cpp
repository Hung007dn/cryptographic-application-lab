// OAEPValidator.cpp
#include "ManualOAEP.hpp"
#include <iostream>
#include <iomanip>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

void testManualOAEP() {
    std::cout << "\n=== Manual OAEP Test ===\n" << std::endl;
    
    AutoSeededRandomPool rng;
    
    // Test vectors
    std::string message = "Hello OAEP manual implementation!";
    std::vector<uint8_t> msg(message.begin(), message.end());
    std::string label = "TestLabel";
    
    // RSA parameters (2048 bits for testing)
    RSA::PrivateKey privKey;
    privKey.GenerateRandomWithKeySize(rng, 3072);
    RSA::PublicKey pubKey(privKey);
    
    size_t k = pubKey.GetModulus().ByteCount();
    
    try {
        // Manual OAEP encoding
        std::cout << "[1] Manual OAEP encoding..." << std::endl;
        auto encoded = ManualOAEP::oaepEncode(msg, label, k);
        std::cout << "    Encoded size: " << encoded.size() << " bytes (k=" << k << ")" << std::endl;
        
        // Manual OAEP decoding
        std::cout << "[2] Manual OAEP decoding..." << std::endl;
        auto decoded = ManualOAEP::oaepDecode(encoded, label, k);
        
        // Verify
        std::string recovered(decoded.begin(), decoded.end());
        std::cout << "[3] Verification: " << (recovered == message ? "PASSED" : "FAILED") << std::endl;
        std::cout << "    Original: " << message << std::endl;
        std::cout << "    Recovered: " << recovered << std::endl;
        
        // Test wrong label (should fail)
        std::cout << "\n[4] Testing wrong label (security check)..." << std::endl;
        try {
            auto failed = ManualOAEP::oaepDecode(encoded, "WrongLabel", k);
            std::cout << "    FAILED: Wrong label was accepted (vulnerability!)" << std::endl;
        } catch (const std::exception& e) {
            std::cout << "    PASSED: Wrong label correctly rejected: " << e.what() << std::endl;
        }
        
        // Constant-time demonstration
        std::cout << "\n[5] Constant-time comparison demo:" << std::endl;
        std::vector<uint8_t> a = {1, 2, 3, 4, 5};
        std::vector<uint8_t> b = {1, 2, 3, 4, 5};
        std::vector<uint8_t> c = {1, 2, 3, 4, 6};
        
        bool eq_ab = ManualOAEP::constantTimeEquals(a, b);
        bool eq_ac = ManualOAEP::constantTimeEquals(a, c);
        
        std::cout << "    a==b: " << (eq_ab ? "true" : "false") << " (time constant)" << std::endl;
        std::cout << "    a==c: " << (eq_ac ? "true" : "false") << " (time constant)" << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }
}