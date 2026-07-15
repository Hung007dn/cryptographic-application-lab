#pragma once
#include <string>
#include <vector>
#include "PQConfig.hpp"

struct KEMResult {
    std::vector<unsigned char> ciphertext;    // ct.bin  (public, send to Bob)
    std::vector<unsigned char> sharedSecret;  // ss.bin  (Alice's secret)
};

class MLKEMEngine {
public:
    // Encapsulation: generate ciphertext + shared secret using public key
    static KEMResult encapsulate(MLKEMLevel level, const std::string& pubKeyPath);

    // Decapsulation: recover shared secret from ciphertext + private key
    static std::vector<unsigned char> decapsulate(
        MLKEMLevel level,
        const std::string& privKeyPath,
        const std::vector<unsigned char>& ciphertext
    );
};
