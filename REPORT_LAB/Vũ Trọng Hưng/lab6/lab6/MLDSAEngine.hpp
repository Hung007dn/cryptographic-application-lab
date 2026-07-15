#pragma once
#include <string>
#include <vector>
#include "PQConfig.hpp"

class MLDSAEngine {
public:
    // Sign a message file with a private key PEM
    static std::vector<unsigned char> sign(
        MLDSALevel level,
        const std::string& privKeyPath,
        const std::vector<unsigned char>& message
    );

    // Verify a signature using a public key PEM
    // Returns true if valid
    static bool verify(
        MLDSALevel level,
        const std::string& pubKeyPath,
        const std::vector<unsigned char>& message,
        const std::vector<unsigned char>& signature
    );
};
