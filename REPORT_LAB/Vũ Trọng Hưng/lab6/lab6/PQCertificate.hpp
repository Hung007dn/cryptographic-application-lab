#pragma once
#include <string>

class PQCertificate {
public:
    // Generate a CA key pair (ML-DSA-44) and sign a subject's public key
    // Subject public key is read from subjectPubPath
    // Certificate JSON is saved to outCertPath
    static void generate(
        const std::string& caPrivPath,
        const std::string& caPubPath,
        const std::string& subjectName,
        const std::string& subjectPubPath,
        const std::string& outCertPath
    );

    // Verify a certificate JSON using the CA public key
    // Returns true if valid
    static bool verify(
        const std::string& certPath,
        const std::string& caPubPath
    );

    // Show certificate content
    static void show(const std::string& certPath);
};
