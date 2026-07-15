#pragma once
#include <string>
#include <stdexcept>

// Supported PQC algorithms
enum class MLDSALevel { MLDSA44, MLDSA65, MLDSA87 };
enum class MLKEMLevel { MLKEM512, MLKEM768, MLKEM1024 };

struct PQConfig {
    // ML-DSA algorithm name for OpenSSL EVP
    static std::string mldsaName(MLDSALevel level) {
        switch (level) {
            case MLDSALevel::MLDSA44: return "ML-DSA-44";
            case MLDSALevel::MLDSA65: return "ML-DSA-65";
            case MLDSALevel::MLDSA87: return "ML-DSA-87";
        }
        throw std::invalid_argument("Unknown ML-DSA level");
    }

    // ML-KEM algorithm name for OpenSSL EVP
    static std::string mlkemName(MLKEMLevel level) {
        switch (level) {
            case MLKEMLevel::MLKEM512:  return "ML-KEM-512";
            case MLKEMLevel::MLKEM768:  return "ML-KEM-768";
            case MLKEMLevel::MLKEM1024: return "ML-KEM-1024";
        }
        throw std::invalid_argument("Unknown ML-KEM level");
    }

    static MLDSALevel parseMldsa(const std::string& s) {
        if (s == "mldsa-44" || s == "ML-DSA-44") return MLDSALevel::MLDSA44;
        if (s == "mldsa-65" || s == "ML-DSA-65") return MLDSALevel::MLDSA65;
        if (s == "mldsa-87" || s == "ML-DSA-87") return MLDSALevel::MLDSA87;
        throw std::invalid_argument("Unknown ML-DSA variant: " + s);
    }

    static MLKEMLevel parseMlkem(const std::string& s) {
        if (s == "mlkem-512"  || s == "ML-KEM-512")  return MLKEMLevel::MLKEM512;
        if (s == "mlkem-768"  || s == "ML-KEM-768")  return MLKEMLevel::MLKEM768;
        if (s == "mlkem-1024" || s == "ML-KEM-1024") return MLKEMLevel::MLKEM1024;
        throw std::invalid_argument("Unknown ML-KEM variant: " + s);
    }
};
