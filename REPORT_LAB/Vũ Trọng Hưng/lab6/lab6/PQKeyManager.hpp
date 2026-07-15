#pragma once
#include <string>
#include <vector>
#include "PQConfig.hpp"

class PQKeyManager {
public:
    // ML-DSA
    static void mldsaKeygen(MLDSALevel level, const std::string& pubPath, const std::string& privPath);
    static std::vector<unsigned char> loadPublicKeyRaw(const std::string& pemPath);
    static std::vector<unsigned char> loadPrivateKeyRaw(const std::string& pemPath);

    // ML-KEM
    static void mlkemKeygen(MLKEMLevel level, const std::string& pubPath, const std::string& privPath);

    // Save raw bytes as PEM-like base64 block
    static void saveRawPEM(const std::string& path, const std::string& label, const std::vector<unsigned char>& data);
    static std::vector<unsigned char> loadRawPEM(const std::string& path, const std::string& label);

    // OpenSSL EVP keygen wrapper (returns PEM strings)
    static std::string keygenToPubPEM(const std::string& algoName);
    static void keygenToFiles(const std::string& algoName, const std::string& pubPath, const std::string& privPath);
};
