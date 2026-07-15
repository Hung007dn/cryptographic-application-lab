#include "MLDSAEngine.hpp"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdexcept>
#include <fstream>
#include <iostream>

static std::string mldsaErrors() {
    std::string out;
    unsigned long e;
    char buf[256];
    while ((e = ERR_get_error())) {
        ERR_error_string_n(e, buf, sizeof(buf));
        out += std::string(buf) + "\n";
    }
    return out;
}

static EVP_PKEY* loadPrivKey(const std::string& path) {
    FILE* fp = fopen(path.c_str(), "rb");
    if (!fp) throw std::runtime_error("Cannot open private key: " + path);
    EVP_PKEY* k = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!k) throw std::runtime_error("Failed to read private key PEM: " + mldsaErrors());
    return k;
}

static EVP_PKEY* loadPubKey(const std::string& path) {
    FILE* fp = fopen(path.c_str(), "rb");
    if (!fp) throw std::runtime_error("Cannot open public key: " + path);
    EVP_PKEY* k = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!k) throw std::runtime_error("Failed to read public key PEM: " + mldsaErrors());
    return k;
}

std::vector<unsigned char> MLDSAEngine::sign(
    MLDSALevel level,
    const std::string& privKeyPath,
    const std::vector<unsigned char>& message)
{
    EVP_PKEY* pkey = loadPrivKey(privKeyPath);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); throw std::runtime_error("EVP_MD_CTX_new failed"); }

    // ML-DSA does not use a separate hash — pass nullptr for MD
    if (EVP_DigestSignInit_ex(ctx, nullptr, nullptr, nullptr, nullptr, pkey, nullptr) <= 0) {
        EVP_MD_CTX_free(ctx); EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_DigestSignInit_ex failed: " + mldsaErrors());
    }

    // Determine signature size
    size_t sigLen = 0;
    if (EVP_DigestSign(ctx, nullptr, &sigLen, message.data(), message.size()) <= 0) {
        EVP_MD_CTX_free(ctx); EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_DigestSign (size) failed: " + mldsaErrors());
    }

    std::vector<unsigned char> sig(sigLen);
    if (EVP_DigestSign(ctx, sig.data(), &sigLen, message.data(), message.size()) <= 0) {
        EVP_MD_CTX_free(ctx); EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_DigestSign (sign) failed: " + mldsaErrors());
    }
    sig.resize(sigLen);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    std::cout << "[INFO] ML-DSA sign complete. Signature size: " << sig.size() << " bytes\n";
    return sig;
}

bool MLDSAEngine::verify(
    MLDSALevel level,
    const std::string& pubKeyPath,
    const std::vector<unsigned char>& message,
    const std::vector<unsigned char>& sig)
{
    EVP_PKEY* pkey = loadPubKey(pubKeyPath);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); throw std::runtime_error("EVP_MD_CTX_new failed"); }

    if (EVP_DigestVerifyInit_ex(ctx, nullptr, nullptr, nullptr, nullptr, pkey, nullptr) <= 0) {
        EVP_MD_CTX_free(ctx); EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_DigestVerifyInit_ex failed: " + mldsaErrors());
    }

    int rc = EVP_DigestVerify(ctx, sig.data(), sig.size(), message.data(), message.size());

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return rc == 1;
}
