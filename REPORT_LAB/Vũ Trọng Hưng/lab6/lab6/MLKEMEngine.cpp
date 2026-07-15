#include "MLKEMEngine.hpp"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdexcept>
#include <iostream>

static std::string kemErrors() {
    std::string out;
    unsigned long e;
    char buf[256];
    while ((e = ERR_get_error())) {
        ERR_error_string_n(e, buf, sizeof(buf));
        out += std::string(buf) + "\n";
    }
    return out;
}

static EVP_PKEY* kemLoadPub(const std::string& path) {
    FILE* fp = fopen(path.c_str(), "rb");
    if (!fp) throw std::runtime_error("Cannot open public key: " + path);
    EVP_PKEY* k = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!k) throw std::runtime_error("PEM_read_PUBKEY failed: " + kemErrors());
    return k;
}

static EVP_PKEY* kemLoadPriv(const std::string& path) {
    FILE* fp = fopen(path.c_str(), "rb");
    if (!fp) throw std::runtime_error("Cannot open private key: " + path);
    EVP_PKEY* k = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!k) throw std::runtime_error("PEM_read_PrivateKey failed: " + kemErrors());
    return k;
}

KEMResult MLKEMEngine::encapsulate(MLKEMLevel level, const std::string& pubKeyPath) {
    EVP_PKEY* pub = kemLoadPub(pubKeyPath);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pub, nullptr);
    if (!ctx) { EVP_PKEY_free(pub); throw std::runtime_error("EVP_PKEY_CTX_new failed"); }

    if (EVP_PKEY_encapsulate_init(ctx, nullptr) <= 0) {
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pub);
        throw std::runtime_error("EVP_PKEY_encapsulate_init failed: " + kemErrors());
    }

    size_t ctLen = 0, ssLen = 0;
    if (EVP_PKEY_encapsulate(ctx, nullptr, &ctLen, nullptr, &ssLen) <= 0) {
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pub);
        throw std::runtime_error("EVP_PKEY_encapsulate (size) failed: " + kemErrors());
    }

    KEMResult result;
    result.ciphertext.resize(ctLen);
    result.sharedSecret.resize(ssLen);

    if (EVP_PKEY_encapsulate(ctx, result.ciphertext.data(), &ctLen,
                              result.sharedSecret.data(), &ssLen) <= 0) {
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pub);
        throw std::runtime_error("EVP_PKEY_encapsulate failed: " + kemErrors());
    }
    result.ciphertext.resize(ctLen);
    result.sharedSecret.resize(ssLen);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pub);

    std::cout << "[INFO] ML-KEM encapsulation complete.\n";
    std::cout << "[INFO] Ciphertext size   : " << result.ciphertext.size()   << " bytes\n";
    std::cout << "[INFO] Shared secret size: " << result.sharedSecret.size() << " bytes\n";
    return result;
}

std::vector<unsigned char> MLKEMEngine::decapsulate(
    MLKEMLevel level,
    const std::string& privKeyPath,
    const std::vector<unsigned char>& ciphertext)
{
    EVP_PKEY* priv = kemLoadPriv(privKeyPath);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, priv, nullptr);
    if (!ctx) { EVP_PKEY_free(priv); throw std::runtime_error("EVP_PKEY_CTX_new failed"); }

    if (EVP_PKEY_decapsulate_init(ctx, nullptr) <= 0) {
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(priv);
        throw std::runtime_error("EVP_PKEY_decapsulate_init failed: " + kemErrors());
    }

    size_t ssLen = 0;
    if (EVP_PKEY_decapsulate(ctx, nullptr, &ssLen, ciphertext.data(), ciphertext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(priv);
        throw std::runtime_error("EVP_PKEY_decapsulate (size) failed: " + kemErrors());
    }

    std::vector<unsigned char> ss(ssLen);
    if (EVP_PKEY_decapsulate(ctx, ss.data(), &ssLen, ciphertext.data(), ciphertext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(priv);
        throw std::runtime_error("EVP_PKEY_decapsulate failed: " + kemErrors());
    }
    ss.resize(ssLen);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv);

    std::cout << "[INFO] ML-KEM decapsulation complete.\n";
    std::cout << "[INFO] Shared secret size: " << ss.size() << " bytes\n";
    return ss;
}
