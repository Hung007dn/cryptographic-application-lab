// RSAPSSEngine.cpp
#include "RSAPSSEngine.hpp"
#include <openssl/evp.h>
#include <openssl/rsa.h>

RSAPSSEngine::RSAPSSEngine() {
    OpenSSL_add_all_algorithms();
}

RSAPSSEngine::~RSAPSSEngine() = default;

int RSAPSSEngine::getNID(HashAlgorithm algo) {
    switch (algo) {
        case HashAlgorithm::SHA256: return NID_sha256;
        case HashAlgorithm::SHA384: return NID_sha384;
        default: return NID_sha256;
    }
}

std::string RSAPSSEngine::hashToString(HashAlgorithm algo) {
    switch (algo) {
        case HashAlgorithm::SHA256: return "SHA256";
        case HashAlgorithm::SHA384: return "SHA384";
        default: return "SHA256";
    }
}

std::vector<uint8_t> RSAPSSEngine::sign(const std::vector<uint8_t>& message,
                                         EVP_PKEY* privateKey,
                                         HashAlgorithm hash_algo) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw SigException("Failed to create context");
    
    const EVP_MD* md = (hash_algo == HashAlgorithm::SHA256) ? EVP_sha256() : EVP_sha384();
    
    // Lấy EVP_PKEY_CTX từ EVP_MD_CTX sau khi init
    EVP_PKEY_CTX* pkey_ctx = nullptr;
    
    if (EVP_DigestSignInit(ctx, &pkey_ctx, md, nullptr, privateKey) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw SigException("Failed to init sign context");
    }
    
    // Bây giờ dùng pkey_ctx để set RSA-PSS parameters
    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw SigException("Failed to set RSA-PSS padding");
    }
    
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1) <= 0) {  // -1 = hash length
        EVP_MD_CTX_free(ctx);
        throw SigException("Failed to set salt length");
    }
    
    // Update message
    if (EVP_DigestSignUpdate(ctx, message.data(), message.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw SigException("Failed to update sign context");
    }
    
    // Get signature
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &sig_len) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw SigException("Failed to get signature length");
    }
    
    std::vector<uint8_t> signature(sig_len);
    if (EVP_DigestSignFinal(ctx, signature.data(), &sig_len) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw SigException("Failed to create signature");
    }
    
    signature.resize(sig_len);
    EVP_MD_CTX_free(ctx);
    
    return signature;
}

bool RSAPSSEngine::verify(const std::vector<uint8_t>& message,
                           const std::vector<uint8_t>& signature,
                           EVP_PKEY* publicKey,
                           HashAlgorithm hash_algo) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw SigException("Failed to create context");
    
    const EVP_MD* md = (hash_algo == HashAlgorithm::SHA256) ? EVP_sha256() : EVP_sha384();
    
    EVP_PKEY_CTX* pkey_ctx = nullptr;
    
    if (EVP_DigestVerifyInit(ctx, &pkey_ctx, md, nullptr, publicKey) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw SigException("Failed to init verify context");
    }
    
    // Configure RSA-PSS padding
    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw SigException("Failed to set RSA-PSS padding");
    }
    
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw SigException("Failed to set salt length");
    }
    
    // Update message
    if (EVP_DigestVerifyUpdate(ctx, message.data(), message.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw SigException("Failed to update verify context");
    }
    
    int result = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
    EVP_MD_CTX_free(ctx);
    
    return result == 1;
}