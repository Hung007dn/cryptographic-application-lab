// ECDSAEngine.cpp
#include "ECDSAEngine.hpp"
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <cstring>

ECDSAEngine::ECDSAEngine() {
    OpenSSL_add_all_algorithms();
}

ECDSAEngine::~ECDSAEngine() = default;

int ECDSAEngine::getNID(HashAlgorithm algo) {
    switch (algo) {
        case HashAlgorithm::SHA256: return NID_sha256;
        case HashAlgorithm::SHA384: return NID_sha384;
        default: return NID_sha256;
    }
}

std::string ECDSAEngine::hashToString(HashAlgorithm algo) {
    switch (algo) {
        case HashAlgorithm::SHA256: return "SHA256";
        case HashAlgorithm::SHA384: return "SHA384";
        default: return "SHA256";
    }
}

std::vector<uint8_t> ECDSAEngine::encodeSignatureDER(const std::vector<uint8_t>& raw_sig) {
    // Raw ECDSA signature is r || s (each 32 or 48 bytes)
    // Convert to DER format
    if (raw_sig.empty()) return {};
    
    size_t half = raw_sig.size() / 2;
    std::vector<uint8_t> r(raw_sig.begin(), raw_sig.begin() + half);
    std::vector<uint8_t> s(raw_sig.begin() + half, raw_sig.end());
    
    // Remove leading zeros
    while (r.size() > 1 && r[0] == 0) r.erase(r.begin());
    while (s.size() > 1 && s[0] == 0) s.erase(s.begin());
    
    // Add leading zero if high bit is set (DER requires positive integer)
    if (r[0] & 0x80) r.insert(r.begin(), 0);
    if (s[0] & 0x80) s.insert(s.begin(), 0);
    
    // DER sequence: 0x30 || len || 0x02 || r_len || r || 0x02 || s_len || s
    std::vector<uint8_t> der;
    der.push_back(0x30);  // SEQUENCE
    
    size_t r_len = r.size();
    size_t s_len = s.size();
    size_t total_len = 2 + r_len + 2 + s_len;
    der.push_back(total_len);
    
    der.push_back(0x02);  // INTEGER
    der.push_back(r_len);
    der.insert(der.end(), r.begin(), r.end());
    
    der.push_back(0x02);  // INTEGER
    der.push_back(s_len);
    der.insert(der.end(), s.begin(), s.end());
    
    return der;
}

std::vector<uint8_t> ECDSAEngine::decodeSignatureDER(const std::vector<uint8_t>& der_sig) {
    // Simplified DER decoding (assumes valid DER)
    if (der_sig.size() < 8) return {};
    
    size_t pos = 2;  // Skip 0x30 and length
    if (der_sig[pos] != 0x02) return {};
    pos++;
    
    size_t r_len = der_sig[pos];
    pos++;
    std::vector<uint8_t> r(der_sig.begin() + pos, der_sig.begin() + pos + r_len);
    pos += r_len;
    
    if (der_sig[pos] != 0x02) return {};
    pos++;
    
    size_t s_len = der_sig[pos];
    pos++;
    std::vector<uint8_t> s(der_sig.begin() + pos, der_sig.begin() + pos + s_len);
    
    // Pad to full length (32 or 48 bytes)
    size_t half_len = (r.size() + s.size()) / 2;
    if (r.size() < half_len) r.insert(r.begin(), half_len - r.size(), 0);
    if (s.size() < half_len) s.insert(s.begin(), half_len - s.size(), 0);
    
    std::vector<uint8_t> result = r;
    result.insert(result.end(), s.begin(), s.end());
    
    return result;
}

std::vector<uint8_t> ECDSAEngine::sign(const std::vector<uint8_t>& message,
                                        EVP_PKEY* privateKey,
                                        HashAlgorithm hash_algo,
                                        bool deterministic) {
    (void)deterministic;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw SigException("Failed to create context");
    
    const EVP_MD* md = (hash_algo == HashAlgorithm::SHA256) ? EVP_sha256() : EVP_sha384();
    
    // Lấy EVP_PKEY_CTX
    EVP_PKEY_CTX* pkey_ctx = nullptr;
    
    if (EVP_DigestSignInit(ctx, &pkey_ctx, md, nullptr, privateKey) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw SigException("Failed to init sign context");
    }
    
    // Update message
    if (EVP_DigestSignUpdate(ctx, message.data(), message.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw SigException("Failed to update sign context");
    }
    
    // Get signature length
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

bool ECDSAEngine::verify(const std::vector<uint8_t>& message,
                          const std::vector<uint8_t>& signature,
                          EVP_PKEY* publicKey,
                          HashAlgorithm hash_algo) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw SigException("Failed to create context");
    
    const EVP_MD* md = (hash_algo == HashAlgorithm::SHA256) ? EVP_sha256() : EVP_sha384();
    
    if (EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, publicKey) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw SigException("Failed to init verify context");
    }
    
    if (EVP_DigestVerifyUpdate(ctx, message.data(), message.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw SigException("Failed to update verify context");
    }
    
    int result = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
    EVP_MD_CTX_free(ctx);
    
    return result == 1;
}