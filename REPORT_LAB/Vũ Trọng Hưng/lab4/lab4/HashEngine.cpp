
// HashEngine.cpp
#include "HashEngine.hpp"

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <memory>

namespace {

struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX* ctx) const {
        EVP_MD_CTX_free(ctx);
    }
};

using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

std::string getOpenSSLErrorString() {
    unsigned long err = ERR_get_error();

    if (err == 0) {
        return "unknown OpenSSL error";
    }

    char buffer[256];
    ERR_error_string_n(err, buffer, sizeof(buffer));
    return std::string(buffer);
}

const EVP_MD* getOpenSSLHashAlgorithm(HashAlgorithm algorithm) {
    switch (algorithm) {
        // SHA-2 Family
        case HashAlgorithm::SHA_224:
            return EVP_sha224();

        case HashAlgorithm::SHA_256:
            return EVP_sha256();

        case HashAlgorithm::SHA_384:
            return EVP_sha384();

        case HashAlgorithm::SHA_512:
            return EVP_sha512();

        // SHA-3 Family
        case HashAlgorithm::SHA3_224:
            return EVP_sha3_224();

        case HashAlgorithm::SHA3_256:
            return EVP_sha3_256();

        case HashAlgorithm::SHA3_384:
            return EVP_sha3_384();

        case HashAlgorithm::SHA3_512:
            return EVP_sha3_512();

        // SHAKE XOF
        case HashAlgorithm::SHAKE128:
            return EVP_shake128();

        case HashAlgorithm::SHAKE256:
            return EVP_shake256();

        default:
            return nullptr;
    }
}

bool isShakeAlgorithm(HashAlgorithm algorithm) {
    return algorithm == HashAlgorithm::SHAKE128 ||
           algorithm == HashAlgorithm::SHAKE256;
}

std::vector<uint8_t> digestDataOpenSSL(
    const EVP_MD* md,
    const uint8_t* data,
    size_t len,
    bool is_xof,
    size_t xof_outlen
) {
    if (!md) {
        throw HashException("Unsupported OpenSSL hash algorithm");
    }

    if (is_xof && xof_outlen == 0) {
        throw HashException("SHAKE output length must be greater than zero");
    }

    EvpMdCtxPtr ctx(EVP_MD_CTX_new());

    if (!ctx) {
        throw HashException("EVP_MD_CTX_new failed: " + getOpenSSLErrorString());
    }

    if (EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1) {
        throw HashException("EVP_DigestInit_ex failed: " + getOpenSSLErrorString());
    }

    if (len > 0 && EVP_DigestUpdate(ctx.get(), data, len) != 1) {
        throw HashException("EVP_DigestUpdate failed: " + getOpenSSLErrorString());
    }

    if (is_xof) {
        std::vector<uint8_t> result(xof_outlen);

        if (EVP_DigestFinalXOF(ctx.get(), result.data(), result.size()) != 1) {
            throw HashException("EVP_DigestFinalXOF failed: " + getOpenSSLErrorString());
        }

        return result;
    }

    int digest_size = EVP_MD_get_size(md);

    if (digest_size <= 0) {
        throw HashException("Invalid OpenSSL digest size");
    }

    std::vector<uint8_t> result(static_cast<size_t>(digest_size));
    unsigned int actual_size = 0;

    if (EVP_DigestFinal_ex(ctx.get(), result.data(), &actual_size) != 1) {
        throw HashException("EVP_DigestFinal_ex failed: " + getOpenSSLErrorString());
    }

    result.resize(actual_size);
    return result;
}

std::vector<uint8_t> digestStreamOpenSSL(
    const EVP_MD* md,
    std::istream& stream,
    bool is_xof,
    size_t xof_outlen
) {
    if (!md) {
        throw HashException("Unsupported OpenSSL hash algorithm");
    }

    if (is_xof && xof_outlen == 0) {
        throw HashException("SHAKE output length must be greater than zero");
    }

    EvpMdCtxPtr ctx(EVP_MD_CTX_new());

    if (!ctx) {
        throw HashException("EVP_MD_CTX_new failed: " + getOpenSSLErrorString());
    }

    if (EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1) {
        throw HashException("EVP_DigestInit_ex failed: " + getOpenSSLErrorString());
    }

    const size_t BUFFER_SIZE = 1024 * 1024;
    std::vector<uint8_t> buffer(BUFFER_SIZE);

    while (stream) {
        stream.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));

        std::streamsize bytes_read = stream.gcount();

        if (bytes_read > 0) {
            if (EVP_DigestUpdate(
                    ctx.get(),
                    buffer.data(),
                    static_cast<size_t>(bytes_read)
                ) != 1) {
                throw HashException("EVP_DigestUpdate failed: " + getOpenSSLErrorString());
            }
        }
    }

    if (stream.bad()) {
        throw HashException("Input stream read error");
    }

    if (is_xof) {
        std::vector<uint8_t> result(xof_outlen);

        if (EVP_DigestFinalXOF(ctx.get(), result.data(), result.size()) != 1) {
            throw HashException("EVP_DigestFinalXOF failed: " + getOpenSSLErrorString());
        }

        return result;
    }

    int digest_size = EVP_MD_get_size(md);

    if (digest_size <= 0) {
        throw HashException("Invalid OpenSSL digest size");
    }

    std::vector<uint8_t> result(static_cast<size_t>(digest_size));
    unsigned int actual_size = 0;

    if (EVP_DigestFinal_ex(ctx.get(), result.data(), &actual_size) != 1) {
        throw HashException("EVP_DigestFinal_ex failed: " + getOpenSSLErrorString());
    }

    result.resize(actual_size);
    return result;
}

} // namespace

HashEngine::HashEngine() = default;

HashEngine::~HashEngine() = default;

std::vector<uint8_t> HashEngine::hashFile(
    const HashConfig& config,
    const std::string& filename
) {
    std::ifstream file(filename, std::ios::binary);

    if (!file.is_open()) {
        throw HashException("Cannot open file: " + filename);
    }

    const EVP_MD* md = getOpenSSLHashAlgorithm(config.algorithm);

    return digestStreamOpenSSL(
        md,
        file,
        isShakeAlgorithm(config.algorithm),
        config.shake_output_length
    );
}

std::vector<uint8_t> HashEngine::hashString(
    const HashConfig& config,
    const std::string& data
) {
    const EVP_MD* md = getOpenSSLHashAlgorithm(config.algorithm);

    return digestDataOpenSSL(
        md,
        reinterpret_cast<const uint8_t*>(data.data()),
        data.size(),
        isShakeAlgorithm(config.algorithm),
        config.shake_output_length
    );
}

std::string HashEngine::hashToHex(const std::vector<uint8_t>& hash) {
    std::ostringstream oss;

    oss << std::hex << std::setfill('0');

    for (uint8_t byte : hash) {
        oss << std::setw(2) << static_cast<int>(byte);
    }

    return oss.str();
}

std::vector<uint8_t> HashEngine::hashToRaw(const std::vector<uint8_t>& hash) {
    return hash;
}

bool HashEngine::verifyHash(
    const std::vector<uint8_t>& hash1,
    const std::vector<uint8_t>& hash2
) {
    if (hash1.size() != hash2.size()) {
        return false;
    }

    if (hash1.empty()) {
        return true;
    }

    return CRYPTO_memcmp(hash1.data(), hash2.data(), hash1.size()) == 0;
}

size_t HashEngine::getDigestSize(const HashConfig& config) {
    return config.getDigestSize();
}

