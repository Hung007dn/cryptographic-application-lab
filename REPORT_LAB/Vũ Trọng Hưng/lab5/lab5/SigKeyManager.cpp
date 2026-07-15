// SigKeyManager.cpp
#include "SigKeyManager.hpp"

#include <nlohmann/json.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>

#include <cstdio>
#include <ctime>
#include <fstream>
#include <iostream>
#include <string>

using json = nlohmann::json;

namespace {

bool isECDSAAlgorithm(SignatureAlgorithm algo) {
return algo == SignatureAlgorithm::ECDSA_P256 ||
algo == SignatureAlgorithm::ECDSA_P384;
}

bool isRSAAlgorithm(SignatureAlgorithm algo) {
return algo == SignatureAlgorithm::RSA_PSS_3072;
}

int expectedKeyBits(SignatureAlgorithm algo) {
if (algo == SignatureAlgorithm::ECDSA_P256) {
return 256;
}


if (algo == SignatureAlgorithm::ECDSA_P384) {
    return 384;
}

if (algo == SignatureAlgorithm::RSA_PSS_3072) {
    return 3072;
}

return 0;


}

void validateKeyForAlgorithm(EVP_PKEY* key, SignatureAlgorithm algo, const std::string& context) {
if (!key) {
throw SigException(context + ": null key");
}


int baseId = EVP_PKEY_base_id(key);

if (isECDSAAlgorithm(algo)) {
    if (baseId != EVP_PKEY_EC) {
        throw SigException(context + ": expected EC public/private key");
    }

    int bits = EVP_PKEY_get_bits(key);
    int expected = expectedKeyBits(algo);

    if (bits != expected) {
        throw SigException(
            context + ": EC key size mismatch. Expected " +
            std::to_string(expected) + " bits, got " +
            std::to_string(bits) + " bits"
        );
    }

    return;
}

if (isRSAAlgorithm(algo)) {
    if (baseId != EVP_PKEY_RSA && baseId != EVP_PKEY_RSA_PSS) {
        throw SigException(context + ": expected RSA public/private key");
    }

    int bits = EVP_PKEY_get_bits(key);

    if (bits < 3072) {
        throw SigException(
            context + ": RSA key is too small. Expected at least 3072 bits, got " +
            std::to_string(bits) + " bits"
        );
    }

    return;
}

throw SigException(context + ": unsupported signature algorithm");


}

std::string bioToString(BIO* bio) {
if (!bio) {
throw SigException("BIO is null");
}


char* data = nullptr;
long len = BIO_get_mem_data(bio, &data);

if (len <= 0 || data == nullptr) {
    throw SigException("Failed to export PEM data");
}

return std::string(data, static_cast<size_t>(len));


}

} // namespace

SigKeyManager::SigKeyManager()
: m_pubkey(nullptr),
m_privkey(nullptr),
m_hasPubKey(false),
m_hasPrivKey(false) {}

SigKeyManager::~SigKeyManager() {
cleanup();
}

void SigKeyManager::cleanup() {
if (m_pubkey) {
EVP_PKEY_free(m_pubkey);
}


if (m_privkey) {
    EVP_PKEY_free(m_privkey);
}

m_pubkey = nullptr;
m_privkey = nullptr;
m_hasPubKey = false;
m_hasPrivKey = false;


}

void SigKeyManager::generateKeyPair(SignatureAlgorithm algo) {
cleanup();
m_algorithm = algo;


EVP_PKEY_CTX* ctx = nullptr;
EVP_PKEY* key = nullptr;

if (isECDSAAlgorithm(algo)) {
    int curve_nid = (algo == SignatureAlgorithm::ECDSA_P256)
        ? NID_X9_62_prime256v1
        : NID_secp384r1;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);

    if (!ctx) {
        throw SigException("Failed to create EC key generation context");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw SigException("Failed to initialize EC key generation");
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_nid) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw SigException("Failed to set EC curve");
    }

    if (EVP_PKEY_keygen(ctx, &key) <= 0 || !key) {
        EVP_PKEY_CTX_free(ctx);
        throw SigException("Failed to generate EC key pair");
    }

} else if (isRSAAlgorithm(algo)) {
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);

    if (!ctx) {
        throw SigException("Failed to create RSA key generation context");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw SigException("Failed to initialize RSA key generation");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw SigException("Failed to set RSA key size");
    }

    if (EVP_PKEY_keygen(ctx, &key) <= 0 || !key) {
        EVP_PKEY_CTX_free(ctx);
        throw SigException("Failed to generate RSA key pair");
    }

} else {
    throw SigException("Unsupported algorithm for key generation");
}

EVP_PKEY_CTX_free(ctx);

validateKeyForAlgorithm(key, algo, "Generated key validation");

m_privkey = key;
m_pubkey = key;
EVP_PKEY_up_ref(m_pubkey);

m_hasPubKey = true;
m_hasPrivKey = true;

std::cout << "[INFO] Generated "
          << SigConfig::algorithmToString(algo)
          << " key pair"
          << std::endl;


}

void SigKeyManager::saveKeyPair(const std::string& pub_file, const std::string& priv_file) {
if (!m_hasPubKey || !m_pubkey) {
throw SigException("No public key to save");
}


if (!m_hasPrivKey || !m_privkey) {
    throw SigException("No private key to save");
}

FILE* pub_fp = std::fopen(pub_file.c_str(), "wb");

if (!pub_fp) {
    throw SigException("Cannot open public key file for writing");
}

if (PEM_write_PUBKEY(pub_fp, m_pubkey) != 1) {
    std::fclose(pub_fp);
    throw SigException("Failed to write public key");
}

std::fclose(pub_fp);

FILE* priv_fp = std::fopen(priv_file.c_str(), "wb");

if (!priv_fp) {
    throw SigException("Cannot open private key file for writing");
}

if (PEM_write_PrivateKey(priv_fp, m_privkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
    std::fclose(priv_fp);
    throw SigException("Failed to write private key");
}

std::fclose(priv_fp);

std::cout << "[INFO] Public key saved: " << pub_file << std::endl;
std::cout << "[INFO] Private key saved: " << priv_file << std::endl;


}

void SigKeyManager::saveMetadata(const std::string& metadata_file) {
json metadata;


metadata["algorithm"] = SigConfig::algorithmToString(m_algorithm);

SigConfig cfg;
cfg.algorithm = m_algorithm;

metadata["key_size_bits"] = cfg.getKeySizeBits();
metadata["creation_time"] = std::time(nullptr);

std::ofstream file(metadata_file);

if (!file.is_open()) {
    throw SigException("Cannot open metadata file for writing");
}

file << metadata.dump(4);

std::cout << "[INFO] Metadata saved: " << metadata_file << std::endl;


}

void SigKeyManager::loadPublicKey(const std::string& pub_file, SignatureAlgorithm algo) {
cleanup();
m_algorithm = algo;


FILE* fp = std::fopen(pub_file.c_str(), "rb");

if (!fp) {
    throw SigException("Cannot open public key file");
}

EVP_PKEY* loaded = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
std::fclose(fp);

if (!loaded) {
    throw SigException("Failed to read public key");
}

try {
    validateKeyForAlgorithm(loaded, algo, "Public key validation");
} catch (...) {
    EVP_PKEY_free(loaded);
    throw;
}

m_pubkey = loaded;
m_hasPubKey = true;

std::cout << "[INFO] Public key loaded" << std::endl;


}

void SigKeyManager::loadPrivateKey(const std::string& priv_file, SignatureAlgorithm algo) {
cleanup();
m_algorithm = algo;


FILE* fp = std::fopen(priv_file.c_str(), "rb");

if (!fp) {
    throw SigException("Cannot open private key file");
}

EVP_PKEY* loaded = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
std::fclose(fp);

if (!loaded) {
    throw SigException("Failed to read private key");
}

try {
    validateKeyForAlgorithm(loaded, algo, "Private key validation");
} catch (...) {
    EVP_PKEY_free(loaded);
    throw;
}

m_privkey = loaded;
m_pubkey = loaded;
EVP_PKEY_up_ref(m_pubkey);

m_hasPrivKey = true;
m_hasPubKey = true;

std::cout << "[INFO] Private key loaded" << std::endl;


}

std::string SigKeyManager::exportPublicKeyPEM() {
if (!m_hasPubKey || !m_pubkey) {
throw SigException("No public key to export");
}


BIO* bio = BIO_new(BIO_s_mem());

if (!bio) {
    throw SigException("Failed to allocate BIO for public key export");
}

if (PEM_write_bio_PUBKEY(bio, m_pubkey) != 1) {
    BIO_free(bio);
    throw SigException("Failed to export public key as PEM");
}

std::string result = bioToString(bio);
BIO_free(bio);

return result;


}

std::string SigKeyManager::exportPrivateKeyPEM() {
if (!m_hasPrivKey || !m_privkey) {
throw SigException("No private key to export");
}


BIO* bio = BIO_new(BIO_s_mem());

if (!bio) {
    throw SigException("Failed to allocate BIO for private key export");
}

if (PEM_write_bio_PrivateKey(bio, m_privkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
    BIO_free(bio);
    throw SigException("Failed to export private key as PEM");
}

std::string result = bioToString(bio);
BIO_free(bio);

return result;


}
