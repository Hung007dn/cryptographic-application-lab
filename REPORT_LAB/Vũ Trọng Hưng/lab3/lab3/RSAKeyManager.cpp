
// RSAKeyManager.cpp
#include "RSAKeyManager.hpp"

#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <filesystem>

using namespace CryptoPP;

RSAKeyManager::RSAKeyManager()
    : m_hasPublicKey(false),
      m_hasPrivateKey(false),
      m_currentKeySize(RSAKeySize::RSA_3072) {}

RSAKeyManager::~RSAKeyManager() = default;

// =========================
// Local helpers
// =========================

static std::string readFileBinary(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);

    if (!file) {
        throw RSAException("Cannot open file: " + filename);
    }

    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

static bool isPEMText(const std::string& data) {
    return data.find("-----BEGIN") != std::string::npos;
}

static std::string pemToDer(const std::string& pem) {
    std::string base64;
    std::istringstream input(pem);
    std::string line;

    while (std::getline(input, line)) {
        if (line.find("-----BEGIN") != std::string::npos) {
            continue;
        }

        if (line.find("-----END") != std::string::npos) {
            continue;
        }

        line.erase(
            std::remove_if(
                line.begin(),
                line.end(),
                [](unsigned char c) {
                    return std::isspace(c);
                }
            ),
            line.end()
        );

        base64 += line;
    }

    if (base64.empty()) {
        throw RSAException("Invalid PEM file: empty base64 body.");
    }

    std::string der;

    StringSource ss(
        base64,
        true,
        new Base64Decoder(
            new StringSink(der)
        )
    );

    return der;
}

static std::string makeSiblingPath(
    const std::string& reference_file,
    const std::string& new_filename
) {
    std::filesystem::path ref(reference_file);
    std::filesystem::path parent = ref.parent_path();

    if (parent.empty()) {
        return new_filename;
    }

    return (parent / new_filename).string();
}

// =========================
// Key generation
// =========================

void RSAKeyManager::generateKeyPair(RSAKeySize key_size) {
    size_t modulus_bits = static_cast<size_t>(key_size);

    // Lab 3 requirement: RSA modulus size must be >= 3072 bits.
    // This implementation only accepts RSA-3072 and RSA-4096.
    if (key_size != RSAKeySize::RSA_3072 && key_size != RSAKeySize::RSA_4096) {
        throw RSAException(
            "Unsupported RSA key size: " + std::to_string(modulus_bits) +
            ". Use 3072 or 4096 bits."
        );
    }

    m_currentKeySize = key_size;

    std::cout << "[INFO] Generating RSA-" << modulus_bits << " key pair..." << std::endl;

    m_privateKey.Initialize(m_rng, modulus_bits);
    m_publicKey = RSA::PublicKey(m_privateKey);

    m_hasPublicKey = true;
    m_hasPrivateKey = true;

    std::cout << "[INFO] Key generation complete!" << std::endl;
    std::cout << "[INFO] Max plaintext size: "
              << (modulus_bits / 8 - 2 * SHA256::DIGESTSIZE - 2)
              << " bytes" << std::endl;
}

// =========================
// Save/load keys
// =========================

void RSAKeyManager::saveKeyPair(
    const std::string& pub_file,
    const std::string& priv_file
) {
    if (!m_hasPublicKey || !m_hasPrivateKey) {
        throw RSAException("No key pair available to save.");
    }

    std::vector<uint8_t> pub_der = exportPublicKeyDER();
    std::vector<uint8_t> priv_der = exportPrivateKeyDER();

    // Save public PEM
    {
        std::ofstream pubPem(pub_file, std::ios::binary);

        if (!pubPem) {
            throw RSAException("Cannot write public key file: " + pub_file);
        }

        pubPem << exportPublicKeyPEM();
    }

    // Save private PEM
    {
        std::ofstream privPem(priv_file, std::ios::binary);

        if (!privPem) {
            throw RSAException("Cannot write private key file: " + priv_file);
        }

        privPem << exportPrivateKeyPEM();
    }

    // Save DER beside PEM files
    std::string pub_der_file = makeSiblingPath(pub_file, "pub.der");
    std::string priv_der_file = makeSiblingPath(priv_file, "priv.der");

    {
        std::ofstream pubDer(pub_der_file, std::ios::binary);

        if (!pubDer) {
            throw RSAException("Cannot write public DER file: " + pub_der_file);
        }

        pubDer.write(
            reinterpret_cast<const char*>(pub_der.data()),
            static_cast<std::streamsize>(pub_der.size())
        );
    }

    {
        std::ofstream privDer(priv_der_file, std::ios::binary);

        if (!privDer) {
            throw RSAException("Cannot write private DER file: " + priv_der_file);
        }

        privDer.write(
            reinterpret_cast<const char*>(priv_der.data()),
            static_cast<std::streamsize>(priv_der.size())
        );
    }

    std::cout << "[INFO] Public PEM saved to: " << pub_file << std::endl;
    std::cout << "[INFO] Private PEM saved to: " << priv_file << std::endl;
    std::cout << "[INFO] Public DER saved to: " << pub_der_file << std::endl;
    std::cout << "[INFO] Private DER saved to: " << priv_der_file << std::endl;
}

void RSAKeyManager::saveMetadata(const std::string& metadata_file) {
    json metadata;
    metadata["creation_time"] = std::time(nullptr);
    metadata["modulus_bits"] = static_cast<int>(m_currentKeySize);
    metadata["hash"] = "SHA-256";
    metadata["padding"] = "OAEP";
    metadata["mgf"] = "MGF1-SHA256";

    std::ofstream file(metadata_file);

    if (!file) {
        throw RSAException("Cannot write metadata file: " + metadata_file);
    }

    file << metadata.dump(4);
    std::cout << "[INFO] Metadata saved to: " << metadata_file << std::endl;
}

void RSAKeyManager::loadPublicKey(const std::string& pub_file) {
    std::string data = readFileBinary(pub_file);

    try {
        std::string der = isPEMText(data) ? pemToDer(data) : data;

        StringSource ss(
            reinterpret_cast<const byte*>(der.data()),
            der.size(),
            true
        );

        m_publicKey.Load(ss);
        m_hasPublicKey = true;

        std::cout << "[INFO] Public key loaded from: " << pub_file << std::endl;

    } catch (const CryptoPP::Exception& e) {
        throw RSAException(
            "Failed to load public key. Invalid PEM/DER format: " +
            std::string(e.what())
        );
    }
}

void RSAKeyManager::loadPrivateKey(const std::string& priv_file) {
    std::string data = readFileBinary(priv_file);

    try {
        std::string der = isPEMText(data) ? pemToDer(data) : data;

        StringSource ss(
            reinterpret_cast<const byte*>(der.data()),
            der.size(),
            true
        );

        m_privateKey.Load(ss);
        m_hasPrivateKey = true;

        m_publicKey = RSA::PublicKey(m_privateKey);
        m_hasPublicKey = true;

        std::cout << "[INFO] Private key loaded from: " << priv_file << std::endl;

    } catch (const CryptoPP::Exception& e) {
        throw RSAException(
            "Failed to load private key. Invalid PEM/DER format: " +
            std::string(e.what())
        );
    }
}

// =========================
// Export PEM / DER
// =========================

std::string RSAKeyManager::exportPublicKeyPEM() {
    std::vector<uint8_t> der_vec = exportPublicKeyDER();
    std::string der(der_vec.begin(), der_vec.end());

    std::string base64;
    Base64Encoder encoder(new StringSink(base64), false);
    encoder.Put(reinterpret_cast<const byte*>(der.data()), der.size());
    encoder.MessageEnd();

    // DEREncode() for CryptoPP::RSA::PublicKey produces SubjectPublicKeyInfo.
    // Therefore the correct PEM header is PUBLIC KEY, not RSA PUBLIC KEY.
    std::string result = "-----BEGIN PUBLIC KEY-----\n";

    for (size_t i = 0; i < base64.size(); i += 64) {
        result += base64.substr(i, 64) + "\n";
    }

    result += "-----END PUBLIC KEY-----\n";

    return result;
}

std::string RSAKeyManager::exportPrivateKeyPEM() {
    std::vector<uint8_t> der_vec = exportPrivateKeyDER();
    std::string der(der_vec.begin(), der_vec.end());

    std::string base64;
    Base64Encoder encoder(new StringSink(base64), false);
    encoder.Put(reinterpret_cast<const byte*>(der.data()), der.size());
    encoder.MessageEnd();

    std::string result = "-----BEGIN RSA PRIVATE KEY-----\n";

    for (size_t i = 0; i < base64.size(); i += 64) {
        result += base64.substr(i, 64) + "\n";
    }

    result += "-----END RSA PRIVATE KEY-----\n";

    return result;
}

std::vector<uint8_t> RSAKeyManager::exportPublicKeyDER() {
    if (!m_hasPublicKey) {
        throw RSAException("No public key available.");
    }

    std::string der;
    StringSink sink(der);
    m_publicKey.DEREncode(sink);

    return std::vector<uint8_t>(der.begin(), der.end());
}

std::vector<uint8_t> RSAKeyManager::exportPrivateKeyDER() {
    if (!m_hasPrivateKey) {
        throw RSAException("No private key available.");
    }

    std::string der;
    StringSink sink(der);
    m_privateKey.DEREncode(sink);

    return std::vector<uint8_t>(der.begin(), der.end());
}

// =========================
// Optional import helpers
// These match declarations in RSAKeyManager.hpp if present.
// =========================

void RSAKeyManager::importPublicKeyDER(const std::vector<uint8_t>& der) {
    try {
        StringSource ss(
            reinterpret_cast<const byte*>(der.data()),
            der.size(),
            true
        );

        m_publicKey.Load(ss);
        m_hasPublicKey = true;

    } catch (const CryptoPP::Exception& e) {
        throw RSAException(
            "Failed to import public DER key: " + std::string(e.what())
        );
    }
}

void RSAKeyManager::importPrivateKeyDER(const std::vector<uint8_t>& der) {
    try {
        StringSource ss(
            reinterpret_cast<const byte*>(der.data()),
            der.size(),
            true
        );

        m_privateKey.Load(ss);
        m_hasPrivateKey = true;

        m_publicKey = RSA::PublicKey(m_privateKey);
        m_hasPublicKey = true;

    } catch (const CryptoPP::Exception& e) {
        throw RSAException(
            "Failed to import private DER key: " + std::string(e.what())
        );
    }
}

void RSAKeyManager::importPublicKeyPEM(const std::string& pem) {
    std::string der = pemToDer(pem);
    std::vector<uint8_t> der_vec(der.begin(), der.end());
    importPublicKeyDER(der_vec);
}

void RSAKeyManager::importPrivateKeyPEM(const std::string& pem) {
    std::string der = pemToDer(pem);
    std::vector<uint8_t> der_vec(der.begin(), der.end());
    importPrivateKeyDER(der_vec);
}

// =========================
// Base64 helpers
// =========================

std::string RSAKeyManager::base64Encode(const std::vector<uint8_t>& data) {
    std::string encoded;

    StringSource ss(
        reinterpret_cast<const byte*>(data.data()),
        data.size(),
        true,
        new Base64Encoder(
            new StringSink(encoded),
            false
        )
    );

    return encoded;
}

std::vector<uint8_t> RSAKeyManager::base64Decode(const std::string& base64) {
    std::string decoded;

    StringSource ss(
        base64,
        true,
        new Base64Decoder(
            new StringSink(decoded)
        )
    );

    return std::vector<uint8_t>(decoded.begin(), decoded.end());
}

void RSAKeyManager::createPEMHeader(const std::string& type, std::string& output) {
    output += "-----BEGIN " + type + "-----\n";
}

