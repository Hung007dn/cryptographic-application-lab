// PQKeyManager.cpp
#include "PQKeyManager.hpp"

#include <algorithm>
#include <ctime>
#include <fstream>
#include <iostream>
#include <iterator>
#include <nlohmann/json.hpp>
#include <sstream>

using json = nlohmann::json;

namespace {

bool isMLDSA(PQAlgorithm algo) {
    return algo == PQAlgorithm::MLDSA_44 ||
           algo == PQAlgorithm::MLDSA_65 ||
           algo == PQAlgorithm::MLDSA_87;
}

bool isMLKEM(PQAlgorithm algo) {
    return algo == PQAlgorithm::MLKEM_512 ||
           algo == PQAlgorithm::MLKEM_768 ||
           algo == PQAlgorithm::MLKEM_1024;
}

std::string sigNameFromAlgorithm(PQAlgorithm algo) {
    switch (algo) {
        case PQAlgorithm::MLDSA_44: return "ML-DSA-44";
        case PQAlgorithm::MLDSA_65: return "ML-DSA-65";
        case PQAlgorithm::MLDSA_87: return "ML-DSA-87";
        default: throw PQException("Not an ML-DSA algorithm");
    }
}

std::string kemNameFromAlgorithm(PQAlgorithm algo) {
    switch (algo) {
        case PQAlgorithm::MLKEM_512: return "ML-KEM-512";
        case PQAlgorithm::MLKEM_768: return "ML-KEM-768";
        case PQAlgorithm::MLKEM_1024: return "ML-KEM-1024";
        default: throw PQException("Not an ML-KEM algorithm");
    }
}

void writeBinaryFile(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary);

    if (!file.is_open()) {
        throw PQException("Cannot open output file: " + filename);
    }

    file.write(
        reinterpret_cast<const char*>(data.data()),
        static_cast<std::streamsize>(data.size())
    );

    if (!file.good()) {
        throw PQException("Failed to write file: " + filename);
    }
}

std::vector<uint8_t> readBinaryFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);

    if (!file.is_open()) {
        throw PQException("Cannot open input file: " + filename);
    }

    return std::vector<uint8_t>(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

} // namespace

PQKeyManager::PQKeyManager()
    : m_algorithm(PQAlgorithm::MLDSA_44),
      m_sig(nullptr),
      m_kem(nullptr)
{
    OQS_init();
}

PQKeyManager::~PQKeyManager() {
    cleanup();
    OQS_destroy();
}

void PQKeyManager::cleanup() {
    if (m_sig) {
        OQS_SIG_free(m_sig);
        m_sig = nullptr;
    }

    if (m_kem) {
        OQS_KEM_free(m_kem);
        m_kem = nullptr;
    }
}

std::string PQKeyManager::base64Encode(const std::vector<uint8_t>& data) {
    static const char* alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    int val = 0;
    int valb = -6;

    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;

        while (valb >= 0) {
            out.push_back(alphabet[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }

    if (valb > -6) {
        out.push_back(alphabet[((val << 8) >> (valb + 8)) & 0x3F]);
    }

    while (out.size() % 4) {
        out.push_back('=');
    }

    return out;
}

std::vector<uint8_t> PQKeyManager::base64Decode(const std::string& base64) {
    static const std::string alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::vector<int> table(256, -1);

    for (int i = 0; i < 64; ++i) {
        table[static_cast<unsigned char>(alphabet[i])] = i;
    }

    std::vector<uint8_t> out;
    int val = 0;
    int valb = -8;

    for (unsigned char c : base64) {
        if (c == '=') {
            break;
        }

        if (table[c] == -1) {
            continue;
        }

        val = (val << 6) + table[c];
        valb += 6;

        if (valb >= 0) {
            out.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }

    return out;
}

void PQKeyManager::generateKeyPair(PQAlgorithm algo) {
    cleanup();

    m_algorithm = algo;
    m_publicKey.clear();
    m_privateKey.clear();

    if (isMLDSA(algo)) {
        std::string sigName = sigNameFromAlgorithm(algo);

        m_sig = OQS_SIG_new(sigName.c_str());

        if (!m_sig) {
            throw PQException("Failed to create ML-DSA context: " + sigName);
        }

        m_publicKey.resize(m_sig->length_public_key);
        m_privateKey.resize(m_sig->length_secret_key);

        OQS_STATUS status = OQS_SIG_keypair(
            m_sig,
            m_publicKey.data(),
            m_privateKey.data()
        );

        if (status != OQS_SUCCESS) {
            throw PQException("Failed to generate ML-DSA key pair");
        }

        std::cout << "[INFO] Generated " << sigName << " key pair\n";
        std::cout << "[INFO] Public key size: " << m_publicKey.size() << " bytes\n";
        std::cout << "[INFO] Private key size: " << m_privateKey.size() << " bytes\n";
        return;
    }

    if (isMLKEM(algo)) {
        std::string kemName = kemNameFromAlgorithm(algo);

        m_kem = OQS_KEM_new(kemName.c_str());

        if (!m_kem) {
            throw PQException("Failed to create ML-KEM context: " + kemName);
        }

        m_publicKey.resize(m_kem->length_public_key);
        m_privateKey.resize(m_kem->length_secret_key);

        OQS_STATUS status = OQS_KEM_keypair(
            m_kem,
            m_publicKey.data(),
            m_privateKey.data()
        );

        if (status != OQS_SUCCESS) {
            throw PQException("Failed to generate ML-KEM key pair");
        }

        std::cout << "[INFO] Generated " << kemName << " key pair\n";
        std::cout << "[INFO] Public key size: " << m_publicKey.size() << " bytes\n";
        std::cout << "[INFO] Private key size: " << m_privateKey.size() << " bytes\n";
        return;
    }

    throw PQException("Unsupported key generation algorithm");
}

void PQKeyManager::saveKeyPair(const std::string& pub_file, const std::string& priv_file) {
    if (m_publicKey.empty() || m_privateKey.empty()) {
        throw PQException("No key pair available to save");
    }

    // Save raw binary key bytes. The lab CLI may name these files .pem,
    // but the actual on-disk format is raw liboqs key material.
    writeBinaryFile(pub_file, m_publicKey);
    writeBinaryFile(priv_file, m_privateKey);

    std::cout << "[INFO] Public key saved: " << pub_file << "\n";
    std::cout << "[INFO] Private key saved: " << priv_file << "\n";
}

void PQKeyManager::saveMetadata(const std::string& metadata_file) {
    json metadata;
    metadata["algorithm"] = PQConfig::algorithmToString(m_algorithm);
    metadata["public_key_size"] = m_publicKey.size();
    metadata["private_key_size"] = m_privateKey.size();
    metadata["creation_time"] = std::time(nullptr);

    std::ofstream file(metadata_file);

    if (!file.is_open()) {
        throw PQException("Cannot open metadata output file: " + metadata_file);
    }

    file << metadata.dump(4);

    std::cout << "[INFO] Metadata saved: " << metadata_file << "\n";
}

void PQKeyManager::loadPublicKey(const std::string& pub_file) {
    m_publicKey = readBinaryFile(pub_file);

    if (m_publicKey.empty()) {
        throw PQException("Public key file is empty: " + pub_file);
    }

    std::cout << "[INFO] Public key loaded: " << m_publicKey.size() << " bytes\n";
}

void PQKeyManager::loadPrivateKey(const std::string& priv_file) {
    m_privateKey = readBinaryFile(priv_file);

    if (m_privateKey.empty()) {
        throw PQException("Private key file is empty: " + priv_file);
    }

    std::cout << "[INFO] Private key loaded: " << m_privateKey.size() << " bytes\n";
}

std::string PQKeyManager::exportPublicKeyPEM() const {
    if (m_publicKey.empty()) {
        throw PQException("No public key available");
    }

    return "-----BEGIN PQ PUBLIC KEY-----\n" +
           base64Encode(m_publicKey) +
           "\n-----END PQ PUBLIC KEY-----\n";
}

std::string PQKeyManager::exportPrivateKeyPEM() const {
    if (m_privateKey.empty()) {
        throw PQException("No private key available");
    }

    return "-----BEGIN PQ PRIVATE KEY-----\n" +
           base64Encode(m_privateKey) +
           "\n-----END PQ PRIVATE KEY-----\n";
}

std::vector<uint8_t> PQKeyManager::exportPublicKeyDER() const {
    if (m_publicKey.empty()) {
        throw PQException("No public key available");
    }

    return m_publicKey;
}

std::vector<uint8_t> PQKeyManager::exportPrivateKeyDER() const {
    if (m_privateKey.empty()) {
        throw PQException("No private key available");
    }

    return m_privateKey;
}
