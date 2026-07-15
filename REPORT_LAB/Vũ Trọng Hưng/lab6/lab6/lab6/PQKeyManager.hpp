// PQKeyManager.hpp
#pragma once

#include "PQConfig.hpp"

#include <oqs/oqs.h>

#include <cstdint>
#include <string>
#include <vector>

class PQKeyManager {
public:
    PQKeyManager();
    ~PQKeyManager();

    // Key generation
    void generateKeyPair(PQAlgorithm algo);
    void saveKeyPair(const std::string& pub_file, const std::string& priv_file);
    void saveMetadata(const std::string& metadata_file);

    // Key loading
    void loadPublicKey(const std::string& pub_file);
    void loadPrivateKey(const std::string& priv_file);

    // Getters
    const std::vector<uint8_t>& getPublicKey() const { return m_publicKey; }
    const std::vector<uint8_t>& getPrivateKey() const { return m_privateKey; }
    bool hasPublicKey() const { return !m_publicKey.empty(); }
    bool hasPrivateKey() const { return !m_privateKey.empty(); }
    PQAlgorithm getAlgorithm() const { return m_algorithm; }

    // Export formats.
    // DER here means raw binary key bytes used by liboqs.
    // PEM here is a simple lab-specific base64 wrapper, not an X.509/OpenSSL PEM object.
    std::string exportPublicKeyPEM() const;
    std::string exportPrivateKeyPEM() const;
    std::vector<uint8_t> exportPublicKeyDER() const;
    std::vector<uint8_t> exportPrivateKeyDER() const;

private:
    std::vector<uint8_t> m_publicKey;
    std::vector<uint8_t> m_privateKey;
    PQAlgorithm m_algorithm;
    OQS_SIG* m_sig;
    OQS_KEM* m_kem;

    static std::string base64Encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64Decode(const std::string& base64);

    void cleanup();
};
