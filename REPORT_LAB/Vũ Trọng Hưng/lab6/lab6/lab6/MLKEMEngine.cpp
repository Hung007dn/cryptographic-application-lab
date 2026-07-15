// MLKEMEngine.cpp
#include "MLKEMEngine.hpp"

#include <iostream>

MLKEMEngine::MLKEMEngine() : m_kem(nullptr) {
    OQS_init();
}

MLKEMEngine::~MLKEMEngine() {
    cleanup();
    OQS_destroy();
}

void MLKEMEngine::cleanup() {
    if (m_kem) {
        OQS_KEM_free(m_kem);
        m_kem = nullptr;
    }
}

OQS_KEM* MLKEMEngine::getContext(PQAlgorithm algo) {
    cleanup();

    std::string name;

    switch (algo) {
        case PQAlgorithm::MLKEM_512: name = "ML-KEM-512"; break;
        case PQAlgorithm::MLKEM_768: name = "ML-KEM-768"; break;
        case PQAlgorithm::MLKEM_1024: name = "ML-KEM-1024"; break;
        default: throw PQException("Not a KEM algorithm");
    }

    m_kem = OQS_KEM_new(name.c_str());

    if (!m_kem) {
        throw PQException("Failed to create " + name + " context");
    }

    return m_kem;
}

KEMResult MLKEMEngine::encapsulate(
    const std::vector<uint8_t>& publicKey,
    PQAlgorithm algo
) {
    auto kem = getContext(algo);

    if (publicKey.size() != kem->length_public_key) {
        throw PQException("Invalid ML-KEM public key size");
    }

    KEMResult result;
    result.ciphertext.resize(kem->length_ciphertext);
    result.sharedSecret.resize(kem->length_shared_secret);

    OQS_STATUS status = OQS_KEM_encaps(
        kem,
        result.ciphertext.data(),
        result.sharedSecret.data(),
        publicKey.data()
    );

    if (status != OQS_SUCCESS) {
        throw PQException("ML-KEM encapsulation failed");
    }

    return result;
}

std::vector<uint8_t> MLKEMEngine::decapsulate(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& privateKey,
    PQAlgorithm algo
) {
    auto kem = getContext(algo);

    if (ciphertext.size() != kem->length_ciphertext) {
        throw PQException("Invalid ML-KEM ciphertext size");
    }

    if (privateKey.size() != kem->length_secret_key) {
        throw PQException("Invalid ML-KEM private key size");
    }

    std::vector<uint8_t> sharedSecret(kem->length_shared_secret);

    OQS_STATUS status = OQS_KEM_decaps(
        kem,
        sharedSecret.data(),
        ciphertext.data(),
        privateKey.data()
    );

    if (status != OQS_SUCCESS) {
        throw PQException("ML-KEM decapsulation failed");
    }

    return sharedSecret;
}
