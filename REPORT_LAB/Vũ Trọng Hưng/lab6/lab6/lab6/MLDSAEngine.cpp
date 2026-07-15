// MLDSAEngine.cpp
#include "MLDSAEngine.hpp"
#include <iostream>

MLDSAEngine::MLDSAEngine() : m_sig(nullptr) {
    OQS_init();
}

MLDSAEngine::~MLDSAEngine() {
    cleanup();
    OQS_destroy();
}

void MLDSAEngine::cleanup() {
    if (m_sig) {
        OQS_SIG_free(m_sig);
        m_sig = nullptr;
    }
}

OQS_SIG* MLDSAEngine::getContext(PQAlgorithm algo) {
    cleanup();
    
    std::string name;
    switch (algo) {
        case PQAlgorithm::MLDSA_44: name = "ML-DSA-44"; break;
        case PQAlgorithm::MLDSA_65: name = "ML-DSA-65"; break;
        case PQAlgorithm::MLDSA_87: name = "ML-DSA-87"; break;
        default: throw PQException("Not a signature algorithm");
    }
    
    m_sig = OQS_SIG_new(name.c_str());
    if (!m_sig) {
        throw PQException("Failed to create " + name + " context");
    }
    
    return m_sig;
}

std::vector<uint8_t> MLDSAEngine::sign(const std::vector<uint8_t>& message,
                                        const std::vector<uint8_t>& privateKey,
                                        PQAlgorithm algo) {
    auto sig = getContext(algo);
    
    size_t sigLen = sig->length_signature;
    std::vector<uint8_t> signature(sigLen);
    
    OQS_STATUS status = OQS_SIG_sign(sig, signature.data(), &sigLen,
                                      message.data(), message.size(),
                                      privateKey.data());
    
    if (status != OQS_SUCCESS) {
        throw PQException("ML-DSA signing failed");
    }
    
    signature.resize(sigLen);
    return signature;
}

bool MLDSAEngine::verify(const std::vector<uint8_t>& message,
                          const std::vector<uint8_t>& signature,
                          const std::vector<uint8_t>& publicKey,
                          PQAlgorithm algo) {
    auto sig = getContext(algo);
    
    OQS_STATUS status = OQS_SIG_verify(sig, message.data(), message.size(),
                                        signature.data(), signature.size(),
                                        publicKey.data());
    
    return status == OQS_SUCCESS;
}