// PQCertificate.hpp
#pragma once
#include "PQConfig.hpp"
#include "PQKeyManager.hpp"
#include "MLDSAEngine.hpp"
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

struct PQCertificate {
    std::string subject;
    std::vector<uint8_t> publicKey;
    std::string issuer;
    std::vector<uint8_t> signature;
    PQAlgorithm algorithm;
    
    std::string toJSON() const;
    static PQCertificate fromJSON(const std::string& jsonStr);
};

class PQCertificateManager {
public:
    PQCertificateManager();
    ~PQCertificateManager();
    
    // Generate CA certificate
    void generateCA(const std::string& subject, PQAlgorithm algo);
    
    // Issue certificate for subject
    PQCertificate issueCertificate(const std::string& subject,
                                    const std::vector<uint8_t>& subjectPublicKey,
                                    PQAlgorithm algo);
    
    // Verify certificate
    bool verifyCertificate(const PQCertificate& cert);
    
    // Detect tampering
    bool detectTampering(const PQCertificate& cert, const std::vector<uint8_t>& originalData);
    
    // Save/Load
    void saveCertificate(const PQCertificate& cert, const std::string& filename);
    PQCertificate loadCertificate(const std::string& filename);
    
    // Getters
    const PQKeyManager& getCAKeyManager() const { return m_caKeyManager; }
    
private:
    PQKeyManager m_caKeyManager;
    PQAlgorithm m_algorithm;
    MLDSAEngine m_engine;
    
    json toJSON(const PQCertificate& cert);
};