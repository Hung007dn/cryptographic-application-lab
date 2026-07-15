#pragma once

#include <string>
#include <vector>
#include <cstdint>

struct CertificateInfo {
    std::string subject;
    std::string issuer;
    std::string serial_number;
    std::string version;
    std::string not_before;
    std::string not_after;

    bool is_currently_valid = false;

    std::string signature_algorithm;
    std::string public_key_algorithm;
    std::string public_key_params;

    std::vector<std::string> key_usage;
    std::vector<std::string> subject_alt_names;

    std::string sha1_fingerprint;
    std::string sha256_fingerprint;

    bool signature_valid = false;
    bool tbs_integrity_valid = false;

    std::string validation_error;
};

class CertificateAnalyzer {
public:
    CertificateAnalyzer();
    ~CertificateAnalyzer();

    bool loadCertificate(const std::string& filename);
    CertificateInfo parseCertificate();

    bool verifySignature(const std::string& issuer_cert_file);
    bool verifyTBSIntegrity();

    void printCertificateInfo(const CertificateInfo& info) const;
    std::string toJSON(const CertificateInfo& info) const;
    bool saveReport(const std::string& output_file);

private:
    std::vector<uint8_t> m_cert_data;
    std::string m_cert_format;

    std::string bytesToHex(const unsigned char* data, size_t len, bool colon = false) const;
    std::string nameToString(const void* x509_name) const;
    std::string asn1TimeToString(const void* asn1_time) const;
    std::string getAlgorithmName(int nid) const;
};