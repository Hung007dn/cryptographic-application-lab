#include "CertificateAnalyzer.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iterator>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

CertificateAnalyzer::CertificateAnalyzer() = default;
CertificateAnalyzer::~CertificateAnalyzer() = default;

bool CertificateAnalyzer::loadCertificate(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Cannot open certificate file: " << filename << std::endl;
        return false;
    }

    m_cert_data.assign(std::istreambuf_iterator<char>(file),
                       std::istreambuf_iterator<char>());

    std::string content(m_cert_data.begin(), m_cert_data.end());
    m_cert_format = content.find("-----BEGIN") != std::string::npos ? "PEM" : "DER";

    return !m_cert_data.empty();
}

std::string CertificateAnalyzer::bytesToHex(const unsigned char* data, size_t len, bool colon) const {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        if (colon && i > 0) oss << ":";
        oss << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::string CertificateAnalyzer::nameToString(const void* namePtr) const {
    const X509_NAME* name = static_cast<const X509_NAME*>(namePtr);
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";

    X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);

    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);

    std::string result;
    if (data && len > 0) {
        result.assign(data, static_cast<size_t>(len));
    }

    BIO_free(bio);
    return result;
}

std::string CertificateAnalyzer::asn1TimeToString(const void* timePtr) const {
    const ASN1_TIME* time = static_cast<const ASN1_TIME*>(timePtr);
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";

    ASN1_TIME_print(bio, time);

    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);

    std::string result;
    if (data && len > 0) {
        result.assign(data, static_cast<size_t>(len));
    }

    BIO_free(bio);
    return result;
}

std::string CertificateAnalyzer::getAlgorithmName(int nid) const {
    const char* shortName = OBJ_nid2sn(nid);
    if (shortName) return std::string(shortName);

    const char* longName = OBJ_nid2ln(nid);
    if (longName) return std::string(longName);

    return "Unknown";
}

static X509* loadX509FromMemory(const std::vector<uint8_t>& data, const std::string& format) {
    BIO* bio = BIO_new_mem_buf(data.data(), static_cast<int>(data.size()));
    if (!bio) return nullptr;

    X509* cert = nullptr;

    if (format == "PEM") {
        cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    } else {
        cert = d2i_X509_bio(bio, nullptr);
    }

    BIO_free(bio);
    return cert;
}
static bool checkCertificateTimeValidity(X509* cert) {
    if (!cert) {
        return false;
    }

    int days = 0;
    int seconds = 0;

    const ASN1_TIME* notBefore = X509_get0_notBefore(cert);
    const ASN1_TIME* notAfter = X509_get0_notAfter(cert);

    if (!notBefore || !notAfter) {
        return false;
    }

    // notBefore must be <= current time.
    if (ASN1_TIME_diff(&days, &seconds, notBefore, nullptr) != 1) {
        return false;
    }

    if (days < 0 || seconds < 0) {
        return false;
    }

    // current time must be <= notAfter.
    if (ASN1_TIME_diff(&days, &seconds, nullptr, notAfter) != 1) {
        return false;
    }

    if (days < 0 || seconds < 0) {
        return false;
    }

    return true;
}
static X509* loadX509FromFile(const std::string& file) {
    std::ifstream in(file, std::ios::binary);
    if (!in.is_open()) return nullptr;

    std::vector<uint8_t> data{
        std::istreambuf_iterator<char>(in),
        std::istreambuf_iterator<char>()
    };

    std::string content(data.begin(), data.end());
    std::string format = content.find("-----BEGIN") != std::string::npos ? "PEM" : "DER";

    return loadX509FromMemory(data, format);
}

CertificateInfo CertificateAnalyzer::parseCertificate() {
    CertificateInfo info;

    X509* cert = loadX509FromMemory(m_cert_data, m_cert_format);
    if (!cert) {
        info.validation_error = "Failed to parse certificate";
        return info;
    }

    info.subject = nameToString(X509_get_subject_name(cert));
    info.issuer = nameToString(X509_get_issuer_name(cert));

    ASN1_INTEGER* serial = X509_get_serialNumber(cert);
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
    char* serialHex = BN_bn2hex(bn);

    if (serialHex) {
        info.serial_number = serialHex;
        OPENSSL_free(serialHex);
    }

    if (bn) BN_free(bn);

    info.version = std::to_string(X509_get_version(cert) + 1);

    const ASN1_TIME* notBefore = X509_get0_notBefore(cert);
    const ASN1_TIME* notAfter = X509_get0_notAfter(cert);

    info.not_before = asn1TimeToString(notBefore);
    info.not_after = asn1TimeToString(notAfter);

    info.is_currently_valid = checkCertificateTimeValidity(cert);

    info.signature_algorithm = getAlgorithmName(X509_get_signature_nid(cert));

    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (pkey) {
        int keyType = EVP_PKEY_base_id(pkey);
        info.public_key_algorithm = getAlgorithmName(keyType);

        if (keyType == EVP_PKEY_RSA) {
            info.public_key_params = "RSA";
        } else if (keyType == EVP_PKEY_EC) {
            info.public_key_params = "EC / ECDSA capable";
        } else {
            info.public_key_params = "Unknown or unsupported parameters";
        }

        EVP_PKEY_free(pkey);
    }

    ASN1_BIT_STRING* keyUsage =
        static_cast<ASN1_BIT_STRING*>(X509_get_ext_d2i(cert, NID_key_usage, nullptr, nullptr));

    if (keyUsage) {
        struct Usage {
            int bit;
            const char* name;
        };

        Usage usages[] = {
            {0, "Digital Signature"},
            {1, "Non-Repudiation"},
            {2, "Key Encipherment"},
            {3, "Data Encipherment"},
            {4, "Key Agreement"},
            {5, "Key Certificate Sign"},
            {6, "CRL Sign"},
            {7, "Encipher Only"},
            {8, "Decipher Only"}
        };

        for (const auto& u : usages) {
            if (ASN1_BIT_STRING_get_bit(keyUsage, u.bit)) {
                info.key_usage.push_back(u.name);
            }
        }

        ASN1_BIT_STRING_free(keyUsage);
    }

    GENERAL_NAMES* sans =
        static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));

    if (sans) {
        int count = sk_GENERAL_NAME_num(sans);

        for (int i = 0; i < count; ++i) {
            const GENERAL_NAME* san = sk_GENERAL_NAME_value(sans, i);

            if (san->type == GEN_DNS) {
                const ASN1_STRING* str = san->d.dNSName;
                const unsigned char* data = ASN1_STRING_get0_data(str);
                int len = ASN1_STRING_length(str);
                info.subject_alt_names.emplace_back(
                    reinterpret_cast<const char*>(data),
                    static_cast<size_t>(len)
                );
            } else if (san->type == GEN_URI) {
                const ASN1_STRING* str = san->d.uniformResourceIdentifier;
                const unsigned char* data = ASN1_STRING_get0_data(str);
                int len = ASN1_STRING_length(str);
                info.subject_alt_names.emplace_back(
                    std::string(reinterpret_cast<const char*>(data), static_cast<size_t>(len)) + " (URI)"
                );
            } else if (san->type == GEN_IPADD) {
                const ASN1_OCTET_STRING* ip = san->d.iPAddress;
                info.subject_alt_names.push_back("IP address (" + std::to_string(ASN1_STRING_length(ip)) + " bytes)");
            }
        }

        GENERAL_NAMES_free(sans);
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;

    if (X509_digest(cert, EVP_sha1(), digest, &digestLen) == 1) {
        info.sha1_fingerprint = bytesToHex(digest, digestLen, true);
    }

    if (X509_digest(cert, EVP_sha256(), digest, &digestLen) == 1) {
        info.sha256_fingerprint = bytesToHex(digest, digestLen, true);
    }

    info.tbs_integrity_valid = verifyTBSIntegrity();

    X509_free(cert);
    return info;
}

bool CertificateAnalyzer::verifySignature(const std::string& issuer_cert_file) {
    X509* cert = loadX509FromMemory(m_cert_data, m_cert_format);
    X509* issuer = loadX509FromFile(issuer_cert_file);

    if (!cert || !issuer) {
        if (cert) X509_free(cert);
        if (issuer) X509_free(issuer);
        return false;
    }

    EVP_PKEY* issuerKey = X509_get_pubkey(issuer);
    if (!issuerKey) {
        X509_free(cert);
        X509_free(issuer);
        return false;
    }

    int ok = X509_verify(cert, issuerKey);

    EVP_PKEY_free(issuerKey);
    X509_free(cert);
    X509_free(issuer);

    return ok == 1;
}

bool CertificateAnalyzer::verifyTBSIntegrity() {
    X509* cert = loadX509FromMemory(m_cert_data, m_cert_format);
    if (!cert) return false;

    unsigned char* tbs = nullptr;
    int tbsLen = i2d_re_X509_tbs(cert, &tbs);

    bool ok = tbsLen > 0 && X509_get_signature_nid(cert) != NID_undef;

    if (tbs) OPENSSL_free(tbs);
    X509_free(cert);

    return ok;
}

void CertificateAnalyzer::printCertificateInfo(const CertificateInfo& info) const {
    std::cout << "\n=== X.509 Certificate Analysis ===\n";
    std::cout << "Subject: " << info.subject << "\n";
    std::cout << "Issuer: " << info.issuer << "\n";
    std::cout << "Serial Number: " << info.serial_number << "\n";
    std::cout << "Version: " << info.version << "\n";
    std::cout << "Not Before: " << info.not_before << "\n";
    std::cout << "Not After: " << info.not_after << "\n";
    std::cout << "Currently Valid: " << (info.is_currently_valid ? "yes" : "no") << "\n";
    std::cout << "Signature Algorithm: " << info.signature_algorithm << "\n";
    std::cout << "Public Key Algorithm: " << info.public_key_algorithm << "\n";
    std::cout << "Public Key Parameters: " << info.public_key_params << "\n";

    std::cout << "Key Usage: ";
    if (info.key_usage.empty()) {
        std::cout << "(none)";
    } else {
        for (size_t i = 0; i < info.key_usage.size(); ++i) {
            if (i) std::cout << ", ";
            std::cout << info.key_usage[i];
        }
    }
    std::cout << "\n";

    std::cout << "Subject Alternative Names: ";
    if (info.subject_alt_names.empty()) {
        std::cout << "(none)";
    } else {
        for (size_t i = 0; i < info.subject_alt_names.size(); ++i) {
            if (i) std::cout << ", ";
            std::cout << info.subject_alt_names[i];
        }
    }
    std::cout << "\n";

    std::cout << "SHA1 Fingerprint: " << info.sha1_fingerprint << "\n";
    std::cout << "SHA256 Fingerprint: " << info.sha256_fingerprint << "\n";
    std::cout << "Signature Valid / TBS Valid: "
              << (info.signature_valid ? "signature valid" :
                  info.tbs_integrity_valid ? "TBS structure valid" : "not verified")
              << "\n";

    if (!info.validation_error.empty()) {
        std::cout << "Validation Error: " << info.validation_error << "\n";
    }
}

std::string CertificateAnalyzer::toJSON(const CertificateInfo& info) const {
    json j;

    j["subject"] = info.subject;
    j["issuer"] = info.issuer;
    j["serial_number"] = info.serial_number;
    j["version"] = info.version;
    j["not_before"] = info.not_before;
    j["not_after"] = info.not_after;
    j["is_currently_valid"] = info.is_currently_valid;
    j["signature_algorithm"] = info.signature_algorithm;
    j["public_key_algorithm"] = info.public_key_algorithm;
    j["public_key_params"] = info.public_key_params;
    j["key_usage"] = info.key_usage;
    j["subject_alt_names"] = info.subject_alt_names;
    j["sha1_fingerprint"] = info.sha1_fingerprint;
    j["sha256_fingerprint"] = info.sha256_fingerprint;
    j["signature_valid"] = info.signature_valid;
    j["tbs_integrity_valid"] = info.tbs_integrity_valid;
    j["validation_error"] = info.validation_error;

    return j.dump(4);
}

bool CertificateAnalyzer::saveReport(const std::string& output_file) {
    CertificateInfo info = parseCertificate();

    std::ofstream out(output_file);
    if (!out.is_open()) {
        return false;
    }

    out << toJSON(info);
    return true;
}