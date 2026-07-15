// PQCertificate.cpp
#include "PQCertificate.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>

namespace {

static const char* B64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64Encode(const std::vector<uint8_t>& data) {
    std::string out;
    int val = 0;
    int valb = -6;

    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;

        while (valb >= 0) {
            out.push_back(B64[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }

    if (valb > -6) {
        out.push_back(B64[((val << 8) >> (valb + 8)) & 0x3F]);
    }

    while (out.size() % 4) {
        out.push_back('=');
    }

    return out;
}

std::vector<uint8_t> base64Decode(const std::string& input) {
    std::vector<int> table(256, -1);

    for (int i = 0; i < 64; ++i) {
        table[static_cast<unsigned char>(B64[i])] = i;
    }

    std::vector<uint8_t> out;
    int val = 0;
    int valb = -8;

    for (unsigned char c : input) {
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

std::string canonicalCertificateData(
    const std::string& subject,
    const std::vector<uint8_t>& publicKey,
    const std::string& issuer,
    PQAlgorithm algorithm
) {
    json data;
    data["subject"] = subject;
    data["public_key"] = base64Encode(publicKey);
    data["issuer"] = issuer;
    data["algorithm"] = PQConfig::algorithmToString(algorithm);

    return data.dump();
}

std::vector<uint8_t> toBytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

} // namespace

std::string PQCertificate::toJSON() const {
    json j;
    j["subject"] = subject;
    j["public_key"] = base64Encode(publicKey);
    j["issuer"] = issuer;
    j["algorithm"] = PQConfig::algorithmToString(algorithm);
    j["signature"] = base64Encode(signature);

    return j.dump(4);
}

PQCertificate PQCertificate::fromJSON(const std::string& jsonStr) {
    json j = json::parse(jsonStr);

    PQCertificate cert;
    cert.subject = j.at("subject").get<std::string>();
    cert.publicKey = base64Decode(j.at("public_key").get<std::string>());
    cert.issuer = j.at("issuer").get<std::string>();
    cert.algorithm = PQConfig::stringToAlgorithm(j.at("algorithm").get<std::string>());
    cert.signature = base64Decode(j.at("signature").get<std::string>());

    return cert;
}

PQCertificateManager::PQCertificateManager()
    : m_algorithm(PQAlgorithm::MLDSA_44)
{}

PQCertificateManager::~PQCertificateManager() = default;

void PQCertificateManager::generateCA(const std::string& subject, PQAlgorithm algo) {
    (void)subject;

    if (!(algo == PQAlgorithm::MLDSA_44 ||
          algo == PQAlgorithm::MLDSA_65 ||
          algo == PQAlgorithm::MLDSA_87)) {
        throw PQException("CA certificate signing requires an ML-DSA algorithm");
    }

    m_algorithm = algo;
    m_caKeyManager.generateKeyPair(algo);
}

PQCertificate PQCertificateManager::issueCertificate(
    const std::string& subject,
    const std::vector<uint8_t>& subjectPublicKey,
    PQAlgorithm algo
) {
    if (!m_caKeyManager.hasPrivateKey()) {
        throw PQException("CA private key is not available");
    }

    if (!(algo == PQAlgorithm::MLDSA_44 ||
          algo == PQAlgorithm::MLDSA_65 ||
          algo == PQAlgorithm::MLDSA_87)) {
        throw PQException("Certificate signing requires an ML-DSA algorithm");
    }

    PQCertificate cert;
    cert.subject = subject;
    cert.publicKey = subjectPublicKey;
    cert.issuer = "PQ-CA";
    cert.algorithm = algo;

    std::string data = canonicalCertificateData(
        cert.subject,
        cert.publicKey,
        cert.issuer,
        cert.algorithm
    );

    cert.signature = m_engine.sign(
        toBytes(data),
        m_caKeyManager.getPrivateKey(),
        algo
    );

    return cert;
}

bool PQCertificateManager::verifyCertificate(const PQCertificate& cert) {
    if (!m_caKeyManager.hasPublicKey()) {
        throw PQException("CA public key is not available");
    }

    std::string data = canonicalCertificateData(
        cert.subject,
        cert.publicKey,
        cert.issuer,
        cert.algorithm
    );

    return m_engine.verify(
        toBytes(data),
        cert.signature,
        m_caKeyManager.getPublicKey(),
        cert.algorithm
    );
}

bool PQCertificateManager::detectTampering(
    const PQCertificate& cert,
    const std::vector<uint8_t>& originalData
) {
    std::string current = canonicalCertificateData(
        cert.subject,
        cert.publicKey,
        cert.issuer,
        cert.algorithm
    );

    std::vector<uint8_t> currentBytes(current.begin(), current.end());

    if (!originalData.empty() && currentBytes != originalData) {
        return true;
    }

    return !verifyCertificate(cert);
}

void PQCertificateManager::saveCertificate(
    const PQCertificate& cert,
    const std::string& filename
) {
    std::ofstream file(filename);

    if (!file.is_open()) {
        throw PQException("Cannot open certificate output file: " + filename);
    }

    file << cert.toJSON();
}

PQCertificate PQCertificateManager::loadCertificate(const std::string& filename) {
    std::ifstream file(filename);

    if (!file.is_open()) {
        throw PQException("Cannot open certificate file: " + filename);
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    return PQCertificate::fromJSON(buffer.str());
}

json PQCertificateManager::toJSON(const PQCertificate& cert) {
    return json::parse(cert.toJSON());
}
