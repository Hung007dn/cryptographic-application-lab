#include "PQCertificate.hpp"
#include "MLDSAEngine.hpp"
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <iomanip>
#include <chrono>
#include <ctime>

using json = nlohmann::json;

// ── helpers ───────────────────────────────────────────────────────────────────
static std::string base64Enc(const std::vector<unsigned char>& data) {
    static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) { out.push_back(t[(val >> valb) & 0x3F]); valb -= 6; }
    }
    if (valb > -6) out.push_back(t[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

static std::vector<unsigned char> base64Dec(const std::string& in) {
    static const int T[256] = {
        [0 ... 255] = -1,
        ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
        ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
        ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
        ['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
        ['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
        ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,
        ['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,
        ['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63
    };
    std::vector<unsigned char> out;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[(unsigned char)c] == -1) break;
        val = (val << 6) + T[(unsigned char)c];
        valb += 6;
        if (valb >= 0) { out.push_back((val >> valb) & 0xFF); valb -= 8; }
    }
    return out;
}

static std::string readPEMasString(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("Cannot open file: " + path);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string currentTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
    return std::string(buf);
}

// ── API ───────────────────────────────────────────────────────────────────────
void PQCertificate::generate(
    const std::string& caPrivPath,
    const std::string& caPubPath,
    const std::string& subjectName,
    const std::string& subjectPubPath,
    const std::string& outCertPath)
{
    // Read subject public key (raw PEM string as the "public_key" field)
    std::string subjectPubPEM = readPEMasString(subjectPubPath);

    // Build the JSON payload we will sign
    json payload;
    payload["subject"]     = subjectName;
    payload["public_key"]  = subjectPubPEM;
    payload["issuer"]      = "PQ-CA";
    payload["issued_at"]   = currentTimestamp();
    payload["algorithm"]   = "ML-DSA-44";

    std::string payloadStr = payload.dump();
    std::vector<unsigned char> msgBytes(payloadStr.begin(), payloadStr.end());

    // Sign payload with CA private key (ML-DSA-44)
    std::vector<unsigned char> sig = MLDSAEngine::sign(MLDSALevel::MLDSA44, caPrivPath, msgBytes);

    // Build final certificate JSON
    json cert = payload;
    cert["ca_public_key"] = readPEMasString(caPubPath);
    cert["signature"]     = base64Enc(sig);

    // Write certificate
    std::ofstream f(outCertPath);
    if (!f) throw std::runtime_error("Cannot write certificate: " + outCertPath);
    f << cert.dump(2) << "\n";

    std::cout << "[INFO] Certificate generated -> " << outCertPath << "\n";
}

bool PQCertificate::verify(const std::string& certPath, const std::string& caPubPath) {
    std::ifstream f(certPath);
    if (!f) throw std::runtime_error("Cannot open certificate: " + certPath);
    json cert;
    f >> cert;

    // Rebuild the signed payload (exclude signature and ca_public_key fields)
    json payload;
    payload["subject"]    = cert.at("subject");
    payload["public_key"] = cert.at("public_key");
    payload["issuer"]     = cert.at("issuer");
    payload["issued_at"]  = cert.at("issued_at");
    payload["algorithm"]  = cert.at("algorithm");

    std::string payloadStr = payload.dump();
    std::vector<unsigned char> msgBytes(payloadStr.begin(), payloadStr.end());

    std::vector<unsigned char> sig = base64Dec(cert.at("signature").get<std::string>());

    bool ok = MLDSAEngine::verify(MLDSALevel::MLDSA44, caPubPath, msgBytes, sig);
    return ok;
}

void PQCertificate::show(const std::string& certPath) {
    std::ifstream f(certPath);
    if (!f) throw std::runtime_error("Cannot open certificate: " + certPath);
    json cert;
    f >> cert;

    std::cout << "\n========== PQ Certificate ==========\n";
    std::cout << "Subject   : " << cert.value("subject",   "N/A") << "\n";
    std::cout << "Issuer    : " << cert.value("issuer",    "N/A") << "\n";
    std::cout << "Algorithm : " << cert.value("algorithm", "N/A") << "\n";
    std::cout << "Issued at : " << cert.value("issued_at", "N/A") << "\n";
    std::string sig = cert.value("signature", "");
    std::cout << "Signature : " << sig.substr(0, 48) << "...\n";
    std::cout << "=====================================\n";
}
