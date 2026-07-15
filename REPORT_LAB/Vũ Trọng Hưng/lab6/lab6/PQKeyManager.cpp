#include "PQKeyManager.hpp"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <fstream>
#include <stdexcept>
#include <sstream>
#include <iostream>
#include <vector>
#include <cstring>

// ── helpers ──────────────────────────────────────────────────────────────────
static std::string opensslErrors() {
    std::string out;
    unsigned long e;
    char buf[256];
    while ((e = ERR_get_error())) {
        ERR_error_string_n(e, buf, sizeof(buf));
        out += std::string(buf) + "\n";
    }
    return out;
}

static std::string base64Encode(const std::vector<unsigned char>& data) {
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

static std::vector<unsigned char> base64Decode(const std::string& in) {
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
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) { out.push_back((val >> valb) & 0xFF); valb -= 8; }
    }
    return out;
}

// ── public API ────────────────────────────────────────────────────────────────
void PQKeyManager::saveRawPEM(const std::string& path, const std::string& label,
                               const std::vector<unsigned char>& data) {
    std::ofstream f(path);
    if (!f) throw std::runtime_error("Cannot open for writing: " + path);
    f << "-----BEGIN " << label << "-----\n";
    std::string b64 = base64Encode(data);
    for (size_t i = 0; i < b64.size(); i += 64)
        f << b64.substr(i, 64) << "\n";
    f << "-----END " << label << "-----\n";
}

std::vector<unsigned char> PQKeyManager::loadRawPEM(const std::string& path, const std::string& label) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("Cannot open file: " + path);
    std::string b64, line;
    bool inside = false;
    while (std::getline(f, line)) {
        if (line.find("-----BEGIN") != std::string::npos) { inside = true; continue; }
        if (line.find("-----END")   != std::string::npos) break;
        if (inside) {
            // strip \r
            while (!line.empty() && (line.back()=='\r'||line.back()=='\n')) line.pop_back();
            b64 += line;
        }
    }
    return base64Decode(b64);
}

void PQKeyManager::keygenToFiles(const std::string& algoName,
                                  const std::string& pubPath,
                                  const std::string& privPath) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, algoName.c_str(), nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_from_name failed: " + opensslErrors());

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen_init failed: " + opensslErrors());
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen failed: " + opensslErrors());
    }
    EVP_PKEY_CTX_free(ctx);

    // Write public key PEM
    {
        FILE* fp = fopen(pubPath.c_str(), "wb");
        if (!fp || PEM_write_PUBKEY(fp, pkey) != 1) {
            if (fp) fclose(fp);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to write public key PEM: " + pubPath);
        }
        fclose(fp);
    }

    // Write private key PEM
    {
        FILE* fp = fopen(privPath.c_str(), "wb");
        if (!fp || PEM_write_PrivateKey(fp, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            if (fp) fclose(fp);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to write private key PEM: " + privPath);
        }
        fclose(fp);
    }

    EVP_PKEY_free(pkey);
    std::cout << "[INFO] " << algoName << " key pair generated.\n";
    std::cout << "[INFO] Public  key -> " << pubPath  << "\n";
    std::cout << "[INFO] Private key -> " << privPath << "\n";
}

void PQKeyManager::mldsaKeygen(MLDSALevel level, const std::string& pub, const std::string& priv) {
    keygenToFiles(PQConfig::mldsaName(level), pub, priv);
}

void PQKeyManager::mlkemKeygen(MLKEMLevel level, const std::string& pub, const std::string& priv) {
    keygenToFiles(PQConfig::mlkemName(level), pub, priv);
}
