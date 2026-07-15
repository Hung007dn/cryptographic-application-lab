#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <openssl/err.h>

#include "PQConfig.hpp"
#include "PQKeyManager.hpp"
#include "MLDSAEngine.hpp"
#include "MLKEMEngine.hpp"
#include "PQCertificate.hpp"
#include "PQBenchmarker.hpp"
#include "PQNegativeTests.hpp"

// ── helpers ───────────────────────────────────────────────────────────────────
static std::vector<unsigned char> readFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open: " + path);
    return {std::istreambuf_iterator<char>(f), {}};
}

static void writeFile(const std::string& path, const std::vector<unsigned char>& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot write: " + path);
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
}

static std::string toHex(const std::vector<unsigned char>& v) {
    std::ostringstream oss;
    for (auto b : v) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
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
        if (T[(unsigned char)c] == -1) break;
        val = (val << 6) + T[(unsigned char)c];
        valb += 6;
        if (valb >= 0) { out.push_back((val >> valb) & 0xFF); valb -= 8; }
    }
    return out;
}

// ── CLI argument parsing ──────────────────────────────────────────────────────
static std::string getArg(int argc, char** argv, const std::string& flag, const std::string& def = "") {
    for (int i = 1; i < argc - 1; i++)
        if (std::string(argv[i]) == flag) return argv[i+1];
    return def;
}

static bool hasFlag(int argc, char** argv, const std::string& flag) {
    for (int i = 1; i < argc; i++)
        if (std::string(argv[i]) == flag) return true;
    return false;
}

// ── usage ─────────────────────────────────────────────────────────────────────
static void printHelp() {
    std::cout << R"(
Lab 6 PQTool - Post-Quantum Signatures & Key Encapsulation

Key generation:
  pqtool keygen --algo mldsa-44   --pub pub.pem --priv priv.pem
  pqtool keygen --algo mldsa-65   --pub pub.pem --priv priv.pem
  pqtool keygen --algo mlkem-512  --pub pub.pem --priv priv.pem
  pqtool keygen --algo mlkem-768  --pub pub.pem --priv priv.pem

ML-DSA signing:
  pqtool sign   --algo mldsa-44 --in msg.bin --priv priv.pem --out sig.bin [--encode base64|hex|raw]
  pqtool verify --algo mldsa-44 --in msg.bin --sig sig.bin   --pub pub.pem [--encode base64|hex|raw]

ML-KEM encapsulation:
  pqtool encaps  --algo mlkem-512 --pub pub.pem --ct ct.bin --ss ss.bin
  pqtool decaps  --algo mlkem-512 --priv priv.pem --ct ct.bin --ss ss.bin

PQ Certificate:
  pqtool cert-gen   --ca-priv ca_priv.pem --ca-pub ca_pub.pem
                    --subject "Alice" --subject-pub alice_pub.pem
                    --out cert.json
  pqtool cert-verify --cert cert.json --ca-pub ca_pub.pem
  pqtool cert-show   --cert cert.json

Other:
  pqtool --benchmark
  pqtool --negative-tests
  pqtool --help

Algorithms:
  mldsa-44, mldsa-65, mldsa-87
  mlkem-512, mlkem-768, mlkem-1024

Encoding (sign/verify):
  raw (default), base64, hex
)";
}

// ── main ──────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    // Initialize OpenSSL error strings
    ERR_load_crypto_strings();

    if (argc < 2 || hasFlag(argc, argv, "--help") || hasFlag(argc, argv, "-h")) {
        printHelp();
        return 0;
    }

    std::string cmd = argv[1];

    try {
        // ── keygen ────────────────────────────────────────────────────────────
        if (cmd == "keygen") {
            std::string algo    = getArg(argc, argv, "--algo");
            std::string pubPath = getArg(argc, argv, "--pub",  "pub.pem");
            std::string privPath= getArg(argc, argv, "--priv", "priv.pem");

            if (algo.empty()) throw std::runtime_error("--algo required");

            // Check if mldsa or mlkem
            if (algo.find("mldsa") != std::string::npos) {
                auto level = PQConfig::parseMldsa(algo);
                PQKeyManager::mldsaKeygen(level, pubPath, privPath);
            } else if (algo.find("mlkem") != std::string::npos) {
                auto level = PQConfig::parseMlkem(algo);
                PQKeyManager::mlkemKeygen(level, pubPath, privPath);
            } else {
                throw std::runtime_error("Unknown algorithm: " + algo);
            }
        }

        // ── sign ──────────────────────────────────────────────────────────────
        else if (cmd == "sign") {
            std::string algo    = getArg(argc, argv, "--algo");
            std::string inPath  = getArg(argc, argv, "--in");
            std::string text    = getArg(argc, argv, "--text");
            std::string privPath= getArg(argc, argv, "--priv");
            std::string outPath = getArg(argc, argv, "--out", "sig.bin");
            std::string encode  = getArg(argc, argv, "--encode", "raw");

            if (algo.empty() || privPath.empty()) throw std::runtime_error("--algo and --priv required");

            std::vector<unsigned char> msg;
            if (!inPath.empty()) msg = readFile(inPath);
            else if (!text.empty()) msg = std::vector<unsigned char>(text.begin(), text.end());
            else throw std::runtime_error("--in or --text required");

            auto level = PQConfig::parseMldsa(algo);
            auto sig   = MLDSAEngine::sign(level, privPath, msg);

            if (encode == "base64") {
                std::string b64 = base64Encode(sig);
                writeFile(outPath, std::vector<unsigned char>(b64.begin(), b64.end()));
            } else if (encode == "hex") {
                std::string h = toHex(sig);
                writeFile(outPath, std::vector<unsigned char>(h.begin(), h.end()));
            } else {
                writeFile(outPath, sig);
            }

            std::cout << "[INFO] Signature written to: " << outPath << "\n";
        }

        // ── verify ────────────────────────────────────────────────────────────
        else if (cmd == "verify") {
            std::string algo    = getArg(argc, argv, "--algo");
            std::string inPath  = getArg(argc, argv, "--in");
            std::string text    = getArg(argc, argv, "--text");
            std::string sigPath = getArg(argc, argv, "--sig");
            std::string pubPath = getArg(argc, argv, "--pub");
            std::string encode  = getArg(argc, argv, "--encode", "raw");

            if (algo.empty() || sigPath.empty() || pubPath.empty())
                throw std::runtime_error("--algo, --sig, and --pub required");

            std::vector<unsigned char> msg;
            if (!inPath.empty()) msg = readFile(inPath);
            else if (!text.empty()) msg = std::vector<unsigned char>(text.begin(), text.end());
            else throw std::runtime_error("--in or --text required");

            auto rawSig = readFile(sigPath);
            std::vector<unsigned char> sig;
            if (encode == "base64") {
                std::string b64(rawSig.begin(), rawSig.end());
                sig = base64Decode(b64);
            } else {
                sig = rawSig;
            }

            auto level = PQConfig::parseMldsa(algo);
            bool ok = MLDSAEngine::verify(level, pubPath, msg, sig);
            if (ok) {
                std::cout << "[INFO] Signature is VALID!\n";
                return 0;
            } else {
                std::cout << "[ERROR] Signature is INVALID!\n";
                return 1;
            }
        }

        // ── encaps ────────────────────────────────────────────────────────────
        else if (cmd == "encaps") {
            std::string algo    = getArg(argc, argv, "--algo");
            std::string pubPath = getArg(argc, argv, "--pub");
            std::string ctPath  = getArg(argc, argv, "--ct",  "ct.bin");
            std::string ssPath  = getArg(argc, argv, "--ss",  "ss.bin");

            if (algo.empty() || pubPath.empty()) throw std::runtime_error("--algo and --pub required");
            auto level = PQConfig::parseMlkem(algo);
            auto res   = MLKEMEngine::encapsulate(level, pubPath);
            writeFile(ctPath, res.ciphertext);
            writeFile(ssPath, res.sharedSecret);
            std::cout << "[INFO] Ciphertext -> " << ctPath << "\n";
            std::cout << "[INFO] Shared secret (Alice) -> " << ssPath << "\n";
            std::cout << "[INFO] Shared secret hex: " << toHex(res.sharedSecret) << "\n";
        }

        // ── decaps ────────────────────────────────────────────────────────────
        else if (cmd == "decaps") {
            std::string algo     = getArg(argc, argv, "--algo");
            std::string privPath = getArg(argc, argv, "--priv");
            std::string ctPath   = getArg(argc, argv, "--ct",  "ct.bin");
            std::string ssPath   = getArg(argc, argv, "--ss",  "ss_bob.bin");

            if (algo.empty() || privPath.empty()) throw std::runtime_error("--algo and --priv required");
            auto level = PQConfig::parseMlkem(algo);
            auto ct = readFile(ctPath);
            auto ss = MLKEMEngine::decapsulate(level, privPath, ct);
            writeFile(ssPath, ss);
            std::cout << "[INFO] Shared secret (Bob)  -> " << ssPath << "\n";
            std::cout << "[INFO] Shared secret hex: " << toHex(ss) << "\n";
        }

        // ── cert-gen ──────────────────────────────────────────────────────────
        else if (cmd == "cert-gen") {
            std::string caPriv   = getArg(argc, argv, "--ca-priv");
            std::string caPub    = getArg(argc, argv, "--ca-pub");
            std::string subject  = getArg(argc, argv, "--subject", "Unknown");
            std::string subPub   = getArg(argc, argv, "--subject-pub");
            std::string outPath  = getArg(argc, argv, "--out", "cert.json");
            if (caPriv.empty() || caPub.empty() || subPub.empty())
                throw std::runtime_error("--ca-priv, --ca-pub, --subject-pub required");
            PQCertificate::generate(caPriv, caPub, subject, subPub, outPath);
        }

        // ── cert-verify ───────────────────────────────────────────────────────
        else if (cmd == "cert-verify") {
            std::string certPath = getArg(argc, argv, "--cert");
            std::string caPub    = getArg(argc, argv, "--ca-pub");
            if (certPath.empty() || caPub.empty())
                throw std::runtime_error("--cert and --ca-pub required");
            bool ok = PQCertificate::verify(certPath, caPub);
            if (ok) { std::cout << "[INFO] Certificate is VALID!\n"; return 0; }
            else    { std::cout << "[ERROR] Certificate is INVALID!\n"; return 1; }
        }

        // ── cert-show ─────────────────────────────────────────────────────────
        else if (cmd == "cert-show") {
            std::string certPath = getArg(argc, argv, "--cert");
            if (certPath.empty()) throw std::runtime_error("--cert required");
            PQCertificate::show(certPath);
        }

        // ── benchmark ─────────────────────────────────────────────────────────
        else if (cmd == "--benchmark") {
            PQBenchmarker::benchmarkAll();
        }

        // ── negative-tests ────────────────────────────────────────────────────
        else if (cmd == "--negative-tests") {
            bool ok = PQNegativeTests::runAll();
            return ok ? 0 : 1;
        }

        else {
            std::cerr << "[ERROR] Unknown command: " << cmd << "\n";
            printHelp();
            return 1;
        }

    } catch (const std::exception& ex) {
        std::cerr << "[ERROR] " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
