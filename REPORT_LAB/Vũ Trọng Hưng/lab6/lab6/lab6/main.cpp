// main.cpp
// Lab 6 - Post-Quantum Signatures and KEM
// Commands: keygen, sign, verify, encaps, decaps, cert-demo,
//           --kat, --negative-tests, --batch-verify-demo, --batch-decaps-bench
//
// Note about unit testing:
// Catch2 unit tests are built through CMake in tests/unit_tests.cpp.
// They are executed with ctest from the build directory, not through this main.cpp.

#include "PQConfig.hpp"
#include "PQKeyManager.hpp"
#include "MLDSAEngine.hpp"
#include "MLKEMEngine.hpp"
#include "PQCertificate.hpp"
#include "PQNegativeTests.hpp"
#include "PQBatchTools.hpp"
#include "PQKAT.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

namespace {

static const char* B64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool isMLDSA(PQAlgorithm algo) {
    return algo == PQAlgorithm::MLDSA_44 ||
           algo == PQAlgorithm::MLDSA_65 ||
           algo == PQAlgorithm::MLDSA_87;
}

bool isMLKEM(PQAlgorithm algo) {
    return algo == PQAlgorithm::MLKEM_512 ||
           algo == PQAlgorithm::MLKEM_768 ||
           algo == PQAlgorithm::MLKEM_1024;
}

bool hasFlag(int argc, char* argv[], const std::string& flag) {
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == flag) {
            return true;
        }
    }

    return false;
}

std::string getArg(
    int argc,
    char* argv[],
    const std::string& name,
    const std::string& defaultValue = ""
) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == name) {
            return argv[i + 1];
        }
    }

    return defaultValue;
}

std::size_t getCountArg(
    int argc,
    char* argv[],
    const std::string& name,
    std::size_t defaultValue
) {
    std::string value = getArg(argc, argv, name);

    if (value.empty()) {
        return defaultValue;
    }

    try {
        return static_cast<std::size_t>(std::stoull(value));
    } catch (const std::exception&) {
        throw PQException("Invalid numeric value for " + name + ": " + value);
    }
}

std::string resolveCommand(int argc, char* argv[]) {
    if (argc < 2) {
        return "";
    }

    // Allow both:
    //   pqtool keygen ... --verbose
    //   pqtool --verbose keygen ...
    if (std::string(argv[1]) == "--verbose") {
        if (argc >= 3) {
            return argv[2];
        }
        return "--help";
    }

    return argv[1];
}

void printVerboseHeader(const std::string& command) {
    std::cout << "[VERBOSE] Command: " << command << "\n";
}

void printUsage() {
    std::cout
        << "Lab 6 PQTool - Post-Quantum Signatures and KEM\n\n"

        << "Key generation:\n"
        << "  pqtool keygen --algo mldsa-44 --pub pub.pem --priv priv.pem\n"
        << "  pqtool keygen --algo mldsa-65 --pub pub.pem --priv priv.pem\n"
        << "  pqtool keygen --algo mlkem-512 --pub pub.pem --priv priv.pem\n\n"

        << "ML-DSA signing:\n"
        << "  pqtool sign --algo mldsa-44 --in msg.bin --priv priv.pem --out sig.bin --encode raw\n"
        << "  pqtool sign --algo mldsa-44 --in msg.bin --priv priv.pem --out sig.b64 --encode base64\n\n"

        << "ML-DSA verification:\n"
        << "  pqtool verify --algo mldsa-44 --in msg.bin --sig sig.bin --pub pub.pem --encode raw\n"
        << "  pqtool verify --algo mldsa-44 --in msg.bin --sig sig.b64 --pub pub.pem --encode base64\n\n"

        << "ML-KEM encapsulation:\n"
        << "  pqtool encaps --algo mlkem-512 --pub pub.pem --ct ct.bin --ss ss.bin\n\n"

        << "ML-KEM decapsulation:\n"
        << "  pqtool decaps --algo mlkem-512 --priv priv.pem --ct ct.bin --ss ss.bin\n\n"

        << "Post-quantum certificate mini-project:\n"
        << "  pqtool cert-demo --algo mldsa-44 --subject Alice --out cert.json\n\n"

        << "Correctness and batch tests:\n"
        << "  pqtool --kat test_vectors.json\n"
        << "  pqtool kat test_vectors.json\n"
        << "  pqtool --negative-tests\n"
        << "  pqtool negative-tests\n"
        << "  pqtool --batch-verify-demo --algo mldsa-44 --count 20\n"
        << "  pqtool --batch-decaps-bench --algo mlkem-512 --count 100\n\n"

        << "Unit testing with CTest:\n"
        << "  Windows:\n"
        << "    cd build\n"
        << "    ctest --output-on-failure -V\n"
        << "  Linux:\n"
        << "    cd build_linux\n"
        << "    LD_LIBRARY_PATH=../../liboqs/build_linux/lib ctest --output-on-failure -V\n\n"

        << "Algorithms:\n"
        << "  ML-DSA: mldsa-44, mldsa-65, mldsa-87\n"
        << "  ML-KEM: mlkem-512, mlkem-768, mlkem-1024\n\n"

        << "Signature encodings:\n"
        << "  raw, base64\n\n"

        << "Options:\n"
        << "  --algo NAME\n"
        << "  --in FILE\n"
        << "  --out FILE\n"
        << "  --pub FILE\n"
        << "  --priv FILE\n"
        << "  --sig FILE\n"
        << "  --ct FILE\n"
        << "  --ss FILE\n"
        << "  --subject NAME\n"
        << "  --metadata FILE\n"
        << "  --encode raw|base64\n"
        << "  --count N\n"
        << "  --verbose\n"
        << "  --help, -h\n";
}

std::vector<uint8_t> readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);

    if (!file.is_open()) {
        throw PQException("Cannot open input file: " + path);
    }

    return std::vector<uint8_t>(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

void writeFile(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);

    if (!file.is_open()) {
        throw PQException("Cannot open output file: " + path);
    }

    file.write(
        reinterpret_cast<const char*>(data.data()),
        static_cast<std::streamsize>(data.size())
    );

    if (!file.good()) {
        throw PQException("Failed while writing output file: " + path);
    }
}

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

std::vector<uint8_t> loadSignature(const std::string& path, OutputFormat fmt) {
    if (fmt == OutputFormat::RAW) {
        return readFile(path);
    }

    if (fmt == OutputFormat::BASE64) {
        auto raw = readFile(path);
        std::string s(raw.begin(), raw.end());
        return base64Decode(s);
    }

    throw PQException("Only raw and base64 are supported for signatures");
}

void saveSignature(
    const std::string& path,
    const std::vector<uint8_t>& sig,
    OutputFormat fmt
) {
    if (fmt == OutputFormat::RAW) {
        writeFile(path, sig);
        return;
    }

    if (fmt == OutputFormat::BASE64) {
        std::string encoded = base64Encode(sig);
        writeFile(path, std::vector<uint8_t>(encoded.begin(), encoded.end()));
        return;
    }

    throw PQException("Only raw and base64 are supported for signatures");
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        bool verbose = hasFlag(argc, argv, "--verbose");

        std::string command = resolveCommand(argc, argv);

        if (command.empty() ||
            command == "--help" ||
            command == "-h" ||
            command == "help") {
            printUsage();
            return 0;
        }

        if (verbose) {
            printVerboseHeader(command);
        }

        if (command == "--kat" || command == "kat") {
            std::string vectorFile = getArg(argc, argv, "--kat");

            if (vectorFile.empty()) {
                // Support: pqtool kat test_vectors.json
                // and:     pqtool --kat test_vectors.json
                for (int i = 1; i < argc; ++i) {
                    std::string arg = argv[i];

                    if (arg == "kat" || arg == "--kat") {
                        if (i + 1 < argc && std::string(argv[i + 1]).rfind("--", 0) != 0) {
                            vectorFile = argv[i + 1];
                        }
                        break;
                    }
                }
            }

            if (vectorFile.empty()) {
                vectorFile = "test_vectors.json";
            }

            if (verbose) {
                std::cout << "[VERBOSE] KAT vector file: " << vectorFile << "\n";
            }

            bool ok = PQKAT::run(vectorFile);
            return ok ? 0 : 1;
        }

        if (command == "--negative-tests" || command == "negative-tests") {
            if (verbose) {
                std::cout << "[VERBOSE] Running Lab 6 negative tests\n";
            }

            bool ok = PQNegativeTests::runAll();
            return ok ? 0 : 1;
        }

        if (command == "--batch-verify-demo" || command == "batch-verify-demo") {
            std::string algoStr = getArg(argc, argv, "--algo", "mldsa-44");
            std::size_t count = getCountArg(argc, argv, "--count", 20);
            PQAlgorithm algo = PQConfig::stringToAlgorithm(algoStr);

            if (!isMLDSA(algo)) {
                throw PQException("batch verification requires an ML-DSA algorithm");
            }

            if (verbose) {
                std::cout << "[VERBOSE] Algorithm: " << algoStr << "\n";
                std::cout << "[VERBOSE] Batch count: " << count << "\n";
            }

            bool ok = PQBatchTools::runBatchVerifyDemo(algo, count);
            return ok ? 0 : 1;
        }

        if (command == "--batch-decaps-bench" ||
            command == "batch-decaps-bench" ||
            command == "--batch-decaps-demo" ||
            command == "batch-decaps-demo") {
            std::string algoStr = getArg(argc, argv, "--algo", "mlkem-512");
            std::size_t count = getCountArg(argc, argv, "--count", 100);
            PQAlgorithm algo = PQConfig::stringToAlgorithm(algoStr);

            if (!isMLKEM(algo)) {
                throw PQException("batch decapsulation requires an ML-KEM algorithm");
            }

            if (verbose) {
                std::cout << "[VERBOSE] Algorithm: " << algoStr << "\n";
                std::cout << "[VERBOSE] Batch count: " << count << "\n";
            }

            bool ok = PQBatchTools::runBatchDecapsulationTiming(algo, count);
            return ok ? 0 : 1;
        }

        if (command == "keygen") {
            std::string algoStr = getArg(argc, argv, "--algo");
            std::string pubFile = getArg(argc, argv, "--pub");
            std::string privFile = getArg(argc, argv, "--priv");
            std::string metadataFile = getArg(argc, argv, "--metadata");

            if (algoStr.empty() || pubFile.empty() || privFile.empty()) {
                throw PQException("keygen requires --algo, --pub, and --priv");
            }

            if (verbose) {
                std::cout << "[VERBOSE] Algorithm: " << algoStr << "\n";
                std::cout << "[VERBOSE] Public key output: " << pubFile << "\n";
                std::cout << "[VERBOSE] Private key output: " << privFile << "\n";
                if (!metadataFile.empty()) {
                    std::cout << "[VERBOSE] Metadata output: " << metadataFile << "\n";
                }
            }

            PQAlgorithm algo = PQConfig::stringToAlgorithm(algoStr);

            PQKeyManager km;
            km.generateKeyPair(algo);
            km.saveKeyPair(pubFile, privFile);

            if (!metadataFile.empty()) {
                km.saveMetadata(metadataFile);
            }

            return 0;
        }

        if (command == "sign") {
            std::string algoStr = getArg(argc, argv, "--algo");
            std::string inFile = getArg(argc, argv, "--in");
            std::string privFile = getArg(argc, argv, "--priv");
            std::string outFile = getArg(argc, argv, "--out");
            std::string encStr = getArg(argc, argv, "--encode", "raw");

            if (algoStr.empty() || inFile.empty() || privFile.empty() || outFile.empty()) {
                throw PQException("sign requires --algo, --in, --priv, and --out");
            }

            if (verbose) {
                std::cout << "[VERBOSE] Algorithm: " << algoStr << "\n";
                std::cout << "[VERBOSE] Input file: " << inFile << "\n";
                std::cout << "[VERBOSE] Private key file: " << privFile << "\n";
                std::cout << "[VERBOSE] Signature output: " << outFile << "\n";
                std::cout << "[VERBOSE] Encoding: " << encStr << "\n";
            }

            PQAlgorithm algo = PQConfig::stringToAlgorithm(algoStr);
            OutputFormat fmt = PQConfig::stringToFormat(encStr);

            if (!isMLDSA(algo)) {
                throw PQException("sign requires an ML-DSA algorithm");
            }

            PQKeyManager km;
            km.loadPrivateKey(privFile);

            auto msg = readFile(inFile);

            MLDSAEngine engine;
            auto sig = engine.sign(msg, km.getPrivateKey(), algo);

            saveSignature(outFile, sig, fmt);

            std::cout << "[OK] Signature written to " << outFile << "\n";
            std::cout << "[INFO] Message size: " << msg.size() << " bytes\n";
            std::cout << "[INFO] Signature size: " << sig.size() << " bytes\n";

            return 0;
        }

        if (command == "verify") {
            std::string algoStr = getArg(argc, argv, "--algo");
            std::string inFile = getArg(argc, argv, "--in");
            std::string sigFile = getArg(argc, argv, "--sig");
            std::string pubFile = getArg(argc, argv, "--pub");
            std::string encStr = getArg(argc, argv, "--encode", "raw");

            if (algoStr.empty() || inFile.empty() || sigFile.empty() || pubFile.empty()) {
                throw PQException("verify requires --algo, --in, --sig, and --pub");
            }

            if (verbose) {
                std::cout << "[VERBOSE] Algorithm: " << algoStr << "\n";
                std::cout << "[VERBOSE] Input file: " << inFile << "\n";
                std::cout << "[VERBOSE] Signature file: " << sigFile << "\n";
                std::cout << "[VERBOSE] Public key file: " << pubFile << "\n";
                std::cout << "[VERBOSE] Encoding: " << encStr << "\n";
            }

            PQAlgorithm algo = PQConfig::stringToAlgorithm(algoStr);
            OutputFormat fmt = PQConfig::stringToFormat(encStr);

            if (!isMLDSA(algo)) {
                throw PQException("verify requires an ML-DSA algorithm");
            }

            PQKeyManager km;
            km.loadPublicKey(pubFile);

            auto msg = readFile(inFile);
            auto sig = loadSignature(sigFile, fmt);

            MLDSAEngine engine;
            bool ok = engine.verify(msg, sig, km.getPublicKey(), algo);

            if (ok) {
                std::cout << "[OK] Signature is valid\n";
                std::cout << "[INFO] Message size: " << msg.size() << " bytes\n";
                std::cout << "[INFO] Signature size: " << sig.size() << " bytes\n";
                return 0;
            }

            std::cout << "[FAIL] Signature is invalid\n";
            return 1;
        }

        if (command == "encaps") {
            std::string algoStr = getArg(argc, argv, "--algo");
            std::string pubFile = getArg(argc, argv, "--pub");
            std::string ctFile = getArg(argc, argv, "--ct");
            std::string ssFile = getArg(argc, argv, "--ss");

            if (algoStr.empty() || pubFile.empty() || ctFile.empty() || ssFile.empty()) {
                throw PQException("encaps requires --algo, --pub, --ct, and --ss");
            }

            if (verbose) {
                std::cout << "[VERBOSE] Algorithm: " << algoStr << "\n";
                std::cout << "[VERBOSE] Public key file: " << pubFile << "\n";
                std::cout << "[VERBOSE] Ciphertext output: " << ctFile << "\n";
                std::cout << "[VERBOSE] Shared secret output: " << ssFile << "\n";
            }

            PQAlgorithm algo = PQConfig::stringToAlgorithm(algoStr);

            if (!isMLKEM(algo)) {
                throw PQException("encaps requires an ML-KEM algorithm");
            }

            PQKeyManager km;
            km.loadPublicKey(pubFile);

            MLKEMEngine engine;
            KEMResult result = engine.encapsulate(km.getPublicKey(), algo);

            writeFile(ctFile, result.ciphertext);
            writeFile(ssFile, result.sharedSecret);

            std::cout << "[OK] Ciphertext written to " << ctFile << "\n";
            std::cout << "[OK] Shared secret written to " << ssFile << "\n";
            std::cout << "[INFO] Ciphertext size: " << result.ciphertext.size() << " bytes\n";
            std::cout << "[INFO] Shared secret size: " << result.sharedSecret.size() << " bytes\n";

            return 0;
        }

        if (command == "decaps") {
            std::string algoStr = getArg(argc, argv, "--algo");
            std::string privFile = getArg(argc, argv, "--priv");
            std::string ctFile = getArg(argc, argv, "--ct");
            std::string ssFile = getArg(argc, argv, "--ss");

            if (algoStr.empty() || privFile.empty() || ctFile.empty() || ssFile.empty()) {
                throw PQException("decaps requires --algo, --priv, --ct, and --ss");
            }

            if (verbose) {
                std::cout << "[VERBOSE] Algorithm: " << algoStr << "\n";
                std::cout << "[VERBOSE] Private key file: " << privFile << "\n";
                std::cout << "[VERBOSE] Ciphertext file: " << ctFile << "\n";
                std::cout << "[VERBOSE] Shared secret output: " << ssFile << "\n";
            }

            PQAlgorithm algo = PQConfig::stringToAlgorithm(algoStr);

            if (!isMLKEM(algo)) {
                throw PQException("decaps requires an ML-KEM algorithm");
            }

            PQKeyManager km;
            km.loadPrivateKey(privFile);

            auto ct = readFile(ctFile);

            MLKEMEngine engine;
            auto ss = engine.decapsulate(ct, km.getPrivateKey(), algo);

            writeFile(ssFile, ss);

            std::cout << "[OK] Shared secret written to " << ssFile << "\n";
            std::cout << "[INFO] Ciphertext size: " << ct.size() << " bytes\n";
            std::cout << "[INFO] Shared secret size: " << ss.size() << " bytes\n";

            return 0;
        }

        if (command == "cert-demo") {
            std::string algoStr = getArg(argc, argv, "--algo", "mldsa-44");
            std::string subject = getArg(argc, argv, "--subject", "Subject");
            std::string outFile = getArg(argc, argv, "--out", "pq_certificate.json");

            if (verbose) {
                std::cout << "[VERBOSE] Algorithm: " << algoStr << "\n";
                std::cout << "[VERBOSE] Subject: " << subject << "\n";
                std::cout << "[VERBOSE] Certificate output: " << outFile << "\n";
            }

            PQAlgorithm algo = PQConfig::stringToAlgorithm(algoStr);

            if (!isMLDSA(algo)) {
                throw PQException("cert-demo requires an ML-DSA algorithm");
            }

            PQCertificateManager ca;
            ca.generateCA("PQ-CA", algo);

            PQKeyManager subjectKeys;
            subjectKeys.generateKeyPair(algo);

            PQCertificate cert = ca.issueCertificate(
                subject,
                subjectKeys.getPublicKey(),
                algo
            );

            ca.saveCertificate(cert, outFile);

            bool ok = ca.verifyCertificate(cert);

            std::cout << "[OK] Certificate written to " << outFile << "\n";
            std::cout << "[INFO] Certificate verification: " << (ok ? "PASS" : "FAIL") << "\n";

            return ok ? 0 : 1;
        }

        throw PQException("Unknown command: " + command);

    } catch (const std::exception& ex) {
        std::cerr << "[ERROR] " << ex.what() << "\n";
        return 1;
    }
}
