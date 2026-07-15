// main.cpp
#include "SigConfig.hpp"
#include "SigKeyManager.hpp"
#include "ECDSAEngine.hpp"
#include "RSAPSSEngine.hpp"
#include "NegativeTests.hpp"
#include "BatchVerifier.hpp"
#include "SigBenchmarker.hpp"
#include "ManualRSAPSS.hpp"
#include "SigKAT.hpp"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static void printUsage() {
    std::cout
        << "Lab 5 SigTool - Classical Digital Signatures\n\n"

        << "Key generation:\n"
        << "  sigtool keygen --algo ecdsa-p256 --pub pub.pem --priv priv.pem\n"
        << "  sigtool keygen --algo ecdsa-p384 --pub pub.pem --priv priv.pem\n"
        << "  sigtool keygen --algo rsa-pss-3072 --pub pub.pem --priv priv.pem\n\n"

        << "Signing:\n"
        << "  sigtool sign --algo ecdsa-p256 --in msg.bin --priv priv.pem --out sig.bin --hash sha256 --encode der\n"
        << "  sigtool sign --algo rsa-pss-3072 --in msg.bin --priv priv.pem --out sig.bin --hash sha256 --encode raw\n\n"

        << "Verification:\n"
        << "  sigtool verify --algo ecdsa-p256 --in msg.bin --sig sig.bin --pub pub.pem --hash sha256 --encode der\n"
        << "  sigtool verify --algo rsa-pss-3072 --in msg.bin --sig sig.bin --pub pub.pem --hash sha256 --encode raw\n\n"

        << "Testing and benchmarks:\n"
        << "  sigtool --negative-tests\n"
        << "  sigtool --benchmark\n"
        << "  sigtool --batch-demo\n"
        << "  sigtool --manual-pss-demo\n\n"

        << "Algorithms:\n"
        << "  ecdsa-p256\n"
        << "  ecdsa-p384\n"
        << "  rsa-pss-3072\n\n"

        << "Hashes:\n"
        << "  sha256\n"
        << "  sha384\n\n"

        << "Signature encodings:\n"
        << "  raw\n"
        << "  der\n"
        << "  base64\n\n"

        << "Options:\n"
        << "  --algo NAME\n"
        << "  --in FILE\n"
        << "  --out FILE\n"
        << "  --pub FILE\n"
        << "  --priv FILE\n"
        << "  --sig FILE\n"
        << "  --hash sha256|sha384\n"
        << "  --encode raw|der|base64\n"
        << "  --help, -h\n";
}

static bool hasArg(int argc, char* argv[], const std::string& name) {
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == name) {
            return true;
        }
    }

    return false;
}

static std::string getArg(
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

static std::vector<uint8_t> readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);

    if (!file.is_open()) {
        throw SigException("Cannot open input file: " + path);
    }

    return std::vector<uint8_t>(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

static void writeFile(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);

    if (!file.is_open()) {
        throw SigException("Cannot open output file: " + path);
    }

    file.write(
        reinterpret_cast<const char*>(data.data()),
        static_cast<std::streamsize>(data.size())
    );

    if (!file.good()) {
        throw SigException("Failed while writing output file: " + path);
    }
}

static std::string base64Encode(const std::vector<uint8_t>& input) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());

    if (!b64 || !mem) {
        if (b64) BIO_free(b64);
        if (mem) BIO_free(mem);
        throw SigException("Failed to create BIO for base64 encoding");
    }

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);

    if (BIO_write(b64, input.data(), static_cast<int>(input.size())) <= 0) {
        BIO_free_all(b64);
        throw SigException("Base64 encoding failed");
    }

    if (BIO_flush(b64) != 1) {
        BIO_free_all(b64);
        throw SigException("Base64 flush failed");
    }

    BUF_MEM* bufferPtr = nullptr;
    BIO_get_mem_ptr(b64, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);

    BIO_free_all(b64);

    return result;
}

static std::vector<uint8_t> base64Decode(const std::vector<uint8_t>& input) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(input.data(), static_cast<int>(input.size()));

    if (!b64 || !mem) {
        if (b64) BIO_free(b64);
        if (mem) BIO_free(mem);
        throw SigException("Failed to create BIO for base64 decoding");
    }

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);

    std::vector<uint8_t> output(input.size());
    int len = BIO_read(b64, output.data(), static_cast<int>(output.size()));

    if (len < 0) {
        BIO_free_all(b64);
        throw SigException("Base64 decoding failed");
    }

    output.resize(static_cast<size_t>(len));

    BIO_free_all(b64);

    return output;
}

static size_t getEcdsaPartLength(SignatureAlgorithm algo) {
    if (algo == SignatureAlgorithm::ECDSA_P256) {
        return 32;
    }

    if (algo == SignatureAlgorithm::ECDSA_P384) {
        return 48;
    }

    throw SigException("ECDSA raw conversion requires ECDSA algorithm");
}

static std::vector<uint8_t> ecdsaDerToRaw(
    const std::vector<uint8_t>& der,
    SignatureAlgorithm algo
) {
    const unsigned char* ptr = der.data();

    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &ptr, static_cast<long>(der.size()));

    if (!sig) {
        throw SigException("Failed to decode ECDSA DER signature");
    }

    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;

    ECDSA_SIG_get0(sig, &r, &s);

    size_t partLen = getEcdsaPartLength(algo);
    std::vector<uint8_t> raw(partLen * 2);

    if (BN_bn2binpad(r, raw.data(), static_cast<int>(partLen)) <= 0 ||
        BN_bn2binpad(s, raw.data() + partLen, static_cast<int>(partLen)) <= 0) {
        ECDSA_SIG_free(sig);
        throw SigException("Failed to convert ECDSA DER signature to raw");
    }

    ECDSA_SIG_free(sig);

    return raw;
}

static std::vector<uint8_t> ecdsaRawToDer(
    const std::vector<uint8_t>& raw,
    SignatureAlgorithm algo
) {
    size_t partLen = getEcdsaPartLength(algo);

    if (raw.size() != partLen * 2) {
        throw SigException("Invalid raw ECDSA signature length");
    }

    BIGNUM* r = BN_bin2bn(raw.data(), static_cast<int>(partLen), nullptr);
    BIGNUM* s = BN_bin2bn(raw.data() + partLen, static_cast<int>(partLen), nullptr);

    if (!r || !s) {
        if (r) BN_free(r);
        if (s) BN_free(s);
        throw SigException("Failed to convert raw ECDSA signature");
    }

    ECDSA_SIG* sig = ECDSA_SIG_new();

    if (!sig) {
        BN_free(r);
        BN_free(s);
        throw SigException("Failed to allocate ECDSA_SIG");
    }

    if (ECDSA_SIG_set0(sig, r, s) != 1) {
        ECDSA_SIG_free(sig);
        BN_free(r);
        BN_free(s);
        throw SigException("Failed to set ECDSA_SIG values");
    }

    int derLen = i2d_ECDSA_SIG(sig, nullptr);

    if (derLen <= 0) {
        ECDSA_SIG_free(sig);
        throw SigException("Failed to calculate ECDSA DER length");
    }

    std::vector<uint8_t> der(static_cast<size_t>(derLen));
    unsigned char* outPtr = der.data();

    if (i2d_ECDSA_SIG(sig, &outPtr) != derLen) {
        ECDSA_SIG_free(sig);
        throw SigException("Failed to encode ECDSA DER signature");
    }

    ECDSA_SIG_free(sig);

    return der;
}

static void validateHashForAlgorithm(SignatureAlgorithm algo, HashAlgorithm hash) {
    if (algo == SignatureAlgorithm::RSA_PSS_3072 && hash != HashAlgorithm::SHA256) {
        throw SigException("RSA-PSS-3072 requires SHA-256 in this lab");
    }

    if (algo == SignatureAlgorithm::ECDSA_P256 && hash != HashAlgorithm::SHA256) {
        throw SigException("ECDSA-P256 requires SHA-256 in this lab");
    }
}

static std::vector<uint8_t> encodeSignatureForOutput(
    SignatureAlgorithm algo,
    const std::vector<uint8_t>& signatureDerOrRaw,
    OutputFormat format
) {
    if (format == OutputFormat::PEM) {
        throw SigException("PEM is not supported for signature output; use raw, der, or base64");
    }

    if (algo == SignatureAlgorithm::ECDSA_P256 ||
        algo == SignatureAlgorithm::ECDSA_P384) {
        if (format == OutputFormat::RAW) {
            return ecdsaDerToRaw(signatureDerOrRaw, algo);
        }

        if (format == OutputFormat::DER) {
            return signatureDerOrRaw;
        }

        if (format == OutputFormat::BASE64) {
            std::string b64 = base64Encode(signatureDerOrRaw);
            return std::vector<uint8_t>(b64.begin(), b64.end());
        }
    }

    if (algo == SignatureAlgorithm::RSA_PSS_3072) {
        if (format == OutputFormat::RAW || format == OutputFormat::DER) {
            return signatureDerOrRaw;
        }

        if (format == OutputFormat::BASE64) {
            std::string b64 = base64Encode(signatureDerOrRaw);
            return std::vector<uint8_t>(b64.begin(), b64.end());
        }
    }

    throw SigException("Unsupported signature encoding");
}

static std::vector<uint8_t> decodeSignatureFromInput(
    SignatureAlgorithm algo,
    const std::vector<uint8_t>& signatureInput,
    OutputFormat format
) {
    if (format == OutputFormat::PEM) {
        throw SigException("PEM is not supported for signature input; use raw, der, or base64");
    }

    std::vector<uint8_t> bytes = signatureInput;

    if (format == OutputFormat::BASE64) {
        bytes = base64Decode(signatureInput);
        format = OutputFormat::DER;
    }

    if (algo == SignatureAlgorithm::ECDSA_P256 ||
        algo == SignatureAlgorithm::ECDSA_P384) {
        if (format == OutputFormat::RAW) {
            return ecdsaRawToDer(bytes, algo);
        }

        if (format == OutputFormat::DER) {
            return bytes;
        }
    }

    if (algo == SignatureAlgorithm::RSA_PSS_3072) {
        return bytes;
    }

    throw SigException("Unsupported signature input");
}

int main(int argc, char* argv[]) {
    try {
        if (argc < 2 ||
            hasArg(argc, argv, "--help") ||
            hasArg(argc, argv, "-h")) {
            printUsage();
            return 0;
        }

        std::string command = argv[1];
        if (command == "--kat" || command == "kat") {
            std::string katFile = getArg(argc, argv, "--kat");

            if (katFile.empty()) {
                katFile = getArg(argc, argv, "--in", "test_vectors.json");
            }

            SigKAT kat;
            bool ok = kat.runFromFile(katFile);
            return ok ? 0 : 1;
        }
        // =========================
        // Negative tests
        // =========================
        if (command == "--negative-tests" || command == "negative-tests") {
            SignatureNegativeTests tests;
            bool ok = tests.runAllTests();

            return ok ? 0 : 1;
        }

        // =========================
        // Benchmark
        // =========================
        if (command == "--benchmark" || command == "benchmark") {
            SigBenchmarker benchmarker(1000);
            benchmarker.runAllBenchmarks();
            benchmarker.exportCSV("signature_benchmark_results.csv");

            return 0;
        }

        // =========================
        // Batch verification demo
        // =========================
        if (command == "--batch-demo" || command == "batch-demo") {
            BatchVerifier verifier;
            verifier.generateTestBatch(20);
            verifier.runBatchPerformanceTest();

            return 0;
        }

        // =========================
        // Manual RSA-PSS educational demo
        // =========================
        if (command == "--manual-pss-demo" || command == "manual-pss-demo") {
            std::vector<uint8_t> messageHash(ManualRSAPSS::HASH_SIZE, 0x11);
            auto salt = ManualRSAPSS::generateSalt(ManualRSAPSS::HASH_SIZE);

            auto encoded = ManualRSAPSS::encodePSS(messageHash, 3071, salt);
            bool ok = ManualRSAPSS::verifyPSS(messageHash, encoded, 3071, salt);

            std::cout << "Manual RSA-PSS padding demo" << std::endl;
            std::cout << "Encoded message length: " << encoded.size() << " bytes" << std::endl;
            std::cout << "Verification: " << (ok ? "PASSED" : "FAILED") << std::endl;

            return ok ? 0 : 1;
        }

        // =========================
        // Key generation
        // =========================
        if (command == "keygen") {
            std::string algoText = getArg(argc, argv, "--algo");
            std::string pubFile = getArg(argc, argv, "--pub");
            std::string privFile = getArg(argc, argv, "--priv");
            std::string metadataFile = getArg(argc, argv, "--metadata");

            if (algoText.empty()) {
                throw SigException("keygen requires --algo");
            }

            if (pubFile.empty() || privFile.empty()) {
                throw SigException("keygen requires --pub and --priv");
            }

            SignatureAlgorithm algo = SigConfig::stringToAlgorithm(algoText);

            SigKeyManager keyManager;
            keyManager.generateKeyPair(algo);
            keyManager.saveKeyPair(pubFile, privFile);

            if (!metadataFile.empty()) {
                keyManager.saveMetadata(metadataFile);
            }

            return 0;
        }

        // =========================
        // Sign
        // =========================
        if (command == "sign") {
            std::string algoText = getArg(argc, argv, "--algo");
            std::string inputFile = getArg(argc, argv, "--in");
            std::string privFile = getArg(argc, argv, "--priv");
            std::string outFile = getArg(argc, argv, "--out");
            std::string hashText = getArg(argc, argv, "--hash", "sha256");
            std::string encodeText = getArg(argc, argv, "--encode", "der");

            if (algoText.empty()) {
                throw SigException("sign requires --algo");
            }

            if (inputFile.empty() || privFile.empty() || outFile.empty()) {
                throw SigException("sign requires --in, --priv, and --out");
            }

            SignatureAlgorithm algo = SigConfig::stringToAlgorithm(algoText);
            HashAlgorithm hash = SigConfig::stringToHash(hashText);
            OutputFormat format = SigConfig::stringToFormat(encodeText);

            validateHashForAlgorithm(algo, hash);

            auto message = readFile(inputFile);

            SigKeyManager keyManager;
            keyManager.loadPrivateKey(privFile, algo);

            std::vector<uint8_t> signature;

            if (algo == SignatureAlgorithm::ECDSA_P256 ||
                algo == SignatureAlgorithm::ECDSA_P384) {
                ECDSAEngine engine;
                signature = engine.sign(
                    message,
                    keyManager.getPrivateKey(),
                    hash,
                    true
                );
            } else {
                RSAPSSEngine engine;
                signature = engine.sign(
                    message,
                    keyManager.getPrivateKey(),
                    hash
                );
            }

            auto output = encodeSignatureForOutput(algo, signature, format);
            writeFile(outFile, output);

            std::cout << "[OK] Signature written to: " << outFile << std::endl;
            std::cout << "Algorithm: " << SigConfig::algorithmToString(algo) << std::endl;
            std::cout << "Hash: " << SigConfig::hashToString(hash) << std::endl;
            std::cout << "Encoding: " << SigConfig::formatToString(format) << std::endl;

            return 0;
        }

        // =========================
        // Verify
        // =========================
        if (command == "verify") {
            std::string algoText = getArg(argc, argv, "--algo");
            std::string inputFile = getArg(argc, argv, "--in");
            std::string sigFile = getArg(argc, argv, "--sig");
            std::string pubFile = getArg(argc, argv, "--pub");
            std::string hashText = getArg(argc, argv, "--hash", "sha256");
            std::string encodeText = getArg(argc, argv, "--encode", "der");

            if (algoText.empty()) {
                throw SigException("verify requires --algo");
            }

            if (inputFile.empty() || sigFile.empty() || pubFile.empty()) {
                throw SigException("verify requires --in, --sig, and --pub");
            }

            SignatureAlgorithm algo = SigConfig::stringToAlgorithm(algoText);
            HashAlgorithm hash = SigConfig::stringToHash(hashText);
            OutputFormat format = SigConfig::stringToFormat(encodeText);

            validateHashForAlgorithm(algo, hash);

            auto message = readFile(inputFile);
            auto sigInput = readFile(sigFile);
            auto signature = decodeSignatureFromInput(algo, sigInput, format);

            SigKeyManager keyManager;
            keyManager.loadPublicKey(pubFile, algo);

            bool ok = false;

            if (algo == SignatureAlgorithm::ECDSA_P256 ||
                algo == SignatureAlgorithm::ECDSA_P384) {
                ECDSAEngine engine;
                ok = engine.verify(
                    message,
                    signature,
                    keyManager.getPublicKey(),
                    hash
                );
            } else {
                RSAPSSEngine engine;
                ok = engine.verify(
                    message,
                    signature,
                    keyManager.getPublicKey(),
                    hash
                );
            }

            if (ok) {
                std::cout << "[OK] Signature verification PASSED" << std::endl;
                return 0;
            }

            std::cout << "[FAIL] Signature verification FAILED" << std::endl;
            return 1;
        }

        throw SigException("Unknown command: " + command);

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}