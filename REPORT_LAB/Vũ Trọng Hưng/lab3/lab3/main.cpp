// main.cpp
#include "RSAConfig.hpp"
#include "RSAKeyManager.hpp"
#include "RSAEngine.hpp"
#include "HybridEncryptor.hpp"
#include "NegativeTests.hpp"
#include "RSABenchmarker.hpp"
#include "RSAValidator.hpp"
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iterator>
#include <sstream>
void testManualOAEP();
static std::vector<uint8_t> readBinaryFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);

    if (!in) {
        throw RSAException("Cannot open input file: " + path);
    }

    return std::vector<uint8_t>(
        std::istreambuf_iterator<char>(in),
        std::istreambuf_iterator<char>()
    );
}

static void writeBinaryFile(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream out(path, std::ios::binary);

    if (!out) {
        throw RSAException("Cannot open output file: " + path);
    }

    out.write(
        reinterpret_cast<const char*>(data.data()),
        static_cast<std::streamsize>(data.size())
    );

    if (!out) {
        throw RSAException("Failed to write output file: " + path);
    }
}

static std::string bytesToHex(const std::vector<uint8_t>& data) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);

    for (uint8_t b : data) {
        out.push_back(hex[(b >> 4) & 0x0F]);
        out.push_back(hex[b & 0x0F]);
    }

    return out;
}

static uint8_t fromHexChar(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);

    throw RSAException("Invalid hex character in ciphertext.");
}

static std::vector<uint8_t> hexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw RSAException("Invalid hex encoding length.");
    }

    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t high = fromHexChar(hex[i]);
        uint8_t low = fromHexChar(hex[i + 1]);
        out.push_back(static_cast<uint8_t>((high << 4) | low));
    }

    return out;
}

static std::string base64EncodeBytes(const std::vector<uint8_t>& data) {
    std::string encoded;

    CryptoPP::StringSource ss(
        reinterpret_cast<const CryptoPP::byte*>(data.data()),
        data.size(),
        true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encoded),
            false
        )
    );

    return encoded;
}

static std::vector<uint8_t> base64DecodeBytes(const std::string& data) {
    std::string decoded;

    try {
        CryptoPP::StringSource ss(
            data,
            true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StringSink(decoded)
            )
        );
    } catch (const CryptoPP::Exception&) {
        throw RSAException("Invalid base64 encoding.");
    }

    return std::vector<uint8_t>(decoded.begin(), decoded.end());
}

static std::vector<uint8_t> encodeOutputBytes(
    const std::vector<uint8_t>& raw,
    OutputFormat fmt
) {
    if (fmt == OutputFormat::RAW) {
        return raw;
    }

    if (fmt == OutputFormat::HEX) {
        std::string hex = bytesToHex(raw);
        return std::vector<uint8_t>(hex.begin(), hex.end());
    }

    if (fmt == OutputFormat::BASE64) {
        std::string b64 = base64EncodeBytes(raw);
        return std::vector<uint8_t>(b64.begin(), b64.end());
    }

    throw RSAException("Unsupported ciphertext output encoding.");
}

static std::vector<uint8_t> decodeInputBytes(
    const std::vector<uint8_t>& encoded,
    OutputFormat fmt
) {
    if (fmt == OutputFormat::RAW) {
        return encoded;
    }

    std::string text(encoded.begin(), encoded.end());

    if (fmt == OutputFormat::HEX) {
        return hexToBytes(text);
    }

    if (fmt == OutputFormat::BASE64) {
        return base64DecodeBytes(text);
    }

    throw RSAException("Unsupported ciphertext input encoding.");
}

void printUsage() {
    std::cout << "RSA Tool - RSA-OAEP & Hybrid Encryption\n\n"
              << "Key Generation:\n"
              << "  rsatool keygen --bits 3072 --pub pub.pem --priv priv.pem\n\n"

              << "Encryption:\n"
              << "  rsatool encrypt --in msg.bin --pub pub.pem --out ct.bin [--label label] [--encode raw|hex|base64]\n\n"

              << "Decryption:\n"
              << "  rsatool decrypt --in ct.bin --priv priv.pem --out msg.bin [--label label] [--encode raw|hex|base64]\n\n"

              << "Testing:\n"
              << "  rsatool --kat test_vectors_rsa.json      Run JSON test vectors\n"
              << "  rsatool --test-vectors test_vectors_rsa.json  Alias for --kat\n"
              << "  rsatool --test-nist                     Run built-in RSA-OAEP validation\n"
              << "  rsatool --benchmark                     Run performance benchmarks\n"
              << "  rsatool --negative-tests                Run negative/error tests\n\n"
              << "  rsatool --manual-oaep-test              Run manual RSA-OAEP tests\n"
              << "Output Format:\n"
              << "  --encode raw|hex|base64 (default: base64)\n"
              << "  --format raw|hex|base64 is also accepted as a compatibility alias\n"
              << "  --out-format pem|der (for keys)\n\n"

              << "Options:\n"
              << "  --force-hybrid   Force hybrid mode even for small messages\n"
              << "  --help, -h       Show this help\n";
}

int main(int argc, char* argv[]) {
    try {
        if (argc < 2) {
            printUsage();
            return 0;
        }

        std::string command = argv[1];

        if (command == "--help" || command == "-h") {
            printUsage();
            return 0;
        }

        else if ((command == "--kat" || command == "--test-vectors") && argc >= 3) {
            RSAValidator validator;
            bool passed = validator.runFromFile(argv[2]);
            return passed ? 0 : 1;
        }
        else if (command == "--manual-oaep-test") {
            testManualOAEP();
            return 0;
        }
        else if (command == "--test-nist") {
            RSAValidator validator;
            bool passed = validator.runNIST_RSA_OAEP_Tests();
            return passed ? 0 : 1;
        }

        else if (command == "--benchmark") {
            RSABenchmarker benchmarker(100);
            benchmarker.runBenchmarks();
            return 0;
        }

        else if (command == "--negative-tests") {
            RSANegativeTests tests;
            bool passed = tests.runAllTests();
            return passed ? 0 : 1;
        }

        else if (command == "keygen") {
            RSAKeyManager keyManager;
            RSAKeySize keySize = RSAKeySize::RSA_3072;
            std::string pubFile = "pub.pem";
            std::string privFile = "priv.pem";
            std::string metaFile;

            for (int i = 2; i < argc; i++) {
                std::string arg = argv[i];

                if (arg == "--bits" && i + 1 < argc) {
                    keySize = RSAConfig::stringToKeySize(argv[++i]);
                } else if (arg == "--pub" && i + 1 < argc) {
                    pubFile = argv[++i];
                } else if (arg == "--priv" && i + 1 < argc) {
                    privFile = argv[++i];
                } else if (arg == "--meta" && i + 1 < argc) {
                    metaFile = argv[++i];
                } else if (arg == "--out-format" && i + 1 < argc) {
                    // Accepted for CLI compatibility. Current implementation saves PEM plus DER.
                    (void)RSAConfig::stringToFormat(argv[++i]);
                } else {
                    throw RSAException("Unknown or incomplete keygen option: " + arg);
                }
            }

            if (metaFile.empty()) {
                metaFile = pubFile + ".metadata.json";
            }

            keyManager.generateKeyPair(keySize);
            keyManager.saveKeyPair(pubFile, privFile);
            keyManager.saveMetadata(metaFile);

            std::cout << "\nKey generation complete!\n";
            std::cout << "Public key: " << pubFile << "\n";
            std::cout << "Private key: " << privFile << "\n";
            std::cout << "Metadata: " << metaFile << "\n";
        }

        else if (command == "encrypt") {
            RSAKeyManager keyManager;
            RSAEngine engine;
            HybridEncryptor hybrid;

            std::string inputFile;
            std::string outputFile;
            std::string pubFile;
            std::string label;
            bool forceHybrid = false;
            OutputFormat fmt = OutputFormat::BASE64;

            for (int i = 2; i < argc; i++) {
                std::string arg = argv[i];

                if (arg == "--in" && i + 1 < argc) {
                    inputFile = argv[++i];
                } else if (arg == "--out" && i + 1 < argc) {
                    outputFile = argv[++i];
                } else if (arg == "--pub" && i + 1 < argc) {
                    pubFile = argv[++i];
                } else if (arg == "--label" && i + 1 < argc) {
                    label = argv[++i];
                } else if (arg == "--force-hybrid") {
                    forceHybrid = true;
                } else if ((arg == "--encode" || arg == "--format") && i + 1 < argc) {
                    fmt = RSAConfig::stringToFormat(argv[++i]);
                } else {
                    throw RSAException("Unknown or incomplete encrypt option: " + arg);
                }
            }

            if (inputFile.empty() || outputFile.empty() || pubFile.empty()) {
                throw RSAException("encrypt requires --in, --pub, and --out.");
            }

            keyManager.loadPublicKey(pubFile);

            std::vector<uint8_t> plaintext = readBinaryFile(inputFile);
            std::vector<uint8_t> result;

            if (forceHybrid || engine.isPlaintextTooLarge(plaintext.size(), keyManager.getPublicKey())) {
                HybridEnvelope envelope = hybrid.hybridEncrypt(
                    plaintext,
                    keyManager.getPublicKey(),
                    label
                );

                std::ofstream headerFile(outputFile + ".json", std::ios::binary);

                if (!headerFile) {
                    throw RSAException("Cannot open envelope output file: " + outputFile + ".json");
                }

                headerFile << envelope.toJSON();

                result = envelope.ciphertext;

                std::cout << "Hybrid mode selected: RSA-OAEP-SHA256 + AES-256-GCM\n";
                std::cout << "Envelope header: " << outputFile << ".json\n";
            } else {
                result = engine.encryptOAEP(
                    plaintext,
                    keyManager.getPublicKey(),
                    label
                );

                std::cout << "Direct RSA-OAEP mode selected\n";
            }

            std::vector<uint8_t> encodedResult = encodeOutputBytes(result, fmt);
            writeBinaryFile(outputFile, encodedResult);

            std::cout << "Encryption complete: " << outputFile << std::endl;
        }

        else if (command == "decrypt") {
            RSAKeyManager keyManager;
            RSAEngine engine;
            HybridEncryptor hybrid;

            std::string inputFile;
            std::string outputFile;
            std::string privFile;
            std::string label;
            OutputFormat fmt = OutputFormat::BASE64;

            for (int i = 2; i < argc; i++) {
                std::string arg = argv[i];

                if (arg == "--in" && i + 1 < argc) {
                    inputFile = argv[++i];
                } else if (arg == "--out" && i + 1 < argc) {
                    outputFile = argv[++i];
                } else if (arg == "--priv" && i + 1 < argc) {
                    privFile = argv[++i];
                } else if (arg == "--label" && i + 1 < argc) {
                    label = argv[++i];
                } else if ((arg == "--encode" || arg == "--format") && i + 1 < argc) {
                    fmt = RSAConfig::stringToFormat(argv[++i]);
                } else {
                    throw RSAException("Unknown or incomplete decrypt option: " + arg);
                }
            }

            if (inputFile.empty() || outputFile.empty() || privFile.empty()) {
                throw RSAException("decrypt requires --in, --priv, and --out.");
            }

            keyManager.loadPrivateKey(privFile);

            std::vector<uint8_t> encodedInput = readBinaryFile(inputFile);
            std::vector<uint8_t> ciphertext = decodeInputBytes(encodedInput, fmt);

            std::vector<uint8_t> plaintext;

            std::ifstream headerFile(inputFile + ".json", std::ios::binary);

            if (headerFile.good()) {
                std::ostringstream buffer;
                buffer << headerFile.rdbuf();

                std::string jsonStr = buffer.str();

                HybridEnvelope envelope = HybridEnvelope::fromJSON(jsonStr);
                envelope.ciphertext = ciphertext;

                plaintext = hybrid.hybridDecrypt(
                    envelope,
                    keyManager.getPrivateKey(),
                    label
                );
            } else {
                plaintext = engine.decryptOAEP(
                    ciphertext,
                    keyManager.getPrivateKey(),
                    label
                );
            }

            writeBinaryFile(outputFile, plaintext);

            std::cout << "Decryption complete: " << outputFile << std::endl;
        }

        else {
            std::cerr << "Unknown command: " << command << std::endl;
            printUsage();
            return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << "\nError: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}