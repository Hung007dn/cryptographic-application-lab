#include "HashConfig.hpp"
#include "HashEngine.hpp"
#include "HashValidator.hpp"
#include "HashBenchmarker.hpp"
#include "NegativeTests.hpp"
#include "CertificateAnalyzer.hpp"
#include "MD5CollisionDemo.hpp"
#include "CustomSHA256Extend.hpp"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static void printUsage() {
    std::cout
        << "Lab 4 HashTool - Hashing, PKI, and Practical Attacks\n\n"

        << "Basic hashing:\n"
        << "  hashtool --algo sha256 --in file.bin\n"
        << "  hashtool --algo sha256 --text \"abc\"\n"
        << "  hashtool --algo sha512 --in large.iso --stream\n"
        << "  hashtool --algo shake256 --outlen 64 --in file.bin\n"
        << "  hashtool --algo sha256 --in file.bin --out digest.bin --format raw\n"
        << "  hashtool --algo sha256 --text \"abc\" --out digest.txt\n\n"

        << "Supported algorithms:\n"
        << "  sha224, sha256, sha384, sha512\n"
        << "  sha3-224, sha3-256, sha3-384, sha3-512\n"
        << "  shake128, shake256\n\n"

        << "Testing:\n"
        << "  hashtool --kat test_vectors.json\n"
        << "  hashtool --test-nist\n"
        << "  hashtool --negative-tests\n\n"

        << "Quick benchmark:\n"
        << "  hashtool --benchmark\n"
        << "  hashtool --benchmark --include-1gb\n"
        << "  Note: the Python scripts perform the official 30-run benchmark.\n\n"

        << "Certificate analysis:\n"
        << "  hashtool --cert --in cert.pem\n"
        << "  hashtool --cert --in cert.pem --issuer issuer.pem\n"
        << "  hashtool --cert --in cert.pem --out cert_report.json\n\n"

        << "MD5 collision verification:\n"
        << "  hashtool --md5-collision --file1 a.bin --file2 b.bin\n"
        << "  hashtool --md5-demo\n\n"

        << "Length extension demo:\n"
        << "  hashtool --length-extension-demo\n\n"

        << "Options:\n"
        << "  --in FILE\n"
        << "  --text TEXT\n"
        << "  --out FILE\n"
        << "  --algo NAME\n"
        << "  --outlen BYTES\n"
        << "  --format hex|raw\n"
        << "  --stream\n"
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

static void writeRawFile(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream out(path, std::ios::binary);

    if (!out.is_open()) {
        throw HashException("Cannot open output file: " + path);
    }

    out.write(
        reinterpret_cast<const char*>(data.data()),
        static_cast<std::streamsize>(data.size())
    );

    if (!out.good()) {
        throw HashException("Failed while writing output file: " + path);
    }
}

static void writeTextFile(const std::string& path, const std::string& text) {
    std::ofstream out(path);

    if (!out.is_open()) {
        throw HashException("Cannot open output file: " + path);
    }

    out << text << "\n";

    if (!out.good()) {
        throw HashException("Failed while writing output file: " + path);
    }
}

int main(int argc, char* argv[]) {
    try {
        if (argc < 2 || hasArg(argc, argv, "--help") || hasArg(argc, argv, "-h")) {
            printUsage();
            return 0;
        }

        // =========================
        // KAT
        // =========================
        if (hasArg(argc, argv, "--kat")) {
            std::string katFile = getArg(argc, argv, "--kat", "test_vectors.json");

            HashValidator validator;
            bool ok = validator.runFromFile(katFile);

            return ok ? 0 : 1;
        }

        // =========================
        // NIST tests
        // =========================
        if (hasArg(argc, argv, "--test-nist")) {
            HashValidator validator;
            bool ok = validator.runNISTTests();

            return ok ? 0 : 1;
        }

        // =========================
        // Negative tests
        // =========================
        if (hasArg(argc, argv, "--negative-tests")) {
            HashNegativeTests tests;
            bool ok = tests.runAllTests();

            return ok ? 0 : 1;
        }

        // =========================
        // Quick benchmark
        // Official 30-run benchmark is done by Python scripts.
        // =========================
        if (hasArg(argc, argv, "--benchmark")) {
            bool include1GB = hasArg(argc, argv, "--include-1gb");

            HashBenchmarker bench(1, include1GB);
            bench.benchmarkAll();
            bench.exportCSV("hash_benchmark_results.csv");

            return 0;
        }

        // =========================
        // Certificate analysis
        // =========================
        if (hasArg(argc, argv, "--cert")) {
            std::string certFile = getArg(argc, argv, "--in");
            std::string issuerFile = getArg(argc, argv, "--issuer");
            std::string outFile = getArg(argc, argv, "--out");

            if (certFile.empty()) {
                throw HashException("--cert requires --in cert.pem");
            }

            CertificateAnalyzer analyzer;

            if (!analyzer.loadCertificate(certFile)) {
                return 1;
            }

            CertificateInfo info = analyzer.parseCertificate();

            if (!issuerFile.empty()) {
                info.signature_valid = analyzer.verifySignature(issuerFile);
            } else {
                info.signature_valid = analyzer.verifyTBSIntegrity();
            }

            analyzer.printCertificateInfo(info);

            if (!outFile.empty()) {
                std::ofstream out(outFile);

                if (!out.is_open()) {
                    throw HashException("Cannot open certificate report output: " + outFile);
                }

                out << analyzer.toJSON(info);

                if (!out.good()) {
                    throw HashException("Failed while writing certificate report: " + outFile);
                }

                std::cout << "\nCertificate report saved to: " << outFile << std::endl;
            }

            return info.validation_error.empty() ? 0 : 1;
        }

        // =========================
        // MD5 collision verification
        // =========================
        if (hasArg(argc, argv, "--md5-collision")) {
            std::string file1 = getArg(argc, argv, "--file1");
            std::string file2 = getArg(argc, argv, "--file2");

            if (file1.empty() || file2.empty()) {
                throw HashException("--md5-collision requires --file1 and --file2");
            }

            MD5CollisionDemo demo;
            bool ok = demo.verifyCollision(file1, file2);

            return ok ? 0 : 1;
        }

        if (hasArg(argc, argv, "--md5-demo")) {
            MD5CollisionDemo demo;
            bool ok = demo.createPythonDemo();

            return ok ? 0 : 1;
        }

        // =========================
        // SHA-256 custom length-extension bonus demo
        // =========================
        if (hasArg(argc, argv, "--length-extension-demo")) {
            CustomSHA256Extend demo;
            demo.demoAttack();

            return 0;
        }

        // =========================
        // Basic hashing
        // =========================
        std::string algo = getArg(argc, argv, "--algo");
        std::string inputFile = getArg(argc, argv, "--in");
        std::string inputText = getArg(argc, argv, "--text");
        std::string outputFile = getArg(argc, argv, "--out");
        std::string format = getArg(argc, argv, "--format", "hex");
        std::string outlenText = getArg(argc, argv, "--outlen", "32");

        if (algo.empty()) {
            throw HashException("Missing required --algo parameter");
        }

        if (inputFile.empty() && inputText.empty()) {
            throw HashException("Missing input: use --in FILE or --text \"...\"");
        }

        if (!inputFile.empty() && !inputText.empty()) {
            throw HashException("Use only one input source: --in FILE or --text \"...\"");
        }

        HashConfig config;
        config.algorithm = HashConfig::stringToAlgorithm(algo);
        config.output_format = HashConfig::stringToFormat(format);
        config.stream_mode = hasArg(argc, argv, "--stream");
        config.input_file = inputFile;
        config.output_file = outputFile;

        try {
            config.shake_output_length = static_cast<size_t>(std::stoul(outlenText));
        } catch (...) {
            throw HashException("Invalid --outlen value");
        }

        if ((config.algorithm == HashAlgorithm::SHAKE128 ||
             config.algorithm == HashAlgorithm::SHAKE256) &&
            config.shake_output_length == 0) {
            throw HashException("SHAKE output length must be greater than zero");
        }

        HashEngine engine;
        std::vector<uint8_t> digest;

        if (!inputFile.empty()) {
            digest = engine.hashFile(config, inputFile);
        } else {
            digest = engine.hashString(config, inputText);
        }

        if (config.output_format == OutputFormat::RAW) {
            if (outputFile.empty()) {
                throw HashException("Raw output requires --out FILE");
            }

            writeRawFile(outputFile, digest);
            std::cout << "Raw digest written to: " << outputFile << std::endl;

        } else {
            std::string hex = engine.hashToHex(digest);
            std::transform(hex.begin(), hex.end(), hex.begin(), ::tolower);

            if (!outputFile.empty()) {
                writeTextFile(outputFile, hex);
                std::cout << "Hex digest written to: " << outputFile << std::endl;
            } else {
                std::cout << hex << std::endl;
            }
        }

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}

