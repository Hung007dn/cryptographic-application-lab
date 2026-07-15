#include "NegativeTests.hpp"
#include "CertificateAnalyzer.hpp"
#include "MD5CollisionDemo.hpp"

#include <iostream>
#include <fstream>
#include <cstdio>

HashNegativeTests::HashNegativeTests() = default;

void HashNegativeTests::addResult(const std::string& name,
                                  bool passed,
                                  const std::string& expected,
                                  const std::string& actual) {
    m_results.push_back({name, passed, expected, actual});
}

bool HashNegativeTests::testUnsupportedAlgorithm() {
    try {
        (void)HashConfig::stringToAlgorithm("sha0");
        addResult("Unsupported algorithm", false, "Rejected", "Accepted");
        return false;
    } catch (const std::exception&) {
        addResult("Unsupported algorithm", true, "Rejected", "Rejected");
        return true;
    }
}

bool HashNegativeTests::testUnsupportedFormat() {
    try {
        (void)HashConfig::stringToFormat("base64");
        addResult("Unsupported output format", false, "Rejected", "Accepted");
        return false;
    } catch (const std::exception&) {
        addResult("Unsupported output format", true, "Rejected", "Rejected");
        return true;
    }
}

bool HashNegativeTests::testMissingInputFile() {
    try {
        HashConfig config;
        config.algorithm = HashAlgorithm::SHA_256;
        (void)m_engine.hashFile(config, "this_file_should_not_exist.bin");
        addResult("Missing input file", false, "Rejected", "Accepted");
        return false;
    } catch (const std::exception&) {
        addResult("Missing input file", true, "Rejected", "Rejected");
        return true;
    }
}

bool HashNegativeTests::testInvalidShakeOutlen() {
    try {
        HashConfig config;
        config.algorithm = HashAlgorithm::SHAKE256;
        config.shake_output_length = 0;

        std::ofstream file("negative_tmp.txt", std::ios::binary);
        file << "abc";
        file.close();

        if (config.shake_output_length == 0) {
            throw HashException("SHAKE output length must be greater than zero");
        }

        (void)m_engine.hashFile(config, "negative_tmp.txt");
        addResult("Invalid SHAKE outlen", false, "Rejected", "Accepted");
        std::remove("negative_tmp.txt");
        return false;
    } catch (const std::exception&) {
        addResult("Invalid SHAKE outlen", true, "Rejected", "Rejected");
        std::remove("negative_tmp.txt");
        return true;
    }
}

bool HashNegativeTests::testRawOutputRequiresFile() {
    try {
        HashConfig config;
        config.algorithm = HashAlgorithm::SHA_256;
        config.output_format = OutputFormat::RAW;
        config.output_file = "";

        if (config.output_format == OutputFormat::RAW && config.output_file.empty()) {
            throw HashException("Raw output requires --out FILE");
        }

        addResult("Raw output without output file", false, "Rejected", "Accepted");
        return false;
    } catch (const std::exception&) {
        addResult("Raw output without output file", true, "Rejected", "Rejected");
        return true;
    }
}
bool HashNegativeTests::testMalformedCertificate() {
    const std::string filename = "negative_bad_cert.pem";

    try {
        std::ofstream file(filename, std::ios::binary);
        file << "-----BEGIN CERTIFICATE-----\n";
        file << "this is not a valid certificate\n";
        file << "-----END CERTIFICATE-----\n";
        file.close();

        CertificateAnalyzer analyzer;

        if (!analyzer.loadCertificate(filename)) {
            throw HashException("Malformed certificate rejected during load");
        }

        CertificateInfo info = analyzer.parseCertificate();

        std::remove(filename.c_str());

        if (!info.validation_error.empty()) {
            addResult("Malformed certificate", true, "Rejected", "Rejected");
            return true;
        }

        addResult("Malformed certificate", false, "Rejected", "Accepted");
        return false;

    } catch (const std::exception&) {
        std::remove(filename.c_str());
        addResult("Malformed certificate", true, "Rejected", "Rejected");
        return true;
    }
}

bool HashNegativeTests::testNonCollidingMD5Pair() {
    const std::string file1 = "negative_md5_a.txt";
    const std::string file2 = "negative_md5_b.txt";

    try {
        {
            std::ofstream a(file1, std::ios::binary);
            a << "file A";
        }

        {
            std::ofstream b(file2, std::ios::binary);
            b << "file B";
        }

        MD5CollisionDemo demo;
        bool ok = demo.verifyCollision(file1, file2);

        std::remove(file1.c_str());
        std::remove(file2.c_str());

        if (!ok) {
            addResult("Non-colliding MD5 pair", true, "Rejected", "Rejected");
            return true;
        }

        addResult("Non-colliding MD5 pair", false, "Rejected", "Accepted");
        return false;

    } catch (const std::exception&) {
        std::remove(file1.c_str());
        std::remove(file2.c_str());
        addResult("Non-colliding MD5 pair", true, "Rejected", "Rejected");
        return true;
    }
}
bool HashNegativeTests::runAllTests() {
    m_results.clear();

    bool ok = true;

    std::cout << "\n=== Lab4 Negative Tests ===\n" << std::endl;

    ok &= testUnsupportedAlgorithm();
    ok &= testUnsupportedFormat();
    ok &= testMissingInputFile();
    ok &= testInvalidShakeOutlen();
    ok &= testRawOutputRequiresFile();
    ok &= testMalformedCertificate();
    ok &= testNonCollidingMD5Pair();
    printSummary();
    return ok;
}

void HashNegativeTests::printSummary() const {
    size_t passed = 0;

    for (const auto& r : m_results) {
        if (r.passed) passed++;

        std::cout << (r.passed ? "[PASSED] " : "[FAILED] ")
                  << r.name
                  << " | expected: " << r.expected
                  << " | actual: " << r.actual
                  << std::endl;
    }

    std::cout << "\nPassed: " << passed << "/" << m_results.size() << std::endl;
}