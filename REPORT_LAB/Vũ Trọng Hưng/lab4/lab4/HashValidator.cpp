
// HashValidator.cpp
#include "HashValidator.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>

HashValidator::HashValidator() = default;

std::vector<uint8_t> HashValidator::hexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("Invalid hex string length");
    }

    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
        result.push_back(byte);
    }

    return result;
}

std::string HashValidator::bytesToHex(const std::vector<uint8_t>& bytes) {
    std::string result;

    for (uint8_t byte : bytes) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", byte);
        result += buf;
    }

    return result;
}

bool HashValidator::compareBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) {
        return false;
    }

    if (a.empty()) {
        return true;
    }

    return std::memcmp(a.data(), b.data(), a.size()) == 0;
}

bool HashValidator::testSHA2_KAT(const json& vector) {
    std::string algo = vector["algorithm"];
    std::string input_hex = vector["input"];
    std::string expected_hex = vector["expected"];

    HashConfig config;
    config.algorithm = HashConfig::stringToAlgorithm(algo);

    auto input = hexToBytes(input_hex);
    std::string input_str(input.begin(), input.end());

    auto result = m_engine.hashString(config, input_str);
    auto result_hex = bytesToHex(result);

    std::transform(result_hex.begin(), result_hex.end(), result_hex.begin(), ::tolower);

    std::string expected_lower = expected_hex;
    std::transform(expected_lower.begin(), expected_lower.end(), expected_lower.begin(), ::tolower);

    if (result_hex != expected_lower) {
        std::cout << "\n    Expected: " << expected_lower << std::endl;
        std::cout << "    Actual:   " << result_hex << std::endl;
        std::cout << "    Expected length: " << expected_lower.size()
                  << " hex chars, Actual length: " << result_hex.size()
                  << " hex chars" << std::endl;
    }

    return result_hex == expected_lower;
}

bool HashValidator::testSHA3_KAT(const json& vector) {
    return testSHA2_KAT(vector);
}

bool HashValidator::testSHAKE_KAT(const json& vector) {
    std::string algo = vector["algorithm"];
    std::string input_hex = vector["input"];
    std::string expected_hex = vector["expected"];
    size_t outlen = vector["outlen"];

    HashConfig config;
    config.algorithm = HashConfig::stringToAlgorithm(algo);
    config.shake_output_length = outlen;

    auto input = hexToBytes(input_hex);
    std::string input_str(input.begin(), input.end());

    auto result = m_engine.hashString(config, input_str);
    auto result_hex = bytesToHex(result);

    std::transform(result_hex.begin(), result_hex.end(), result_hex.begin(), ::tolower);

    std::string expected_lower = expected_hex;
    std::transform(expected_lower.begin(), expected_lower.end(), expected_lower.begin(), ::tolower);

    if (result_hex != expected_lower) {
        std::cout << "\n    Expected: " << expected_lower << std::endl;
        std::cout << "    Actual:   " << result_hex << std::endl;
        std::cout << "    Expected length: " << expected_lower.size()
                  << " hex chars, Actual length: " << result_hex.size()
                  << " hex chars" << std::endl;
    }

    return result_hex == expected_lower;
}

bool HashValidator::runFromFile(const std::string& json_file) {
    std::ifstream file(json_file);

    if (!file.good()) {
        std::cerr << "Cannot open: " << json_file << std::endl;
        return false;
    }

    json data;
    file >> data;

    std::cout << "\n=== Hash Function KAT Test Suite ===\n" << std::endl;

    m_results.clear();

    for (const auto& test : data["tests"]) {
        KATResult result;
        result.name = test.value("name", "Unnamed");
        result.algorithm = test.value("algorithm", "unknown");

        auto start = std::chrono::high_resolution_clock::now();

        try {
            std::string algo_lower = result.algorithm;
            std::transform(algo_lower.begin(), algo_lower.end(), algo_lower.begin(), ::tolower);

            if (algo_lower.find("shake") != std::string::npos) {
                result.passed = testSHAKE_KAT(test);
            } else if (algo_lower.find("sha3") != std::string::npos) {
                result.passed = testSHA3_KAT(test);
            } else {
                result.passed = testSHA2_KAT(test);
            }

        } catch (const std::exception& e) {
            result.passed = false;
            result.error_message = e.what();
        }

        auto end = std::chrono::high_resolution_clock::now();

        result.execution_time_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        m_results.push_back(result);

        std::cout << (result.passed ? "[PASSED] " : "[FAILED] ")
                  << std::setw(45) << std::left << result.name
                  << " (" << result.execution_time_ms << "ms)" << std::endl;

        if (!result.passed && !result.error_message.empty()) {
            std::cout << "    Error: " << result.error_message << std::endl;
        }
    }

    printSummary();

    for (const auto& r : m_results) {
        if (!r.passed) {
            return false;
        }
    }

    return true;
}

bool HashValidator::runNISTTests() {
    std::cout << "\n=== NIST Hash Function Validation ===\n" << std::endl;

    struct TestVector {
        std::string name;
        std::string algo;
        std::string input;
        std::string expected;
    };

    std::vector<TestVector> vectors = {
        {"SHA-224 Empty", "sha224", "", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"},
        {"SHA-224 abc", "sha224", "616263", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},

        {"SHA-256 Empty", "sha256", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"SHA-256 abc", "sha256", "616263", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},

        {"SHA-384 Empty", "sha384", "", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"},
        {"SHA-384 abc", "sha384", "616263", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},

        {"SHA-512 Empty", "sha512", "", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
        {"SHA-512 abc", "sha512", "616263", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},

        {"SHA3-256 Empty", "sha3-256", "", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
        {"SHA3-256 abc", "sha3-256", "616263", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"}
    };

    size_t passed_count = 0;

    for (const auto& v : vectors) {
        try {
            HashConfig config;
            config.algorithm = HashConfig::stringToAlgorithm(v.algo);

            auto input = hexToBytes(v.input);
            std::string input_str(input.begin(), input.end());

            auto result = m_engine.hashString(config, input_str);
            auto result_hex = bytesToHex(result);

            std::transform(result_hex.begin(), result_hex.end(), result_hex.begin(), ::tolower);

            std::string expected_lower = v.expected;
            std::transform(expected_lower.begin(), expected_lower.end(), expected_lower.begin(), ::tolower);

            bool passed = (result_hex == expected_lower);

            if (passed) {
                passed_count++;
            }

            std::cout << "[NIST] " << std::setw(35) << std::left << v.name
                      << (passed ? "[PASSED]" : "[FAILED]") << std::endl;

            if (!passed) {
                std::cout << "    Expected: " << expected_lower << std::endl;
                std::cout << "    Actual:   " << result_hex << std::endl;
            }

        } catch (const std::exception& e) {
            std::cout << "[NIST] " << std::setw(35) << std::left << v.name
                      << "[FAILED] (" << e.what() << ")" << std::endl;
        }
    }

    std::cout << "\nNIST Tests: " << passed_count << "/" << vectors.size()
              << " passed" << std::endl;

    return passed_count == vectors.size();
}

void HashValidator::printSummary() {
    size_t passed = 0;

    for (const auto& r : m_results) {
        if (r.passed) {
            passed++;
        }
    }

    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << "Total: " << m_results.size() << std::endl;
    std::cout << "Passed: " << passed << std::endl;
    std::cout << "Failed: " << (m_results.size() - passed) << std::endl;

    if (!m_results.empty()) {
        std::cout << "Success rate: " << (passed * 100.0 / m_results.size()) << "%" << std::endl;
    }
}

void HashValidator::exportResults(const std::string& output_file) {
    json results_json = json::array();

    for (const auto& r : m_results) {
        results_json.push_back({
            {"name", r.name},
            {"algorithm", r.algorithm},
            {"passed", r.passed},
            {"execution_time_ms", r.execution_time_ms},
            {"error", r.error_message}
        });
    }

    std::ofstream file(output_file);
    file << results_json.dump(4);

    std::cout << "Results exported to " << output_file << std::endl;
}

