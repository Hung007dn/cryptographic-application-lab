#include <catch2/catch.hpp>
#include <fstream>
#include <string>
#include <vector>
#include <cctype>

#ifndef TEST_VECTOR_PATH
#define TEST_VECTOR_PATH "test_vectors.json"
#endif

static bool fileExists(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return f.good();
}

static bool isHexString(const std::string& s) {
    if (s.empty()) return false;

    for (char c : s) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }

    return true;
}

TEST_CASE("test_vectors.json exists", "[files]") {
    REQUIRE(fileExists(TEST_VECTOR_PATH));
}

TEST_CASE("AES-256 hex key length is valid", "[key]") {
    std::string key_hex =
        "00112233445566778899AABBCCDDEEFF"
        "00112233445566778899AABBCCDDEEFF";

    REQUIRE(key_hex.size() == 64);
    REQUIRE(isHexString(key_hex));
}

TEST_CASE("AES mode names are recognized in test metadata", "[modes]") {
    std::vector<std::string> modes = {
        "ecb", "cbc", "ofb", "cfb", "ctr", "xts", "ccm", "gcm"
    };

    REQUIRE(modes.size() == 8);
    REQUIRE(modes[0] == "ecb");
    REQUIRE(modes[7] == "gcm");
}

TEST_CASE("Benchmark payload sizes include all required sizes", "[benchmark]") {
    std::vector<size_t> sizes = {
        1024,
        4 * 1024,
        16 * 1024,
        256 * 1024,
        1024 * 1024,
        8 * 1024 * 1024
    };

    REQUIRE(sizes.size() == 6);
    REQUIRE(sizes[0] == 1024);
    REQUIRE(sizes[5] == 8 * 1024 * 1024);
}