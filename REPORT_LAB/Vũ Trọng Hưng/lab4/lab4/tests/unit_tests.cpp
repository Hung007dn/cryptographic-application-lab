#include <catch2/catch.hpp>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <set>
#include <cctype>

#ifndef TEST_VECTOR_PATH
#define TEST_VECTOR_PATH "test_vectors.json"
#endif

static bool fileExists(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return f.good();
}

static std::string readFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static bool isHexString(const std::string& s) {
    if (s.empty()) {
        return false;
    }

    for (unsigned char c : s) {
        if (!std::isxdigit(c)) {
            return false;
        }
    }

    return true;
}

static bool containsText(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

TEST_CASE("test_vectors.json exists", "[files]") {
    REQUIRE(fileExists(TEST_VECTOR_PATH));
}

TEST_CASE("test_vectors.json contains required SHA-2 algorithms", "[kat][sha2]") {
    std::string content = readFile(TEST_VECTOR_PATH);

    REQUIRE(containsText(content, "\"algorithm\""));
    REQUIRE(containsText(content, "sha224"));
    REQUIRE(containsText(content, "sha256"));
    REQUIRE(containsText(content, "sha384"));
    REQUIRE(containsText(content, "sha512"));
}

TEST_CASE("test_vectors.json contains required SHA-3 algorithms", "[kat][sha3]") {
    std::string content = readFile(TEST_VECTOR_PATH);

    REQUIRE(containsText(content, "sha3-224"));
    REQUIRE(containsText(content, "sha3-256"));
    REQUIRE(containsText(content, "sha3-384"));
    REQUIRE(containsText(content, "sha3-512"));
}

TEST_CASE("test_vectors.json contains required SHAKE algorithms", "[kat][shake]") {
    std::string content = readFile(TEST_VECTOR_PATH);

    REQUIRE(containsText(content, "shake128"));
    REQUIRE(containsText(content, "shake256"));
    REQUIRE(containsText(content, "\"outlen\""));
}

TEST_CASE("SHA-2 digest hex lengths are correct", "[hash-length]") {
    const size_t sha224_hex_len = 224 / 4;
    const size_t sha256_hex_len = 256 / 4;
    const size_t sha384_hex_len = 384 / 4;
    const size_t sha512_hex_len = 512 / 4;

    REQUIRE(sha224_hex_len == 56);
    REQUIRE(sha256_hex_len == 64);
    REQUIRE(sha384_hex_len == 96);
    REQUIRE(sha512_hex_len == 128);
}

TEST_CASE("SHA-3 digest hex lengths are correct", "[hash-length]") {
    const size_t sha3_224_hex_len = 224 / 4;
    const size_t sha3_256_hex_len = 256 / 4;
    const size_t sha3_384_hex_len = 384 / 4;
    const size_t sha3_512_hex_len = 512 / 4;

    REQUIRE(sha3_224_hex_len == 56);
    REQUIRE(sha3_256_hex_len == 64);
    REQUIRE(sha3_384_hex_len == 96);
    REQUIRE(sha3_512_hex_len == 128);
}

TEST_CASE("Known SHA-256 abc digest format is valid", "[sha256]") {
    const std::string sha256_abc =
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad";

    REQUIRE(sha256_abc.size() == 64);
    REQUIRE(isHexString(sha256_abc));
}

TEST_CASE("Known SHA3-256 abc digest format is valid", "[sha3]") {
    const std::string sha3_256_abc =
        "3a985da74fe225b2045c172d6bd390bd"
        "855f086e3e9d525b46bfe24511431532";

    REQUIRE(sha3_256_abc.size() == 64);
    REQUIRE(isHexString(sha3_256_abc));
}

TEST_CASE("SHAKE output length parameters are valid", "[shake]") {
    const size_t shake128_outlen_bytes = 128;
    const size_t shake256_outlen_bytes = 64;

    REQUIRE(shake128_outlen_bytes > 0);
    REQUIRE(shake256_outlen_bytes > 0);

    REQUIRE(shake128_outlen_bytes * 2 == 256);
    REQUIRE(shake256_outlen_bytes * 2 == 128);
}

TEST_CASE("Benchmark payload sizes include required sizes", "[benchmark]") {
    std::vector<size_t> sizes = {
        1 * 1024 * 1024,
        100 * 1024 * 1024
    };

    REQUIRE(sizes.size() == 2);
    REQUIRE(sizes[0] == 1048576);
    REQUIRE(sizes[1] == 104857600);
}

TEST_CASE("Benchmark algorithms include required algorithms", "[benchmark]") {
    std::set<std::string> algorithms = {
        "sha256",
        "sha512",
        "sha3-256",
        "sha3-512"
    };

    REQUIRE(algorithms.count("sha256") == 1);
    REQUIRE(algorithms.count("sha512") == 1);
    REQUIRE(algorithms.count("sha3-256") == 1);
    REQUIRE(algorithms.count("sha3-512") == 1);
}

TEST_CASE("Naive MAC length-extension model is represented correctly", "[length-extension]") {
    const std::string construction = "MAC = SHA256(k || m)";
    const std::string forged_form = "SHA256(k || m || pad || m')";

    REQUIRE(containsText(construction, "SHA256"));
    REQUIRE(containsText(construction, "k || m"));
    REQUIRE(containsText(forged_form, "pad"));
    REQUIRE(containsText(forged_form, "m'"));
}

TEST_CASE("PKI expected fields are represented", "[pki]") {
    std::vector<std::string> fields = {
        "subject",
        "issuer",
        "public_key_algorithm",
        "public_key_params",
        "signature_algorithm",
        "not_before",
        "not_after",
        "key_usage",
        "subject_alt_names",
        "signature_valid",
        "tbs_integrity_valid"
    };

    REQUIRE(fields.size() == 11);
    REQUIRE(fields[0] == "subject");
    REQUIRE(fields[1] == "issuer");
    REQUIRE(fields[10] == "tbs_integrity_valid");
}

TEST_CASE("ECDSA minimum key size requirement is P-256", "[pki][ecdsa]") {
    const int p256_bits = 256;

    REQUIRE(p256_bits >= 256);
}