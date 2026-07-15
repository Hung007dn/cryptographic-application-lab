#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

struct SHA256State {
    uint32_t h[8];
    uint64_t length;
};

class CustomSHA256Extend {
public:
    CustomSHA256Extend();
    ~CustomSHA256Extend();

    uint32_t rotr(uint32_t x, uint32_t n);
    uint32_t shr(uint32_t x, uint32_t n);
    uint32_t ch(uint32_t x, uint32_t y, uint32_t z);
    uint32_t maj(uint32_t x, uint32_t y, uint32_t z);
    uint32_t sigma0(uint32_t x);
    uint32_t sigma1(uint32_t x);
    uint32_t gamma0(uint32_t x);
    uint32_t gamma1(uint32_t x);

    void compress(uint32_t state[8], const uint8_t* block);

    std::vector<uint8_t> generatePadding(size_t message_length_bytes);

    SHA256State reconstructState(const std::string& hash_hex, size_t original_length);

    std::string lengthExtend(const std::string& original_hash,
                             size_t key_length,
                             const std::string& original_message,
                             const std::string& append_data);

    std::string sha256(const std::string& data);

    std::string vulnerableMAC(const std::string& key, const std::string& message);

    void demoAttack();

    void explainStateManipulation();

private:
    std::string bytesToHex(const std::vector<uint8_t>& bytes);
    std::vector<uint8_t> hexToBytes(const std::string& hex);
    std::vector<uint8_t> stringToBytes(const std::string& str);

    static const uint32_t K[64];
};