
// HashEngine.hpp
#pragma once

#include "HashConfig.hpp"

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

class HashEngine {
public:
    HashEngine();
    ~HashEngine();

    // Hash a file using streaming I/O.
    std::vector<uint8_t> hashFile(const HashConfig& config, const std::string& filename);

    // Hash a UTF-8 string / byte string.
    std::vector<uint8_t> hashString(const HashConfig& config, const std::string& data);

    // Convert hash bytes to lowercase hex string.
    std::string hashToHex(const std::vector<uint8_t>& hash);

    // Return raw hash bytes.
    std::vector<uint8_t> hashToRaw(const std::vector<uint8_t>& hash);

    // Constant-time hash comparison.
    bool verifyHash(const std::vector<uint8_t>& hash1, const std::vector<uint8_t>& hash2);

    // Get digest size for an algorithm.
    size_t getDigestSize(const HashConfig& config);
};


    
