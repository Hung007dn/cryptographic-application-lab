// ManualOAEP.cpp
#include "ManualOAEP.hpp"
#include <cstring>
#include <stdexcept>
#include <iostream>

using namespace CryptoPP;

std::vector<uint8_t> ManualOAEP::hashLabel(const std::string& label) {
    std::vector<uint8_t> hash(HASH_SIZE);
    SHA256().CalculateDigest(hash.data(), 
                              reinterpret_cast<const byte*>(label.data()), 
                              label.size());
    return hash;
}

void ManualOAEP::xorBytes(std::vector<uint8_t>& target, const std::vector<uint8_t>& mask) {
    size_t len = std::min(target.size(), mask.size());
    for (size_t i = 0; i < len; i++) {
        target[i] ^= mask[i];
    }
}

bool ManualOAEP::constantTimeEquals(const std::vector<uint8_t>& a, 
                                     const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    
    uint8_t result = 0;
    for (size_t i = 0; i < a.size(); i++) {
        result |= a[i] ^ b[i];  // XOR = 0 if equal, non-zero if different
    }
    return result == 0;
}

std::vector<uint8_t> ManualOAEP::MGF1(const std::vector<uint8_t>& seed, size_t mask_len) {
    std::vector<uint8_t> mask;
    mask.reserve(mask_len);
    
    SHA256 hash;
    std::vector<uint8_t> counter(4, 0);  // 4-byte counter (big-endian)
    std::vector<uint8_t> input = seed;
    
    for (uint32_t c = 0; mask.size() < mask_len; c++) {
        // Update counter (big-endian)
        counter[0] = (c >> 24) & 0xFF;
        counter[1] = (c >> 16) & 0xFF;
        counter[2] = (c >> 8) & 0xFF;
        counter[3] = c & 0xFF;
        
        // Build input: seed || counter
        input.resize(seed.size());
        input.insert(input.end(), counter.begin(), counter.end());
        
        // Hash
        std::vector<uint8_t> digest(HASH_SIZE);
        hash.CalculateDigest(digest.data(), input.data(), input.size());
        
        // Append to mask
        size_t needed = mask_len - mask.size();
        size_t to_copy = std::min(needed, HASH_SIZE);
        mask.insert(mask.end(), digest.begin(), digest.begin() + to_copy);
        
        input.resize(seed.size());  // Reset to seed only
    }
    
    return mask;
}

std::vector<uint8_t> ManualOAEP::oaepEncode(const std::vector<uint8_t>& message,
                                             const std::string& label,
                                             size_t k) {
    size_t mLen = message.size();
    size_t maxLen = k - 2 * HASH_SIZE - 2;
    
    if (mLen > maxLen) {
        throw std::runtime_error("Message too long for OAEP encoding");
    }
    
    // Step 1: Hash label
    std::vector<uint8_t> lHash = hashLabel(label);
    
    // Step 2: Create padding string PS (zeros)
    size_t psLen = k - mLen - 2 * HASH_SIZE - 2;
    std::vector<uint8_t> PS(psLen, 0x00);
    
    // Step 3: Create data block DB = lHash || PS || 0x01 || M
    std::vector<uint8_t> DB;
    DB.insert(DB.end(), lHash.begin(), lHash.end());
    DB.insert(DB.end(), PS.begin(), PS.end());
    DB.push_back(0x01);
    DB.insert(DB.end(), message.begin(), message.end());
    
    // Step 4: Generate random seed
    AutoSeededRandomPool rng;
    std::vector<uint8_t> seed(HASH_SIZE);
    rng.GenerateBlock(seed.data(), seed.size());
    
    // Step 5: dbMask = MGF1(seed, k - HASH_SIZE - 1)
    size_t dbMaskLen = k - HASH_SIZE - 1;
    std::vector<uint8_t> dbMask = MGF1(seed, dbMaskLen);
    
    // Step 6: maskedDB = DB XOR dbMask
    std::vector<uint8_t> maskedDB = DB;
    xorBytes(maskedDB, dbMask);
    
    // Step 7: seedMask = MGF1(maskedDB, HASH_SIZE)
    std::vector<uint8_t> seedMask = MGF1(maskedDB, HASH_SIZE);
    
    // Step 8: maskedSeed = seed XOR seedMask
    std::vector<uint8_t> maskedSeed = seed;
    xorBytes(maskedSeed, seedMask);
    
    // Step 9: EM = 0x00 || maskedSeed || maskedDB
    std::vector<uint8_t> EM;
    EM.push_back(0x00);
    EM.insert(EM.end(), maskedSeed.begin(), maskedSeed.end());
    EM.insert(EM.end(), maskedDB.begin(), maskedDB.end());
    
    return EM;
}

std::vector<uint8_t> ManualOAEP::oaepDecode(const std::vector<uint8_t>& padded,
                                             const std::string& label,
                                             size_t k) {
    // Step 1: Parse EM = Y || maskedSeed || maskedDB
    if (padded.size() != k) {
        throw std::runtime_error("Invalid padded message length");
    }
    
    uint8_t Y = padded[0];
    std::vector<uint8_t> maskedSeed(padded.begin() + 1, 
                                     padded.begin() + 1 + HASH_SIZE);
    std::vector<uint8_t> maskedDB(padded.begin() + 1 + HASH_SIZE, 
                                   padded.end());
    
    // Step 2: seedMask = MGF1(maskedDB, HASH_SIZE)
    std::vector<uint8_t> seedMask = MGF1(maskedDB, HASH_SIZE);
    
    // Step 3: seed = maskedSeed XOR seedMask
    std::vector<uint8_t> seed = maskedSeed;
    xorBytes(seed, seedMask);
    
    // Step 4: dbMask = MGF1(seed, k - HASH_SIZE - 1)
    size_t dbMaskLen = k - HASH_SIZE - 1;
    std::vector<uint8_t> dbMask = MGF1(seed, dbMaskLen);
    
    // Step 5: DB = maskedDB XOR dbMask
    std::vector<uint8_t> DB = maskedDB;
    xorBytes(DB, dbMask);
    
    // Step 6: Extract lHash, PS, and message
    std::vector<uint8_t> lHash(DB.begin(), DB.begin() + HASH_SIZE);
    std::vector<uint8_t> expectedLHash = hashLabel(label);
    
    // Constant-time comparison for security!
    if (!constantTimeEquals(lHash, expectedLHash)) {
        throw std::runtime_error("Invalid label hash");
    }
    
    // Find the 0x01 separator
    size_t separatorPos = HASH_SIZE;
    while (separatorPos < DB.size() && DB[separatorPos] == 0x00) {
        separatorPos++;
    }
    
    // Constant-time validation of separator
    if (separatorPos >= DB.size() || DB[separatorPos] != 0x01) {
        throw std::runtime_error("Invalid padding");
    }
    
    // Extract message
    std::vector<uint8_t> message(DB.begin() + separatorPos + 1, DB.end());
    
    // Also check Y == 0 (constant-time)
    if (Y != 0) {
        throw std::runtime_error("Invalid leading byte");
    }
    
    return message;
}