// ManualRSAPSS.cpp - Đã sửa hoàn chỉnh
#include "ManualRSAPSS.hpp"
#include "ModularArithmetic.hpp"

#include <cryptopp/sha.h>
#include <cstring>
#include <cryptopp/osrng.h>
#include <stdexcept>
using namespace CryptoPP;

// ============ Forward declarations ============
static std::vector<uint8_t> hash(const std::vector<uint8_t>& data);
static std::vector<uint8_t> hash2(const std::vector<uint8_t>& data1, const std::vector<uint8_t>& data2);

std::vector<uint8_t> hash(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result(ManualRSAPSS::HASH_SIZE);
    SHA256().CalculateDigest(result.data(), data.data(), data.size());
    return result;
}

std::vector<uint8_t> hash2(const std::vector<uint8_t>& data1, const std::vector<uint8_t>& data2) {
    SHA256 hash;
    hash.Update(data1.data(), data1.size());
    hash.Update(data2.data(), data2.size());
    std::vector<uint8_t> result(ManualRSAPSS::HASH_SIZE);
    hash.Final(result.data());
    return result;
}

void ManualRSAPSS::xorBytes(std::vector<uint8_t>& target, const std::vector<uint8_t>& mask) {
    for (size_t i = 0; i < target.size() && i < mask.size(); i++) {
        target[i] ^= mask[i];
    }
}

std::vector<uint8_t> ManualRSAPSS::i2osp(uint32_t x, size_t len) {
    std::vector<uint8_t> result(len, 0);
    for (size_t i = 0; i < len; i++) {
        result[len - 1 - i] = (x >> (i * 8)) & 0xFF;
    }
    return result;
}

uint32_t ManualRSAPSS::os2ip(const std::vector<uint8_t>& bytes) {
    uint32_t result = 0;
    for (size_t i = 0; i < bytes.size() && i < 4; i++) {
        result = (result << 8) | bytes[i];
    }
    return result;
}

std::vector<uint8_t> ManualRSAPSS::mgf1(const std::vector<uint8_t>& seed, size_t maskLen) {
    std::vector<uint8_t> mask;
    mask.reserve(maskLen);
    
    for (uint32_t counter = 0; mask.size() < maskLen; counter++) {
        std::vector<uint8_t> input = seed;
        auto counterBytes = i2osp(counter, 4);
        input.insert(input.end(), counterBytes.begin(), counterBytes.end());
        
        auto digest = ::hash(input);
        
        size_t needed = maskLen - mask.size();
        size_t toCopy = std::min(needed, HASH_SIZE);
        mask.insert(mask.end(), digest.begin(), digest.begin() + toCopy);
    }
    
    return mask;
}

std::vector<uint8_t> ManualRSAPSS::generateSalt(size_t saltLen) {
    std::vector<uint8_t> salt(saltLen);
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(salt.data(), salt.size());
    return salt;
}
std::vector<uint8_t> ManualRSAPSS::encodePSS(
    const std::vector<uint8_t>& messageHash,
    size_t emBits,
    const std::vector<uint8_t>& salt
) {
    const size_t hLen = HASH_SIZE;
    const size_t sLen = salt.size();
    const size_t emLen = (emBits + 7) / 8;

    if (messageHash.size() != hLen) {
        throw std::runtime_error("PSS encode: invalid message hash length");
    }

    if (emLen < hLen + sLen + 2) {
        throw std::runtime_error("PSS encode: encoded message too short");
    }

    // RFC 8017:
    // M' = 0x00 00 00 00 00 00 00 00 || mHash || salt
    std::vector<uint8_t> mPrime(8, 0x00);
    mPrime.insert(mPrime.end(), messageHash.begin(), messageHash.end());
    mPrime.insert(mPrime.end(), salt.begin(), salt.end());

    // H = Hash(M')
    auto H = ::hash(mPrime);

    // DB = PS || 0x01 || salt
    // PS length = emLen - sLen - hLen - 2
    const size_t psLen = emLen - sLen - hLen - 2;

    std::vector<uint8_t> DB(psLen, 0x00);
    DB.push_back(0x01);
    DB.insert(DB.end(), salt.begin(), salt.end());

    // dbMask = MGF1(H, emLen - hLen - 1)
    auto dbMask = mgf1(H, emLen - hLen - 1);

    // maskedDB = DB XOR dbMask
    auto maskedDB = DB;
    xorBytes(maskedDB, dbMask);

    // Set leftmost 8emLen - emBits bits of maskedDB[0] to zero
    const size_t unusedBits = 8 * emLen - emBits;
    if (unusedBits > 0) {
        maskedDB[0] &= static_cast<uint8_t>(0xFF >> unusedBits);
    }

    // EM = maskedDB || H || 0xbc
    std::vector<uint8_t> EM;
    EM.insert(EM.end(), maskedDB.begin(), maskedDB.end());
    EM.insert(EM.end(), H.begin(), H.end());
    EM.push_back(0xBC);

    return EM;
}

bool ManualRSAPSS::verifyPSS(
    const std::vector<uint8_t>& messageHash,
    const std::vector<uint8_t>& EM,
    size_t emBits,
    const std::vector<uint8_t>& salt
) {
    const size_t hLen = HASH_SIZE;
    const size_t sLen = salt.size();
    const size_t emLen = (emBits + 7) / 8;

    if (messageHash.size() != hLen) {
        return false;
    }

    if (EM.size() != emLen) {
        return false;
    }

    if (emLen < hLen + sLen + 2) {
        return false;
    }

    if (EM.back() != 0xBC) {
        return false;
    }

    const size_t dbLen = emLen - hLen - 1;

    // Split EM = maskedDB || H || 0xbc
    std::vector<uint8_t> maskedDB(EM.begin(), EM.begin() + dbLen);
    std::vector<uint8_t> H(EM.begin() + dbLen, EM.end() - 1);

    // Check leftmost unused bits of maskedDB[0] are zero
    const size_t unusedBits = 8 * emLen - emBits;
    if (unusedBits > 0) {
        uint8_t forbiddenMask = static_cast<uint8_t>(0xFF << (8 - unusedBits));
        if ((maskedDB[0] & forbiddenMask) != 0) {
            return false;
        }
    }

    // DB = maskedDB XOR MGF1(H, dbLen)
    auto dbMask = mgf1(H, dbLen);
    auto DB = maskedDB;
    xorBytes(DB, dbMask);

    // Clear leftmost unused bits of DB[0]
    if (unusedBits > 0) {
        DB[0] &= static_cast<uint8_t>(0xFF >> unusedBits);
    }

    // Expected DB = PS || 0x01 || salt
    const size_t psLen = emLen - sLen - hLen - 2;

    // PS must be all zero
    for (size_t i = 0; i < psLen; ++i) {
        if (DB[i] != 0x00) {
            return false;
        }
    }

    // Separator must be 0x01
    if (DB[psLen] != 0x01) {
        return false;
    }

    // Salt must match expected salt
    std::vector<uint8_t> recoveredSalt(
        DB.begin() + psLen + 1,
        DB.end()
    );

    if (!ModularArithmetic::constantTimeCompare(recoveredSalt, salt)) {
        return false;
    }

    // Recompute H' = Hash(0x00...00 || mHash || salt)
    std::vector<uint8_t> mPrime(8, 0x00);
    mPrime.insert(mPrime.end(), messageHash.begin(), messageHash.end());
    mPrime.insert(mPrime.end(), recoveredSalt.begin(), recoveredSalt.end());

    auto H2 = ::hash(mPrime);

    return ModularArithmetic::constantTimeCompare(H, H2);
}