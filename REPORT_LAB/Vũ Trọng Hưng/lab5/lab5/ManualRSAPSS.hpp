// ManualRSAPSS.hpp
#pragma once
#include <vector>
#include <string>
#include <cryptopp/sha.h>

class ManualRSAPSS {
public:
    static constexpr size_t HASH_SIZE = CryptoPP::SHA256::DIGESTSIZE;  // 32 bytes
    
    // PSS padding generation (RFC 8017)
    static std::vector<uint8_t> encodePSS(const std::vector<uint8_t>& messageHash,
                                           size_t emBits,
                                           const std::vector<uint8_t>& salt);
    
    // PSS padding verification
    static bool verifyPSS(const std::vector<uint8_t>& messageHash,
                          const std::vector<uint8_t>& em,
                          size_t emBits,
                          const std::vector<uint8_t>& salt);
    
    // MGF1 mask generation function
    static std::vector<uint8_t> mgf1(const std::vector<uint8_t>& seed, size_t maskLen);
    
    // I2OSP and OS2IP conversions
    static std::vector<uint8_t> i2osp(uint32_t x, size_t len);
    static uint32_t os2ip(const std::vector<uint8_t>& bytes);
    
    // Generate random salt
    static std::vector<uint8_t> generateSalt(size_t saltLen);
    
private:
    // XOR two byte arrays (constant-time)
    static void xorBytes(std::vector<uint8_t>& target, const std::vector<uint8_t>& mask);
    
    // Hash helper
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& data1,
                                      const std::vector<uint8_t>& data2);
};