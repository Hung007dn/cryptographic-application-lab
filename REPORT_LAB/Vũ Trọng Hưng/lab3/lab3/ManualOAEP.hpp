// ManualOAEP.hpp
#pragma once
#include <vector>
#include <string>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>

class ManualOAEP {
public:
    // OAEP parameters
    static constexpr size_t HASH_SIZE = CryptoPP::SHA256::DIGESTSIZE;  // 32 bytes
    static constexpr size_t LABEL_HASH_SIZE = HASH_SIZE;
    
    /**
     * MGF1 - Mask Generation Function (RFC 8017)
     * @param seed Input seed
     * @param mask_len Desired output length
     * @return Generated mask
     */
    static std::vector<uint8_t> MGF1(const std::vector<uint8_t>& seed, size_t mask_len);
    
    /**
     * OAEP Encode (padding)
     * @param message Plaintext message
     * @param label Optional label (can be empty)
     * @param k RSA modulus size in bytes
     * @return Padded message ready for RSA encryption
     * @throws std::runtime_error if message too long
     */
    static std::vector<uint8_t> oaepEncode(const std::vector<uint8_t>& message,
                                            const std::string& label,
                                            size_t k);
    
    /**
     * OAEP Decode (unpadding) with constant-time validation
     * @param padded Padded message from RSA decryption
     * @param label Expected label (must match encoding)
     * @param k RSA modulus size in bytes
     * @return Original message
     * @throws std::runtime_error if padding invalid (constant-time)
     */
    static std::vector<uint8_t> oaepDecode(const std::vector<uint8_t>& padded,
                                            const std::string& label,
                                            size_t k);
    
    /**
     * Constant-time comparison (prevents timing attacks)
     */
    static bool constantTimeEquals(const std::vector<uint8_t>& a,
                                    const std::vector<uint8_t>& b);
    
private:
    static void xorBytes(std::vector<uint8_t>& target, const std::vector<uint8_t>& mask);
    static std::vector<uint8_t> hashLabel(const std::string& label);
};