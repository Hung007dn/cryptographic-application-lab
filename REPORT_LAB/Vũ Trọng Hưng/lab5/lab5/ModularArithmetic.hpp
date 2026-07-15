// ModularArithmetic.hpp
#pragma once
#include <vector>
#include <cstdint>

class ModularArithmetic {
public:
    // Modular exponentiation: base^exp mod mod
    // Constant-time implementation using square-and-multiply
    static std::vector<uint8_t> modExp(const std::vector<uint8_t>& base,
                                        const std::vector<uint8_t>& exp,
                                        const std::vector<uint8_t>& mod);
    
    // Modular multiplication: a * b mod mod
    static std::vector<uint8_t> modMul(const std::vector<uint8_t>& a,
                                        const std::vector<uint8_t>& b,
                                        const std::vector<uint8_t>& mod);
    
    // Extended Euclidean Algorithm for modular inverse
    static std::vector<uint8_t> modInverse(const std::vector<uint8_t>& a,
                                            const std::vector<uint8_t>& mod);
    
    // Compare in constant time (prevents timing attacks)
    static bool constantTimeCompare(const std::vector<uint8_t>& a,
                                     const std::vector<uint8_t>& b);
    
    // Montgomery multiplication (faster for repeated operations)
    static void montgomeryMultiply(uint32_t* result,
                                    const uint32_t* a,
                                    const uint32_t* b,
                                    const uint32_t* mod,
                                    size_t len,
                                    uint32_t inv);
    
private:
    // Helper: add with carry (constant-time)
    static uint8_t addWithCarry(uint8_t* a, uint8_t b, uint8_t carry);
    
    // Helper: subtract with borrow (constant-time)
    static uint8_t subWithBorrow(uint8_t* a, uint8_t b, uint8_t borrow);
};