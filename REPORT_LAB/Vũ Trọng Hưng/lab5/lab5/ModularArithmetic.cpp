// ModularArithmetic.cpp
#include "ModularArithmetic.hpp"
#include <cstring>
#include <algorithm>
#include <stdexcept>

using namespace std;

uint8_t ModularArithmetic::addWithCarry(uint8_t* a, uint8_t b, uint8_t carry) {
    uint16_t sum = *a + b + carry;
    *a = sum & 0xFF;
    return (sum >> 8) & 0xFF;
}

uint8_t ModularArithmetic::subWithBorrow(uint8_t* a, uint8_t b, uint8_t borrow) {
    uint16_t diff = *a - b - borrow;
    *a = diff & 0xFF;
    return (diff >> 8) & 0x01;
}

bool ModularArithmetic::constantTimeCompare(const vector<uint8_t>& a,
                                              const vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    
    uint8_t result = 0;
    for (size_t i = 0; i < a.size(); i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

vector<uint8_t> ModularArithmetic::modMul(const vector<uint8_t>& a,
                                           const vector<uint8_t>& b,
                                           const vector<uint8_t>& mod) {
    // Simple multiplication with modulo (can be optimized with Montgomery)
    vector<uint8_t> result(mod.size(), 0);
    
    // Grade school multiplication
    for (size_t i = 0; i < a.size(); i++) {
        uint16_t carry = 0;
        for (size_t j = 0; j < b.size(); j++) {
            uint16_t prod = (uint16_t)a[i] * b[j] + carry;
            if (i + j < result.size()) {
                prod += result[i + j];
            }
            carry = prod >> 8;
            if (i + j < result.size()) {
                result[i + j] = prod & 0xFF;
            }
        }
        if (carry > 0 && i + b.size() < result.size()) {
            result[i + b.size()] += carry;
        }
    }
    
    // Modulo reduction (simple subtraction)
    while (result.size() > mod.size()) {
        result.pop_back();
    }
    
    while (result.size() < mod.size()) {
        result.insert(result.begin(), 0);
    }
    
    // Subtract mod if result >= mod
    bool greater = false;
    for (size_t i = 0; i < mod.size(); i++) {
        if (result[i] > mod[i]) {
            greater = true;
            break;
        } else if (result[i] < mod[i]) {
            break;
        }
    }
    
    if (greater) {
        uint8_t borrow = 0;
        for (size_t i = mod.size(); i > 0; i--) {
            uint16_t diff = result[i - 1] - mod[i - 1] - borrow;
            result[i - 1] = diff & 0xFF;
            borrow = (diff >> 8) & 0x01;
        }
    }
    
    // Remove leading zeros
    while (result.size() > 1 && result[0] == 0) {
        result.erase(result.begin());
    }
    
    return result;
}

vector<uint8_t> ModularArithmetic::modExp(const vector<uint8_t>& base,
                                           const vector<uint8_t>& exp,
                                           const vector<uint8_t>& mod) {
    vector<uint8_t> result = {1};
    vector<uint8_t> current = base;
    
    // Square and multiply (constant-time implementation)
    for (int i = exp.size() * 8 - 1; i >= 0; i--) {
        // Always square (constant-time)
        result = modMul(result, result, mod);
        
        // Conditionally multiply based on bit (constant-time with bit mask)
        size_t byteIdx = i / 8;
        size_t bitIdx = i % 8;
        uint8_t bit = 0;
        if (byteIdx < exp.size()) {
            bit = (exp[exp.size() - 1 - byteIdx] >> bitIdx) & 1;
        }
        
        // Always compute multiplication, but conditionally use result
        auto temp = modMul(result, current, mod);
        
        // Constant-time select
        for (size_t j = 0; j < result.size(); j++) {
            result[j] = (temp[j] & bit) | (result[j] & ~bit);
        }
        
        // Square current for next iteration
        current = modMul(current, current, mod);
    }
    
    return result;
}

vector<uint8_t> ModularArithmetic::modInverse(const vector<uint8_t>& a,
                                               const vector<uint8_t>& mod) {
    // Extended Euclidean Algorithm
    vector<uint8_t> x = {1}, y = {0};
    vector<uint8_t> lastX = {0}, lastY = {1};
    vector<uint8_t> b = mod;
    vector<uint8_t> aCopy = a;
    
    while (!(b.size() == 1 && b[0] == 0)) {
        // Compute quotient
        vector<uint8_t> quotient;
        vector<uint8_t> remainder;
        
        // Simple division for small numbers (simplified)
        uint32_t aVal = 0, bVal = 0;
        for (size_t i = 0; i < aCopy.size(); i++) {
            aVal = (aVal << 8) | aCopy[i];
        }
        for (size_t i = 0; i < b.size(); i++) {
            bVal = (bVal << 8) | b[i];
        }
        
        if (bVal == 0) break;
        
        uint32_t q = aVal / bVal;
        uint32_t r = aVal % bVal;
        
        quotient.push_back(q & 0xFF);
        if (q > 0xFF) quotient.insert(quotient.begin(), (q >> 8) & 0xFF);
        
        remainder.push_back(r & 0xFF);
        if (r > 0xFF) remainder.insert(remainder.begin(), (r >> 8) & 0xFF);
        
        // Update a and b
        aCopy = b;
        b = remainder;
        
        // Update coefficients
        vector<uint8_t> tempX = x;
        vector<uint8_t> tempY = y;
        
        // x = lastX - quotient * x
        auto qx = modMul(quotient, x, mod);
        x = lastX;
        // Subtract
        uint8_t borrow = 0;
        for (size_t i = 0; i < x.size(); i++) {
            uint16_t diff = x[i] - (i < qx.size() ? qx[i] : 0) - borrow;
            x[i] = diff & 0xFF;
            borrow = (diff >> 8) & 0x01;
        }
        
        // y = lastY - quotient * y
        auto qy = modMul(quotient, y, mod);
        y = lastY;
        borrow = 0;
        for (size_t i = 0; i < y.size(); i++) {
            uint16_t diff = y[i] - (i < qy.size() ? qy[i] : 0) - borrow;
            y[i] = diff & 0xFF;
            borrow = (diff >> 8) & 0x01;
        }
        
        lastX = tempX;
        lastY = tempY;
    }
    
    // Ensure positive result
    if (!lastX.empty() && lastX[0] == 0 && lastX.size() > 1) {
        lastX.erase(lastX.begin());
    }
    
    return lastX;
}