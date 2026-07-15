#pragma once
#include "CryptoConfig.hpp"
#include <string>
#include <vector>
#include <cstdint>

struct NISTTestVector {
    std::string name;
    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> aad;      // For AEAD modes
    std::vector<uint8_t> tag;      // For AEAD modes
};

class NISTValidator {
public:
    NISTValidator();
    
    bool loadTestVectors(const std::string& vector_file, CipherMode mode);
    bool validateMode(CipherMode mode);
    bool validateAEAD(CipherMode mode);
    
    void runAllTests();
    
private:
    std::vector<NISTTestVector> m_vectors;
    
    bool testECB();
    bool testCBC();
    bool testOFB();
    bool testCFB();
    bool testCTR();
    bool testXTS();
    bool testCCM();
    bool testGCM();
    
    void printResult(const std::string& test_name, bool passed);
    
    // NIST-specific test vectors (hardcoded for validation)
    void loadAES128CBCVectors();
    void loadAES128GCMVectors();
    void loadAES256CTRVectors();
};