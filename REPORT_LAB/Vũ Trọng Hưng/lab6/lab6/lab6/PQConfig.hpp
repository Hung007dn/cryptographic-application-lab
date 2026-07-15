// PQConfig.hpp
#pragma once
#include <string>
#include <cstdint>
#include <stdexcept>

enum class PQAlgorithm {
    MLDSA_44,
    MLDSA_65,
    MLDSA_87,
    MLKEM_512,
    MLKEM_768,
    MLKEM_1024
};

enum class OutputFormat {
    RAW, BASE64, PEM, DER
};

struct PQConfig {
    PQAlgorithm algorithm;
    OutputFormat output_format;
    
    PQConfig();
    
    static PQAlgorithm stringToAlgorithm(const std::string& algo);
    static std::string algorithmToString(PQAlgorithm algo);
    static OutputFormat stringToFormat(const std::string& fmt);
    static std::string formatToString(OutputFormat fmt);
    
    size_t getPublicKeySize() const;
    size_t getPrivateKeySize() const;
    size_t getSignatureSize() const;
    size_t getCiphertextSize() const;
    size_t getSharedSecretSize() const;
    std::string getAlgorithmName() const;
};

class PQException : public std::runtime_error {
public:
    explicit PQException(const std::string& msg) : std::runtime_error(msg) {}
};