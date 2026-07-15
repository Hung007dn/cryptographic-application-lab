// HashConfig.hpp
#pragma once
#include <string>
#include <cstdint>
#include <stdexcept>  // ← THÊM DÒNG NÀY

enum class HashAlgorithm {
    SHA_224, SHA_256, SHA_384, SHA_512,
    SHA3_224, SHA3_256, SHA3_384, SHA3_512,
    SHAKE128, SHAKE256
};

enum class OutputFormat {
    HEX, RAW
};

struct HashConfig {
    HashAlgorithm algorithm;
    OutputFormat output_format;
    size_t shake_output_length;
    bool stream_mode;
    std::string input_file;
    std::string output_file;
    
    HashConfig();
    
    static HashAlgorithm stringToAlgorithm(const std::string& algo);
    static std::string algorithmToString(HashAlgorithm algo);
    static OutputFormat stringToFormat(const std::string& fmt);
    static std::string formatToString(OutputFormat fmt);
    
    size_t getDigestSize() const;
    std::string getAlgorithmName() const;
};

class HashException : public std::runtime_error {
public:
    explicit HashException(const std::string& msg) : std::runtime_error(msg) {}
};