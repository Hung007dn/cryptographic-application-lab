// MD5CollisionDemo.hpp
#pragma once

#include <string>
#include <vector>
#include <cstdint>

struct CollisionPair {
    std::string file1_name;
    std::string file2_name;

    std::string md5_hash1;
    std::string md5_hash2;

    std::string sha256_hash1;
    std::string sha256_hash2;

    bool files_are_different;
};

class MD5CollisionDemo {
public:
    MD5CollisionDemo();
    ~MD5CollisionDemo();

    // Generate a controlled MD5 collision using fastcoll/hashclash-style tool.
    bool generateCollision(const std::string& prefix,
                           const std::string& output1,
                           const std::string& output2);

    // Verify two files have same MD5 and usually different SHA-256.
    bool verifyCollision(const std::string& file1, const std::string& file2);

    // Create two benign C++ demo files. This is only a helper/demo.
    // For final submission, prefer using --md5-collision --file1 --file2
    // with two prepared benign PNG or C++ files.
    bool createCppDemo();

    // Backward-compatible name used by older main.cpp.
    bool createPythonDemo();

    void displayCollisionInfo(const CollisionPair& pair);

    std::string computeMD5(const std::string& filename);
    std::string computeSHA256(const std::string& filename);

private:
    std::vector<uint8_t> readFile(const std::string& filename);
    void writeFile(const std::string& filename, const std::vector<uint8_t>& data);

    std::string bytesToHex(const std::vector<uint8_t>& bytes);
    std::vector<uint8_t> hexToBytes(const std::string& hex);

    bool filesDiffer(const std::string& file1, const std::string& file2);
};