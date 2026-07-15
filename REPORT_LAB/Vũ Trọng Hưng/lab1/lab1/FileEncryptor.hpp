#pragma once
#include "CryptoConfig.hpp"
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <cryptopp/filters.h>
#include <atomic>
#include <unordered_map>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class FileEncryptor {
public:
    explicit FileEncryptor(const CryptoConfig& config);
    ~FileEncryptor();
    
    // Main operations
    void encrypt(const std::string& input_file, const std::string& output_file);
    void decrypt(const std::string& input_file, const std::string& output_file);
    void encryptFromString(const std::string& input_text, const std::string& output_file);
    
    // Getters
    std::vector<uint8_t> getLastTag() const { return m_last_tag; }
    json getMetadata() const { return m_metadata; }
    
private:
    CryptoConfig m_config;
    std::vector<uint8_t> m_last_tag;
    json m_metadata;
    std::string m_input_data;
    std::string m_output_data;
    std::string m_input_file;
    std::string m_output_file;
    
    // Key handling
    void loadKeyFromHex(const std::string& hex_string);
    void loadKeyFromFile(const std::string& filename);
    void loadKeyFromRawFile(const std::string& filename);
    void loadKeyFromHexFile(const std::string& filename);
    
    // IV/Nonce handling
    void loadIVFromFile(const std::string& filename);
    void generateIV();
    void saveIVToSidecar();
    
    // AAD handling
    void loadAADFromFile(const std::string& filename);
    void loadAADFromString(const std::string& text);
    
    // Input handling
    void loadInputFromFile(const std::string& filename);
    void loadInputFromString(const std::string& text);
    
    // Output handling
    void saveOutput(const std::string& filename);
    void saveSidecarJSON(const std::string& filename);
    std::string formatOutput(const std::string& data);
    
    // Encryption/Decryption core
    void encryptData();
    void decryptData();
    
    // Validation functions - THÊM CÁC HÀM NÀY
    void checkECBRestriction(size_t file_size);
    void checkNonceReuse();
    void saveNonceRecord();
    void loadMetadata(const std::string& metadata_file);
    void verifyAEADTag(bool verification_result);
    
    // Helpers
    std::string bytesToHex(const std::vector<uint8_t>& bytes);
    std::string bytesToBase64(const std::vector<uint8_t>& bytes);
    std::vector<uint8_t> hexToBytes(const std::string& hex);
    
    static std::atomic<uint64_t> s_nonce_counter;
    std::unordered_map<std::string, std::string> m_nonce_db;
    std::string m_nonce_db_file;
};