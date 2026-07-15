#include "FileEncryptor.hpp"
#include <fstream>
#include <iostream>
#include <cstring>
#include <chrono>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/xts.h>
#include <cryptopp/ccm.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/config.h>
#include <cctype>
#include <algorithm>
#include <cryptopp/sha.h>

constexpr int CCM_TAG_SIZE = 16;
constexpr int GCM_TAG_SIZE = 16;
constexpr size_t ECB_MAX_SIZE = 16 * 1024;
std::atomic<uint64_t> FileEncryptor::s_nonce_counter{0};


static std::string trimAscii(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) a++;
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) b--;
    return s.substr(a, b - a);
}

static bool isLikelyHexText(const std::string& s) {
    std::string t = trimAscii(s);
    if (t.rfind("HEX:", 0) == 0 || t.rfind("hex:", 0) == 0) {
        t = trimAscii(t.substr(4));
    }
    if (t.empty() || (t.size() % 2 != 0)) return false;
    for (char c : t) {
        if (!std::isxdigit(static_cast<unsigned char>(c)) && !std::isspace(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return true;
}

static std::string normalizeHexKeyText(const std::string& s) {
    std::string t = trimAscii(s);
    if (t.rfind("HEX:", 0) == 0 || t.rfind("hex:", 0) == 0) {
        t = trimAscii(t.substr(4));
    }
    t.erase(std::remove_if(t.begin(), t.end(), [](unsigned char ch) {
        return std::isspace(ch) != 0;
    }), t.end());
    return t;
}

static std::string sha256Hex(const CryptoPP::SecByteBlock& data) {
    CryptoPP::SHA256 hash;
    std::string digest;
    CryptoPP::StringSource ss(data.data(), data.size(), true,
        new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(digest)));

    std::string encoded;
    CryptoPP::StringSource hs(reinterpret_cast<const CryptoPP::byte*>(digest.data()), digest.size(), true,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded), false));
    return encoded;
}

FileEncryptor::FileEncryptor(const CryptoConfig& config) : m_config(config) {
    m_nonce_db_file = ".nonce_db.json";
    
    // Load key
    if (!m_config.key_file.empty()) {
        loadKeyFromFile(m_config.key_file);
    } else if (!m_config.key_hex.empty()) {
        loadKeyFromHex(m_config.key_hex);
    }
    
    // Load IV/nonce if provided
    if (!m_config.iv_file.empty()) {
        loadIVFromFile(m_config.iv_file);
    } else if (!m_config.nonce_file.empty()) {
        loadIVFromFile(m_config.nonce_file);
    }

    // Load AAD if provided
    if (!m_config.aad_file.empty()) {
        loadAADFromFile(m_config.aad_file);
    } else if (!m_config.aad_text.empty()) {
        loadAADFromString(m_config.aad_text);
    }
    
    m_config.validateParameters();
}

FileEncryptor::~FileEncryptor() = default;

// ============ ECB RESTRICTION ============
void FileEncryptor::checkECBRestriction(size_t file_size) {
    if (m_config.mode == CipherMode::ECB) {
        std::cerr << "\n  WARNING: ECB mode is insecure! "
                  << "Identical plaintext blocks produce identical ciphertext.\n";
        
        if (file_size > ECB_MAX_SIZE && !m_config.allow_ecb) {
            throw CryptoException(
                "ECB mode blocked for files > 16 KiB. "
                "Use --allow-ecb to override (NOT RECOMMENDED)."
            );
        }
        
        if (m_config.allow_ecb && file_size > ECB_MAX_SIZE) {
            std::cerr << "  FORCED: ECB mode allowed for " << file_size 
                      << " bytes (override active)\n";
        }
    }
}

// ============ METADATA HANDLING ============
void FileEncryptor::loadMetadata(const std::string& metadata_file) {
    std::ifstream file(metadata_file);
    if (!file.good()) {
        throw CryptoException("Metadata file not found: " + metadata_file);
    }
    
    file >> m_metadata;
    
    // Load IV from metadata
    if (m_metadata.contains("iv")) {
        std::string iv_hex = m_metadata["iv"];
        std::vector<uint8_t> iv_bytes = hexToBytes(iv_hex);
        m_config.iv.Assign(iv_bytes.data(), iv_bytes.size());
    }
    
    // Load AAD from metadata if present and not already supplied
    if (m_metadata.contains("aad") && m_config.aad_data.empty()) {
        std::string aad_hex = m_metadata["aad"];
        m_config.aad_data = hexToBytes(aad_hex);
    }

    // Load tag if present
    if (m_metadata.contains("tag")) {
        std::string tag_hex = m_metadata["tag"];
        m_last_tag = hexToBytes(tag_hex);
    }
    
    std::cout << "[INFO] Loaded metadata from " << metadata_file << std::endl;
}

void FileEncryptor::saveSidecarJSON(const std::string& filename) {
    m_metadata["algorithm"] = CryptoConfig::modeToString(m_config.mode);
    m_metadata["mode"] = CryptoConfig::modeToString(m_config.mode);
    m_metadata["key_size"] = m_config.key.size() * 8;
    
    // Save IV
    if (m_config.iv.size() > 0) {
        std::vector<uint8_t> iv_vec(m_config.iv.begin(), m_config.iv.end());
        m_metadata["iv"] = bytesToHex(iv_vec);
    }
    
    // Save AAD
    if (!m_config.aad_data.empty()) {
        m_metadata["aad"] = bytesToHex(m_config.aad_data);
    }
    
    // Save tag
    if (!m_last_tag.empty()) {
        m_metadata["tag"] = bytesToHex(m_last_tag);
        m_metadata["tag_length"] = m_last_tag.size() * 8;
    }
    
    std::ofstream file(filename + ".json");
    file << m_metadata.dump(4);
    std::cout << "[INFO] Sidecar JSON saved to " << filename << ".json" << std::endl;
}

// ============ NONCE HANDLING ============
void FileEncryptor::checkNonceReuse() {
    if (!m_config.isAEADMode() && m_config.mode != CipherMode::CTR) {
        return;
    }
    
    // Create key+nonce fingerprint
    std::string key_fingerprint = sha256Hex(m_config.key);
    std::string nonce_fingerprint = bytesToHex(std::vector<uint8_t>(
        m_config.iv.begin(), m_config.iv.end()
    ));
    std::string combined = key_fingerprint + ":" + nonce_fingerprint;
    
    // Load existing nonce database
    std::unordered_map<std::string, std::string> nonce_db;
    std::ifstream db_file(m_nonce_db_file);
    if (db_file.good()) {
        json db_json;
        db_file >> db_json;
        for (auto& [key, value] : db_json.items()) {
            nonce_db[key] = value;
        }
    }
    
    // Check for reuse
    if (nonce_db.find(combined) != nonce_db.end()) {
        throw CryptoException(
            " SECURITY VIOLATION: Nonce reuse detected!\n"
            "   Key + Nonce combination has been used before."
        );
    }
    
    std::cout << "[SECURITY] Nonce check passed for " 
              << CryptoConfig::modeToString(m_config.mode) << std::endl;
}

void FileEncryptor::saveNonceRecord() {
    if (!m_config.isAEADMode() && m_config.mode != CipherMode::CTR) {
        return;
    }
    
    std::string key_fingerprint = sha256Hex(m_config.key);
    std::string nonce_fingerprint = bytesToHex(std::vector<uint8_t>(
        m_config.iv.begin(), m_config.iv.end()
    ));
    std::string combined = key_fingerprint + ":" + nonce_fingerprint;
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::string timestamp = std::ctime(&time_t);
    timestamp.pop_back(); // Remove newline
    
    // Load existing database
    json db_json;
    std::ifstream db_file(m_nonce_db_file);
    if (db_file.good()) {
        db_file >> db_json;
    }
    
    db_json[combined] = timestamp;
    
    std::ofstream out_file(m_nonce_db_file);
    out_file << db_json.dump(4);
}

// ============ AEAD TAG VERIFICATION ============
void FileEncryptor::verifyAEADTag(bool verification_result) {
    if (!verification_result) {
        throw CryptoException(
            " AEAD TAG VERIFICATION FAILED!\n"
            "   Ciphertext has been tampered with or corrupted."
        );
    }
    std::cout << "[SECURITY] ✓ AEAD tag verified successfully\n";
}

// ============ IV GENERATION ============
void FileEncryptor::generateIV() {
    CryptoPP::AutoSeededRandomPool rng;
    size_t iv_size = m_config.getRequiredIVSize();
    m_config.iv.resize(iv_size);
    rng.GenerateBlock(m_config.iv, iv_size);
    m_config.iv_generated_securely = true;
    
    std::cout << "[INFO] Generated secure " << iv_size << "-byte IV/nonce" << std::endl;
}

// ============ INPUT HANDLING ============
void FileEncryptor::loadInputFromFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.good()) {
        throw CryptoException("Cannot open input file: " + filename);
    }
    m_input_data.assign((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    std::cout << "[INFO] Loaded " << m_input_data.size() << " bytes from " << filename << std::endl;
}

void FileEncryptor::loadInputFromString(const std::string& text) {
    m_input_data = text;
    std::cout << "[INFO] Loaded " << m_input_data.size() << " bytes from string" << std::endl;
}

// ============ OUTPUT HANDLING ============
void FileEncryptor::saveOutput(const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    file << m_output_data;
    std::cout << "[INFO] Saved " << m_output_data.size() << " bytes to " << filename << std::endl;
}

std::string FileEncryptor::formatOutput(const std::string& data) {
    switch (m_config.output_format) {
        case OutputFormat::HEX: {
            std::string result;
            CryptoPP::HexEncoder encoder;
            encoder.Attach(new CryptoPP::StringSink(result));
            encoder.Put((const CryptoPP::byte*)data.data(), data.size());
            encoder.MessageEnd();
            return result;
        }
        case OutputFormat::BASE64: {
            std::string result;
            CryptoPP::Base64Encoder encoder;
            encoder.Attach(new CryptoPP::StringSink(result));
            encoder.Put((const CryptoPP::byte*)data.data(), data.size());
            encoder.MessageEnd();
            return result;
        }
        default:
            return data;
    }
}

// ============ ENCRYPT/DECRYPT METHODS ============
void FileEncryptor::encrypt(const std::string& input_file, const std::string& output_file) {
    m_input_file = input_file;
    m_output_file = output_file;
    
    loadInputFromFile(input_file);
    checkECBRestriction(m_input_data.size());
    
    if (m_config.requiresIV() && m_config.iv.empty()) {
        generateIV();
    }
    
    checkNonceReuse();
    encryptData();
    saveOutput(output_file);
    saveSidecarJSON(output_file);
    saveNonceRecord();
}

void FileEncryptor::decrypt(const std::string& input_file, const std::string& output_file) {
    m_input_file = input_file;
    m_output_file = output_file;
    
    loadMetadata(input_file + ".json");
    loadInputFromFile(input_file);
    decryptData();
    saveOutput(output_file);
}

void FileEncryptor::encryptFromString(const std::string& input_text, const std::string& output_file) {
    m_input_file = "string_input";
    m_output_file = output_file;
    
    loadInputFromString(input_text);
    checkECBRestriction(m_input_data.size());
    
    if (m_config.requiresIV() && m_config.iv.empty()) {
        generateIV();
    }
    
    checkNonceReuse();
    encryptData();
    saveOutput(output_file);
    saveSidecarJSON(output_file);
    saveNonceRecord();
}

// ============ REAL AES ENCRYPTION/DECRYPTION CORE ============
void FileEncryptor::encryptData() {
    using namespace CryptoPP;

    m_output_data.clear();
    m_last_tag.clear();

    try {
        switch (m_config.mode) {
            case CipherMode::ECB: {
                ECB_Mode<AES>::Encryption enc;
                enc.SetKey(m_config.key, m_config.key.size());
                StringSource ss(m_input_data, true,
                    new StreamTransformationFilter(enc, new StringSink(m_output_data))
                );
                break;
            }

            case CipherMode::CBC: {
                CBC_Mode<AES>::Encryption enc;
                enc.SetKeyWithIV(m_config.key, m_config.key.size(), m_config.iv, m_config.iv.size());
                StringSource ss(m_input_data, true,
                    new StreamTransformationFilter(enc, new StringSink(m_output_data))
                );
                break;
            }

            case CipherMode::OFB: {
                OFB_Mode<AES>::Encryption enc;
                enc.SetKeyWithIV(m_config.key, m_config.key.size(), m_config.iv, m_config.iv.size());
                StringSource ss(m_input_data, true,
                    new StreamTransformationFilter(enc, new StringSink(m_output_data),
                        StreamTransformationFilter::NO_PADDING)
                );
                break;
            }

            case CipherMode::CFB: {
                CFB_Mode<AES>::Encryption enc;
                enc.SetKeyWithIV(m_config.key, m_config.key.size(), m_config.iv, m_config.iv.size());
                StringSource ss(m_input_data, true,
                    new StreamTransformationFilter(enc, new StringSink(m_output_data),
                        StreamTransformationFilter::NO_PADDING)
                );
                break;
            }

            case CipherMode::CTR: {
                CTR_Mode<AES>::Encryption enc;
                enc.SetKeyWithIV(m_config.key, m_config.key.size(), m_config.iv, m_config.iv.size());
                StringSource ss(m_input_data, true,
                    new StreamTransformationFilter(enc, new StringSink(m_output_data),
                        StreamTransformationFilter::NO_PADDING)
                );
                break;
            }

            case CipherMode::XTS: {
                XTS_Mode<AES>::Encryption enc;
                enc.SetKeyWithIV(m_config.key, m_config.key.size(), m_config.iv, m_config.iv.size());
                StringSource ss(m_input_data, true,
                    new StreamTransformationFilter(enc, new StringSink(m_output_data),
                        StreamTransformationFilter::NO_PADDING)
                );
                break;
            }

            case CipherMode::GCM: {
                GCM<AES>::Encryption enc;
                enc.SetKeyWithIV(m_config.key, m_config.key.size(), m_config.iv, m_config.iv.size());

                std::string combined;
                AuthenticatedEncryptionFilter ef(
                    enc,
                    new StringSink(combined),
                    false,
                    GCM_TAG_SIZE
                );

                if (!m_config.aad_data.empty()) {
                    ef.ChannelPut(AAD_CHANNEL, m_config.aad_data.data(), m_config.aad_data.size());
                }
                ef.ChannelMessageEnd(AAD_CHANNEL);

                ef.ChannelPut(DEFAULT_CHANNEL,
                    reinterpret_cast<const byte*>(m_input_data.data()),
                    m_input_data.size());
                ef.ChannelMessageEnd(DEFAULT_CHANNEL);

                if (combined.size() < static_cast<size_t>(GCM_TAG_SIZE)) {
                    throw CryptoException("GCM output shorter than tag size");
                }

                m_output_data.assign(combined.begin(), combined.end() - GCM_TAG_SIZE);
                m_last_tag.assign(combined.end() - GCM_TAG_SIZE, combined.end());
                break;
            }

            case CipherMode::CCM: {
                CCM<AES, CCM_TAG_SIZE>::Encryption enc;
                enc.SetKeyWithIV(m_config.key, m_config.key.size(), m_config.iv, m_config.iv.size());
                enc.SpecifyDataLengths(m_config.aad_data.size(), m_input_data.size(), 0);

                std::string combined;
                AuthenticatedEncryptionFilter ef(
                    enc,
                    new StringSink(combined),
                    false,
                    CCM_TAG_SIZE
                );

                if (!m_config.aad_data.empty()) {
                    ef.ChannelPut(AAD_CHANNEL, m_config.aad_data.data(), m_config.aad_data.size());
                }
                ef.ChannelMessageEnd(AAD_CHANNEL);

                ef.ChannelPut(DEFAULT_CHANNEL,
                    reinterpret_cast<const byte*>(m_input_data.data()),
                    m_input_data.size());
                ef.ChannelMessageEnd(DEFAULT_CHANNEL);

                if (combined.size() < static_cast<size_t>(CCM_TAG_SIZE)) {
                    throw CryptoException("CCM output shorter than tag size");
                }

                m_output_data.assign(combined.begin(), combined.end() - CCM_TAG_SIZE);
                m_last_tag.assign(combined.end() - CCM_TAG_SIZE, combined.end());
                break;
            }

            default:
                throw CryptoException("Unsupported encryption mode");
        }

        std::cout << "[INFO] Encryption completed using "
                  << CryptoConfig::modeToString(m_config.mode) << std::endl;
    } catch (const CryptoPP::Exception& e) {
        throw CryptoException(std::string("Crypto++ encryption error: ") + e.what());
    }
}

void FileEncryptor::decryptData() {
    using namespace CryptoPP;

    m_output_data.clear();

    try {
        switch (m_config.mode) {
            case CipherMode::ECB: {
                ECB_Mode<AES>::Decryption dec;
                dec.SetKey(m_config.key, m_config.key.size());
                StringSource ss(m_input_data, true,
                    new StreamTransformationFilter(dec, new StringSink(m_output_data))
                );
                break;
            }

            case CipherMode::CBC: {
                CBC_Mode<AES>::Decryption dec;
                dec.SetKeyWithIV(m_config.key, m_config.key.size(), m_config.iv, m_config.iv.size());
                StringSource ss(m_input_data, true,
                    new StreamTransformationFilter(dec, new StringSink(m_output_data))
                );
                break;
            }

            case CipherMode::OFB: {
                OFB_Mode<AES>::Decryption dec;
                dec.SetKeyWithIV(m_config.key, m_config.key.size(), m_config.iv, m_config.iv.size());
                StringSource ss(m_input_data, true,
                    new StreamTransformationFilter(dec, new StringSink(m_output_data),
                        StreamTransformationFilter::NO_PADDING)
                );
                break;
            }

            case CipherMode::CFB: {
                CFB_Mode<AES>::Decryption dec;
                dec.SetKeyWithIV(m_config.key, m_config.key.size(), m_config.iv, m_config.iv.size());
                StringSource ss(m_input_data, true,
                    new StreamTransformationFilter(dec, new StringSink(m_output_data),
                        StreamTransformationFilter::NO_PADDING)
                );
                break;
            }

            case CipherMode::CTR: {
                CTR_Mode<AES>::Decryption dec;
                dec.SetKeyWithIV(m_config.key, m_config.key.size(), m_config.iv, m_config.iv.size());
                StringSource ss(m_input_data, true,
                    new StreamTransformationFilter(dec, new StringSink(m_output_data),
                        StreamTransformationFilter::NO_PADDING)
                );
                break;
            }

            case CipherMode::XTS: {
                XTS_Mode<AES>::Decryption dec;
                dec.SetKeyWithIV(m_config.key, m_config.key.size(), m_config.iv, m_config.iv.size());
                StringSource ss(m_input_data, true,
                    new StreamTransformationFilter(dec, new StringSink(m_output_data),
                        StreamTransformationFilter::NO_PADDING)
                );
                break;
            }

            case CipherMode::GCM: {
                if (m_last_tag.empty()) {
                    throw CryptoException("GCM authentication tag missing from sidecar JSON");
                }

                GCM<AES>::Decryption dec;
                dec.SetKeyWithIV(m_config.key, m_config.key.size(), m_config.iv, m_config.iv.size());

                std::string combined = m_input_data;
                combined.append(reinterpret_cast<const char*>(m_last_tag.data()), m_last_tag.size());

                AuthenticatedDecryptionFilter df(
                    dec,
                    new StringSink(m_output_data),
                    AuthenticatedDecryptionFilter::THROW_EXCEPTION,
                    static_cast<int>(m_last_tag.size())
                );

                if (!m_config.aad_data.empty()) {
                    df.ChannelPut(AAD_CHANNEL, m_config.aad_data.data(), m_config.aad_data.size());
                }
                df.ChannelMessageEnd(AAD_CHANNEL);

                df.ChannelPut(DEFAULT_CHANNEL,
                    reinterpret_cast<const byte*>(combined.data()),
                    combined.size());
                df.ChannelMessageEnd(DEFAULT_CHANNEL);

                std::cout << "[SECURITY] GCM tag verified successfully" << std::endl;
                break;
            }

            case CipherMode::CCM: {
                if (m_last_tag.empty()) {
                    throw CryptoException("CCM authentication tag missing from sidecar JSON");
                }

                CCM<AES, CCM_TAG_SIZE>::Decryption dec;
                dec.SetKeyWithIV(m_config.key, m_config.key.size(), m_config.iv, m_config.iv.size());
                dec.SpecifyDataLengths(m_config.aad_data.size(), m_input_data.size(), 0);

                std::string combined = m_input_data;
                combined.append(reinterpret_cast<const char*>(m_last_tag.data()), m_last_tag.size());

                AuthenticatedDecryptionFilter df(
                    dec,
                    new StringSink(m_output_data),
                    AuthenticatedDecryptionFilter::THROW_EXCEPTION,
                    static_cast<int>(m_last_tag.size())
                );

                if (!m_config.aad_data.empty()) {
                    df.ChannelPut(AAD_CHANNEL, m_config.aad_data.data(), m_config.aad_data.size());
                }
                df.ChannelMessageEnd(AAD_CHANNEL);

                df.ChannelPut(DEFAULT_CHANNEL,
                    reinterpret_cast<const byte*>(combined.data()),
                    combined.size());
                df.ChannelMessageEnd(DEFAULT_CHANNEL);

                std::cout << "[SECURITY] CCM tag verified successfully" << std::endl;
                break;
            }

            default:
                throw CryptoException("Unsupported decryption mode");
        }

        std::cout << "[INFO] Decryption completed using "
                  << CryptoConfig::modeToString(m_config.mode) << std::endl;
    } catch (const CryptoPP::Exception& e) {
        throw CryptoException(std::string("Crypto++ decryption/authentication error: ") + e.what());
    }
}

// ============ HELPER FUNCTIONS ============
std::string FileEncryptor::bytesToHex(const std::vector<uint8_t>& bytes) {
    std::string result;
    CryptoPP::HexEncoder encoder;
    encoder.Attach(new CryptoPP::StringSink(result));
    encoder.Put(bytes.data(), bytes.size());
    encoder.MessageEnd();
    return result;
}

std::string FileEncryptor::bytesToBase64(const std::vector<uint8_t>& bytes) {
    std::string result;
    CryptoPP::Base64Encoder encoder;
    encoder.Attach(new CryptoPP::StringSink(result));
    encoder.Put(bytes.data(), bytes.size());
    encoder.MessageEnd();
    return result;
}

std::vector<uint8_t> FileEncryptor::hexToBytes(const std::string& hex) {
    std::vector<uint8_t> result;
    CryptoPP::HexDecoder decoder;
    decoder.Attach(new CryptoPP::VectorSink(result));
    decoder.Put((const CryptoPP::byte*)hex.data(), hex.size());
    decoder.MessageEnd();
    return result;
}

// ============ KEY HANDLING ============
void FileEncryptor::loadKeyFromHex(const std::string& hex_string) {
    std::vector<uint8_t> key_bytes = hexToBytes(hex_string);
    m_config.key.resize(key_bytes.size());
    memcpy(m_config.key.data(), key_bytes.data(), key_bytes.size());
    m_config.key_size = key_bytes.size();
}

void FileEncryptor::loadKeyFromFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.good()) {
        throw CryptoException("Cannot open key file: " + filename);
    }

    std::vector<uint8_t> file_bytes((std::istreambuf_iterator<char>(file)),
                                    std::istreambuf_iterator<char>());
    std::string as_text(file_bytes.begin(), file_bytes.end());

    std::vector<uint8_t> key_bytes;
    if (isLikelyHexText(as_text)) {
        key_bytes = hexToBytes(normalizeHexKeyText(as_text));
        std::cout << "[INFO] Loaded hex-encoded key from " << filename << std::endl;
    } else {
        key_bytes = file_bytes;
        std::cout << "[INFO] Loaded raw binary key from " << filename << std::endl;
    }

    m_config.key.resize(key_bytes.size());
    if (!key_bytes.empty()) {
        memcpy(m_config.key.data(), key_bytes.data(), key_bytes.size());
    }
    m_config.key_size = key_bytes.size();

    std::cout << "[INFO] Key size: " << key_bytes.size() << " bytes" << std::endl;
}

void FileEncryptor::loadKeyFromRawFile(const std::string& filename) {
    loadKeyFromFile(filename);
}

void FileEncryptor::loadKeyFromHexFile(const std::string& filename) {
    std::ifstream file(filename);
    std::string hex_string;
    std::getline(file, hex_string);
    loadKeyFromHex(hex_string);
}

void FileEncryptor::loadIVFromFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    std::vector<uint8_t> iv_bytes((std::istreambuf_iterator<char>(file)),
                                    std::istreambuf_iterator<char>());
    m_config.iv.resize(iv_bytes.size());
    memcpy(m_config.iv.data(), iv_bytes.data(), iv_bytes.size());
    m_config.iv_size = iv_bytes.size();
}

void FileEncryptor::loadAADFromFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    m_config.aad_data.assign((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
}

void FileEncryptor::loadAADFromString(const std::string& text) {
    m_config.aad_data.assign(text.begin(), text.end());
}

void FileEncryptor::saveIVToSidecar() {
    // Already handled in saveSidecarJSON
}