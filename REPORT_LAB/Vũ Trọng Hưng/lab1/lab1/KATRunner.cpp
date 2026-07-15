#include "KATRunner.hpp"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <chrono>
#include <cstring>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/ccm.h>
#include <cryptopp/hex.h>

KATRunner::KATRunner() = default;

std::vector<uint8_t> KATRunner::hexToBytes(const std::string& hex) {
    std::vector<uint8_t> result;
    CryptoPP::HexDecoder decoder;
    decoder.Attach(new CryptoPP::VectorSink(result));
    decoder.Put((const CryptoPP::byte*)hex.data(), hex.size());
    decoder.MessageEnd();
    return result;
}

std::string KATRunner::bytesToHex(const std::vector<uint8_t>& bytes) {
    std::string result;
    CryptoPP::HexEncoder encoder;
    encoder.Attach(new CryptoPP::StringSink(result));
    encoder.Put(bytes.data(), bytes.size());
    encoder.MessageEnd();
    return result;
}

bool KATRunner::compareBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    return memcmp(a.data(), b.data(), a.size()) == 0;
}

//CBC KAT
std::vector<uint8_t> KATRunner::encryptCBC(const std::vector<uint8_t>& key,
                                            const std::vector<uint8_t>& iv,
                                            const std::vector<uint8_t>& plaintext) {
    using namespace CryptoPP;
    std::string ciphertext;
    
    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    
    StringSource ss(plaintext.data(), plaintext.size(), true,
        new StreamTransformationFilter(enc,
            new StringSink(ciphertext),
            StreamTransformationFilter::NO_PADDING
        )
    );
    
    return std::vector<uint8_t>(ciphertext.begin(), ciphertext.end());
}

bool KATRunner::testCBC_KAT(const json& vector) {
    auto key = hexToBytes(vector["key"]);
    auto iv = hexToBytes(vector["iv"]);
    auto plaintext = hexToBytes(vector["plaintext"]);
    auto expected = hexToBytes(vector["ciphertext"]);
    
    auto result = encryptCBC(key, iv, plaintext);
    
    bool passed = compareBytes(result, expected);
    return passed;
}

//CFB
std::vector<uint8_t> KATRunner::encryptCFB(const std::vector<uint8_t>& key,
                                            const std::vector<uint8_t>& iv,
                                            const std::vector<uint8_t>& plaintext) {
    using namespace CryptoPP;
    std::string ciphertext;
    
    CFB_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    
    StringSource ss(plaintext.data(), plaintext.size(), true,
        new StreamTransformationFilter(enc,
            new StringSink(ciphertext),
            StreamTransformationFilter::NO_PADDING
        )
    );
    
    return std::vector<uint8_t>(ciphertext.begin(), ciphertext.end());
}

bool KATRunner::testCFB_KAT(const json& vector) {
    auto key = hexToBytes(vector["key"]);
    auto iv = hexToBytes(vector["iv"]);
    auto plaintext = hexToBytes(vector["plaintext"]);
    auto expected = hexToBytes(vector["ciphertext"]);
    
    auto result = encryptCFB(key, iv, plaintext);
    return compareBytes(result, expected);
}

//OFB
std::vector<uint8_t> KATRunner::encryptOFB(const std::vector<uint8_t>& key,
                                            const std::vector<uint8_t>& iv,
                                            const std::vector<uint8_t>& plaintext) {
    using namespace CryptoPP;
    std::string ciphertext;
    
    OFB_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    
    StringSource ss(plaintext.data(), plaintext.size(), true,
        new StreamTransformationFilter(enc,
            new StringSink(ciphertext),
            StreamTransformationFilter::NO_PADDING
        )
    );
    
    return std::vector<uint8_t>(ciphertext.begin(), ciphertext.end());
}

bool KATRunner::testOFB_KAT(const json& vector) {
    auto key = hexToBytes(vector["key"]);
    auto iv = hexToBytes(vector["iv"]);
    auto plaintext = hexToBytes(vector["plaintext"]);
    auto expected = hexToBytes(vector["ciphertext"]);
    
    auto result = encryptOFB(key, iv, plaintext);
    return compareBytes(result, expected);
}

//CTR
std::vector<uint8_t> KATRunner::encryptCTR(const std::vector<uint8_t>& key,
                                            const std::vector<uint8_t>& iv,
                                            const std::vector<uint8_t>& plaintext) {
    using namespace CryptoPP;
    std::string ciphertext;
    
    CTR_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    
    StringSource ss(plaintext.data(), plaintext.size(), true,
        new StreamTransformationFilter(enc,
            new StringSink(ciphertext),
            StreamTransformationFilter::NO_PADDING
        )
    );
    
    return std::vector<uint8_t>(ciphertext.begin(), ciphertext.end());
}

bool KATRunner::testCTR_KAT(const json& vector) {
    auto key = hexToBytes(vector["key"]);
    auto iv = hexToBytes(vector["iv"]);
    auto plaintext = hexToBytes(vector["plaintext"]);
    auto expected = hexToBytes(vector["ciphertext"]);
    
    auto result = encryptCTR(key, iv, plaintext);
    return compareBytes(result, expected);
}

//GCM
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> KATRunner::encryptGCM(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& aad) {
    
    using namespace CryptoPP;
    std::string ciphertext_with_tag;
    
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    
    AuthenticatedEncryptionFilter ef(enc,
        new StringSink(ciphertext_with_tag), false, 16);
    
    if (!aad.empty()) {
        ef.ChannelPut(AAD_CHANNEL, aad.data(), aad.size());
    }
    ef.ChannelMessageEnd(AAD_CHANNEL);
    
    ef.ChannelPut(DEFAULT_CHANNEL, plaintext.data(), plaintext.size());
    ef.ChannelMessageEnd(DEFAULT_CHANNEL);
    
    std::vector<uint8_t> result(ciphertext_with_tag.begin(), 
                                 ciphertext_with_tag.end() - 16);
    std::vector<uint8_t> tag(ciphertext_with_tag.end() - 16,
                              ciphertext_with_tag.end());
    
    return {result, tag};
}

bool KATRunner::testGCM_KAT(const json& vector) {
    auto key = hexToBytes(vector["key"]);
    auto iv = hexToBytes(vector["iv"]);
    auto plaintext = hexToBytes(vector["plaintext"]);
    auto expected_ciphertext = hexToBytes(vector["ciphertext"]);
    auto expected_tag = hexToBytes(vector["tag"]);
    auto aad = hexToBytes(vector.value("aad", ""));
    
    auto [ciphertext, tag] = encryptGCM(key, iv, plaintext, aad);
    
    bool ciphertext_ok = compareBytes(ciphertext, expected_ciphertext);
    bool tag_ok = compareBytes(tag, expected_tag);
    return ciphertext_ok && tag_ok;
}
//CCM KAT
template<int TAG_SIZE>
static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encryptCCMWithTagSize(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& aad) {

    using namespace CryptoPP;
    std::string ciphertext_with_tag;

    typename CCM<AES, TAG_SIZE>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    enc.SpecifyDataLengths(aad.size(), plaintext.size(), 0);

    AuthenticatedEncryptionFilter ef(enc,
        new StringSink(ciphertext_with_tag), false, TAG_SIZE);

    if (!aad.empty()) {
        ef.ChannelPut(AAD_CHANNEL, aad.data(), aad.size());
    }
    ef.ChannelMessageEnd(AAD_CHANNEL);

    ef.ChannelPut(DEFAULT_CHANNEL, plaintext.data(), plaintext.size());
    ef.ChannelMessageEnd(DEFAULT_CHANNEL);

    std::vector<uint8_t> result(ciphertext_with_tag.begin(),
                                 ciphertext_with_tag.end() - TAG_SIZE);
    std::vector<uint8_t> tag(ciphertext_with_tag.end() - TAG_SIZE,
                              ciphertext_with_tag.end());

    return {result, tag};
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> KATRunner::encryptCCM(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& aad) {
    return encryptCCMWithTagSize<16>(key, iv, plaintext, aad);
}

bool KATRunner::testCCM_KAT(const json& vector) {
    auto key = hexToBytes(vector["key"]);
    auto iv = hexToBytes(vector["iv"]);
    auto plaintext = hexToBytes(vector["plaintext"]);
    auto expected = hexToBytes(vector["ciphertext"]);
    auto expected_tag = hexToBytes(vector["tag"]);
    auto aad = hexToBytes(vector.value("aad", ""));
    int tag_size = vector.value("tag_size", static_cast<int>(expected_tag.size()));

    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> out;
    switch (tag_size) {
        case 4:  out = encryptCCMWithTagSize<4>(key, iv, plaintext, aad); break;
        case 6:  out = encryptCCMWithTagSize<6>(key, iv, plaintext, aad); break;
        case 8:  out = encryptCCMWithTagSize<8>(key, iv, plaintext, aad); break;
        case 10: out = encryptCCMWithTagSize<10>(key, iv, plaintext, aad); break;
        case 12: out = encryptCCMWithTagSize<12>(key, iv, plaintext, aad); break;
        case 14: out = encryptCCMWithTagSize<14>(key, iv, plaintext, aad); break;
        case 16: out = encryptCCMWithTagSize<16>(key, iv, plaintext, aad); break;
        default: throw std::runtime_error("Unsupported CCM tag size in KAT. Use 4,6,8,10,12,14,16 bytes.");
    }

    auto [ciphertext, tag] = out;
    return compareBytes(ciphertext, expected) && compareBytes(tag, expected_tag);
}

//Run KAT from JSON
bool KATRunner::runFromFile(const std::string& json_file) {
    std::ifstream file(json_file);
    if (!file.good()) {
        std::cerr << "Cannot open: " << json_file << std::endl;
        return false;
    }
    
    json data;
    file >> data;
    
    std::cout << "\n=== KAT Test Suite ===\n" << std::endl;
    
    for (const auto& test : data["tests"]) {
        KATResult result;
        result.name = test.value("name", "Unnamed");
        result.mode = test.value("mode", "unknown");
        
        auto start = std::chrono::high_resolution_clock::now();
        
        try {
            if (result.mode == "cbc") {
                result.passed = testCBC_KAT(test);
            } else if (result.mode == "cfb") {
                result.passed = testCFB_KAT(test);
            } else if (result.mode == "ofb") {
                result.passed = testOFB_KAT(test);
            } else if (result.mode == "ctr") {
                result.passed = testCTR_KAT(test);
            } else if (result.mode == "gcm") {
                result.passed = testGCM_KAT(test);
            } else if (result.mode == "ccm") {
                result.passed = testCCM_KAT(test);
            } else {
                result.passed = false;
                result.error_message = "Unknown mode: " + result.mode;
            }
        } catch (const std::exception& e) {
            result.passed = false;
            result.error_message = e.what();
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        result.execution_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        
        m_results.push_back(result);
        
        std::cout << (result.passed ? "[PASS] " : "[FAIL] ")
                  << std::setw(55) << std::left << result.name
                  << " mode=" << std::setw(4) << std::left << result.mode
                  << " (" << result.execution_time_ms << "ms)" << std::endl;
        if (!result.passed && !result.error_message.empty()) {
            std::cout << "    Error: " << result.error_message << std::endl;
        }
    }
    
    printSummary();
    return true;
}

void KATRunner::printSummary() {
    int passed = 0;
    for (const auto& r : m_results) {
        if (r.passed) passed++;
    }

    int failed = static_cast<int>(m_results.size()) - passed;
    double success_rate = m_results.empty()
        ? 0.0
        : (passed * 100.0 / static_cast<double>(m_results.size()));

    std::cout << "\n=== KAT Summary ===" << std::endl;
    std::cout << "Total : " << m_results.size() << std::endl;
    std::cout << "Passed: " << passed << std::endl;
    std::cout << "Failed: " << failed << std::endl;
    std::cout << "Success rate: " << success_rate << "%" << std::endl;

    std::cout << "\nMode summary:" << std::endl;
    for (const auto& r : m_results) {
        std::cout << "  - " << std::setw(4) << std::left << r.mode
                  << " : " << (r.passed ? "PASS" : "FAIL")
                  << " | " << r.name << std::endl;
    }
}

void KATRunner::exportResults(const std::string& output_file) {
    json results_json = json::array();
    for (const auto& r : m_results) {
        results_json.push_back({
            {"name", r.name},
            {"mode", r.mode},
            {"passed", r.passed},
            {"execution_time_ms", r.execution_time_ms},
            {"error", r.error_message}
        });
    }
    
    std::ofstream file(output_file);
    file << results_json.dump(4);
    std::cout << "Results exported to " << output_file << std::endl;
}