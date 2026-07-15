#include "Benchmarker.hpp"
#include <iostream>
#include <iomanip>
#include <random>
#include <fstream>
#include <chrono>
#include <thread>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/ccm.h>
#include <cryptopp/gcm.h>
#include <cryptopp/xts.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/resource.h>
    #include <unistd.h>
#endif

using namespace CryptoPP;
static double elapsedMs(
    const std::chrono::high_resolution_clock::time_point& start,
    const std::chrono::high_resolution_clock::time_point& end
) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

static std::string formatSize(size_t bytes) {
    if (bytes < 1024) {
        return std::to_string(bytes) + " B";
    }
    if (bytes < 1024 * 1024) {
        return std::to_string(bytes / 1024) + " KB";
    }
    return std::to_string(bytes / (1024 * 1024)) + " MB";
}
Benchmarker::Benchmarker(size_t iterations) : m_iterations(iterations) {
    m_payload_sizes = {
        1024,           // 1 KB
        4 * 1024,       // 4 KB
        16 * 1024,      // 16 KB
        256 * 1024,     // 256 KB
        1024 * 1024,    // 1 MB
        8 * 1024 * 1024 // 8 MB
    };
}

std::vector<uint8_t> Benchmarker::generateTestData(size_t size_bytes) {
    std::vector<uint8_t> data(size_bytes);
    AutoSeededRandomPool rng;
    rng.GenerateBlock(data.data(), data.size());
    return data;
}

std::string Benchmarker::getOSName() {
#ifdef _WIN32
    return "Windows";
#else
    return "Linux";
#endif
}

std::string Benchmarker::getCPUInfo() {
#ifdef _WIN32
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    return "Unknown (Windows)";
#else
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    while (std::getline(cpuinfo, line)) {
        if (line.find("model name") != std::string::npos) {
            return line.substr(line.find(":") + 2);
        }
    }
    return "Unknown";
#endif
}


BenchmarkResult Benchmarker::benchmarkMode(const CryptoConfig& config, size_t data_mb) {
    using namespace std::chrono;
    
    BenchmarkResult result;
    result.mode = config.mode;
    result.data_size_mb = data_mb;
    result.iterations = m_iterations;
    
    auto test_data = generateTestData(data_mb * 1024 * 1024);
    std::string plaintext(test_data.begin(), test_data.end());
    
    double total_encrypt_ms = 0;
    double total_decrypt_ms = 0;
    
    for (size_t iter = 0; iter < m_iterations; iter++) {
        std::string ciphertext;
        std::string decryptedtext;
        
        // ENCRYPTION 
        auto enc_start = high_resolution_clock::now();
        
        try {
            switch (config.mode) {
                case CipherMode::ECB: {
                    ECB_Mode<AES>::Encryption enc;
                    enc.SetKey(config.key, config.key.size());
                    StringSource ss(plaintext, true,
                        new StreamTransformationFilter(enc,
                            new StringSink(ciphertext)
                        )
                    );
                    break;
                }
                case CipherMode::CBC: {
                    CBC_Mode<AES>::Encryption enc;
                    enc.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                    StringSource ss(plaintext, true,
                        new StreamTransformationFilter(enc,
                            new StringSink(ciphertext)
                        )
                    );
                    break;
                }
                case CipherMode::OFB: {
                    OFB_Mode<AES>::Encryption enc;
                    enc.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                    StringSource ss(plaintext, true,
                        new StreamTransformationFilter(enc,
                            new StringSink(ciphertext)
                        )
                    );
                    break;
                }
                case CipherMode::CFB: {
                    CFB_Mode<AES>::Encryption enc;
                    enc.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                    StringSource ss(plaintext, true,
                        new StreamTransformationFilter(enc,
                            new StringSink(ciphertext)
                        )
                    );
                    break;
                }
                case CipherMode::CTR: {
                    CTR_Mode<AES>::Encryption enc;
                    enc.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                    StringSource ss(plaintext, true,
                        new StreamTransformationFilter(enc,
                            new StringSink(ciphertext)
                        )
                    );
                    break;
                }
                case CipherMode::XTS: {
                    XTS_Mode<AES>::Encryption enc;
                    enc.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                    StringSource ss(plaintext, true,
                        new StreamTransformationFilter(enc,
                            new StringSink(ciphertext)
                        )
                    );
                    break;
                }
                case CipherMode::CCM: {
                    CCM<AES, 16>::Encryption enc;
                    enc.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                    enc.SpecifyDataLengths(0, plaintext.size(), 0);
                    AuthenticatedEncryptionFilter ef(enc,
                        new StringSink(ciphertext), false, 16);
                    ef.ChannelPut(DEFAULT_CHANNEL, (const byte*)plaintext.data(), plaintext.size());
                    ef.ChannelMessageEnd(DEFAULT_CHANNEL);
                    break;
                }
                case CipherMode::GCM: {
                    GCM<AES>::Encryption enc;
                    enc.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                    AuthenticatedEncryptionFilter ef(enc,
                        new StringSink(ciphertext), false, 16);
                    ef.ChannelPut(DEFAULT_CHANNEL, (const byte*)plaintext.data(), plaintext.size());
                    ef.ChannelMessageEnd(DEFAULT_CHANNEL);
                    break;
                }
            }
        } catch (const Exception& e) {
            std::cerr << "Encryption error: " << e.what() << std::endl;
            continue;
        }
        
        auto enc_end = high_resolution_clock::now();
        total_encrypt_ms += duration_cast<milliseconds>(enc_end - enc_start).count();
        
        // DECRYPTION 
        auto dec_start = high_resolution_clock::now();
        
        try {
            switch (config.mode) {
                case CipherMode::ECB: {
                    ECB_Mode<AES>::Decryption dec;
                    dec.SetKey(config.key, config.key.size());
                    StringSource ss(ciphertext, true,
                        new StreamTransformationFilter(dec,
                            new StringSink(decryptedtext)
                        )
                    );
                    break;
                }
                case CipherMode::CBC: {
                    CBC_Mode<AES>::Decryption dec;
                    dec.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                    StringSource ss(ciphertext, true,
                        new StreamTransformationFilter(dec,
                            new StringSink(decryptedtext)
                        )
                    );
                    break;
                }
                case CipherMode::OFB: {
                    OFB_Mode<AES>::Decryption dec;
                    dec.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                    StringSource ss(ciphertext, true,
                        new StreamTransformationFilter(dec,
                            new StringSink(decryptedtext)
                        )
                    );
                    break;
                }
                case CipherMode::CFB: {
                    CFB_Mode<AES>::Decryption dec;
                    dec.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                    StringSource ss(ciphertext, true,
                        new StreamTransformationFilter(dec,
                            new StringSink(decryptedtext)
                        )
                    );
                    break;
                }
                case CipherMode::CTR: {
                    CTR_Mode<AES>::Decryption dec;
                    dec.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                    StringSource ss(ciphertext, true,
                        new StreamTransformationFilter(dec,
                            new StringSink(decryptedtext)
                        )
                    );
                    break;
                }
                case CipherMode::XTS: {
                    XTS_Mode<AES>::Decryption dec;
                    dec.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                    StringSource ss(ciphertext, true,
                        new StreamTransformationFilter(dec,
                            new StringSink(decryptedtext)
                        )
                    );
                    break;
                }
                case CipherMode::CCM: {
                    CCM<AES, 16>::Decryption dec;
                    dec.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                    dec.SpecifyDataLengths(0, ciphertext.size() - 16, 0);
                    AuthenticatedDecryptionFilter df(dec,
                        new StringSink(decryptedtext), 16);
                    df.ChannelPut(DEFAULT_CHANNEL, (const byte*)ciphertext.data(), ciphertext.size());
                    df.ChannelMessageEnd(DEFAULT_CHANNEL);
                    break;
                }
                case CipherMode::GCM: {
                    GCM<AES>::Decryption dec;
                    dec.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                    AuthenticatedDecryptionFilter df(dec,
                        new StringSink(decryptedtext), 16);
                    df.ChannelPut(DEFAULT_CHANNEL, (const byte*)ciphertext.data(), ciphertext.size());
                    df.ChannelMessageEnd(DEFAULT_CHANNEL);
                    break;
                }
            }
        } catch (const Exception& e) {
            std::cerr << "Decryption error: " << e.what() << std::endl;
            continue;
        }
        
        auto dec_end = high_resolution_clock::now();
        total_decrypt_ms += duration_cast<milliseconds>(dec_end - dec_start).count();
    }
    
    result.encrypt_time_ms = total_encrypt_ms / m_iterations;
    result.decrypt_time_ms = total_decrypt_ms / m_iterations;
    
    double total_sec = (total_encrypt_ms + total_decrypt_ms) / 1000.0;
    if (total_sec > 0) {
        result.throughput_mbps = (data_mb * m_iterations * 2) / total_sec;
    } else {
        result.throughput_mbps = 0;
    }
    
    return result;
}


std::vector<DetailedBenchmarkResult> Benchmarker::benchmarkDetailedMode(const CryptoConfig& config) {
    using namespace std::chrono;

    std::vector<DetailedBenchmarkResult> results;

    for (size_t size_bytes : m_payload_sizes) {
        DetailedBenchmarkResult result;
        result.mode = config.mode;
        result.data_size_bytes = size_bytes;
        result.iterations = m_iterations;
        result.is_aead = config.isAEADMode();
        result.mode_type = (config.mode == CipherMode::CTR ||
                            config.mode == CipherMode::CFB ||
                            config.mode == CipherMode::OFB) ? "stream" : "block";

        auto test_data = generateTestData(size_bytes);
        std::string plaintext(test_data.begin(), test_data.end());

        double total_encrypt_ms = 0.0;
        double total_decrypt_ms = 0.0;

        for (int warm = 0; warm < 5; ++warm) {
            std::string warm_cipher;
            try {
                switch (config.mode) {
                    case CipherMode::CBC: {
                        CBC_Mode<AES>::Encryption enc;
                        enc.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                        StringSource ss(plaintext, true,
                            new StreamTransformationFilter(enc, new StringSink(warm_cipher)));
                        break;
                    }
                    case CipherMode::CTR: {
                        CTR_Mode<AES>::Encryption enc;
                        enc.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                        StringSource ss(plaintext, true,
                            new StreamTransformationFilter(enc, new StringSink(warm_cipher)));
                        break;
                    }
                    case CipherMode::GCM: {
                        GCM<AES>::Encryption enc;
                        enc.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                        AuthenticatedEncryptionFilter ef(enc, new StringSink(warm_cipher), false, 16);
                        ef.ChannelPut(DEFAULT_CHANNEL,
                                      reinterpret_cast<const byte*>(plaintext.data()),
                                      plaintext.size());
                        ef.ChannelMessageEnd(DEFAULT_CHANNEL);
                        break;
                    }
                    case CipherMode::CCM: {
                        CCM<AES, 16>::Encryption enc;
                        enc.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                        enc.SpecifyDataLengths(0, plaintext.size(), 0);
                        AuthenticatedEncryptionFilter ef(enc, new StringSink(warm_cipher), false, 16);
                        ef.ChannelPut(DEFAULT_CHANNEL,
                                      reinterpret_cast<const byte*>(plaintext.data()),
                                      plaintext.size());
                        ef.ChannelMessageEnd(DEFAULT_CHANNEL);
                        break;
                    }
                    default:
                        break;
                }
            } catch (...) {
            }
        }

        for (size_t iter = 0; iter < m_iterations; iter++) {
            std::string ciphertext;
            std::string decryptedtext;

            auto enc_start = high_resolution_clock::now();

            try {
                switch (config.mode) {
                    case CipherMode::CBC: {
                        CBC_Mode<AES>::Encryption enc;
                        enc.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                        StringSource ss(plaintext, true,
                            new StreamTransformationFilter(enc, new StringSink(ciphertext)));
                        break;
                    }

                    case CipherMode::CTR: {
                        CTR_Mode<AES>::Encryption enc;
                        enc.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                        StringSource ss(plaintext, true,
                            new StreamTransformationFilter(enc, new StringSink(ciphertext)));
                        break;
                    }

                    case CipherMode::GCM: {
                        GCM<AES>::Encryption enc;
                        enc.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());

                        AuthenticatedEncryptionFilter ef(
                            enc,
                            new StringSink(ciphertext),
                            false,
                            16
                        );

                        ef.ChannelPut(
                            DEFAULT_CHANNEL,
                            reinterpret_cast<const byte*>(plaintext.data()),
                            plaintext.size()
                        );

                        ef.ChannelMessageEnd(DEFAULT_CHANNEL);
                        break;
                    }

                    case CipherMode::CCM: {
                        CCM<AES, 16>::Encryption enc;
                        enc.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());
                        enc.SpecifyDataLengths(0, plaintext.size(), 0);

                        AuthenticatedEncryptionFilter ef(
                            enc,
                            new StringSink(ciphertext),
                            false,
                            16
                        );

                        ef.ChannelPut(
                            DEFAULT_CHANNEL,
                            reinterpret_cast<const byte*>(plaintext.data()),
                            plaintext.size()
                        );

                        ef.ChannelMessageEnd(DEFAULT_CHANNEL);
                        break;
                    }

                    default:
                        break;
                }
            } catch (...) {
            }

            auto enc_end = high_resolution_clock::now();
            total_encrypt_ms += elapsedMs(enc_start, enc_end);

            auto dec_start = high_resolution_clock::now();

            try {
                switch (config.mode) {
                    case CipherMode::CBC: {
                        CBC_Mode<AES>::Decryption dec;
                        dec.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());

                        StringSource ss(
                            ciphertext,
                            true,
                            new StreamTransformationFilter(dec, new StringSink(decryptedtext))
                        );

                        break;
                    }

                    case CipherMode::CTR: {
                        CTR_Mode<AES>::Decryption dec;
                        dec.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());

                        StringSource ss(
                            ciphertext,
                            true,
                            new StreamTransformationFilter(dec, new StringSink(decryptedtext))
                        );

                        break;
                    }

                    case CipherMode::GCM: {
                        GCM<AES>::Decryption dec;
                        dec.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());

                        AuthenticatedDecryptionFilter df(
                            dec,
                            new StringSink(decryptedtext),
                            AuthenticatedDecryptionFilter::THROW_EXCEPTION,
                            16
                        );

                        df.ChannelPut(
                            DEFAULT_CHANNEL,
                            reinterpret_cast<const byte*>(ciphertext.data()),
                            ciphertext.size()
                        );

                        df.ChannelMessageEnd(DEFAULT_CHANNEL);
                        break;
                    }

                    case CipherMode::CCM: {
                        CCM<AES, 16>::Decryption dec;
                        dec.SetKeyWithIV(config.key, config.key.size(), config.iv, config.iv.size());

                        if (ciphertext.size() < 16) {
                            throw std::runtime_error("CCM ciphertext shorter than tag size");
                        }

                        dec.SpecifyDataLengths(0, ciphertext.size() - 16, 0);

                        AuthenticatedDecryptionFilter df(
                            dec,
                            new StringSink(decryptedtext),
                            AuthenticatedDecryptionFilter::THROW_EXCEPTION,
                            16
                        );

                        df.ChannelPut(
                            DEFAULT_CHANNEL,
                            reinterpret_cast<const byte*>(ciphertext.data()),
                            ciphertext.size()
                        );

                        df.ChannelMessageEnd(DEFAULT_CHANNEL);
                        break;
                    }

                    default:
                        break;
                }
            } catch (...) {
            }

            auto dec_end = high_resolution_clock::now();
            total_decrypt_ms += elapsedMs(dec_start, dec_end);
        }

        result.encrypt_time_ms = total_encrypt_ms / static_cast<double>(m_iterations);
        result.decrypt_time_ms = total_decrypt_ms / static_cast<double>(m_iterations);

        double total_sec = (total_encrypt_ms + total_decrypt_ms) / 1000.0;
        double data_mb = size_bytes / (1024.0 * 1024.0);

        if (total_sec > 0.0) {
            result.throughput_mbps = (data_mb * static_cast<double>(m_iterations) * 2.0) / total_sec;
        } else {
            result.throughput_mbps = 0.0;
        }

        results.push_back(result);
    }

    return results;
}


void Benchmarker::printResults(const std::vector<BenchmarkResult>& results) {
    std::cout << "\n=== Performance Benchmarks ===" << std::endl;
    std::cout << std::left 
              << std::setw(12) << "Mode"
              << std::setw(12) << "Data (MB)"
              << std::setw(16) << "Encrypt (ms)"
              << std::setw(16) << "Decrypt (ms)"
              << std::setw(16) << "Throughput (MB/s)"
              << std::endl;
    std::cout << std::string(72, '-') << std::endl;
    
    for (const auto& r : results) {
        std::cout << std::left
                  << std::setw(12) << CryptoConfig::modeToString(r.mode)
                  << std::setw(12) << r.data_size_mb
                  << std::setw(16) << std::fixed << std::setprecision(2) << r.encrypt_time_ms
                  << std::setw(16) << std::fixed << std::setprecision(2) << r.decrypt_time_ms
                  << std::setw(16) << std::fixed << std::setprecision(2) << r.throughput_mbps
                  << std::endl;
    }
}

void Benchmarker::printDetailedResults(const std::vector<DetailedBenchmarkResult>& results) {
    std::cout << "\n=== Detailed Benchmarks ===" << std::endl;
    std::cout << std::left 
              << std::setw(12) << "Mode"
              << std::setw(12) << "Size"
              << std::setw(16) << "Encrypt (ms)"
              << std::setw(16) << "Decrypt (ms)"
              << std::setw(16) << "Throughput (MB/s)"
              << std::endl;
    std::cout << std::string(72, '-') << std::endl;
    
    for (const auto& r : results) {
        std::string size_str;
        if (r.data_size_bytes < 1024) {
            size_str = std::to_string(r.data_size_bytes) + " B";
        } else if (r.data_size_bytes < 1024*1024) {
            size_str = std::to_string(r.data_size_bytes / 1024) + " KB";
        } else {
            size_str = std::to_string(r.data_size_bytes / (1024*1024)) + " MB";
        }
        
        std::cout << std::left
                  << std::setw(12) << CryptoConfig::modeToString(r.mode)
                  << std::setw(12) << size_str
                  << std::setw(16) << std::fixed << std::setprecision(2) << r.encrypt_time_ms
                  << std::setw(16) << std::fixed << std::setprecision(2) << r.decrypt_time_ms
                  << std::setw(16) << std::fixed << std::setprecision(2) << r.throughput_mbps
                  << std::endl;
    }
}


void Benchmarker::exportCSV(const std::string& filename, const std::vector<BenchmarkResult>& results) {
    std::ofstream file(filename);
    file << "Mode,DataSizeMB,EncryptTimeMS,DecryptTimeMS,ThroughputMBps,Iterations\n";
    
    for (const auto& r : results) {
        file << CryptoConfig::modeToString(r.mode) << ","
             << r.data_size_mb << ","
             << r.encrypt_time_ms << ","
             << r.decrypt_time_ms << ","
             << r.throughput_mbps << ","
             << r.iterations << "\n";
    }
    
    std::cout << "Benchmark results exported to " << filename << std::endl;
}

void Benchmarker::exportToCSV(const std::string& filename, const std::vector<DetailedBenchmarkResult>& results) {
    std::ofstream file(filename);
    file << "Mode,DataSizeBytes,EncryptTimeMS,DecryptTimeMS,ThroughputMBps,Iterations,IsAEAD,ModeType\n";
    
    for (const auto& r : results) {
        file << CryptoConfig::modeToString(r.mode) << ","
             << r.data_size_bytes << ","
             << r.encrypt_time_ms << ","
             << r.decrypt_time_ms << ","
             << r.throughput_mbps << ","
             << r.iterations << ","
             << (r.is_aead ? "AEAD" : "Non-AEAD") << ","
             << r.mode_type << "\n";
    }
    
    std::cout << "Detailed results exported to " << filename << std::endl;
}


void Benchmarker::benchmarkAllModes(size_t data_mb) {
    std::vector<BenchmarkResult> results;
    
    std::vector<CipherMode> modes = {
        CipherMode::ECB, CipherMode::CBC, CipherMode::OFB,
        CipherMode::CFB, CipherMode::CTR, CipherMode::XTS,
        CipherMode::CCM, CipherMode::GCM
    };
    
    AutoSeededRandomPool rng;
    
    for (auto mode : modes) {
        std::cout << "Benchmarking " << CryptoConfig::modeToString(mode) << "... " << std::flush;
        
        CryptoConfig config;
        config.mode = mode;
        config.key.resize(32);
        rng.GenerateBlock(config.key.data(), config.key.size());
        
        if (mode != CipherMode::ECB) {
            config.iv.resize(config.getRequiredIVSize());
            rng.GenerateBlock(config.iv.data(), config.iv.size());
        }
        
        if (mode == CipherMode::XTS) {
            config.tweak_key.resize(32);
            rng.GenerateBlock(config.tweak_key.data(), config.tweak_key.size());
        }
        
        auto result = benchmarkMode(config, data_mb);
        results.push_back(result);
        
        std::cout << "Done." << std::endl;
    }
    
    printResults(results);
    exportCSV("benchmark_results.csv", results);
}


void Benchmarker::benchmarkAllSizes() {
    std::cout << "\n=== DETAILED BENCHMARK: Multiple Payload Sizes ===" << std::endl;
    std::cout << "==================================================\n" << std::endl;
    
    std::vector<CipherMode> modes = {
        CipherMode::CBC, CipherMode::CTR, CipherMode::GCM, CipherMode::CCM
    };
    
    AutoSeededRandomPool rng;
    std::vector<DetailedBenchmarkResult> all_results;
    
    for (auto mode : modes) {
        std::cout << "Benchmarking " << CryptoConfig::modeToString(mode) << "..." << std::endl;
        
        CryptoConfig config;
        config.mode = mode;
        config.key.resize(32);
        rng.GenerateBlock(config.key.data(), config.key.size());
        
        size_t iv_size = (mode == CipherMode::GCM || mode == CipherMode::CCM) ? 12 : 16;
        config.iv.resize(iv_size);
        rng.GenerateBlock(config.iv.data(), iv_size);
        
        auto results = benchmarkDetailedMode(config);
        for (const auto& r : results) {
            all_results.push_back(r);
        }
        
        std::cout << "  Size: 1KB -> " << std::fixed << std::setprecision(2) 
                  << results[0].throughput_mbps << " MB/s" << std::endl;
        std::cout << "  Size: 8MB -> " << std::fixed << std::setprecision(2) 
                  << results[5].throughput_mbps << " MB/s" << std::endl;
    }
    
    exportToCSV("performance_report.csv", all_results);
    generateReport();
}


void Benchmarker::compareStreamVsBlock() {
    std::cout << "\n===       Stream vs Block Modes       ===" << std::endl;
    std::cout << "================================================\n" << std::endl;

    AutoSeededRandomPool rng;

    CryptoConfig stream_config;
    stream_config.mode = CipherMode::CTR;
    stream_config.key.resize(32);
    rng.GenerateBlock(stream_config.key.data(), stream_config.key.size());
    stream_config.iv.resize(16);
    rng.GenerateBlock(stream_config.iv.data(), stream_config.iv.size());

    CryptoConfig block_config;
    block_config.mode = CipherMode::CBC;
    block_config.key.resize(32);
    rng.GenerateBlock(block_config.key.data(), block_config.key.size());
    block_config.iv.resize(16);
    rng.GenerateBlock(block_config.iv.data(), block_config.iv.size());

    auto stream_results = benchmarkDetailedMode(stream_config);
    auto block_results = benchmarkDetailedMode(block_config);

    std::cout << std::left
              << std::setw(12) << "Size"
              << std::setw(16) << "Stream (ms)"
              << std::setw(16) << "Block (ms)"
              << std::setw(16) << "Speedup"
              << std::endl;

    std::cout << std::string(60, '-') << std::endl;

    for (size_t i = 0; i < m_payload_sizes.size(); i++) {
        double stream_time = stream_results[i].encrypt_time_ms + stream_results[i].decrypt_time_ms;
        double block_time = block_results[i].encrypt_time_ms + block_results[i].decrypt_time_ms;

        double speedup = 0.0;
        if (stream_time > 0.0) {
            speedup = block_time / stream_time;
        }

        std::cout << std::left
                  << std::setw(12) << formatSize(m_payload_sizes[i])
                  << std::setw(16) << std::fixed << std::setprecision(4) << stream_time
                  << std::setw(16) << std::fixed << std::setprecision(4) << block_time
                  << std::setw(16) << std::fixed << std::setprecision(2) << speedup << "x"
                  << std::endl;
    }
}

void Benchmarker::compareAEADvsNonAEAD() {
    std::cout << "\n===         AEAD vs Non-AEAD         ===" << std::endl;
    std::cout << "===========================================\n" << std::endl;

    AutoSeededRandomPool rng;

    CryptoConfig aead_config;
    aead_config.mode = CipherMode::GCM;
    aead_config.key.resize(32);
    rng.GenerateBlock(aead_config.key.data(), aead_config.key.size());
    aead_config.iv.resize(12);
    rng.GenerateBlock(aead_config.iv.data(), aead_config.iv.size());

    CryptoConfig non_aead_config;
    non_aead_config.mode = CipherMode::CBC;
    non_aead_config.key.resize(32);
    rng.GenerateBlock(non_aead_config.key.data(), non_aead_config.key.size());
    non_aead_config.iv.resize(16);
    rng.GenerateBlock(non_aead_config.iv.data(), non_aead_config.iv.size());

    auto aead_results = benchmarkDetailedMode(aead_config);
    auto non_aead_results = benchmarkDetailedMode(non_aead_config);

    std::cout << std::left
              << std::setw(12) << "Size"
              << std::setw(16) << "AEAD (ms)"
              << std::setw(16) << "Non-AEAD (ms)"
              << std::setw(16) << "Overhead (%)"
              << std::endl;

    std::cout << std::string(60, '-') << std::endl;

    for (size_t i = 0; i < m_payload_sizes.size(); i++) {
        double aead_time = aead_results[i].encrypt_time_ms + aead_results[i].decrypt_time_ms;
        double non_aead_time = non_aead_results[i].encrypt_time_ms + non_aead_results[i].decrypt_time_ms;

        double overhead = 0.0;
        if (non_aead_time > 0.0) {
            overhead = ((aead_time - non_aead_time) / non_aead_time) * 100.0;
        }

        std::cout << std::left
                  << std::setw(12) << formatSize(m_payload_sizes[i])
                  << std::setw(16) << std::fixed << std::setprecision(4) << aead_time
                  << std::setw(16) << std::fixed << std::setprecision(4) << non_aead_time
                  << std::setw(16) << std::fixed << std::setprecision(2) << overhead << "%"
                  << std::endl;
    }
}

void Benchmarker::analyzeTagOverhead() {
    std::cout << "\n===      Tag Overhead (GCM vs CCM)       ===" << std::endl;
    std::cout << "===================================================\n" << std::endl;

    AutoSeededRandomPool rng;

    CryptoConfig gcm_config;
    gcm_config.mode = CipherMode::GCM;
    gcm_config.key.resize(32);
    rng.GenerateBlock(gcm_config.key.data(), gcm_config.key.size());
    gcm_config.iv.resize(12);
    rng.GenerateBlock(gcm_config.iv.data(), gcm_config.iv.size());

    CryptoConfig ccm_config;
    ccm_config.mode = CipherMode::CCM;
    ccm_config.key.resize(32);
    rng.GenerateBlock(ccm_config.key.data(), ccm_config.key.size());
    ccm_config.iv.resize(12);
    rng.GenerateBlock(ccm_config.iv.data(), ccm_config.iv.size());

    auto gcm_results = benchmarkDetailedMode(gcm_config);
    auto ccm_results = benchmarkDetailedMode(ccm_config);

    std::cout << std::left
              << std::setw(12) << "Size"
              << std::setw(16) << "GCM (ms)"
              << std::setw(16) << "CCM (ms)"
              << std::setw(20) << "CCM over GCM (%)"
              << std::endl;

    std::cout << std::string(68, '-') << std::endl;

    for (size_t i = 0; i < m_payload_sizes.size(); i++) {
        double gcm_time = gcm_results[i].encrypt_time_ms + gcm_results[i].decrypt_time_ms;
        double ccm_time = ccm_results[i].encrypt_time_ms + ccm_results[i].decrypt_time_ms;

        double ccm_over_gcm = 0.0;
        if (gcm_time > 0.0) {
            ccm_over_gcm = ((ccm_time - gcm_time) / gcm_time) * 100.0;
        }

        std::cout << std::left
                  << std::setw(12) << formatSize(m_payload_sizes[i])
                  << std::setw(16) << std::fixed << std::setprecision(4) << gcm_time
                  << std::setw(16) << std::fixed << std::setprecision(4) << ccm_time
                  << std::setw(20) << std::fixed << std::setprecision(2) << ccm_over_gcm << "%"
                  << std::endl;
    }
}

void Benchmarker::generateReport() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "     PERFORMANCE EVALUATION REPORT" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "OS: " << getOSName() << std::endl;
    std::cout << "CPU: " << getCPUInfo() << std::endl;
    std::cout << "Iterations per test: " << m_iterations << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    compareStreamVsBlock();
    compareAEADvsNonAEAD();
    analyzeTagOverhead();
    
    std::cout << "\n[INFO] Detailed results exported to 'performance_report.csv'" << std::endl;
}