#pragma once
#include "CryptoConfig.hpp"
#include <chrono>
#include <vector>
#include <string>
#include <map>

struct BenchmarkResult {
    CipherMode mode;
    size_t data_size_mb;
    double encrypt_time_ms;
    double decrypt_time_ms;
    double throughput_mbps;
    size_t iterations;
};

struct DetailedBenchmarkResult {
    CipherMode mode;
    size_t data_size_bytes;
    double encrypt_time_ms;
    double decrypt_time_ms;
    double throughput_mbps;
    size_t iterations;
    bool is_aead;
    std::string mode_type;
};

class Benchmarker {
public:
    Benchmarker(size_t iterations = 10);
    
    // Original benchmark
    BenchmarkResult benchmarkMode(const CryptoConfig& config, size_t data_mb = 100);
    
    // Detailed benchmark for multiple sizes
    std::vector<DetailedBenchmarkResult> benchmarkDetailedMode(const CryptoConfig& config);
    
    // Run all benchmarks
    void benchmarkAllModes(size_t data_mb = 100);
    void benchmarkAllSizes();
    
    // Comparative studies
    void compareStreamVsBlock();
    void compareAEADvsNonAEAD();
    void analyzeTagOverhead();
    
    // Output methods
    void printResults(const std::vector<BenchmarkResult>& results);
    void printDetailedResults(const std::vector<DetailedBenchmarkResult>& results);
    void exportCSV(const std::string& filename, const std::vector<BenchmarkResult>& results);
    void exportToCSV(const std::string& filename, const std::vector<DetailedBenchmarkResult>& results);
    void generateReport();
    
private:
    size_t m_iterations;
    std::vector<size_t> m_payload_sizes;
    
    std::vector<uint8_t> generateTestData(size_t size_bytes);
    std::string getOSName();
    std::string getCPUInfo();
};