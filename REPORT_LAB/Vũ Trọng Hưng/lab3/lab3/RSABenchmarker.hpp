// RSABenchmarker.hpp
#pragma once
#include "RSAConfig.hpp"
#include "RSAKeyManager.hpp"
#include "RSAEngine.hpp"
#include "HybridEncryptor.hpp"
#include <chrono>
#include <vector>
#include <string>

struct RSABenchmarkResult {
    std::string test_name;
    int key_bits;
    double time_ms;
    double throughput_mbps;
    size_t data_size_bytes;
};

class RSABenchmarker {
public:
    RSABenchmarker(size_t iterations = 10);
    
    void runBenchmarks();
    void exportCSV(const std::string& filename);
    
private:
    size_t m_iterations;
    std::vector<RSABenchmarkResult> m_results;
    
    // Benchmarks
    void benchmarkKeyGeneration();
    void benchmarkRSAEncryptDecrypt();
    void benchmarkHybridEncryptDecrypt();
    void compareKeySizes();
    
    // Helpers
    std::string formatTime(double ms);
    void printSummary();
};