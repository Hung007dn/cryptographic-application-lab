#pragma once

#include "SigConfig.hpp"
#include "SigKeyManager.hpp"
#include "ECDSAEngine.hpp"
#include "RSAPSSEngine.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <chrono>

struct SignatureBenchmarkResult {
    std::string algorithm;
    std::string operation;
    std::string message_size_name;
    size_t message_size_bytes;
    double time_ms;
    double throughput_ops_per_sec;
    int iterations;
};

class SigBenchmarker {
public:
    explicit SigBenchmarker(int iterations = 1000);

    void runAllBenchmarks();
    void exportCSV(const std::string& filename) const;

private:
    int m_iterations;
    std::vector<SignatureBenchmarkResult> m_results;

    ECDSAEngine m_ecdsaEngine;
    RSAPSSEngine m_rsaEngine;

    static std::vector<uint8_t> generateMessage(size_t size);
    static std::string sizeName(size_t size);
    static double elapsedMilliseconds(
        const std::chrono::high_resolution_clock::time_point& start,
        const std::chrono::high_resolution_clock::time_point& end
    );

    void addResult(
        const std::string& algorithm,
        const std::string& operation,
        const std::string& message_size_name,
        size_t message_size_bytes,
        double time_ms,
        double throughput_ops_per_sec,
        int iterations
    );

    void benchmarkKeyGeneration();
    void benchmarkSignAndVerify();
};