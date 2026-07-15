#pragma once

#include "HashConfig.hpp"
#include "HashEngine.hpp"

#include <cstddef>
#include <string>
#include <vector>

struct HashBenchmarkResult {
    std::string algorithm;
    size_t file_size_bytes;
    double time_seconds;
    double throughput_mbps;
    std::string mode;
    size_t iterations;
};

class HashBenchmarker {
public:
    HashBenchmarker(size_t iterations = 3, bool include_1gb = false);

    void benchmarkAll();
    void benchmarkAlgorithm(const std::string& algorithm, size_t file_size_bytes);
    void printResults() const;
    void exportCSV(const std::string& filename) const;

private:
    size_t m_iterations;
    bool m_include_1gb;
    std::vector<HashBenchmarkResult> m_results;
    HashEngine m_engine;

    std::string createTestFile(size_t size_bytes);
    std::string formatSize(size_t bytes) const;
};