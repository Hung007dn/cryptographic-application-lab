#include "HashBenchmarker.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>

HashBenchmarker::HashBenchmarker(size_t iterations, bool include_1gb)
    : m_iterations(iterations),
      m_include_1gb(include_1gb) {}

std::string HashBenchmarker::formatSize(size_t bytes) const {
    if (bytes < 1024) {
        return std::to_string(bytes) + " B";
    }

    if (bytes < 1024ULL * 1024ULL) {
        return std::to_string(bytes / 1024ULL) + " KiB";
    }

    if (bytes < 1024ULL * 1024ULL * 1024ULL) {
        return std::to_string(bytes / (1024ULL * 1024ULL)) + " MiB";
    }

    return std::to_string(bytes / (1024ULL * 1024ULL * 1024ULL)) + " GiB";
}

std::string HashBenchmarker::createTestFile(size_t size_bytes) {
    std::string filename = "hash_benchmark_input_" + std::to_string(size_bytes) + ".bin";

    std::ifstream existing(filename, std::ios::binary | std::ios::ate);

    if (existing.good() && static_cast<size_t>(existing.tellg()) == size_bytes) {
        return filename;
    }

    existing.close();

    std::ofstream out(filename, std::ios::binary);

    if (!out.is_open()) {
        throw HashException("Cannot create benchmark file: " + filename);
    }

    const size_t bufferSize = 1024 * 1024;
    std::vector<char> buffer(bufferSize);

    for (size_t i = 0; i < buffer.size(); ++i) {
        buffer[i] = static_cast<char>(i & 0xff);
    }

    size_t remaining = size_bytes;

    while (remaining > 0) {
        size_t chunk = std::min(remaining, bufferSize);

        out.write(buffer.data(), static_cast<std::streamsize>(chunk));

        if (!out.good()) {
            throw HashException("Failed while writing benchmark file: " + filename);
        }

        remaining -= chunk;
    }

    return filename;
}

void HashBenchmarker::benchmarkAlgorithm(const std::string& algorithm, size_t file_size_bytes) {
    std::string filename = createTestFile(file_size_bytes);

    HashConfig config;
    config.algorithm = HashConfig::stringToAlgorithm(algorithm);
    config.stream_mode = true;

    // Warm-up
    (void)m_engine.hashFile(config, filename);

    double totalSeconds = 0.0;

    for (size_t i = 0; i < m_iterations; ++i) {
        auto start = std::chrono::high_resolution_clock::now();

        (void)m_engine.hashFile(config, filename);

        auto end = std::chrono::high_resolution_clock::now();

        totalSeconds += std::chrono::duration<double>(end - start).count();
    }

    double avgSeconds = totalSeconds / static_cast<double>(m_iterations);
    double mb = static_cast<double>(file_size_bytes) / (1024.0 * 1024.0);

    HashBenchmarkResult result;
    result.algorithm = algorithm;
    result.file_size_bytes = file_size_bytes;
    result.time_seconds = avgSeconds;
    result.throughput_mbps = mb / avgSeconds;
    result.mode = "streaming";
    result.iterations = m_iterations;

    m_results.push_back(result);

    std::remove(filename.c_str());
}

void HashBenchmarker::benchmarkAll() {
    m_results.clear();

    std::vector<std::string> algorithms = {
        "sha256",
        "sha512",
        "sha3-256",
        "sha3-512"
    };

    std::vector<size_t> sizes = {
        1ULL * 1024ULL * 1024ULL,
        100ULL * 1024ULL * 1024ULL
    };

    if (m_include_1gb) {
        sizes.push_back(1024ULL * 1024ULL * 1024ULL);
    }

    std::cout << "\n=== Hash Benchmark ===\n";
    std::cout << "Mode: streaming I/O\n";
    std::cout << "Iterations per case: " << m_iterations << "\n\n";

    for (const auto& algo : algorithms) {
        for (size_t size : sizes) {
            std::cout << "Benchmarking " << algo << " / " << formatSize(size) << "... " << std::flush;
            benchmarkAlgorithm(algo, size);
            std::cout << "done\n";
        }
    }

    printResults();
}

void HashBenchmarker::printResults() const {
    std::cout << "\n"
              << std::left
              << std::setw(14) << "Algorithm"
              << std::setw(12) << "Size"
              << std::setw(14) << "Time(s)"
              << std::setw(18) << "Throughput"
              << std::setw(12) << "Mode"
              << "\n";

    std::cout << std::string(70, '-') << "\n";

    for (const auto& r : m_results) {
        std::cout << std::left
                  << std::setw(14) << r.algorithm
                  << std::setw(12) << formatSize(r.file_size_bytes)
                  << std::setw(14) << std::fixed << std::setprecision(4) << r.time_seconds
                  << std::setw(18) << std::fixed << std::setprecision(2) << r.throughput_mbps
                  << std::setw(12) << r.mode
                  << "\n";
    }
}

void HashBenchmarker::exportCSV(const std::string& filename) const {
    std::ofstream out(filename);

    if (!out.is_open()) {
        throw HashException("Cannot open benchmark CSV output: " + filename);
    }

    out << "Algorithm,FileSizeBytes,TimeSeconds,ThroughputMBps,Mode,Iterations\n";

    for (const auto& r : m_results) {
        out << r.algorithm << ","
            << r.file_size_bytes << ","
            << r.time_seconds << ","
            << r.throughput_mbps << ","
            << r.mode << ","
            << r.iterations << "\n";
    }

    std::cout << "\nBenchmark CSV saved to: " << filename << std::endl;
}