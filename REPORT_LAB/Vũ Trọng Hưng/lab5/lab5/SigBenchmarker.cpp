#include "SigBenchmarker.hpp"

#include <chrono>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <algorithm>

SigBenchmarker::SigBenchmarker(int iterations)
    : m_iterations(iterations > 0 ? iterations : 1000) {}

std::vector<uint8_t> SigBenchmarker::generateMessage(size_t size) {
    std::vector<uint8_t> data(size);

    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>(i & 0xFF);
    }

    return data;
}

std::string SigBenchmarker::sizeName(size_t size) {
    if (size == 1024) {
        return "1KiB";
    }

    if (size == 16 * 1024) {
        return "16KiB";
    }

    if (size == 1024 * 1024) {
        return "1MiB";
    }

    if (size == 8 * 1024 * 1024) {
        return "8MiB";
    }

    return std::to_string(size) + "B";
}

double SigBenchmarker::elapsedMilliseconds(
    const std::chrono::high_resolution_clock::time_point& start,
    const std::chrono::high_resolution_clock::time_point& end
) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

void SigBenchmarker::addResult(
    const std::string& algorithm,
    const std::string& operation,
    const std::string& message_size_name,
    size_t message_size_bytes,
    double time_ms,
    double throughput_ops_per_sec,
    int iterations
) {
    SignatureBenchmarkResult result;
    result.algorithm = algorithm;
    result.operation = operation;
    result.message_size_name = message_size_name;
    result.message_size_bytes = message_size_bytes;
    result.time_ms = time_ms;
    result.throughput_ops_per_sec = throughput_ops_per_sec;
    result.iterations = iterations;

    m_results.push_back(result);
}

void SigBenchmarker::benchmarkKeyGeneration() {
    std::cout << "\n=== Key Generation Benchmark ===\n" << std::endl;

    struct KeygenCase {
        std::string name;
        SignatureAlgorithm algorithm;
    };

    std::vector<KeygenCase> cases = {
        {"ECDSA-P256", SignatureAlgorithm::ECDSA_P256},
        {"ECDSA-P384", SignatureAlgorithm::ECDSA_P384},
        {"RSA-PSS-3072", SignatureAlgorithm::RSA_PSS_3072}
    };

    // RSA key generation is much heavier than signing/verifying.
    // Keep keygen iterations practical per run, while Python scripts repeat the run 30 times.
    int keygenIterations = std::min(m_iterations, 10);
    if (keygenIterations < 3) {
        keygenIterations = 3;
    }

    for (const auto& test : cases) {
        auto start = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < keygenIterations; ++i) {
            SigKeyManager km;
            km.generateKeyPair(test.algorithm);
        }

        auto end = std::chrono::high_resolution_clock::now();

        double total_ms = elapsedMilliseconds(start, end);
        double mean_ms = total_ms / static_cast<double>(keygenIterations);
        double ops = (mean_ms > 0.0) ? (1000.0 / mean_ms) : 0.0;

        addResult(
            test.name,
            "keygen",
            "N/A",
            0,
            mean_ms,
            ops,
            keygenIterations
        );

        std::cout << std::setw(16) << std::left << test.name
                  << " keygen mean: " << mean_ms
                  << " ms, throughput: " << ops
                  << " ops/sec" << std::endl;
    }
}

void SigBenchmarker::benchmarkSignAndVerify() {
    std::cout << "\n=== Sign / Verify Benchmark ===\n" << std::endl;

    std::vector<size_t> messageSizes = {
        1024,
        16 * 1024,
        1024 * 1024,
        8 * 1024 * 1024
    };

    SigKeyManager ecdsa256;
    SigKeyManager ecdsa384;
    SigKeyManager rsa3072;

    ecdsa256.generateKeyPair(SignatureAlgorithm::ECDSA_P256);
    ecdsa384.generateKeyPair(SignatureAlgorithm::ECDSA_P384);
    rsa3072.generateKeyPair(SignatureAlgorithm::RSA_PSS_3072);

    for (size_t msgSize : messageSizes) {
        std::vector<uint8_t> message = generateMessage(msgSize);
        std::string msgName = sizeName(msgSize);

        std::cout << "\nMessage size: " << msgName << std::endl;

        // =========================
        // ECDSA-P256 sign
        // =========================
        {
            auto start = std::chrono::high_resolution_clock::now();

            std::vector<uint8_t> signature;

            for (int i = 0; i < m_iterations; ++i) {
                signature = m_ecdsaEngine.sign(
                    message,
                    ecdsa256.getPrivateKey(),
                    HashAlgorithm::SHA256,
                    true
                );
            }

            auto end = std::chrono::high_resolution_clock::now();

            double total_ms = elapsedMilliseconds(start, end);
            double mean_ms = total_ms / static_cast<double>(m_iterations);
            double ops = (mean_ms > 0.0) ? (1000.0 / mean_ms) : 0.0;

            addResult(
                "ECDSA-P256",
                "sign",
                msgName,
                msgSize,
                mean_ms,
                ops,
                m_iterations
            );

            bool valid = m_ecdsaEngine.verify(
                message,
                signature,
                ecdsa256.getPublicKey(),
                HashAlgorithm::SHA256
            );

            if (!valid) {
                throw SigException("ECDSA-P256 benchmark verification failed");
            }

            std::cout << "  ECDSA-P256 sign   mean: " << mean_ms
                      << " ms, throughput: " << ops << " ops/sec" << std::endl;
        }

        // =========================
        // ECDSA-P256 verify
        // =========================
        {
            auto signature = m_ecdsaEngine.sign(
                message,
                ecdsa256.getPrivateKey(),
                HashAlgorithm::SHA256,
                true
            );

            auto start = std::chrono::high_resolution_clock::now();

            bool valid = true;

            for (int i = 0; i < m_iterations; ++i) {
                valid = m_ecdsaEngine.verify(
                    message,
                    signature,
                    ecdsa256.getPublicKey(),
                    HashAlgorithm::SHA256
                );

                if (!valid) {
                    throw SigException("ECDSA-P256 verify benchmark failed");
                }
            }

            auto end = std::chrono::high_resolution_clock::now();

            double total_ms = elapsedMilliseconds(start, end);
            double mean_ms = total_ms / static_cast<double>(m_iterations);
            double ops = (mean_ms > 0.0) ? (1000.0 / mean_ms) : 0.0;

            addResult(
                "ECDSA-P256",
                "verify",
                msgName,
                msgSize,
                mean_ms,
                ops,
                m_iterations
            );

            std::cout << "  ECDSA-P256 verify mean: " << mean_ms
                      << " ms, throughput: " << ops << " ops/sec" << std::endl;
        }

        // =========================
        // ECDSA-P384 sign
        // =========================
        {
            auto start = std::chrono::high_resolution_clock::now();

            std::vector<uint8_t> signature;

            for (int i = 0; i < m_iterations; ++i) {
                signature = m_ecdsaEngine.sign(
                    message,
                    ecdsa384.getPrivateKey(),
                    HashAlgorithm::SHA384,
                    true
                );
            }

            auto end = std::chrono::high_resolution_clock::now();

            double total_ms = elapsedMilliseconds(start, end);
            double mean_ms = total_ms / static_cast<double>(m_iterations);
            double ops = (mean_ms > 0.0) ? (1000.0 / mean_ms) : 0.0;

            addResult(
                "ECDSA-P384",
                "sign",
                msgName,
                msgSize,
                mean_ms,
                ops,
                m_iterations
            );

            bool valid = m_ecdsaEngine.verify(
                message,
                signature,
                ecdsa384.getPublicKey(),
                HashAlgorithm::SHA384
            );

            if (!valid) {
                throw SigException("ECDSA-P384 benchmark verification failed");
            }

            std::cout << "  ECDSA-P384 sign   mean: " << mean_ms
                      << " ms, throughput: " << ops << " ops/sec" << std::endl;
        }

        // =========================
        // ECDSA-P384 verify
        // =========================
        {
            auto signature = m_ecdsaEngine.sign(
                message,
                ecdsa384.getPrivateKey(),
                HashAlgorithm::SHA384,
                true
            );

            auto start = std::chrono::high_resolution_clock::now();

            bool valid = true;

            for (int i = 0; i < m_iterations; ++i) {
                valid = m_ecdsaEngine.verify(
                    message,
                    signature,
                    ecdsa384.getPublicKey(),
                    HashAlgorithm::SHA384
                );

                if (!valid) {
                    throw SigException("ECDSA-P384 verify benchmark failed");
                }
            }

            auto end = std::chrono::high_resolution_clock::now();

            double total_ms = elapsedMilliseconds(start, end);
            double mean_ms = total_ms / static_cast<double>(m_iterations);
            double ops = (mean_ms > 0.0) ? (1000.0 / mean_ms) : 0.0;

            addResult(
                "ECDSA-P384",
                "verify",
                msgName,
                msgSize,
                mean_ms,
                ops,
                m_iterations
            );

            std::cout << "  ECDSA-P384 verify mean: " << mean_ms
                      << " ms, throughput: " << ops << " ops/sec" << std::endl;
        }

        // =========================
        // RSA-PSS-3072 sign
        // =========================
        {
            auto start = std::chrono::high_resolution_clock::now();

            std::vector<uint8_t> signature;

            for (int i = 0; i < m_iterations; ++i) {
                signature = m_rsaEngine.sign(
                    message,
                    rsa3072.getPrivateKey(),
                    HashAlgorithm::SHA256
                );
            }

            auto end = std::chrono::high_resolution_clock::now();

            double total_ms = elapsedMilliseconds(start, end);
            double mean_ms = total_ms / static_cast<double>(m_iterations);
            double ops = (mean_ms > 0.0) ? (1000.0 / mean_ms) : 0.0;

            addResult(
                "RSA-PSS-3072",
                "sign",
                msgName,
                msgSize,
                mean_ms,
                ops,
                m_iterations
            );

            bool valid = m_rsaEngine.verify(
                message,
                signature,
                rsa3072.getPublicKey(),
                HashAlgorithm::SHA256
            );

            if (!valid) {
                throw SigException("RSA-PSS-3072 benchmark verification failed");
            }

            std::cout << "  RSA-PSS-3072 sign mean: " << mean_ms
                      << " ms, throughput: " << ops << " ops/sec" << std::endl;
        }

        // =========================
        // RSA-PSS-3072 verify
        // =========================
        {
            auto signature = m_rsaEngine.sign(
                message,
                rsa3072.getPrivateKey(),
                HashAlgorithm::SHA256
            );

            auto start = std::chrono::high_resolution_clock::now();

            bool valid = true;

            for (int i = 0; i < m_iterations; ++i) {
                valid = m_rsaEngine.verify(
                    message,
                    signature,
                    rsa3072.getPublicKey(),
                    HashAlgorithm::SHA256
                );

                if (!valid) {
                    throw SigException("RSA-PSS-3072 verify benchmark failed");
                }
            }

            auto end = std::chrono::high_resolution_clock::now();

            double total_ms = elapsedMilliseconds(start, end);
            double mean_ms = total_ms / static_cast<double>(m_iterations);
            double ops = (mean_ms > 0.0) ? (1000.0 / mean_ms) : 0.0;

            addResult(
                "RSA-PSS-3072",
                "verify",
                msgName,
                msgSize,
                mean_ms,
                ops,
                m_iterations
            );

            std::cout << "  RSA-PSS-3072 verify mean: " << mean_ms
                      << " ms, throughput: " << ops << " ops/sec" << std::endl;
        }
    }
}

void SigBenchmarker::runAllBenchmarks() {
    m_results.clear();

    std::cout << "\n========================================" << std::endl;
    std::cout << "Lab 5 Signature Performance Benchmark" << std::endl;
    std::cout << "Iterations per sign/verify test: " << m_iterations << std::endl;
    std::cout << "Message sizes: 1 KiB, 16 KiB, 1 MiB, 8 MiB" << std::endl;
    std::cout << "========================================" << std::endl;

    benchmarkKeyGeneration();
    benchmarkSignAndVerify();

    std::cout << "\n[+] Benchmark complete. Results collected: "
              << m_results.size() << std::endl;
}

void SigBenchmarker::exportCSV(const std::string& filename) const {
    std::ofstream out(filename);

    if (!out.is_open()) {
        throw SigException("Cannot open benchmark CSV for writing: " + filename);
    }

    out << "Algorithm,Operation,MessageSizeName,MessageSizeBytes,TimeMS,ThroughputOpsPerSec,Iterations\n";

    out << std::fixed << std::setprecision(9);

    for (const auto& r : m_results) {
        out << r.algorithm << ","
            << r.operation << ","
            << r.message_size_name << ","
            << r.message_size_bytes << ","
            << r.time_ms << ","
            << r.throughput_ops_per_sec << ","
            << r.iterations << "\n";
    }

    std::cout << "[+] Benchmark CSV saved to: " << filename << std::endl;
}