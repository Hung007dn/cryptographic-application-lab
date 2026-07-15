// RSABenchmarker.cpp
#include "RSABenchmarker.hpp"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <chrono>
#include <vector>
#include <string>

using namespace std;
using namespace std::chrono;

RSABenchmarker::RSABenchmarker(size_t iterations)
    : m_iterations(iterations) {}

static double elapsedMs(high_resolution_clock::time_point start,
                        high_resolution_clock::time_point end) {
    return duration<double, milli>(end - start).count();
}

static double safeRatio(double a, double b) {
    if (b <= 0.0) {
        return 0.0;
    }
    return a / b;
}

static double safeThroughputMBps(size_t bytes, double ms) {
    if (ms <= 0.0) {
        return 0.0;
    }

    double mb = static_cast<double>(bytes) / (1024.0 * 1024.0);
    double sec = ms / 1000.0;

    return mb / sec;
}

void RSABenchmarker::benchmarkKeyGeneration() {
    cout << "\n--- Key Generation Benchmark ---" << endl;

    /*
        Key generation is expensive, especially RSA-4096.
        Use fewer iterations to keep benchmark time reasonable.
    */
    size_t keygenIterations = min<size_t>(m_iterations, 5);

    for (int bits : {3072, 4096}) {
        double total_ms = 0.0;

        for (size_t i = 0; i < keygenIterations; i++) {
            RSAKeyManager km;

            auto start = high_resolution_clock::now();
            km.generateKeyPair(static_cast<RSAKeySize>(bits));
            auto end = high_resolution_clock::now();

            total_ms += elapsedMs(start, end);
        }

        double avg_ms = total_ms / keygenIterations;

        RSABenchmarkResult result;
        result.test_name = "Key Generation";
        result.key_bits = bits;
        result.time_ms = avg_ms;
        result.throughput_mbps = 0.0;
        result.data_size_bytes = 0;

        m_results.push_back(result);

        cout << "  RSA-" << bits << ": "
             << fixed << setprecision(3) << avg_ms << " ms"
             << endl;
    }
}

void RSABenchmarker::benchmarkRSAEncryptDecrypt() {
    cout << "\n--- RSA-OAEP Encrypt/Decrypt Benchmark ---" << endl;

    vector<int> key_sizes = {3072, 4096};

    string plaintext = "Small message for RSA encryption";
    vector<uint8_t> plain(plaintext.begin(), plaintext.end());

    cout << left << setw(12) << "Key Size"
         << setw(16) << "Encrypt (ms)"
         << setw(16) << "Decrypt (ms)"
         << setw(16) << "Ratio (D/E)" << endl;

    cout << string(60, '-') << endl;

    for (int bits : key_sizes) {
        RSAKeyManager km;
        km.generateKeyPair(static_cast<RSAKeySize>(bits));

        RSAEngine engine;

        /*
            RSA public-key encryption is very fast and may be below timer
            resolution if measured once. Run many encryptions in one timed
            batch and divide by the number of operations.
        */
        size_t encryptInner = 1000;
        size_t encryptOuter = min<size_t>(m_iterations, 20);

        double enc_total = 0.0;

        for (size_t outer = 0; outer < encryptOuter; outer++) {
            auto start = high_resolution_clock::now();

            for (size_t i = 0; i < encryptInner; i++) {
                auto cipher = engine.encryptOAEP(
                    plain,
                    km.getPublicKey(),
                    "bench"
                );

                // Prevent unused variable warnings and over-aggressive optimization.
                if (cipher.empty()) {
                    throw RSAException("Unexpected empty RSA ciphertext.");
                }
            }

            auto end = high_resolution_clock::now();

            enc_total += elapsedMs(start, end);
        }

        double enc_avg = enc_total / static_cast<double>(encryptOuter * encryptInner);

        /*
            RSA private-key decryption is slower.
            Use fewer repetitions to keep runtime acceptable.
        */
        auto cipher = engine.encryptOAEP(
            plain,
            km.getPublicKey(),
            "bench"
        );

        size_t decryptInner = 5;
        size_t decryptOuter = min<size_t>(m_iterations, 20);

        double dec_total = 0.0;

        for (size_t outer = 0; outer < decryptOuter; outer++) {
            auto start = high_resolution_clock::now();

            for (size_t i = 0; i < decryptInner; i++) {
                auto decrypted = engine.decryptOAEP(
                    cipher,
                    km.getPrivateKey(),
                    "bench"
                );

                if (decrypted != plain) {
                    throw RSAException("RSA decrypt benchmark verification failed.");
                }
            }

            auto end = high_resolution_clock::now();

            dec_total += elapsedMs(start, end);
        }

        double dec_avg = dec_total / static_cast<double>(decryptOuter * decryptInner);
        double ratio = safeRatio(dec_avg, enc_avg);

        cout << left << setw(12) << ("RSA-" + to_string(bits))
             << setw(16) << fixed << setprecision(6) << enc_avg
             << setw(16) << fixed << setprecision(6) << dec_avg
             << setw(16) << fixed << setprecision(2) << ratio << "x"
             << endl;

        RSABenchmarkResult r_enc;
        r_enc.test_name = "RSA Encrypt";
        r_enc.key_bits = bits;
        r_enc.time_ms = enc_avg;
        r_enc.throughput_mbps = safeThroughputMBps(plain.size(), enc_avg);
        r_enc.data_size_bytes = plain.size();
        m_results.push_back(r_enc);

        RSABenchmarkResult r_dec;
        r_dec.test_name = "RSA Decrypt";
        r_dec.key_bits = bits;
        r_dec.time_ms = dec_avg;
        r_dec.throughput_mbps = safeThroughputMBps(plain.size(), dec_avg);
        r_dec.data_size_bytes = plain.size();
        m_results.push_back(r_dec);
    }
}

void RSABenchmarker::compareKeySizes() {
    cout << "\n--- Key Size Comparison (RSA-3072 vs RSA-4096) ---" << endl;

    string plaintext = "Benchmark comparison text";
    vector<uint8_t> plain(plaintext.begin(), plaintext.end());

    cout << left << setw(12) << "Operation"
         << setw(16) << "RSA-3072 (ms)"
         << setw(16) << "RSA-4096 (ms)"
         << setw(16) << "Slowdown" << endl;

    cout << string(60, '-') << endl;

    for (const string op : {"Encrypt", "Decrypt"}) {
        vector<double> times;

        for (int bits : {3072, 4096}) {
            RSAKeyManager km;
            km.generateKeyPair(static_cast<RSAKeySize>(bits));

            RSAEngine engine;

            auto cipher = engine.encryptOAEP(
                plain,
                km.getPublicKey(),
                "bench"
            );

            double total = 0.0;

            if (op == "Encrypt") {
                size_t inner = 1000;
                size_t outer = min<size_t>(m_iterations, 20);

                for (size_t o = 0; o < outer; o++) {
                    auto start = high_resolution_clock::now();

                    for (size_t i = 0; i < inner; i++) {
                        auto c = engine.encryptOAEP(
                            plain,
                            km.getPublicKey(),
                            "bench"
                        );

                        if (c.empty()) {
                            throw RSAException("Unexpected empty RSA ciphertext.");
                        }
                    }

                    auto end = high_resolution_clock::now();

                    total += elapsedMs(start, end);
                }

                times.push_back(total / static_cast<double>(outer * inner));

            } else {
                size_t inner = 5;
                size_t outer = min<size_t>(m_iterations, 20);

                for (size_t o = 0; o < outer; o++) {
                    auto start = high_resolution_clock::now();

                    for (size_t i = 0; i < inner; i++) {
                        auto d = engine.decryptOAEP(
                            cipher,
                            km.getPrivateKey(),
                            "bench"
                        );

                        if (d != plain) {
                            throw RSAException("RSA decrypt verification failed.");
                        }
                    }

                    auto end = high_resolution_clock::now();

                    total += elapsedMs(start, end);
                }

                times.push_back(total / static_cast<double>(outer * inner));
            }
        }

        double slowdown = safeRatio(times[1], times[0]);

        cout << left << setw(12) << op
             << setw(16) << fixed << setprecision(6) << times[0]
             << setw(16) << fixed << setprecision(6) << times[1]
             << setw(16) << fixed << setprecision(2) << slowdown << "x"
             << endl;
    }
}

void RSABenchmarker::benchmarkHybridEncryptDecrypt() {
    cout << "\n--- Hybrid Encryption Benchmark (RSA-3072 + AES-256-GCM) ---" << endl;

    RSAKeyManager km;
    km.generateKeyPair(RSAKeySize::RSA_3072);

    HybridEncryptor hybrid;

    vector<size_t> sizes = {
        1024,
        1024 * 1024,
        100 * 1024 * 1024
    };

    vector<string> size_names = {
        "1 KB",
        "1 MB",
        "100 MB"
    };

    cout << left << setw(12) << "Size"
         << setw(20) << "Encrypt (ms)"
         << setw(20) << "Decrypt (ms)"
         << setw(20) << "Throughput" << endl;

    cout << string(72, '-') << endl;

    for (size_t idx = 0; idx < sizes.size(); idx++) {
        size_t size_bytes = sizes[idx];
        vector<uint8_t> plaintext(size_bytes, 'X');

        /*
            Adaptive repetitions:
            1 KB is fast, so use more repetitions.
            1 MB uses moderate repetitions.
            100 MB uses a small number to avoid excessive runtime.
        */
        size_t reps = 1;

        if (size_bytes <= 1024) {
            reps = 50;
        } else if (size_bytes <= 1024 * 1024) {
            reps = 10;
        } else {
            reps = 1;
        }

        reps = min(reps, max<size_t>(1, m_iterations));

        double enc_total = 0.0;
        double dec_total = 0.0;

        HybridEnvelope lastEnvelope;

        for (size_t i = 0; i < reps; i++) {
            auto start = high_resolution_clock::now();

            lastEnvelope = hybrid.hybridEncrypt(
                plaintext,
                km.getPublicKey(),
                "bench"
            );

            auto end = high_resolution_clock::now();

            enc_total += elapsedMs(start, end);
        }

        double enc_avg = enc_total / reps;

        for (size_t i = 0; i < reps; i++) {
            auto start = high_resolution_clock::now();

            auto decrypted = hybrid.hybridDecrypt(
                lastEnvelope,
                km.getPrivateKey(),
                "bench"
            );

            auto end = high_resolution_clock::now();

            if (decrypted != plaintext) {
                throw RSAException("Hybrid decrypt benchmark verification failed.");
            }

            dec_total += elapsedMs(start, end);
        }

        double dec_avg = dec_total / reps;
        double throughput = safeThroughputMBps(size_bytes, enc_avg);

        cout << left << setw(12) << size_names[idx]
             << setw(20) << fixed << setprecision(6) << enc_avg
             << setw(20) << fixed << setprecision(6) << dec_avg
             << setw(20) << fixed << setprecision(2) << throughput << " MB/s"
             << endl;

        RSABenchmarkResult r_enc;
        r_enc.test_name = "Hybrid Encrypt (" + size_names[idx] + ")";
        r_enc.key_bits = 3072;
        r_enc.time_ms = enc_avg;
        r_enc.throughput_mbps = throughput;
        r_enc.data_size_bytes = size_bytes;
        m_results.push_back(r_enc);

        RSABenchmarkResult r_dec;
        r_dec.test_name = "Hybrid Decrypt (" + size_names[idx] + ")";
        r_dec.key_bits = 3072;
        r_dec.time_ms = dec_avg;
        r_dec.throughput_mbps = safeThroughputMBps(size_bytes, dec_avg);
        r_dec.data_size_bytes = size_bytes;
        m_results.push_back(r_dec);
    }
}

string RSABenchmarker::formatTime(double ms) {
    if (ms < 1.0) {
        return to_string(static_cast<int>(ms * 1000.0)) + " us";
    }

    return to_string(static_cast<int>(ms)) + " ms";
}

void RSABenchmarker::printSummary() {
    cout << "\n=== Performance Summary ===" << endl;
    cout << "Iterations per test: " << m_iterations << endl;

    double total_time = 0.0;

    for (const auto& r : m_results) {
        total_time += r.time_ms;
    }

    cout << "Accumulated average operation time: "
         << fixed << setprecision(3)
         << total_time << " ms" << endl;
}

void RSABenchmarker::exportCSV(const string& filename) {
    ofstream file(filename);

    if (!file) {
        cerr << "Cannot open benchmark CSV output file: " << filename << endl;
        return;
    }

    file << "Test Name,Key Bits,Time (ms),Throughput (MB/s),Data Size (bytes)\n";

    for (const auto& r : m_results) {
        file << r.test_name << ","
             << r.key_bits << ","
             << fixed << setprecision(6) << r.time_ms << ","
             << fixed << setprecision(6) << r.throughput_mbps << ","
             << r.data_size_bytes << "\n";
    }

    cout << "Benchmark results exported to " << filename << endl;
}

void RSABenchmarker::runBenchmarks() {
    cout << "\n========================================\n";
    cout << "       RSA PERFORMANCE BENCHMARK\n";
    cout << "========================================\n";

    m_results.clear();

    benchmarkKeyGeneration();
    benchmarkRSAEncryptDecrypt();
    compareKeySizes();
    benchmarkHybridEncryptDecrypt();

    printSummary();
    exportCSV("rsa_benchmark_results.csv");
}