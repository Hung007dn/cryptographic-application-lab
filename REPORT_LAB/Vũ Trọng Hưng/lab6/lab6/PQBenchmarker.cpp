#include "PQBenchmarker.hpp"
#include "PQKeyManager.hpp"
#include "MLDSAEngine.hpp"
#include "MLKEMEngine.hpp"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <chrono>
#include <iostream>
#include <numeric>
#include <algorithm>
#include <vector>
#include <cmath>
#include <cstdio>
#include <cstring>

using Clock = std::chrono::high_resolution_clock;
using Ms    = std::chrono::duration<double, std::milli>;

static double mean(const std::vector<double>& v) {
    return std::accumulate(v.begin(), v.end(), 0.0) / v.size();
}
static double stddev(const std::vector<double>& v, double m) {
    double s = 0;
    for (double x : v) s += (x - m)*(x - m);
    return std::sqrt(s / v.size());
}
static double median(std::vector<double> v) {
    std::sort(v.begin(), v.end());
    size_t n = v.size();
    return (n % 2 == 0) ? (v[n/2-1]+v[n/2])/2.0 : v[n/2];
}

static void printStats(const std::string& label, std::vector<double>& times) {
    double m = mean(times), med = median(times), sd = stddev(times, m);
    double ci95 = 1.96 * sd / std::sqrt((double)times.size());
    std::cout << "  " << label << ":\n"
              << "    Mean   : " << m   << " ms\n"
              << "    Median : " << med << " ms\n"
              << "    StdDev : " << sd  << " ms\n"
              << "    95% CI : ±" << ci95 << " ms\n";
}

// In-memory keygen helper returning EVP_PKEY*
static EVP_PKEY* keygen_inmem(const std::string& algoName) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, algoName.c_str(), nullptr);
    if (!ctx) return nullptr;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

void PQBenchmarker::benchmarkMLDSA(MLDSALevel level, int iters) {
    std::string algoName = PQConfig::mldsaName(level);
    std::cout << "\n========== Benchmark: " << algoName << " (" << iters << " iterations) ==========\n";

    // Test message (1 KiB)
    std::vector<unsigned char> msg(1024, 0xAB);

    std::vector<double> keygenTimes, signTimes, verifyTimes;

    // Warmup
    for (int i = 0; i < 3; i++) {
        EVP_PKEY* k = keygen_inmem(algoName);
        if (k) EVP_PKEY_free(k);
    }

    for (int i = 0; i < iters; i++) {
        // Keygen
        auto t0 = Clock::now();
        EVP_PKEY* pkey = keygen_inmem(algoName);
        keygenTimes.push_back(Ms(Clock::now() - t0).count());
        if (!pkey) { std::cerr << "[WARN] keygen failed iter " << i << "\n"; continue; }

        // Write to temp files for sign/verify engines
        const char* pubTmp  = "._bench_pub.pem";
        const char* privTmp = "._bench_priv.pem";
        FILE* fp = fopen(pubTmp, "wb");  PEM_write_PUBKEY(fp, pkey);       fclose(fp);
        fp = fopen(privTmp, "wb"); PEM_write_PrivateKey(fp, pkey, nullptr, nullptr, 0, nullptr, nullptr); fclose(fp);

        // Sign
        auto t1 = Clock::now();
        auto sig = MLDSAEngine::sign(level, privTmp, msg);
        signTimes.push_back(Ms(Clock::now() - t1).count());

        // Verify
        auto t2 = Clock::now();
        MLDSAEngine::verify(level, pubTmp, msg, sig);
        verifyTimes.push_back(Ms(Clock::now() - t2).count());

        EVP_PKEY_free(pkey);
        remove(pubTmp); remove(privTmp);
    }

    printStats("Keygen", keygenTimes);
    printStats("Sign",   signTimes);
    printStats("Verify", verifyTimes);
}

void PQBenchmarker::benchmarkMLKEM(MLKEMLevel level, int iters) {
    std::string algoName = PQConfig::mlkemName(level);
    std::cout << "\n========== Benchmark: " << algoName << " (" << iters << " iterations) ==========\n";

    std::vector<double> keygenTimes, encapsTimes, decapsTimes;

    // Warmup
    for (int i = 0; i < 3; i++) {
        EVP_PKEY* k = keygen_inmem(algoName);
        if (k) EVP_PKEY_free(k);
    }

    for (int i = 0; i < iters; i++) {
        auto t0 = Clock::now();
        EVP_PKEY* pkey = keygen_inmem(algoName);
        keygenTimes.push_back(Ms(Clock::now() - t0).count());
        if (!pkey) { std::cerr << "[WARN] keygen failed iter " << i << "\n"; continue; }

        const char* pubTmp  = "._bench_kem_pub.pem";
        const char* privTmp = "._bench_kem_priv.pem";
        FILE* fp = fopen(pubTmp, "wb");  PEM_write_PUBKEY(fp, pkey);       fclose(fp);
        fp = fopen(privTmp, "wb"); PEM_write_PrivateKey(fp, pkey, nullptr, nullptr, 0, nullptr, nullptr); fclose(fp);

        auto t1 = Clock::now();
        auto res = MLKEMEngine::encapsulate(level, pubTmp);
        encapsTimes.push_back(Ms(Clock::now() - t1).count());

        auto t2 = Clock::now();
        MLKEMEngine::decapsulate(level, privTmp, res.ciphertext);
        decapsTimes.push_back(Ms(Clock::now() - t2).count());

        EVP_PKEY_free(pkey);
        remove(pubTmp); remove(privTmp);
    }

    printStats("Keygen",     keygenTimes);
    printStats("Encapsulate", encapsTimes);
    printStats("Decapsulate", decapsTimes);
}

void PQBenchmarker::benchmarkAll() {
    benchmarkMLDSA(MLDSALevel::MLDSA44, 50);
    benchmarkMLDSA(MLDSALevel::MLDSA65, 50);
    benchmarkMLKEM(MLKEMLevel::MLKEM512, 50);
    benchmarkMLKEM(MLKEMLevel::MLKEM768, 50);
}
