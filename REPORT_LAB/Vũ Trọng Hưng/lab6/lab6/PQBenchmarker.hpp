#pragma once
#include <string>
#include "PQConfig.hpp"

class PQBenchmarker {
public:
    // Run ML-DSA keygen / sign / verify benchmark
    static void benchmarkMLDSA(MLDSALevel level, int iterations = 100);

    // Run ML-KEM keygen / encaps / decaps benchmark
    static void benchmarkMLKEM(MLKEMLevel level, int iterations = 100);

    // Run full benchmark (all supported variants)
    static void benchmarkAll();
};
