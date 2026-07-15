// PQBatchTools.cpp
#include "PQBatchTools.hpp"

#include "PQKeyManager.hpp"
#include "MLDSAEngine.hpp"
#include "MLKEMEngine.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <string>
#include <vector>

namespace {

bool isMLDSA(PQAlgorithm algo) {
    return algo == PQAlgorithm::MLDSA_44 ||
           algo == PQAlgorithm::MLDSA_65 ||
           algo == PQAlgorithm::MLDSA_87;
}

bool isMLKEM(PQAlgorithm algo) {
    return algo == PQAlgorithm::MLKEM_512 ||
           algo == PQAlgorithm::MLKEM_768 ||
           algo == PQAlgorithm::MLKEM_1024;
}

std::vector<uint8_t> makeMessage(std::size_t i) {
    std::string s = "Lab 6 batch verification message #" + std::to_string(i);
    return std::vector<uint8_t>(s.begin(), s.end());
}

bool sameBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

} // namespace

bool PQBatchTools::runBatchVerifyDemo(PQAlgorithm algo, std::size_t count) {
    if (!isMLDSA(algo)) {
        throw PQException("Batch verification demo requires an ML-DSA algorithm");
    }

    if (count == 0) {
        throw PQException("Batch count must be greater than zero");
    }

    PQKeyManager km;
    km.generateKeyPair(algo);

    MLDSAEngine engine;

    std::vector<std::vector<uint8_t>> messages;
    std::vector<std::vector<uint8_t>> signatures;
    messages.reserve(count);
    signatures.reserve(count);

    for (std::size_t i = 0; i < count; ++i) {
        auto msg = makeMessage(i);
        auto sig = engine.sign(msg, km.getPrivateKey(), algo);
        messages.push_back(std::move(msg));
        signatures.push_back(std::move(sig));
    }

    auto start = std::chrono::high_resolution_clock::now();

    std::size_t valid = 0;
    for (std::size_t i = 0; i < count; ++i) {
        if (engine.verify(messages[i], signatures[i], km.getPublicKey(), algo)) {
            ++valid;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();
    double ops = (ms > 0.0) ? (static_cast<double>(count) * 1000.0 / ms) : 0.0;

    std::cout << "=== Batch ML-DSA verification ===\n";
    std::cout << "Algorithm: " << PQConfig::algorithmToString(algo) << "\n";
    std::cout << "Signatures verified: " << valid << "/" << count << "\n";
    std::cout << "Verification time: " << ms << " ms\n";
    std::cout << "Throughput: " << ops << " verify ops/sec\n";

    return valid == count;
}

bool PQBatchTools::runBatchDecapsulationTiming(PQAlgorithm algo, std::size_t count) {
    if (!isMLKEM(algo)) {
        throw PQException("Batch decapsulation timing requires an ML-KEM algorithm");
    }

    if (count == 0) {
        throw PQException("Batch count must be greater than zero");
    }

    PQKeyManager km;
    km.generateKeyPair(algo);

    MLKEMEngine engine;

    std::vector<KEMResult> encapsulations;
    encapsulations.reserve(count);

    for (std::size_t i = 0; i < count; ++i) {
        encapsulations.push_back(engine.encapsulate(km.getPublicKey(), algo));
    }

    auto start = std::chrono::high_resolution_clock::now();

    std::size_t matched = 0;
    for (const auto& item : encapsulations) {
        auto recovered = engine.decapsulate(item.ciphertext, km.getPrivateKey(), algo);
        if (sameBytes(recovered, item.sharedSecret)) {
            ++matched;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();
    double ops = (ms > 0.0) ? (static_cast<double>(count) * 1000.0 / ms) : 0.0;

    std::cout << "=== Batch ML-KEM decapsulation timing ===\n";
    std::cout << "Algorithm: " << PQConfig::algorithmToString(algo) << "\n";
    std::cout << "Shared secrets matched: " << matched << "/" << count << "\n";
    std::cout << "Decapsulation time: " << ms << " ms\n";
    std::cout << "Throughput: " << ops << " decaps ops/sec\n";

    return matched == count;
}
