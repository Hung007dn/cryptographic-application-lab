// BatchVerifier.cpp
#include "BatchVerifier.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>

using namespace std;

BatchVerifier::BatchVerifier() {
    m_keyManager.generateKeyPair(SignatureAlgorithm::ECDSA_P256);
}

BatchVerifier::~BatchVerifier() = default;

BatchResult BatchVerifier::verifyBatch(const vector<string>& messages,
                                        const vector<vector<uint8_t>>& signatures,
                                        EVP_PKEY* publicKey,
                                        SignatureAlgorithm algo,
                                        HashAlgorithm hash_algo) {
    if (messages.size() != signatures.size()) {
    throw SigException("Batch verification input size mismatch");
    }
    BatchResult result;
    result.total = messages.size();
    result.valid = 0;
    result.invalid = 0;
    
    auto start = chrono::high_resolution_clock::now();
    
    for (size_t i = 0; i < messages.size(); i++) {
        auto msg_bytes = vector<uint8_t>(messages[i].begin(), messages[i].end());
        bool valid = false;
        
        if (algo == SignatureAlgorithm::ECDSA_P256 || algo == SignatureAlgorithm::ECDSA_P384) {
            valid = m_ecdsaEngine.verify(msg_bytes, signatures[i], publicKey, hash_algo);
        } else {
            valid = m_rsaEngine.verify(msg_bytes, signatures[i], publicKey, hash_algo);
        }
        
        if (valid) {
            result.valid++;
        } else {
            result.invalid++;
            result.failed_indices.push_back(i);
        }
    }
    
    auto end = chrono::high_resolution_clock::now();
    result.total_time_ms = chrono::duration<double, milli>(end - start).count();
    
    return result;
}

void BatchVerifier::generateTestBatch(size_t count) {
    m_testMessages.clear();
    m_testSignatures.clear();
    
    cout << "Generating " << count << " test signatures..." << endl;
    
    for (size_t i = 0; i < count; i++) {
        string message = "Test message " + to_string(i) + " with some content for signing";
        auto msg_bytes = vector<uint8_t>(message.begin(), message.end());
        
        auto sig = m_ecdsaEngine.sign(msg_bytes, m_keyManager.getPrivateKey(),
                                       HashAlgorithm::SHA256, true);
        
        m_testMessages.push_back(message);
        m_testSignatures.push_back(sig);
    }
    
    cout << "Generated " << m_testMessages.size() << " signatures" << endl;
}

void BatchVerifier::printBatchResult(const BatchResult& result) {
    cout << "\n=== Batch Verification Result ===" << endl;
    cout << "  Total signatures: " << result.total << endl;
    cout << "  Valid: " << result.valid << endl;
    cout << "  Invalid: " << result.invalid << endl;
    cout << "  Success rate: " << fixed << setprecision(2) 
         << (result.valid * 100.0 / result.total) << "%" << endl;
    cout << "  Total time: " << fixed << setprecision(2) << result.total_time_ms << " ms" << endl;
    cout << "  Avg time per signature: " << fixed << setprecision(3) 
         << (result.total_time_ms / result.total) << " ms" << endl;
    
    if (!result.failed_indices.empty()) {
        cout << "  Failed indices: ";
        for (size_t idx : result.failed_indices) {
            cout << idx << " ";
        }
        cout << endl;
    }
}

void BatchVerifier::runBatchPerformanceTest() {
    cout << "\n=== Batch Verification Performance Test ===" << endl;
    
    vector<size_t> batch_sizes = {1, 10, 50, 100, 500};
    
    cout << left << setw(12) << "Batch Size"
         << setw(16) << "Time (ms)"
         << setw(20) << "Avg per sig (ms)"
         << endl;
    cout << string(48, '-') << endl;
    
    for (size_t size : batch_sizes) {
        generateTestBatch(size);
        
        BatchResult result = verifyBatch(m_testMessages, m_testSignatures,
                                          m_keyManager.getPublicKey(),
                                          SignatureAlgorithm::ECDSA_P256,
                                          HashAlgorithm::SHA256);
        
        cout << left << setw(12) << size
             << setw(16) << fixed << setprecision(2) << result.total_time_ms
             << setw(20) << fixed << setprecision(3) << (result.total_time_ms / size)
             << endl;
    }
}