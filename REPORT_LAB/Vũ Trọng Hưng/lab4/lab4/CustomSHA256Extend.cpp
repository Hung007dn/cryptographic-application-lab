// CustomSHA256Extend.cpp
#include "CustomSHA256Extend.hpp"
#include <iostream>
#include <iomanip>
#include <cstring>

using namespace std;

// SHA-256 constants
const uint32_t CustomSHA256Extend::K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

CustomSHA256Extend::CustomSHA256Extend() = default;
CustomSHA256Extend::~CustomSHA256Extend() = default;

// ============ Basic Operations ============
uint32_t CustomSHA256Extend::rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

uint32_t CustomSHA256Extend::shr(uint32_t x, uint32_t n) {
    return x >> n;
}

uint32_t CustomSHA256Extend::ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

uint32_t CustomSHA256Extend::maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t CustomSHA256Extend::sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

uint32_t CustomSHA256Extend::sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

uint32_t CustomSHA256Extend::gamma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3);
}

uint32_t CustomSHA256Extend::gamma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10);
}

// ============ SHA-256 Compression Function ============
void CustomSHA256Extend::compress(uint32_t state[8], const uint8_t* block) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    
    // Prepare message schedule
    for (int i = 0; i < 16; i++) {
        w[i] = (block[i*4] << 24) | (block[i*4+1] << 16) |
               (block[i*4+2] << 8) | (block[i*4+3]);
    }
    for (int i = 16; i < 64; i++) {
        w[i] = gamma1(w[i-2]) + w[i-7] + gamma0(w[i-15]) + w[i-16];
    }
    
    // Initialize working variables
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];
    
    // Main compression loop
    for (int i = 0; i < 64; i++) {
        uint32_t temp1 = h + sigma1(e) + ch(e, f, g) + K[i] + w[i];
        uint32_t temp2 = sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    
    // Update state
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

// ============ SHA-256 Padding (RFC 6234) ============
vector<uint8_t> CustomSHA256Extend::generatePadding(size_t message_length_bytes) {
    vector<uint8_t> padding;
    uint64_t bit_length = message_length_bytes * 8;
    
    // Append 0x80
    padding.push_back(0x80);
    
    // Append zeros until length ≡ 56 mod 64
    size_t current_length = message_length_bytes + 1;
    while ((current_length % 64) != 56) {
        padding.push_back(0x00);
        current_length++;
    }
    
    // Append original length in bits (64-bit, big-endian)
    for (int i = 7; i >= 0; i--) {
        padding.push_back((bit_length >> (i * 8)) & 0xFF);
    }
    
    return padding;
}

// ============ Reconstruct Internal State ============
// Explanation: SHA-256's internal state is the 8 x 32-bit hash value
// When we see H(k || m), we can set this as the starting state
SHA256State CustomSHA256Extend::reconstructState(const string& hash_hex, 
                                                   size_t original_length) {
    SHA256State state;
    state.length = original_length;
    
    // Parse hex hash into 8 x 32-bit values (big-endian)
    vector<uint8_t> hash_bytes = hexToBytes(hash_hex);
    for (int i = 0; i < 8; i++) {
        state.h[i] = (hash_bytes[i*4] << 24) |
                     (hash_bytes[i*4+1] << 16) |
                     (hash_bytes[i*4+2] << 8) |
                     (hash_bytes[i*4+3]);
    }
    
    return state;
}

// ============ Length Extension Attack ============
string CustomSHA256Extend::lengthExtend(const string& original_hash,
                                         size_t key_length,
                                         const string& original_message,
                                         const string& append_data) {
    // Step 1: Compute total length of original message
    size_t total_length = key_length + original_message.size();
    
    // Step 2: Generate padding for original message
    vector<uint8_t> padding = generatePadding(total_length);
    
    // Step 3: Reconstruct internal state from original hash
    SHA256State state = reconstructState(original_hash, total_length + padding.size());
    
    // Step 4: Set internal state as the starting point for extension
    uint32_t h[8];
    for (int i = 0; i < 8; i++) {
        h[i] = state.h[i];
    }
    
    // Step 5: Process append_data in chunks
    vector<uint8_t> append_bytes = stringToBytes(append_data);
    size_t processed = 0;
    uint8_t block[64] = {0};
    
    while (processed < append_bytes.size()) {
        size_t remaining = append_bytes.size() - processed;
        if (remaining >= 64) {
            memcpy(block, &append_bytes[processed], 64);
            compress(h, block);
            processed += 64;
        } else {
            // Last partial block - need padding
            vector<uint8_t> final_block = vector<uint8_t>(append_bytes.begin() + processed,
                                                           append_bytes.end());
            final_block.push_back(0x80);
            
            // Add zeros
            while (final_block.size() < 56) {
                final_block.push_back(0x00);
            }
            
            // Add length
            uint64_t new_length = (total_length + padding.size() + append_data.size()) * 8;
            for (int i = 7; i >= 0; i--) {
                final_block.push_back((new_length >> (i * 8)) & 0xFF);
            }
            
            compress(h, final_block.data());
            break;
        }
    }
    
    // Step 6: Convert final state to hex
    vector<uint8_t> result;
    for (int i = 0; i < 8; i++) {
        result.push_back((h[i] >> 24) & 0xFF);
        result.push_back((h[i] >> 16) & 0xFF);
        result.push_back((h[i] >> 8) & 0xFF);
        result.push_back(h[i] & 0xFF);
    }
    
    return bytesToHex(result);
}

// ============ Standard SHA-256 (for verification) ============
string CustomSHA256Extend::sha256(const string& data) {
    vector<uint8_t> bytes = stringToBytes(data);
    
    // Initial hash values
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    size_t length = bytes.size();
    size_t processed = 0;
    uint8_t block[64] = {0};
    
    // Process full blocks
    while (processed + 64 <= length) {
        memcpy(block, &bytes[processed], 64);
        compress(h, block);
        processed += 64;
    }
    
    // Process remaining + padding
    vector<uint8_t> final_block(bytes.begin() + processed, bytes.end());
    final_block.push_back(0x80);
    
    while (final_block.size() < 56) {
        final_block.push_back(0x00);
    }
    
    uint64_t bit_length = length * 8;
    for (int i = 7; i >= 0; i--) {
        final_block.push_back((bit_length >> (i * 8)) & 0xFF);
    }
    
    compress(h, final_block.data());
    
    // Convert to hex
    vector<uint8_t> result;
    for (int i = 0; i < 8; i++) {
        result.push_back((h[i] >> 24) & 0xFF);
        result.push_back((h[i] >> 16) & 0xFF);
        result.push_back((h[i] >> 8) & 0xFF);
        result.push_back(h[i] & 0xFF);
    }
    
    return bytesToHex(result);
}

// ============ Vulnerable MAC: H(key || message) ============
string CustomSHA256Extend::vulnerableMAC(const string& key, const string& message) {
    return sha256(key + message);
}

// ============ Attack Demonstration ============
void CustomSHA256Extend::demoAttack() {
    cout << "\n========================================" << endl;
    cout << "  CUSTOM SHA-256 LENGTH EXTENSION ATTACK" << endl;
    cout << "========================================" << endl;
    
    // Setup
    string key = "secret_123";           // Unknown to attacker
    string original_msg = "Transfer $100 to Alice";
    string append_msg = "&Transfer $10000 to Eve";
    
    cout << "\n[1] Setup" << endl;
    cout << "    Key (unknown): \"" << key << "\"" << endl;
    cout << "    Original message: \"" << original_msg << "\"" << endl;
    cout << "    Attacker knows key length: " << key.length() << " bytes" << endl;
    
    // Compute original MAC (what attacker sees)
    string original_mac = vulnerableMAC(key, original_msg);
    cout << "\n[2] Attacker intercepts:" << endl;
    cout << "    Message: " << original_msg << endl;
    cout << "    MAC(H(k||m)): " << original_mac << endl;
    
    // Attacker forges extended message
    string forged_msg = original_msg;
    size_t total_length = key.length() + original_msg.length();
    vector<uint8_t> padding = generatePadding(total_length);
    
    cout << "\n[3] Attacker computes:" << endl;
    cout << "    - Original length: " << total_length << " bytes" << endl;
    cout << "    - SHA-256 padding (hex): ";
    for (uint8_t b : padding) printf("%02x", b);
    cout << endl;
    cout << "    - Forged message: H(k || m || pad || m')" << endl;
    
    // Perform length extension attack
    string forged_mac = lengthExtend(original_mac, key.length(), original_msg, append_msg);
    forged_msg = original_msg + string(padding.begin(), padding.end()) + append_msg;
    
    cout << "\n[4] Forged message (hex): ";
    for (char c : forged_msg) printf("%02x", (unsigned char)c);
    cout << endl;
    cout << "    Forged MAC: " << forged_mac << endl;
    
    // Verification
    string expected_mac = vulnerableMAC(key, forged_msg);
    cout << "\n[5] Verification:" << endl;
    cout << "    Server computes H(k || forged_msg) = " << expected_mac << endl;
    
    if (forged_mac == expected_mac) {
        cout << "     ATTACK SUCCESSFUL! Server accepts forged message!" << endl;
    } else {
        cout << "     Attack failed" << endl;
    }
    
    // Explanation
    explainStateManipulation();
    
    // Mitigation
    cout << "\n[Mitigation]" << endl;
    cout << "    Use HMAC instead: HMAC(k, m) = HMAC(k XOR opad || H(k XOR ipad || m))" << endl;
    cout << "    HMAC is NOT vulnerable to length extension attacks." << endl;
}

// ============ Explanation of Internal State Manipulation ============
void CustomSHA256Extend::explainStateManipulation() {
    cout << "\n========================================" << endl;
    cout << "  INTERNAL STATE MANIPULATION EXPLANATION" << endl;
    cout << "========================================" << endl;
    
    cout << "\n[How SHA-256 Works]" << endl;
    cout << "    SHA-256 is a Merkle-Damgard hash function:" << endl;
    cout << "    H0 = IV (initial vector)" << endl;
    cout << "    Hi+1 = compress(Hi, Mi)" << endl;
    cout << "    Hash = Hn" << endl;
    
    cout << "\n[Internal State]" << endl;
    cout << "    SHA-256 internal state is 8 x 32-bit words (256 bits total)" << endl;
    cout << "    These are the 'h' values after processing each block" << endl;
    cout << "    The final hash IS the internal state after the last block!" << endl;
    
    cout << "\n[Why Length Extension Works]" << endl;
    cout << "    1. Attacker sees H(k || m) - which is the internal state" << endl;
    cout << "    2. Attacker sets this as starting state H0'" << endl;
    cout << "    3. Attacker computes padding for H(k || m)" << endl;
    cout << "    4. Attacker continues compression with m'" << endl;
    cout << "    5. Result: H(k || m || pad || m') without knowing k!" << endl;
    
    cout << "\n[Visual Representation]" << endl;
    cout << "    Normal hash:   IV -> [k||m] -> H1 -> [padding] -> H2 -> FINAL" << endl;
    cout << "    Attack:        H1 (from above) -> [m'] -> H2' -> FINAL" << endl;
    cout << "    The attacker starts from H1 instead of IV!" << endl;
    
    cout << "\n[Why This Works]" << endl;
    cout << "    - SHA-256 uses Merkle-Damgard construction" << endl;
    cout << "    - No domain separation between key and message" << endl;
    cout << "    - Padding is deterministic" << endl;
}

// ============ Helper Functions ============
string CustomSHA256Extend::bytesToHex(const vector<uint8_t>& bytes) {
    string result;
    for (uint8_t b : bytes) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", b);
        result += buf;
    }
    return result;
}

vector<uint8_t> CustomSHA256Extend::hexToBytes(const string& hex) {
    vector<uint8_t> result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(stoi(hex.substr(i, 2), nullptr, 16));
        result.push_back(byte);
    }
    return result;
}

vector<uint8_t> CustomSHA256Extend::stringToBytes(const string& str) {
    return vector<uint8_t>(str.begin(), str.end());
}