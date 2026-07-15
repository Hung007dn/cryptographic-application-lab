// MD5CollisionDemo.cpp
#include "MD5CollisionDemo.hpp"

#include <openssl/evp.h>
#include <openssl/err.h>

#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>

using namespace std;

namespace {

struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX* ctx) const {
        EVP_MD_CTX_free(ctx);
    }
};

using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

string getOpenSSLErrorString() {
    unsigned long err = ERR_get_error();

    if (err == 0) {
        return "unknown OpenSSL error";
    }

    char buffer[256];
    ERR_error_string_n(err, buffer, sizeof(buffer));
    return string(buffer);
}

string bytesToHexLocal(const vector<uint8_t>& bytes) {
    ostringstream oss;

    oss << hex << setfill('0');

    for (uint8_t b : bytes) {
        oss << setw(2) << nouppercase << static_cast<int>(b);
    }

    return oss.str();
}

vector<uint8_t> computeDigestOpenSSL(const vector<uint8_t>& data, const EVP_MD* md) {
    if (!md) {
        throw runtime_error("Unsupported OpenSSL digest algorithm");
    }

    EvpMdCtxPtr ctx(EVP_MD_CTX_new());

    if (!ctx) {
        throw runtime_error("EVP_MD_CTX_new failed: " + getOpenSSLErrorString());
    }

    if (EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1) {
        throw runtime_error("EVP_DigestInit_ex failed: " + getOpenSSLErrorString());
    }

    if (!data.empty()) {
        if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1) {
            throw runtime_error("EVP_DigestUpdate failed: " + getOpenSSLErrorString());
        }
    }

    int digest_size = EVP_MD_get_size(md);

    if (digest_size <= 0) {
        throw runtime_error("Invalid OpenSSL digest size");
    }

    vector<uint8_t> digest(static_cast<size_t>(digest_size));
    unsigned int actual_size = 0;

    if (EVP_DigestFinal_ex(ctx.get(), digest.data(), &actual_size) != 1) {
        throw runtime_error("EVP_DigestFinal_ex failed: " + getOpenSSLErrorString());
    }

    digest.resize(actual_size);
    return digest;
}

} // namespace

MD5CollisionDemo::MD5CollisionDemo() {
    cout << "[MD5 Collision Demo] Initialized" << endl;
}

MD5CollisionDemo::~MD5CollisionDemo() = default;

vector<uint8_t> MD5CollisionDemo::readFile(const string& filename) {
    ifstream file(filename, ios::binary);

    if (!file.is_open()) {
        throw runtime_error("Cannot open file: " + filename);
    }

    return vector<uint8_t>(
        istreambuf_iterator<char>(file),
        istreambuf_iterator<char>()
    );
}

void MD5CollisionDemo::writeFile(const string& filename, const vector<uint8_t>& data) {
    ofstream file(filename, ios::binary);

    if (!file.is_open()) {
        throw runtime_error("Cannot write file: " + filename);
    }

    file.write(
        reinterpret_cast<const char*>(data.data()),
        static_cast<streamsize>(data.size())
    );
}

string MD5CollisionDemo::bytesToHex(const vector<uint8_t>& bytes) {
    return bytesToHexLocal(bytes);
}

vector<uint8_t> MD5CollisionDemo::hexToBytes(const string& hex) {
    if (hex.size() % 2 != 0) {
        throw runtime_error("Invalid hex string length");
    }

    vector<uint8_t> out;
    out.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(stoul(byteString, nullptr, 16));
        out.push_back(byte);
    }

    return out;
}

string MD5CollisionDemo::computeMD5(const string& filename) {
    vector<uint8_t> data = readFile(filename);
    vector<uint8_t> digest = computeDigestOpenSSL(data, EVP_md5());
    return bytesToHexLocal(digest);
}

string MD5CollisionDemo::computeSHA256(const string& filename) {
    vector<uint8_t> data = readFile(filename);
    vector<uint8_t> digest = computeDigestOpenSSL(data, EVP_sha256());
    return bytesToHexLocal(digest);
}

bool MD5CollisionDemo::filesDiffer(const string& file1, const string& file2) {
    vector<uint8_t> a = readFile(file1);
    vector<uint8_t> b = readFile(file2);

    return a != b;
}

bool MD5CollisionDemo::generateCollision(
    const string& prefix,
    const string& output1,
    const string& output2
) {
    cout << "\n[MD5 Collision] Generating controlled collision..." << endl;
    cout << "Prefix: " << prefix << endl;

    ofstream prefixFile("md5_prefix.txt", ios::binary);

    if (!prefixFile.is_open()) {
        cerr << "Error: cannot create md5_prefix.txt" << endl;
        return false;
    }

    prefixFile << prefix;
    prefixFile.close();

#ifdef _WIN32
    string cmd =
        "fastcoll.exe -p md5_prefix.txt -o \"" + output1 + "\" \"" + output2 + "\"";
#else
    string cmd =
        "fastcoll -p md5_prefix.txt -o \"" + output1 + "\" \"" + output2 + "\"";
#endif

    int ret = system(cmd.c_str());

    if (ret != 0) {
        cerr << "Error: collision generation failed." << endl;
        cerr << "Install hashclash/fastcoll or provide two pre-generated collision files." << endl;
        cerr << "You can still verify prepared files with:" << endl;
        cerr << "  hashtool --md5-collision --file1 a.bin --file2 b.bin" << endl;

        remove("md5_prefix.txt");
        return false;
    }

    remove("md5_prefix.txt");

    cout << "[+] Collision files generated." << endl;
    return verifyCollision(output1, output2);
}

bool MD5CollisionDemo::verifyCollision(const string& file1, const string& file2) {
    try {
        string md5_1 = computeMD5(file1);
        string md5_2 = computeMD5(file2);

        string sha256_1 = computeSHA256(file1);
        string sha256_2 = computeSHA256(file2);

        bool differentFiles = filesDiffer(file1, file2);

        CollisionPair pair;
        pair.file1_name = file1;
        pair.file2_name = file2;
        pair.md5_hash1 = md5_1;
        pair.md5_hash2 = md5_2;
        pair.sha256_hash1 = sha256_1;
        pair.sha256_hash2 = sha256_2;
        pair.files_are_different = differentFiles;

        displayCollisionInfo(pair);

        bool collision = !md5_1.empty() &&
                         md5_1 == md5_2 &&
                         differentFiles;

        if (collision) {
            cout << "\n[+] MD5 collision confirmed." << endl;

            if (sha256_1 != sha256_2) {
                cout << "[+] SHA-256 differs, showing that the collision is specific to MD5." << endl;
            } else {
                cout << "[!] SHA-256 also matches. This is unusual; verify the files." << endl;
            }

            return true;
        }

        cerr << "\n[-] No valid MD5 collision detected." << endl;
        return false;

    } catch (const exception& e) {
        cerr << "Collision verification error: " << e.what() << endl;
        return false;
    }
}

bool MD5CollisionDemo::createCppDemo() {
    cout << "\n[MD5 Collision Demo Helper]" << endl;
    cout << "This helper creates two benign C++ source files as placeholders." << endl;
    cout << "For a real MD5 collision deliverable, generate two colliding C++ files" << endl;
    cout << "with hashclash/fastcoll and verify them using --md5-collision." << endl;

    const string file1 = "md5_demo_a.cpp";
    const string file2 = "md5_demo_b.cpp";

    {
        ofstream a(file1, ios::binary);
        a << "#include <iostream>\n"
          << "int main(){ std::cout << \"Benign demo A\" << std::endl; return 0; }\n";
    }

    {
        ofstream b(file2, ios::binary);
        b << "#include <iostream>\n"
          << "int main(){ std::cout << \"Benign demo B\" << std::endl; return 0; }\n";
    }

    cout << "Created placeholder files:" << endl;
    cout << "  " << file1 << endl;
    cout << "  " << file2 << endl;
    cout << "These files are not expected to collide until processed by a collision tool." << endl;

    return true;
}

bool MD5CollisionDemo::createPythonDemo() {
    return createCppDemo();
}

void MD5CollisionDemo::displayCollisionInfo(const CollisionPair& pair) {
    cout << "\n========================================" << endl;
    cout << "        MD5 COLLISION VERIFICATION" << endl;
    cout << "========================================" << endl;

    cout << "\n[Files]" << endl;
    cout << "  File 1: " << pair.file1_name << endl;
    cout << "  File 2: " << pair.file2_name << endl;
    cout << "  Files differ: " << (pair.files_are_different ? "yes" : "no") << endl;

    cout << "\n[MD5]" << endl;
    cout << "  File 1: " << pair.md5_hash1 << endl;
    cout << "  File 2: " << pair.md5_hash2 << endl;

    cout << "\n[SHA-256]" << endl;
    cout << "  File 1: " << pair.sha256_hash1 << endl;
    cout << "  File 2: " << pair.sha256_hash2 << endl;

    cout << "\n[Explanation]" << endl;
    cout << "  A valid MD5 collision means two different files have the same MD5 digest." << endl;
    cout << "  This demonstrates collision weakness, not preimage recovery." << endl;
}

