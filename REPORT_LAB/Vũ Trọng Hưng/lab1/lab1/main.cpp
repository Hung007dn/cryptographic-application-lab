#include "CryptoConfig.hpp"
#include "FileEncryptor.hpp"
#include "NISTValidator.hpp"
#include "Benchmarker.hpp"
#include "KATRunner.hpp"
#include "NegativeTests.hpp"
#include <iostream>
#include <string>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cstring>
#include <cryptopp/base64.h>
#include <cstdio>
#include <vector>
#include <fstream>

void printUsage(const char* program_name) {
    std::cout << "Usage:\n"
              << "  " << program_name << " encrypt --mode <mode> --key <key> [options]\n"
              << "  " << program_name << " decrypt --mode <mode> --key <key> [options]\n\n"
              << "Required:\n"
              << "  --mode <mode>       ecb|cbc|ofb|cfb|ctr|xts|ccm|gcm\n"
              << "  --key <file>        Key file (raw or hex-encoded)\n"
              << "  --key-hex <hex>     Key as hex string\n"
              << "  --in <file>         Input file\n"
              << "  --out <file>        Output file; if omitted, output is printed to screen\n\n"
              << "IV/Nonce (optional):\n"
              << "  --iv <file>         IV/nonce file\n"
              << "  --iv-hex <hex>      IV/nonce as hex string\n"
              << "  --nonce <file>      Nonce file (for AEAD)\n"
              << "  --nonce-hex <hex>   Nonce as hex string\n"
              << "  If omitted, auto-generated securely\n\n"
              << "AEAD Options (CCM/GCM):\n"
              << "  --aad <file>        Additional Authenticated Data file\n"
              << "  --aad-text <str>    AAD as string\n"
              << "  --aead              Enable authenticated mode flag for CCM/GCM\n\n"
              << "Input Options:\n"
              << "  --text <str>        Encrypt/decrypt text directly\n\n"
              << "Output Format:\n"
              << "  --encode <format>   raw|hex|base64 (default: raw)\n\n"
              << "ECB Restrictions:\n"
              << "  --allow-ecb         Override ECB restrictions (NOT RECOMMENDED)\n\n"
              << "Testing Options:\n"
              << "  --kat <file>        Run Known Answer Tests from JSON file\n"
              << "  --test-nist         Run NIST test vector validation\n"
              << "  --negative-tests    Run negative/error tests\n"
              << "  --benchmark         Run performance benchmarks\n"
              << "  --help, -h          Show this help\n\n"
              << "Examples:\n"
              << "  " << program_name << " encrypt --mode gcm --key key.bin --in msg.txt --out ct.bin\n"
              << "  " << program_name << " decrypt --mode gcm --key key.bin --in ct.bin --out msg.txt\n"
              << "  " << program_name << " encrypt --mode cbc --key-hex 001122 --text \"Hello\" --out out.enc\n";
}

static CryptoPP::SecByteBlock hexToSecBlock(const std::string& hex) {
    std::string decoded;
    CryptoPP::StringSource ss(
        hex,
        true,
        new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded))
    );

    CryptoPP::SecByteBlock out(decoded.size());
    if (!decoded.empty()) {
        std::memcpy(out.data(), decoded.data(), decoded.size());
    }
    return out;
}


static std::vector<uint8_t> readBinaryFileForDisplay(const std::string& filename) {
    std::ifstream in(filename, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
}

static std::string bytesToHexForDisplay(const std::vector<uint8_t>& data) {
    std::string encoded;
    CryptoPP::StringSource ss(data.data(), data.size(), true,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded), false));
    return encoded;
}

static std::string bytesToBase64ForDisplay(const std::vector<uint8_t>& data) {
    std::string encoded;
    CryptoPP::StringSource ss(data.data(), data.size(), true,
        new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));
    return encoded;
}

static void printOutputFile(const std::string& filename, OutputFormat format) {
    auto data = readBinaryFileForDisplay(filename);
    if (format == OutputFormat::HEX) {
        std::cout << bytesToHexForDisplay(data) << std::endl;
    } else if (format == OutputFormat::BASE64) {
        std::cout << bytesToBase64ForDisplay(data) << std::endl;
    } else {
        std::cout.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        std::cout << std::endl;
    }
}

int main(int argc, char* argv[]) {
    try {
        if (argc < 2) {
            printUsage(argv[0]);
            return 0;
        }
        
        std::string command = argv[1];
        
        if (command == "--help" || command == "-h") {
            printUsage(argv[0]);
            return 0;
        }
        else if (command == "--test-nist") {
            NISTValidator validator;
            validator.runAllTests();
            return 0;
        }
        else if (command == "--benchmark") {
            Benchmarker benchmarker(5);
            benchmarker.benchmarkAllModes(10);
            return 0;
        }
        else if (command == "--compare") {
        Benchmarker benchmarker(1000);  
        benchmarker.benchmarkAllSizes();
        return 0;
        }
        else if (command == "--negative-tests") {
            NegativeTests tests;
            bool all_passed = tests.runAllTests();
            return all_passed ? 0 : 1;
        }
        else if (command == "--kat" && argc >= 3) {
            KATRunner runner;
            runner.runFromFile(argv[2]);
            return 0;
        }
        else if (command == "encrypt" || command == "decrypt") {
            // Parse encryption/decryption arguments
            CryptoConfig config;
            std::string input_file, output_file;
            
            for (int i = 2; i < argc; i++) {
                std::string arg = argv[i];
                if (arg == "--mode" && i+1 < argc) {
                    config.mode = CryptoConfig::stringToMode(argv[++i]);
                }
                else if (arg == "--key" && i+1 < argc) {
                    config.key_file = argv[++i];
                }
                else if (arg == "--key-hex" && i+1 < argc) {
                    config.key_hex = argv[++i];
                }
                else if (arg == "--iv" && i+1 < argc) {
                    config.iv_file = argv[++i];
                }
                else if (arg == "--iv-hex" && i+1 < argc) {
                    config.iv = hexToSecBlock(argv[++i]);
                    config.iv_size = config.iv.size();
                }
                else if (arg == "--nonce" && i+1 < argc) {
                    config.nonce_file = argv[++i];
                }
                else if (arg == "--nonce-hex" && i+1 < argc) {
                    config.iv = hexToSecBlock(argv[++i]);
                    config.iv_size = config.iv.size();
                }
                else if (arg == "--in" && i+1 < argc) {
                    input_file = argv[++i];
                }
                else if (arg == "--out" && i+1 < argc) {
                    output_file = argv[++i];
                }
                else if (arg == "--text" && i+1 < argc) {
                    config.text_input = argv[++i];
                    config.is_text_input = true;
                }
                else if (arg == "--aad" && i+1 < argc) {
                    config.aad_file = argv[++i];
                }
                else if (arg == "--aad-text" && i+1 < argc) {
                    config.aad_text = argv[++i];
                }
                else if (arg == "--aead") {
                    config.use_aead = true;
                }
                else if (arg == "--encode" && i+1 < argc) {
                    config.output_format = CryptoConfig::stringToFormat(argv[++i]);
                }
                else if (arg == "--allow-ecb") {
                    config.allow_ecb = true;
                    std::cerr << "  ECB override active. Security warning!\n";
                }
            }
            
            // Validate required parameters
            if (input_file.empty() && !config.is_text_input) {
                throw std::runtime_error("Input file or --text required");
            }
            bool print_to_screen = output_file.empty();
            if (print_to_screen) {
                output_file = command == "encrypt" ? ".aestool_stdout.enc" : ".aestool_stdout.dec";
                if (config.output_format == OutputFormat::RAW) {
                    // Raw ciphertext is often binary and can corrupt the terminal, so hex is safer by default.
                    config.output_format = OutputFormat::HEX;
                }
            }
            if (config.key_file.empty() && config.key_hex.empty()) {
                throw std::runtime_error("Key required (--key or --key-hex)");
            }
            
            FileEncryptor engine(config);
            
            if (command == "encrypt") {
                if (config.is_text_input) {
                    engine.encryptFromString(config.text_input, output_file);
                } else {
                    engine.encrypt(input_file, output_file);
                }
                if (print_to_screen) {
                    printOutputFile(output_file, config.output_format);
                    std::remove(output_file.c_str());
                    std::remove((output_file + ".json").c_str());
                } else {
                    std::cout << " Encryption complete: " << output_file << std::endl;
                }
            } else {
                engine.decrypt(input_file, output_file);
                if (print_to_screen) {
                    printOutputFile(output_file, config.output_format);
                    std::remove(output_file.c_str());
                } else {
                    std::cout << " Decryption complete: " << output_file << std::endl;
                }
            }
        }
        else {
            std::cerr << "Unknown command: " << command << std::endl;
            printUsage(argv[0]);
            return 1;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "\n Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}