
// HybridEncryptor.cpp
#include "HybridEncryptor.hpp"

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>

#include <stdexcept>
#include <iostream>
#include <string>
#include <vector>

using namespace CryptoPP;

static std::string makeEnvelopeAAD(
    const std::string& mode,
    int rsa_modulus,
    const std::string& hash,
    const std::string& label
) {
    return mode + "|" +
           std::to_string(rsa_modulus) + "|" +
           hash + "|" +
           label;
}

HybridEncryptor::HybridEncryptor() = default;
HybridEncryptor::~HybridEncryptor() = default;

std::string HybridEncryptor::base64Encode(const std::vector<uint8_t>& data) {
    std::string encoded;

    StringSource ss(
        reinterpret_cast<const CryptoPP::byte*>(data.data()),
        data.size(),
        true,
        new Base64Encoder(
            new StringSink(encoded),
            false
        )
    );

    return encoded;
}

std::vector<uint8_t> HybridEncryptor::base64Decode(const std::string& base64) {
    std::string decoded;

    try {
        StringSource ss(
            base64,
            true,
            new Base64Decoder(
                new StringSink(decoded)
            )
        );
    } catch (const CryptoPP::Exception&) {
        throw RSAException("Base64 decode failed.");
    }

    return std::vector<uint8_t>(decoded.begin(), decoded.end());
}

std::string HybridEnvelope::toJSON() const {
    json j;

    j["mode"] = mode;
    j["rsa_modulus"] = rsa_modulus;
    j["hash"] = hash;
    j["wrapped_key"] = wrapped_key;
    j["iv"] = iv;
    j["tag"] = tag;

    std::string ct_encoded;

    StringSource ss(
        reinterpret_cast<const CryptoPP::byte*>(ciphertext.data()),
        ciphertext.size(),
        true,
        new Base64Encoder(
            new StringSink(ct_encoded),
            false
        )
    );

    j["ciphertext"] = ct_encoded;

    return j.dump(4);
}

HybridEnvelope HybridEnvelope::fromJSON(const std::string& json_str) {
    HybridEnvelope env;

    try {
        json j = json::parse(json_str);

        env.mode = j.at("mode").get<std::string>();
        env.rsa_modulus = j.at("rsa_modulus").get<int>();
        env.hash = j.at("hash").get<std::string>();
        env.wrapped_key = j.at("wrapped_key").get<std::string>();
        env.iv = j.at("iv").get<std::string>();
        env.tag = j.at("tag").get<std::string>();

        if (!j.contains("ciphertext")) {
            throw RSAException("Hybrid envelope missing ciphertext field.");
        }

        std::string ct_b64 = j.at("ciphertext").get<std::string>();
        std::string ct_raw;

        StringSource ss(
            ct_b64,
            true,
            new Base64Decoder(
                new StringSink(ct_raw)
            )
        );

        env.ciphertext.assign(ct_raw.begin(), ct_raw.end());

    } catch (const RSAException&) {
        throw;
    } catch (const std::exception&) {
        throw RSAException("Malformed hybrid envelope JSON.");
    }

    return env;
}

std::vector<uint8_t> HybridEncryptor::generateAESKey() {
    std::vector<uint8_t> key(RSAConfig::AES_KEY_SIZE);

    m_rng.GenerateBlock(
        reinterpret_cast<CryptoPP::byte*>(key.data()),
        key.size()
    );

    return key;
}

std::vector<uint8_t> HybridEncryptor::generateIV() {
    std::vector<uint8_t> iv(RSAConfig::GCM_IV_SIZE);

    m_rng.GenerateBlock(
        reinterpret_cast<CryptoPP::byte*>(iv.data()),
        iv.size()
    );

    return iv;
}

std::vector<uint8_t> HybridEncryptor::aesGCMEncrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::string& label,
    std::vector<uint8_t>& tag
) {
    if (key.size() != RSAConfig::AES_KEY_SIZE) {
        throw RSAException("Invalid AES key size. AES-256 requires 32 bytes.");
    }

    if (iv.size() != RSAConfig::GCM_IV_SIZE) {
        throw RSAException("Invalid AES-GCM IV size. GCM requires 96-bit IV.");
    }

    std::string combined;

    try {
        GCM<AES>::Encryption enc;

        enc.SetKeyWithIV(
            reinterpret_cast<const CryptoPP::byte*>(key.data()),
            key.size(),
            reinterpret_cast<const CryptoPP::byte*>(iv.data()),
            iv.size()
        );

        AuthenticatedEncryptionFilter ef(
            enc,
            new StringSink(combined),
            false,
            RSAConfig::GCM_TAG_SIZE
        );

        // Here, the parameter name "label" is used as the complete AAD string.
        // In hybridEncrypt(), this AAD contains: mode | rsa_modulus | hash | user label.
        if (!label.empty()) {
            ef.ChannelPut(
                AAD_CHANNEL,
                reinterpret_cast<const CryptoPP::byte*>(label.data()),
                label.size()
            );

            ef.ChannelMessageEnd(AAD_CHANNEL);
        }

        ef.ChannelPut(
            DEFAULT_CHANNEL,
            reinterpret_cast<const CryptoPP::byte*>(plaintext.data()),
            plaintext.size()
        );

        ef.ChannelMessageEnd(DEFAULT_CHANNEL);

    } catch (const CryptoPP::Exception&) {
        throw RSAException("AES-GCM encryption failed.");
    }

    if (combined.size() < RSAConfig::GCM_TAG_SIZE) {
        throw RSAException("AES-GCM encryption failed: output shorter than tag size.");
    }

    std::vector<uint8_t> ciphertext(
        combined.begin(),
        combined.end() - RSAConfig::GCM_TAG_SIZE
    );

    tag.assign(
        combined.end() - RSAConfig::GCM_TAG_SIZE,
        combined.end()
    );

    return ciphertext;
}

std::vector<uint8_t> HybridEncryptor::aesGCMDecrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& tag,
    const std::string& label
) {
    if (key.size() != RSAConfig::AES_KEY_SIZE) {
        throw RSAException("Invalid AES key size. AES-256 requires 32 bytes.");
    }

    if (iv.size() != RSAConfig::GCM_IV_SIZE) {
        throw RSAException("Invalid AES-GCM IV size. GCM requires 96-bit IV.");
    }

    if (tag.size() != RSAConfig::GCM_TAG_SIZE) {
        throw RSAException("Invalid AES-GCM authentication tag size.");
    }

    std::string recovered;
    std::string ciphertext_with_tag;

    ciphertext_with_tag.assign(ciphertext.begin(), ciphertext.end());
    ciphertext_with_tag.append(tag.begin(), tag.end());

    try {
        GCM<AES>::Decryption dec;

        dec.SetKeyWithIV(
            reinterpret_cast<const CryptoPP::byte*>(key.data()),
            key.size(),
            reinterpret_cast<const CryptoPP::byte*>(iv.data()),
            iv.size()
        );

        AuthenticatedDecryptionFilter df(
            dec,
            new StringSink(recovered),
            AuthenticatedDecryptionFilter::THROW_EXCEPTION,
            RSAConfig::GCM_TAG_SIZE
        );

        // Here, the parameter name "label" is used as the complete AAD string.
        // In hybridDecrypt(), this AAD is recomputed from the received header.
        // If the header was tampered, authentication fails.
        if (!label.empty()) {
            df.ChannelPut(
                AAD_CHANNEL,
                reinterpret_cast<const CryptoPP::byte*>(label.data()),
                label.size()
            );

            df.ChannelMessageEnd(AAD_CHANNEL);
        }

        df.ChannelPut(
            DEFAULT_CHANNEL,
            reinterpret_cast<const CryptoPP::byte*>(ciphertext_with_tag.data()),
            ciphertext_with_tag.size()
        );

        df.ChannelMessageEnd(DEFAULT_CHANNEL);

    } catch (const CryptoPP::Exception&) {
        throw RSAException(
            "AES-GCM authentication failed. Wrong label, wrong key, tampered header, or tampered ciphertext/tag."
        );
    }

    return std::vector<uint8_t>(recovered.begin(), recovered.end());
}

HybridEnvelope HybridEncryptor::hybridEncrypt(
    const std::vector<uint8_t>& plaintext,
    CryptoPP::RSA::PublicKey& publicKey,
    const std::string& label
) {
    std::vector<uint8_t> aesKey = generateAESKey();
    std::vector<uint8_t> iv = generateIV();
    std::vector<uint8_t> tag;

    const std::string mode = "RSA-OAEP-AES-GCM";
    const int rsa_modulus = static_cast<int>(publicKey.GetModulus().BitCount());
    const std::string hash = "SHA-256";

    std::string aad = makeEnvelopeAAD(
        mode,
        rsa_modulus,
        hash,
        label
    );

    std::vector<uint8_t> ciphertext = aesGCMEncrypt(
        plaintext,
        aesKey,
        iv,
        aad,
        tag
    );

    std::vector<uint8_t> wrappedKey = m_rsaEngine.encryptOAEP(
        aesKey,
        publicKey,
        label
    );

    HybridEnvelope envelope;

    envelope.mode = mode;
    envelope.rsa_modulus = rsa_modulus;
    envelope.hash = hash;
    envelope.wrapped_key = base64Encode(wrappedKey);
    envelope.iv = base64Encode(iv);
    envelope.tag = base64Encode(tag);
    envelope.ciphertext = ciphertext;

    return envelope;
}

std::vector<uint8_t> HybridEncryptor::hybridDecrypt(
    const HybridEnvelope& envelope,
    CryptoPP::RSA::PrivateKey& privateKey,
    const std::string& label
) {
    if (envelope.mode != "RSA-OAEP-AES-GCM") {
        throw RSAException("Unsupported hybrid envelope mode.");
    }

    if (envelope.hash != "SHA-256") {
        throw RSAException("Unsupported hash in hybrid envelope.");
    }

    if (envelope.rsa_modulus != 3072 && envelope.rsa_modulus != 4096) {
        throw RSAException("Tampered or unsupported RSA modulus in envelope header.");
    }

    int actual_modulus = static_cast<int>(privateKey.GetModulus().BitCount());

    if (envelope.rsa_modulus != actual_modulus) {
        throw RSAException("Envelope RSA modulus does not match private key.");
    }

    if (envelope.wrapped_key.empty()) {
        throw RSAException("Envelope missing wrapped AES key.");
    }

    if (envelope.iv.empty()) {
        throw RSAException("Envelope missing AES-GCM IV.");
    }

    if (envelope.tag.empty()) {
        throw RSAException("Envelope missing AES-GCM tag.");
    }

    if (envelope.ciphertext.empty()) {
        throw RSAException("Envelope missing ciphertext payload.");
    }

    std::vector<uint8_t> wrappedKey = base64Decode(envelope.wrapped_key);
    std::vector<uint8_t> iv = base64Decode(envelope.iv);
    std::vector<uint8_t> tag = base64Decode(envelope.tag);

    std::vector<uint8_t> aesKey = m_rsaEngine.decryptOAEP(
        wrappedKey,
        privateKey,
        label
    );

    std::string aad = makeEnvelopeAAD(
        envelope.mode,
        envelope.rsa_modulus,
        envelope.hash,
        label
    );

    return aesGCMDecrypt(
        envelope.ciphertext,
        aesKey,
        iv,
        tag,
        aad
    );
}

std::vector<uint8_t> HybridEncryptor::encryptAuto(
    const std::vector<uint8_t>& plaintext,
    CryptoPP::RSA::PublicKey& publicKey,
    const std::string& label,
    bool force_hybrid
) {
    if (!force_hybrid &&
        !m_rsaEngine.isPlaintextTooLarge(plaintext.size(), publicKey)) {
        return m_rsaEngine.encryptOAEP(
            plaintext,
            publicKey,
            label
        );
    }

    HybridEnvelope envelope = hybridEncrypt(
        plaintext,
        publicKey,
        label
    );

    std::string envelopeJson = envelope.toJSON();

    return std::vector<uint8_t>(
        envelopeJson.begin(),
        envelopeJson.end()
    );
}

std::vector<uint8_t> HybridEncryptor::decryptAuto(
    const std::vector<uint8_t>& ciphertext,
    CryptoPP::RSA::PrivateKey& privateKey,
    const std::string& label
) {
    std::string input(
        ciphertext.begin(),
        ciphertext.end()
    );

    try {
        HybridEnvelope envelope = HybridEnvelope::fromJSON(input);

        if (envelope.mode == "RSA-OAEP-AES-GCM") {
            return hybridDecrypt(
                envelope,
                privateKey,
                label
            );
        }
    } catch (...) {
        // Not a valid hybrid envelope. Fall back to direct RSA-OAEP.
    }

    return m_rsaEngine.decryptOAEP(
        ciphertext,
        privateKey,
        label
    );
}
