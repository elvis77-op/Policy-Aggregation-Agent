#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <string>
#include <vector>
#include <cstddef>
// 0905
#include <cstdint>

namespace attestation {
namespace utils {

class CryptoUtils {
public:

    // ============================================================
    // Basic utilities
    // ============================================================

    static bool GenerateNonce(
        std::string* nonce,
        size_t size = 32,
        std::string* error_msg = nullptr
    );

    static bool ReadFile(
        const std::string& file_path,
        std::string* content,
        std::string* error_msg = nullptr
    );

    static std::vector<uint8_t> HexToBytes(
        const std::string& hex
    );

    static std::string BytesToHex(
        const uint8_t* data,
        size_t size
    );


    // ============================================================
    // SHA-256
    // ============================================================

    static bool Sha256(
        const std::string& data,
        std::string* hash,
        std::string* error_msg = nullptr
    );


    // ============================================================
    // Generic field encoding
    // ============================================================

    static std::string BuildSignedData(
        const std::string& nonce,
        const std::string& policy_hash,
        const std::string& policy_id,
        const std::string& participant_id
    );

    static std::string BuildQuoteBindingData(
        const std::string& nonce,
        const std::string& public_key_hash
    );

    static std::string BuildAggregatedPolicyRequestSignedData(
        const std::string& client_id,
        const std::string& session_id,
        const std::string& policy_hash,
        const std::string& roster_hash,
        const std::string& request_nonce
    );

    // ============================================================
    // RSA Key Generation / Public Key Serialization
    //
    // Used for:
    //
    // Key 2:
    //     TA PK2 / SK2
    //
    // Key 3:
    //     Participant PK3 / SK3
    // ============================================================

    static bool GenerateRSAKeyPair(
        const std::string& private_key_path,
        const std::string& public_key_path,
        int bits = 2048,
        std::string* error_msg = nullptr
    );

    static bool LoadPublicKeyPem(
        const std::string& public_key_path,
        std::string* public_key_pem,
        std::string* error_msg = nullptr
    );

    static bool PublicKeyToPem(
        const std::string& private_key_path,
        std::string* public_key_pem,
        std::string* error_msg = nullptr
    );


    // ============================================================
    // Signature
    // ============================================================

    static bool SignData(
        const std::string& data,
        const std::string& private_key_path,
        std::string* signature,
        std::string* error_msg = nullptr
    );

    static bool VerifySignatureWithPublicKey(
        const std::string& data,
        const std::string& signature,
        const std::string& public_key_pem,
        std::string* error_msg = nullptr
    );

    static bool VerifySignature(
        const std::string& data,
        const std::string& signature,
        const std::string& certificate_path,
        std::string* error_msg = nullptr
    );


    // ============================================================
    // Hybrid Encryption
    //
    // Participant -> TA:
    //
    //   random AES-256 key
    //       +
    //   AES-256-GCM(message)
    //       +
    //   RSA-OAEP-SHA256(PK2, AES key)
    //
    // ============================================================

    static bool HybridEncrypt(
        const std::string& plaintext,
        const std::string& recipient_public_key_pem,
        std::string* encrypted_key,
        std::string* nonce,
        std::string* ciphertext,
        std::string* authentication_tag,
        std::string* error_msg = nullptr
    );

    static bool HybridDecrypt(
        const std::string& encrypted_key,
        const std::string& nonce,
        const std::string& ciphertext,
        const std::string& authentication_tag,
        const std::string& recipient_private_key_path,
        std::string* plaintext,
        std::string* error_msg = nullptr
    );
};

} // namespace utils
} // namespace attestation

#endif