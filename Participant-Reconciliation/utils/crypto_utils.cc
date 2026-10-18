#include "crypto_utils.h"

#include <fstream>
#include <sstream>
#include <cstring>
#include <iomanip>

#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

namespace attestation {
namespace utils {

namespace {

std::string GetOpenSSLError() {
    unsigned long error = ERR_get_error();

    if (error == 0) {
        return "Unknown OpenSSL error";
    }

    char buffer[256];
    ERR_error_string_n(error, buffer, sizeof(buffer));

    return std::string(buffer);
}


void AppendField(
    std::string* output,
    const std::string& field
) {
    uint64_t length = field.size();

    for (int i = 7; i >= 0; --i) {
        output->push_back(
            static_cast<char>((length >> (i * 8)) & 0xFF)
        );
    }

    output->append(field);
}


bool LoadPrivateKey(
    const std::string& private_key_path,
    EVP_PKEY** key,
    std::string* error_msg
) {
    *key = nullptr;

    FILE* fp = fopen(
        private_key_path.c_str(),
        "r"
    );

    if (!fp) {
        if (error_msg) {
            *error_msg =
                "Failed to open private key: "
                + private_key_path;
        }
        return false;
    }

    *key = PEM_read_PrivateKey(
        fp,
        nullptr,
        nullptr,
        nullptr
    );

    fclose(fp);

    if (!*key) {
        if (error_msg) {
            *error_msg = GetOpenSSLError();
        }
        return false;
    }

    return true;
}


bool LoadPublicKeyFromPem(
    const std::string& public_key_pem,
    EVP_PKEY** key,
    std::string* error_msg
) {
    *key = nullptr;

    BIO* bio = BIO_new_mem_buf(
        public_key_pem.data(),
        static_cast<int>(public_key_pem.size())
    );

    if (!bio) {
        if (error_msg) {
            *error_msg = GetOpenSSLError();
        }
        return false;
    }

    *key = PEM_read_bio_PUBKEY(
        bio,
        nullptr,
        nullptr,
        nullptr
    );

    BIO_free(bio);

    if (!*key) {
        if (error_msg) {
            *error_msg = GetOpenSSLError();
        }
        return false;
    }

    return true;
}


bool AesGcmEncrypt(
    const std::string& plaintext,
    const std::string& key,
    const std::string& nonce,
    std::string* ciphertext,
    std::string* tag,
    std::string* error_msg
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        if (error_msg) {
            *error_msg = GetOpenSSLError();
        }
        return false;
    }

    bool success = false;

    do {
        if (EVP_EncryptInit_ex(
                ctx,
                EVP_aes_256_gcm(),
                nullptr,
                nullptr,
                nullptr
            ) != 1) {

            if (error_msg) {
                *error_msg = GetOpenSSLError();
            }
            break;
        }

        if (EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_GCM_SET_IVLEN,
                static_cast<int>(nonce.size()),
                nullptr
            ) != 1) {

            if (error_msg) {
                *error_msg = GetOpenSSLError();
            }
            break;
        }

        if (EVP_EncryptInit_ex(
                ctx,
                nullptr,
                nullptr,
                reinterpret_cast<const unsigned char*>(key.data()),
                reinterpret_cast<const unsigned char*>(nonce.data())
            ) != 1) {

            if (error_msg) {
                *error_msg = GetOpenSSLError();
            }
            break;
        }

        ciphertext->resize(plaintext.size() + 16);

        int out_len = 0;
        int total = 0;

        if (!plaintext.empty()) {
            if (EVP_EncryptUpdate(
                    ctx,
                    reinterpret_cast<unsigned char*>(ciphertext->data()),
                    &out_len,
                    reinterpret_cast<const unsigned char*>(
                        plaintext.data()
                    ),
                    static_cast<int>(plaintext.size())
                ) != 1) {

                if (error_msg) {
                    *error_msg = GetOpenSSLError();
                }
                break;
            }

            total += out_len;
        }

        if (EVP_EncryptFinal_ex(
                ctx,
                reinterpret_cast<unsigned char*>(
                    ciphertext->data()
                ) + total,
                &out_len
            ) != 1) {

            if (error_msg) {
                *error_msg = GetOpenSSLError();
            }
            break;
        }

        total += out_len;
        ciphertext->resize(total);

        tag->resize(16);

        if (EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_GCM_GET_TAG,
                16,
                tag->data()
            ) != 1) {

            if (error_msg) {
                *error_msg = GetOpenSSLError();
            }
            break;
        }

        success = true;

    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return success;
}


bool AesGcmDecrypt(
    const std::string& ciphertext,
    const std::string& key,
    const std::string& nonce,
    const std::string& tag,
    std::string* plaintext,
    std::string* error_msg
) {
    if (tag.size() != 16) {
        if (error_msg) {
            *error_msg = "Invalid AES-GCM tag length";
        }
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        if (error_msg) {
            *error_msg = GetOpenSSLError();
        }
        return false;
    }

    bool success = false;

    do {
        if (EVP_DecryptInit_ex(
                ctx,
                EVP_aes_256_gcm(),
                nullptr,
                nullptr,
                nullptr
            ) != 1) {

            if (error_msg) {
                *error_msg = GetOpenSSLError();
            }
            break;
        }

        if (EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_GCM_SET_IVLEN,
                static_cast<int>(nonce.size()),
                nullptr
            ) != 1) {

            if (error_msg) {
                *error_msg = GetOpenSSLError();
            }
            break;
        }

        if (EVP_DecryptInit_ex(
                ctx,
                nullptr,
                nullptr,
                reinterpret_cast<const unsigned char*>(key.data()),
                reinterpret_cast<const unsigned char*>(nonce.data())
            ) != 1) {

            if (error_msg) {
                *error_msg = GetOpenSSLError();
            }
            break;
        }

        plaintext->resize(ciphertext.size());

        int out_len = 0;
        int total = 0;

        if (!ciphertext.empty()) {
            if (EVP_DecryptUpdate(
                    ctx,
                    reinterpret_cast<unsigned char*>(plaintext->data()),
                    &out_len,
                    reinterpret_cast<const unsigned char*>(
                        ciphertext.data()
                    ),
                    static_cast<int>(ciphertext.size())
                ) != 1) {

                if (error_msg) {
                    *error_msg = GetOpenSSLError();
                }
                break;
            }

            total += out_len;
        }

        if (EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_GCM_SET_TAG,
                static_cast<int>(tag.size()),
                const_cast<char*>(tag.data())
            ) != 1) {

            if (error_msg) {
                *error_msg = GetOpenSSLError();
            }
            break;
        }

        int final_len = 0;

        int result = EVP_DecryptFinal_ex(
            ctx,
            reinterpret_cast<unsigned char*>(
                plaintext->data()
            ) + total,
            &final_len
        );

        if (result != 1) {
            if (error_msg) {
                *error_msg =
                    "AES-GCM authentication failed";
            }
            break;
        }

        total += final_len;
        plaintext->resize(total);

        success = true;

    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return success;
}

} // anonymous namespace


bool CryptoUtils::GenerateNonce(
    std::string* nonce,
    size_t size,
    std::string* error_msg
) {
    if (!nonce || size == 0) {
        if (error_msg) {
            *error_msg = "Invalid nonce parameter";
        }
        return false;
    }

    nonce->resize(size);

    if (RAND_bytes(
            reinterpret_cast<unsigned char*>(nonce->data()),
            static_cast<int>(size)
        ) != 1) {

        if (error_msg) {
            *error_msg = GetOpenSSLError();
        }

        nonce->clear();
        return false;
    }

    return true;
}


bool CryptoUtils::ReadFile(
    const std::string& file_path,
    std::string* content,
    std::string* error_msg
) {
    if (!content) {
        if (error_msg) {
            *error_msg = "Content pointer is null";
        }
        return false;
    }

    std::ifstream file(
        file_path,
        std::ios::binary
    );

    if (!file.is_open()) {
        if (error_msg) {
            *error_msg =
                "Failed to open file: " + file_path;
        }
        return false;
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();

    *content = buffer.str();

    return true;
}


std::vector<uint8_t> CryptoUtils::HexToBytes(
    const std::string& hex
) {
    std::vector<uint8_t> bytes;

    if (hex.size() % 2 != 0) {
        return bytes;
    }

    bytes.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        try {
            uint8_t byte = static_cast<uint8_t>(
                std::stoul(
                    hex.substr(i, 2),
                    nullptr,
                    16
                )
            );

            bytes.push_back(byte);
        }
        catch (...) {
            bytes.clear();
            return bytes;
        }
    }

    return bytes;
}


std::string CryptoUtils::BytesToHex(
    const uint8_t* data,
    size_t size
) {
    std::ostringstream oss;

    for (size_t i = 0; i < size; ++i) {
        oss
            << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(data[i]);
    }

    return oss.str();
}


bool CryptoUtils::Sha256(
    const std::string& data,
    std::string* hash,
    std::string* error_msg
) {
    if (!hash) {
        if (error_msg) {
            *error_msg = "Hash pointer is null";
        }
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (!ctx) {
        if (error_msg) {
            *error_msg = GetOpenSSLError();
        }
        return false;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    bool success = false;

    do {
        if (EVP_DigestInit_ex(
                ctx,
                EVP_sha256(),
                nullptr
            ) != 1) {
            break;
        }

        if (!data.empty()) {
            if (EVP_DigestUpdate(
                    ctx,
                    data.data(),
                    data.size()
                ) != 1) {
                break;
            }
        }

        if (EVP_DigestFinal_ex(
                ctx,
                digest,
                &digest_len
            ) != 1) {
            break;
        }

        hash->assign(
            reinterpret_cast<const char*>(digest),
            digest_len
        );

        success = true;

    } while (false);

    if (!success && error_msg) {
        *error_msg = GetOpenSSLError();
    }

    EVP_MD_CTX_free(ctx);
    return success;
}


std::string CryptoUtils::BuildSignedData(
    const std::string& nonce,
    const std::string& policy_hash,
    const std::string& policy_id,
    const std::string& participant_id
) {
    std::string result;

    AppendField(&result, nonce);
    AppendField(&result, policy_hash);
    AppendField(&result, policy_id);
    AppendField(&result, participant_id);

    return result;
}


std::string CryptoUtils::BuildQuoteBindingData(
    const std::string& nonce,
    const std::string& public_key_hash
) {
    std::string result;

    AppendField(&result, "TACVM-QUOTE");
    AppendField(&result, nonce);
    AppendField(&result, public_key_hash);

    return result;
}

std::string
CryptoUtils::BuildAggregatedPolicyRequestSignedData(
    const std::string& client_id,
    const std::string& session_id,
    const std::string& policy_hash,
    const std::string& roster_hash,
    const std::string& request_nonce
) {
    std::string result;

    AppendField(
        &result,
        "TACVM-AGGREGATED-POLICY"
    );

    AppendField(&result, client_id);
    AppendField(&result, session_id);
    AppendField(&result, policy_hash);
    AppendField(&result, roster_hash);
    AppendField(&result, request_nonce);

    return result;
}

bool CryptoUtils::GenerateRSAKeyPair(
    const std::string& private_key_path,
    const std::string& public_key_path,
    int bits,
    std::string* error_msg
) {
    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new_id(
            EVP_PKEY_RSA,
            nullptr
        );

    if (!ctx) {
        if (error_msg) {
            *error_msg = GetOpenSSLError();
        }
        return false;
    }

    EVP_PKEY* key = nullptr;
    bool success = false;

    do {
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            break;
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(
                ctx,
                bits
            ) <= 0) {
            break;
        }

        if (EVP_PKEY_keygen(
                ctx,
                &key
            ) <= 0) {
            break;
        }

        FILE* private_fp = fopen(
            private_key_path.c_str(),
            "w"
        );

        if (!private_fp) {
            if (error_msg) {
                *error_msg =
                    "Cannot write private key";
            }
            break;
        }

        int private_ok =
            PEM_write_PrivateKey(
                private_fp,
                key,
                nullptr,
                nullptr,
                0,
                nullptr,
                nullptr
            );

        fclose(private_fp);

        if (private_ok != 1) {
            break;
        }

        FILE* public_fp = fopen(
            public_key_path.c_str(),
            "w"
        );

        if (!public_fp) {
            if (error_msg) {
                *error_msg =
                    "Cannot write public key";
            }
            break;
        }

        int public_ok =
            PEM_write_PUBKEY(
                public_fp,
                key
            );

        fclose(public_fp);

        if (public_ok != 1) {
            break;
        }

        success = true;

    } while (false);

    if (!success && error_msg) {
        *error_msg = GetOpenSSLError();
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);

    return success;
}


bool CryptoUtils::LoadPublicKeyPem(
    const std::string& public_key_path,
    std::string* public_key_pem,
    std::string* error_msg
) {
    return ReadFile(
        public_key_path,
        public_key_pem,
        error_msg
    );
}


bool CryptoUtils::PublicKeyToPem(
    const std::string& private_key_path,
    std::string* public_key_pem,
    std::string* error_msg
) {
    EVP_PKEY* key = nullptr;

    if (!LoadPrivateKey(
            private_key_path,
            &key,
            error_msg
        )) {
        return false;
    }

    BIO* bio = BIO_new(
        BIO_s_mem()
    );

    if (!bio) {
        EVP_PKEY_free(key);

        if (error_msg) {
            *error_msg = GetOpenSSLError();
        }

        return false;
    }

    bool success = false;

    if (PEM_write_bio_PUBKEY(
            bio,
            key
        ) == 1) {

        char* data = nullptr;
        long size =
            BIO_get_mem_data(
                bio,
                &data
            );

        if (size > 0 && data) {
            public_key_pem->assign(
                data,
                size
            );

            success = true;
        }
    }

    if (!success && error_msg) {
        *error_msg = GetOpenSSLError();
    }

    BIO_free(bio);
    EVP_PKEY_free(key);

    return success;
}


bool CryptoUtils::SignData(
    const std::string& data,
    const std::string& private_key_path,
    std::string* signature,
    std::string* error_msg
) {
    EVP_PKEY* private_key = nullptr;

    if (!LoadPrivateKey(
            private_key_path,
            &private_key,
            error_msg
        )) {
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (!ctx) {
        EVP_PKEY_free(private_key);

        if (error_msg) {
            *error_msg =
                "Failed to create EVP_MD_CTX";
        }

        return false;
    }

    bool success = false;

    do {
        if (EVP_DigestSignInit(
                ctx,
                nullptr,
                EVP_sha256(),
                nullptr,
                private_key
            ) != 1) {
            break;
        }

        if (EVP_DigestSignUpdate(
                ctx,
                data.data(),
                data.size()
            ) != 1) {
            break;
        }

        size_t signature_length = 0;

        if (EVP_DigestSignFinal(
                ctx,
                nullptr,
                &signature_length
            ) != 1) {
            break;
        }

        signature->resize(signature_length);

        if (EVP_DigestSignFinal(
                ctx,
                reinterpret_cast<unsigned char*>(
                    signature->data()
                ),
                &signature_length
            ) != 1) {

            signature->clear();
            break;
        }

        signature->resize(signature_length);
        success = true;

    } while (false);

    if (!success && error_msg) {
        *error_msg = GetOpenSSLError();
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(private_key);

    return success;
}


bool CryptoUtils::VerifySignatureWithPublicKey(
    const std::string& data,
    const std::string& signature,
    const std::string& public_key_pem,
    std::string* error_msg
) {
    EVP_PKEY* public_key = nullptr;

    if (!LoadPublicKeyFromPem(
            public_key_pem,
            &public_key,
            error_msg
        )) {
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (!ctx) {
        EVP_PKEY_free(public_key);

        if (error_msg) {
            *error_msg =
                "Failed to create EVP_MD_CTX";
        }

        return false;
    }

    bool success = false;

    do {
        if (EVP_DigestVerifyInit(
                ctx,
                nullptr,
                EVP_sha256(),
                nullptr,
                public_key
            ) != 1) {
            break;
        }

        if (EVP_DigestVerifyUpdate(
                ctx,
                data.data(),
                data.size()
            ) != 1) {
            break;
        }

        int result =
            EVP_DigestVerifyFinal(
                ctx,
                reinterpret_cast<
                    const unsigned char*
                >(signature.data()),
                signature.size()
            );

        success = (result == 1);

        if (!success && error_msg) {
            *error_msg =
                "Signature verification failed";
        }

    } while (false);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(public_key);

    return success;
}


bool CryptoUtils::VerifySignature(
    const std::string& data,
    const std::string& signature,
    const std::string& certificate_path,
    std::string* error_msg
) {
    FILE* fp = fopen(
        certificate_path.c_str(),
        "r"
    );

    if (!fp) {
        if (error_msg) {
            *error_msg =
                "Failed to open certificate: "
                + certificate_path;
        }

        return false;
    }

    X509* certificate =
        PEM_read_X509(
            fp,
            nullptr,
            nullptr,
            nullptr
        );

    fclose(fp);

    if (!certificate) {
        if (error_msg) {
            *error_msg = GetOpenSSLError();
        }

        return false;
    }

    EVP_PKEY* public_key =
        X509_get_pubkey(certificate);

    X509_free(certificate);

    if (!public_key) {
        if (error_msg) {
            *error_msg = GetOpenSSLError();
        }

        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (!ctx) {
        EVP_PKEY_free(public_key);
        return false;
    }

    bool success = false;

    do {
        if (EVP_DigestVerifyInit(
                ctx,
                nullptr,
                EVP_sha256(),
                nullptr,
                public_key
            ) != 1) {
            break;
        }

        if (EVP_DigestVerifyUpdate(
                ctx,
                data.data(),
                data.size()
            ) != 1) {
            break;
        }

        success =
            EVP_DigestVerifyFinal(
                ctx,
                reinterpret_cast<
                    const unsigned char*
                >(signature.data()),
                signature.size()
            ) == 1;

    } while (false);

    if (!success && error_msg) {
        *error_msg =
            "Signature verification failed";
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(public_key);

    return success;
}


bool CryptoUtils::HybridEncrypt(
    const std::string& plaintext,
    const std::string& recipient_public_key_pem,
    std::string* encrypted_key,
    std::string* nonce,
    std::string* ciphertext,
    std::string* authentication_tag,
    std::string* error_msg
) {
    if (!encrypted_key
        || !nonce
        || !ciphertext
        || !authentication_tag) {

        if (error_msg) {
            *error_msg =
                "Invalid HybridEncrypt output";
        }

        return false;
    }

    std::string aes_key;

    if (!GenerateNonce(
            &aes_key,
            32,
            error_msg
        )) {
        return false;
    }

    if (!GenerateNonce(
            nonce,
            12,
            error_msg
        )) {
        return false;
    }

    if (!AesGcmEncrypt(
            plaintext,
            aes_key,
            *nonce,
            ciphertext,
            authentication_tag,
            error_msg
        )) {
        return false;
    }

    EVP_PKEY* public_key = nullptr;

    if (!LoadPublicKeyFromPem(
            recipient_public_key_pem,
            &public_key,
            error_msg
        )) {
        return false;
    }

    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new(
            public_key,
            nullptr
        );

    if (!ctx) {
        EVP_PKEY_free(public_key);

        if (error_msg) {
            *error_msg = GetOpenSSLError();
        }

        return false;
    }

    bool success = false;

    do {
        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            break;
        }

        if (EVP_PKEY_base_id(public_key)
            == EVP_PKEY_RSA) {

            if (EVP_PKEY_CTX_set_rsa_padding(
                    ctx,
                    RSA_PKCS1_OAEP_PADDING
                ) <= 0) {
                break;
            }

            if (EVP_PKEY_CTX_set_rsa_oaep_md(
                    ctx,
                    EVP_sha256()
                ) <= 0) {
                break;
            }

            if (EVP_PKEY_CTX_set_rsa_mgf1_md(
                    ctx,
                    EVP_sha256()
                ) <= 0) {
                break;
            }
        }

        size_t encrypted_key_len = 0;

        if (EVP_PKEY_encrypt(
                ctx,
                nullptr,
                &encrypted_key_len,
                reinterpret_cast<
                    const unsigned char*
                >(aes_key.data()),
                aes_key.size()
            ) <= 0) {
            break;
        }

        encrypted_key->resize(
            encrypted_key_len
        );

        if (EVP_PKEY_encrypt(
                ctx,
                reinterpret_cast<unsigned char*>(
                    encrypted_key->data()
                ),
                &encrypted_key_len,
                reinterpret_cast<
                    const unsigned char*
                >(aes_key.data()),
                aes_key.size()
            ) <= 0) {
            encrypted_key->clear();
            break;
        }

        encrypted_key->resize(
            encrypted_key_len
        );

        success = true;

    } while (false);

    if (!success && error_msg) {
        *error_msg = GetOpenSSLError();
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(public_key);

    return success;
}


bool CryptoUtils::HybridDecrypt(
    const std::string& encrypted_key,
    const std::string& nonce,
    const std::string& ciphertext,
    const std::string& authentication_tag,
    const std::string& recipient_private_key_path,
    std::string* plaintext,
    std::string* error_msg
) {
    EVP_PKEY* private_key = nullptr;

    if (!LoadPrivateKey(
            recipient_private_key_path,
            &private_key,
            error_msg
        )) {
        return false;
    }

    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new(
            private_key,
            nullptr
        );

    if (!ctx) {
        EVP_PKEY_free(private_key);
        return false;
    }

    std::string aes_key;
    bool success = false;

    do {
        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
            break;
        }

        if (EVP_PKEY_base_id(private_key)
            == EVP_PKEY_RSA) {

            if (EVP_PKEY_CTX_set_rsa_padding(
                    ctx,
                    RSA_PKCS1_OAEP_PADDING
                ) <= 0) {
                break;
            }

            if (EVP_PKEY_CTX_set_rsa_oaep_md(
                    ctx,
                    EVP_sha256()
                ) <= 0) {
                break;
            }

            if (EVP_PKEY_CTX_set_rsa_mgf1_md(
                    ctx,
                    EVP_sha256()
                ) <= 0) {
                break;
            }
        }

        size_t aes_key_len = 0;

        if (EVP_PKEY_decrypt(
                ctx,
                nullptr,
                &aes_key_len,
                reinterpret_cast<
                    const unsigned char*
                >(encrypted_key.data()),
                encrypted_key.size()
            ) <= 0) {
            break;
        }

        aes_key.resize(aes_key_len);

        if (EVP_PKEY_decrypt(
                ctx,
                reinterpret_cast<unsigned char*>(
                    aes_key.data()
                ),
                &aes_key_len,
                reinterpret_cast<
                    const unsigned char*
                >(encrypted_key.data()),
                encrypted_key.size()
            ) <= 0) {
            break;
        }

        aes_key.resize(aes_key_len);

        if (aes_key.size() != 32) {
            if (error_msg) {
                *error_msg =
                    "Invalid recovered AES key";
            }
            break;
        }

        if (!AesGcmDecrypt(
                ciphertext,
                aes_key,
                nonce,
                authentication_tag,
                plaintext,
                error_msg
            )) {
            break;
        }

        success = true;

    } while (false);

    if (!success && error_msg) {
        *error_msg = GetOpenSSLError();
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(private_key);

    return success;
}

} // namespace utils
} // namespace attestation