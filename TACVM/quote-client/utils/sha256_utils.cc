#include "sha256_utils.h"

#include <openssl/evp.h>
#include <stdexcept>

std::vector<unsigned char> sha256(
    const std::vector<unsigned char>& data
) {
    std::vector<unsigned char> hash(EVP_MAX_MD_SIZE);
    unsigned int hash_len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash.data(), &hash_len) != 1) {

        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA256 failed");
    }

    EVP_MD_CTX_free(ctx);
    hash.resize(hash_len);

    return hash;
}

std::vector<unsigned char> sha256(
    const std::string& data
) {
    return sha256(
        std::vector<unsigned char>(data.begin(), data.end())
    );
}