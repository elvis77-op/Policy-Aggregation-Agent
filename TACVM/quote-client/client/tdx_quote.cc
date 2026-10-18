#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <tdx_attest.h>

#include "crypto_utils.h"

/*
 * Generates a TDX Quote bound to REPORTDATA = [ N_att (32B) || H(PK2) (32B) ],
 * matching the layout policy_server.cc expects to find at offset 0x170.
 */
int GetQuote(
    const std::string& nonce_hex,
    const std::string& pubkey_hash_hex,
    std::vector<uint8_t>& quote_data
) {
    const std::vector<uint8_t> nonce_bytes =
        attestation::utils::CryptoUtils::HexToBytes(nonce_hex);

    const std::vector<uint8_t> pubkey_hash_bytes =
        attestation::utils::CryptoUtils::HexToBytes(pubkey_hash_hex);

    if (nonce_bytes.size() != 32 || pubkey_hash_bytes.size() != 32) {
        return 1;
    }

    tdx_report_data_t report_data;
    std::memcpy(report_data.d, nonce_bytes.data(), 32);
    std::memcpy(report_data.d + 32, pubkey_hash_bytes.data(), 32);

    uint8_t* p_quote = nullptr;
    uint32_t quote_size = 0;

    const tdx_attest_error_t ret = tdx_att_get_quote(
        &report_data,
        nullptr,
        0,
        nullptr,
        &p_quote,
        &quote_size,
        0
    );

    if (ret != TDX_ATTEST_SUCCESS || !p_quote || quote_size == 0) {
        std::cerr
            << "tdx_att_get_quote failed: error="
            << static_cast<int>(ret)
            << " quote_size="
            << quote_size
            << "\n";

        if (p_quote) {
            tdx_att_free_quote(p_quote);
        }

        return 1;
    }

    quote_data.assign(p_quote, p_quote + quote_size);

    tdx_att_free_quote(p_quote);

    return 0;
}
