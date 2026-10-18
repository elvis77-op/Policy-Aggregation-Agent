#include "quote_verifier.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <sgx_dcap_quoteverify.h>
#include <sgx_dcap_qal.h>

namespace tacvm {
namespace attestation {

namespace {

/*
 * ============================================================
 * Format DCAP error.
 * ============================================================
 */

std::string DcapError(
    const std::string& operation,
    quote3_error_t error
) {
    std::ostringstream oss;

    oss
        << operation
        << " failed: 0x"
        << std::hex
        << static_cast<unsigned int>(error);

    return oss.str();
}

}  // namespace


/*
 * ============================================================
 * Main public verification API.
 *
 * Verifies that the quote is a validly signed SGX/TDX quote.
 * Appraisal policy checking has been removed.
 * ============================================================
 */

bool VerifyQuoteWithQVL(
    const std::vector<uint8_t>& quote,
    std::string* error_msg
) {
    if (error_msg) {
        error_msg->clear();
    }


    /*
     * --------------------------------------------------------
     * Step 0: Basic validation.
     * --------------------------------------------------------
     */

    if (quote.empty()) {

        if (error_msg) {
            *error_msg = "Quote is empty";
        }

        return false;
    }


    /*
     * --------------------------------------------------------
     * Step 1: Verify Quote signature and collateral via QVL.
     * --------------------------------------------------------
     */

    quote3_error_t dcap_ret =
        SGX_QL_ERROR_UNEXPECTED;

    unsigned int jwt_token_size = 0;

    uint8_t* jwt_token = nullptr;


    dcap_ret =
        tee_verify_quote_qvt(
            quote.data(),
            static_cast<uint32_t>(
                quote.size()
            ),
            nullptr,
            nullptr,
            nullptr,
            &jwt_token_size,
            &jwt_token
        );


    if (dcap_ret != SGX_QL_SUCCESS) {

        if (error_msg) {

            *error_msg =
                DcapError(
                    "tee_verify_quote_qvt",
                    dcap_ret
                );
        }

        return false;
    }


    std::cout
        << "[QVL] Quote verification succeeded\n";


    /*
     * Free quote verification result token.
     */

    if (jwt_token) {

        quote3_error_t free_ret =
            tee_free_verify_quote_qvt(
                jwt_token,
                &jwt_token_size
            );

        if (free_ret != SGX_QL_SUCCESS) {

            std::cerr
                << "[QVL] Warning: "
                << DcapError(
                    "tee_free_verify_quote_qvt",
                    free_ret
                )
                << "\n";
        }
    }


    return true;
}

}  // namespace attestation
}  // namespace tacvm