#include "quote_verifier.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include <sgx_dcap_quoteverify.h>
#include <sgx_dcap_qal.h>

namespace tacvm {
namespace attestation {

namespace {

std::mutex appraisal_mutex;

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

bool ReadAppraisalPolicy(
    std::string* policy,
    std::string* error_msg
) {
    const char* configured_path =
        std::getenv("TACVM_TDX_PLATFORM_POLICY_JWT");

    const std::string policy_path =
        configured_path
            ? configured_path
            : "/app/QuoteAppraisal/Policies/tdx_platform_policy_min_eval_num.jwt";

    std::ifstream input(policy_path, std::ios::binary);

    if (!input) {
        if (error_msg) {
            *error_msg = "Unable to open appraisal policy JWT: " + policy_path;
        }

        return false;
    }

    *policy = std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()
    );

    if (policy->empty()) {
        if (error_msg) {
            *error_msg = "Appraisal policy JWT is empty: " + policy_path;
        }

        return false;
    }

    return true;
}

}  // namespace


/*
 * ============================================================
 * Main public verification API.
 *
 * Verifies the quote and appraises the verification result against the
 * configured TDX platform policy.
 * ============================================================
 */

bool VerifyQuoteWithQVL(
    const std::vector<uint8_t>& quote,
    std::string* error_msg
) {
    std::lock_guard<std::mutex> lock(appraisal_mutex);

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


    std::string appraisal_policy;

    if (!ReadAppraisalPolicy(&appraisal_policy, error_msg)) {
        return false;
    }

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


    std::vector<uint8_t> appraisal_policy_bytes(
        appraisal_policy.begin(),
        appraisal_policy.end()
    );
    appraisal_policy_bytes.push_back('\0');

    uint8_t* quote_appraisal_policies[] = {
        appraisal_policy_bytes.data()
    };

    unsigned int appraisal_token_size = 0;
    uint8_t* appraisal_token = nullptr;

    quote3_error_t appraisal_ret =
        tee_appraise_verification_token(
            jwt_token,
            quote_appraisal_policies,
            1,
            std::time(nullptr),
            nullptr,
            &appraisal_token_size,
            &appraisal_token
        );

    if (appraisal_ret != SGX_QL_SUCCESS) {
        if (jwt_token) {
            tee_free_verify_quote_qvt(jwt_token, &jwt_token_size);
        }

        if (error_msg) {
            *error_msg = DcapError(
                "tee_appraise_verification_token",
                appraisal_ret
            );
        }

        return false;
    }

    tee_policy_bundle_t policies = {};
    policies.platform_policy.pt = CUSTOMIZED;
    policies.platform_policy.p_policy = appraisal_policy_bytes.data();

    tee_policy_auth_result_t auth_result = TEE_AUTH_FAILURE;

    quote3_error_t auth_ret =
        tee_authenticate_appraisal_result_ex(
            quote.data(),
            static_cast<uint32_t>(quote.size()),
            appraisal_token,
            &policies,
            nullptr,
            nullptr,
            &auth_result,
            nullptr
        );

    if (auth_ret != SGX_QL_SUCCESS || auth_result == TEE_AUTH_FAILURE) {
        if (appraisal_token) {
            tee_free_appraisal_token(appraisal_token);
        }

        if (jwt_token) {
            tee_free_verify_quote_qvt(jwt_token, &jwt_token_size);
        }

        if (error_msg) {
            *error_msg = auth_ret != SGX_QL_SUCCESS
                ? DcapError(
                    "tee_authenticate_appraisal_result_ex",
                    auth_ret
                )
                : "Appraisal policy rejected the quote";
        }

        return false;
    }

    std::cout
        << "[QVL] Quote verification and appraisal succeeded"
        << " (policy auth result: "
        << static_cast<int>(auth_result)
        << ")\n";


    /*
     * Free quote verification result token.
     */

    if (appraisal_token) {
        quote3_error_t free_appraisal_ret =
            tee_free_appraisal_token(appraisal_token);

        if (free_appraisal_ret != SGX_QL_SUCCESS) {
            std::cerr
                << "[QVL] Warning: "
                << DcapError(
                    "tee_free_appraisal_token",
                    free_appraisal_ret
                )
                << "\n";
        }
    }

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
