#include "quote_verifier.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <iostream>

#include <jwt-cpp/jwt.h>

// 0905
// #include <sgx_dcap_quoteverify.h>
// #include <tee_qv.h>
// #include <tee_appraisal.h>

#include <sgx_dcap_quoteverify.h>
#include <sgx_dcap_qal.h>

namespace tacvm {
namespace attestation {

namespace {

/*
 * ============================================================
 * Policy configuration
 *
 * These paths are intentionally kept equivalent to the original
 * QVLAppraisal App.cpp.
 * ============================================================
 */

const std::string kPolicyPublicKey =
    "QuoteAppraisal/Policies/ec_pub.pem";

const std::string kSgxEnclavePolicy =
    "QuoteAppraisal/Policies/sgx_enclave_policy.jwt";

const std::string kTdxTenantPolicy =
    "QuoteAppraisal/Policies/tenant_td_policy.jwt";

const std::vector<std::string> kSgxPlatformPolicies = {
    "QuoteAppraisal/Policies/sgx_platform_policy_strict.jwt"
};

const std::vector<std::string> kTdxPlatformPolicies = {
    "QuoteAppraisal/Policies/tdx_platform_policy_strict.jwt",
    "QuoteAppraisal/Policies/tdx_platform_policy_platform_grace_period.jwt",
    "QuoteAppraisal/Policies/tdx_platform_policy_collateral_grace_period.jwt",
    "QuoteAppraisal/Policies/tdx_platform_policy_rejected_id.jwt",
    "QuoteAppraisal/Policies/alibabacloud_tdx_platform_policy_90C06F000000.jwt"
};


/*
 * Quote type constants from the original App.cpp.
 */

constexpr uint32_t kSgxQuoteType = 0x0;
constexpr uint32_t kTdxQuoteType = 0x81;


/*
 * ============================================================
 * Read a binary/text file.
 * ============================================================
 */

bool ReadFile(
    const std::string& path,
    std::vector<uint8_t>* output,
    std::string* error_msg
) {
    if (!output) {
        if (error_msg) {
            *error_msg = "Output buffer is null";
        }
        return false;
    }

    std::ifstream file(
        path,
        std::ios::binary
    );

    if (!file.is_open()) {
        if (error_msg) {
            *error_msg =
                "Failed to open file: " + path;
        }
        return false;
    }

    file.seekg(
        0,
        std::ios::end
    );

    std::streampos size =
        file.tellg();

    if (size < 0) {
        if (error_msg) {
            *error_msg =
                "Failed to determine file size: " + path;
        }
        return false;
    }

    file.seekg(
        0,
        std::ios::beg
    );

    output->resize(
        static_cast<size_t>(size)
    );

    if (size > 0) {
        file.read(
            reinterpret_cast<char*>(output->data()),
            size
        );

        if (!file) {
            if (error_msg) {
                *error_msg =
                    "Failed to read file: " + path;
            }
            return false;
        }
    }

    return true;
}


/*
 * ============================================================
 * Load policy token.
 *
 * Equivalent to original get_policy_token().
 *
 * The returned buffer is allocated with malloc() and must be
 * freed by the caller.
 * ============================================================
 */

bool LoadPolicyToken(
    const std::string& path,
    uint8_t** token,
    std::string* error_msg
) {
    if (!token) {
        if (error_msg) {
            *error_msg =
                "Policy token output pointer is null";
        }
        return false;
    }

    *token = nullptr;

    std::vector<uint8_t> content;

    if (!ReadFile(
            path,
            &content,
            error_msg
        )) {
        return false;
    }

    /*
     * Original code adds a trailing '\0'.
     */

    uint8_t* buffer =
        static_cast<uint8_t*>(
            std::malloc(content.size() + 1)
        );

    if (!buffer) {
        if (error_msg) {
            *error_msg =
                "Failed to allocate policy token buffer";
        }
        return false;
    }

    if (!content.empty()) {
        std::memcpy(
            buffer,
            content.data(),
            content.size()
        );
    }

    buffer[content.size()] = '\0';

    *token = buffer;

    return true;
}


/*
 * ============================================================
 * Determine quote type and select policies.
 *
 * Original App.cpp:
 *
 * uint32_t *p_type =
 *     (uint32_t *)(quote + sizeof(uint16_t) * 2);
 *
 * For safety, use memcpy rather than an unaligned pointer cast.
 * ============================================================
 */

bool SelectPoliciesForQuote(
    const std::vector<uint8_t>& quote,
    std::string* tenant_policy,
    const std::vector<std::string>** platform_policies,
    std::string* error_msg
) {
    if (!tenant_policy ||
        !platform_policies) {

        if (error_msg) {
            *error_msg =
                "Policy selection output pointer is null";
        }

        return false;
    }

    constexpr size_t kQuoteTypeOffset =
        sizeof(uint16_t) * 2;

    if (quote.size()
        < kQuoteTypeOffset + sizeof(uint32_t)) {

        if (error_msg) {
            *error_msg =
                "Quote is too small to determine quote type";
        }

        return false;
    }

    uint32_t quote_type = 0;

    std::memcpy(
        &quote_type,
        quote.data() + kQuoteTypeOffset,
        sizeof(quote_type)
    );


    if (quote_type == kSgxQuoteType) {

        std::cout
            << "[QVL] Quote type: SGX\n";

        *tenant_policy =
            kSgxEnclavePolicy;

        *platform_policies =
            &kSgxPlatformPolicies;

        return true;
    }


    if (quote_type == kTdxQuoteType) {

        std::cout
            << "[QVL] Quote type: TDX\n";

        *tenant_policy =
            kTdxTenantPolicy;

        *platform_policies =
            &kTdxPlatformPolicies;

        return true;
    }


    if (error_msg) {

        std::ostringstream oss;

        oss
            << "Unsupported quote type: 0x"
            << std::hex
            << quote_type;

        *error_msg = oss.str();
    }

    return false;
}


/*
 * ============================================================
 * Check overall appraisal result.
 *
 * Original App.cpp decodes the appraisal JWT and checks:
 *
 * "overall_appraisal_result":1
 * ============================================================
 */

bool IsOverallAppraisalSuccessful(
    const uint8_t* appraisal_result,
    std::string* error_msg
) {
    if (!appraisal_result) {
        if (error_msg) {
            *error_msg =
                "Appraisal result token is null";
        }
        return false;
    }

    try {

        std::string jwt_string(
            reinterpret_cast<const char*>(
                appraisal_result
            )
        );

        auto decoded =
            jwt::decode(jwt_string);

        auto result_string =
            decoded
                .get_payload_claim(
                    "appraisal_result"
                )
                .to_json()
                .to_str();


        if (
            result_string.find(
                "\"overall_appraisal_result\":1"
            )
            != std::string::npos
        ) {

            return true;
        }


        if (error_msg) {
            *error_msg =
                "Appraisal result indicates failure: "
                + result_string;
        }

        return false;

    } catch (
        const std::exception& e
    ) {

        if (error_msg) {
            *error_msg =
                std::string(
                    "Failed to parse appraisal JWT: "
                )
                + e.what();
        }

        return false;
    }
}


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
     * Step 1: Select correct SGX/TDX policies.
     * --------------------------------------------------------
     */

    std::string tenant_policy;

    const std::vector<std::string>*
        platform_policies = nullptr;

    if (!SelectPoliciesForQuote(
            quote,
            &tenant_policy,
            &platform_policies,
            error_msg
        )) {

        return false;
    }


    /*
     * --------------------------------------------------------
     * Step 2: Load appraisal policy owner public key.
     *
     * Equivalent to original:
     *
     * vector<uint8_t> pub_key =
     *     readBinaryContent(PUBKEY_FILENAME);
     *
     * pub_key.push_back(0);
     * --------------------------------------------------------
     */

    std::vector<uint8_t> policy_owner_public_key;

    if (!ReadFile(
            kPolicyPublicKey,
            &policy_owner_public_key,
            error_msg
        )) {

        return false;
    }

    policy_owner_public_key.push_back('\0');

    const uint8_t* key_list[1];

    key_list[0] =
        policy_owner_public_key.data();


    /*
     * --------------------------------------------------------
     * Step 3: Verify Quote.
     *
     * This is the original:
     *
     * tee_verify_quote_qvt(...)
     *
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
     * jwt_token must be freed at the end.
     */

    bool success = false;


    /*
     * --------------------------------------------------------
     * Step 4: Try each platform policy.
     *
     * Original App.cpp considers verification successful when
     * one policy path succeeds.
     * --------------------------------------------------------
     */

    for (
        const std::string& platform_policy
            : *platform_policies
    ) {

        uint8_t* policies[2] = {
            nullptr,
            nullptr
        };

        uint8_t policy_count = 0;

        uint8_t* appraisal_result =
            nullptr;

        uint32_t appraisal_result_size =
            0;


        /*
         * Load tenant policy.
         */

        std::string local_error;

        if (!LoadPolicyToken(
                tenant_policy,
                &policies[policy_count],
                &local_error
            )) {

            std::cerr
                << "[QVL] Failed to load tenant policy: "
                << local_error
                << "\n";

            continue;
        }

        ++policy_count;


        /*
         * Load platform policy.
         */

        if (!LoadPolicyToken(
                platform_policy,
                &policies[policy_count],
                &local_error
            )) {

            std::cerr
                << "[QVL] Failed to load platform policy: "
                << local_error
                << "\n";

            for (
                uint8_t i = 0;
                i < policy_count;
                ++i
            ) {
                std::free(policies[i]);
            }

            continue;
        }

        ++policy_count;


        /*
         * ----------------------------------------------------
         * Step 4a: Appraise quote verification token.
         *
         * Original:
         *
         * tee_appraise_verification_token(...)
         * ----------------------------------------------------
         */

        dcap_ret =
            tee_appraise_verification_token(
                jwt_token,
                policies,
                policy_count,
                std::time(nullptr),
                nullptr,
                &appraisal_result_size,
                &appraisal_result
            );


        if (dcap_ret != SGX_QL_SUCCESS) {

            local_error =
                DcapError(
                    "tee_appraise_verification_token",
                    dcap_ret
                );

            goto POLICY_CLEANUP;
        }


        /*
         * ----------------------------------------------------
         * Step 4b: Check:
         *
         * overall_appraisal_result == 1
         * ----------------------------------------------------
         */

        if (!IsOverallAppraisalSuccessful(
                appraisal_result,
                &local_error
            )) {

            goto POLICY_CLEANUP;
        }


        /*
         * ----------------------------------------------------
         * Step 4c: Authenticate policies used in appraisal.
         *
         * Original:
         *
         * tee_authenticate_appraisal_result(...)
         * ----------------------------------------------------
         */

        {
            tee_policy_bundle_t bundle;

            std::memset(
                &bundle,
                0,
                sizeof(bundle)
            );

            bundle.p_tenant_identity_policy =
                policies[0];

            bundle.platform_policy.p_policy =
                policies[1];

            bundle.platform_policy.pt =
                CUSTOMIZED;


            tee_policy_auth_result_t auth_result =
                TEE_AUTH_FAILURE;


            dcap_ret =
                tee_authenticate_appraisal_result(
                    appraisal_result,
                    &bundle,
                    &auth_result
                );


            if (dcap_ret != SGX_QL_SUCCESS) {

                local_error =
                    DcapError(
                        "tee_authenticate_appraisal_result",
                        dcap_ret
                    );

                goto POLICY_CLEANUP;
            }


            if (auth_result != TEE_AUTH_SUCCESS) {

                local_error =
                    "Appraisal policy authentication failed";

                goto POLICY_CLEANUP;
            }
        }


        /*
         * ----------------------------------------------------
         * Step 4d: Authenticate policy owner.
         *
         * Original:
         *
         * tee_authenticate_policy_owner(...)
         * ----------------------------------------------------
         */

        {
            tee_policy_auth_result_t auth_result =
                TEE_AUTH_FAILURE;


            dcap_ret =
                tee_authenticate_policy_owner(
                    quote.data(),
                    static_cast<uint32_t>(
                        quote.size()
                    ),
                    appraisal_result,
                    key_list,
                    1,
                    nullptr,
                    nullptr,
                    &auth_result,
                    nullptr
                );


            if (dcap_ret != SGX_QL_SUCCESS) {

                local_error =
                    DcapError(
                        "tee_authenticate_policy_owner",
                        dcap_ret
                    );

                goto POLICY_CLEANUP;
            }


            if (auth_result != TEE_AUTH_SUCCESS) {

                local_error =
                    "Policy owner authentication failed";

                goto POLICY_CLEANUP;
            }
        }


        /*
         * All checks for this policy combination passed.
         */

        success = true;

        std::cout
            << "[QVL] Appraisal succeeded with:\n"
            << "      tenant policy: "
            << tenant_policy
            << "\n"
            << "      platform policy: "
            << platform_policy
            << "\n";


POLICY_CLEANUP:

        /*
         * Free policy buffers.
         */

        for (
            uint8_t i = 0;
            i < policy_count;
            ++i
        ) {

            if (policies[i]) {

                std::free(
                    policies[i]
                );

                policies[i] = nullptr;
            }
        }


        /*
         * Free appraisal result.
         */

        if (appraisal_result) {

            quote3_error_t free_ret =
                tee_free_appraisal_token(
                    appraisal_result
                );

            if (free_ret != SGX_QL_SUCCESS) {

                std::cerr
                    << "[QVL] Warning: "
                    << DcapError(
                        "tee_free_appraisal_token",
                        free_ret
                    )
                    << "\n";
            }

            appraisal_result = nullptr;
        }


        if (success) {
            break;
        }


        std::cerr
            << "[QVL] Appraisal failed for platform policy: "
            << platform_policy
            << "\n"
            << "      Reason: "
            << local_error
            << "\n";


        if (error_msg) {
            *error_msg = local_error;
        }
    }


    /*
     * --------------------------------------------------------
     * Step 5: Free Quote Verification Token.
     *
     * Original:
     *
     * tee_free_verify_quote_qvt(...)
     * --------------------------------------------------------
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


    if (!success &&
        error_msg &&
        error_msg->empty()) {

        *error_msg =
            "No appraisal policy combination accepted the quote";
    }


    return success;
}

}  // namespace attestation
}  // namespace tacvm