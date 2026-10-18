#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tacvm {
namespace attestation {

/**
 * Verify and appraise an SGX/TDX quote.
 *
 * For the current TACVM deployment, TDX quotes are expected.
 *
 * Returns:
 *   true  - quote verification and appraisal succeeded
 *   false - any verification/appraisal/authentication step failed
 */
bool VerifyQuoteWithQVL(
    const std::vector<uint8_t>& quote,
    std::string* error_msg
);

}  // namespace attestation
}  // namespace tacvm