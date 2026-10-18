#ifndef POLICY_VERIFIER_H
#define POLICY_VERIFIER_H

#include <string>

// Verify that `candidate_text` (JSON or YAML) does not admit behaviors
// forbidden by `proposal_text` (JSON or YAML) for `participant_id`.
// Returns true on success; on failure returns false and sets `error_msg`.
bool verify_candidate_against_proposal(
    const std::string& participant_id,
    const std::string& proposal_text,
    const std::string& candidate_text,
    std::string* error_msg = nullptr
);

#endif
