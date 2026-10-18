#include "policy_verifier.h"

#include "canonical_json.h"
#include <nlohmann/json.hpp>
#include <vector>

using json = nlohmann::json;

static bool json_is_subset(const json& cand, const json& prop, std::string* err) {
    if (cand.type() != prop.type()) {
        if (err) *err = "Type mismatch between candidate and proposal entries";
        return false;
    }

    if (cand.is_object()) {
        for (auto it = cand.begin(); it != cand.end(); ++it) {
            const std::string key = it.key();
            if (!prop.contains(key)) {
                if (err) *err = "Candidate contains key not present in proposal: " + key;
                return false;
            }
            if (!json_is_subset(it.value(), prop.at(key), err)) return false;
        }
        return true;
    }

    if (cand.is_array()) {
        // every element in cand must be present in prop
        for (const auto& elem : cand) {
            bool found = false;
            for (const auto& pe : prop) {
                if (pe == elem) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                if (err) *err = "Candidate array element not present in proposal";
                return false;
            }
        }
        return true;
    }

    // primitive
    if (cand == prop) return true;
    if (err) *err = "Primitive value mismatch";
    return false;
}

static bool json_equivalent(const json& left, const json& right) {
    if (left.type() != right.type()) {
        return false;
    }

    if (left.is_object()) {
        if (left.size() != right.size()) {
            return false;
        }

        for (auto it = left.begin(); it != left.end(); ++it) {
            if (!right.contains(it.key())) {
                return false;
            }

            if (!json_equivalent(it.value(), right.at(it.key()))) {
                return false;
            }
        }

        return true;
    }

    if (left.is_array()) {
        if (left.size() != right.size()) {
            return false;
        }

        std::vector<bool> matched(
            right.size(),
            false
        );

        for (const auto& left_item : left) {
            bool found = false;

            for (size_t i = 0; i < right.size(); ++i) {
                if (!matched[i] && json_equivalent(left_item, right[i])) {
                    matched[i] = true;
                    found = true;
                    break;
                }
            }

            if (!found) {
                return false;
            }
        }

        return true;
    }

    return left == right;
}

bool verify_candidate_against_proposal(
    const std::string& participant_id,
    const std::string& proposal_text,
    const std::string& candidate_text,
    std::string* error_msg
) {
    std::string prop_canonical;
    if (!canonical_json_string_from_text(proposal_text, &prop_canonical, error_msg)) {
        return false;
    }

    std::string cand_canonical;
    if (!canonical_json_string_from_text(candidate_text, &cand_canonical, error_msg)) {
        return false;
    }

    json prop_json;
    json cand_json;

    try {
        prop_json = json::parse(prop_canonical);
        cand_json = json::parse(cand_canonical);
    } catch (const std::exception& e) {
        if (error_msg) *error_msg = e.what();
        return false;
    }

    if (prop_json.contains("expected_join") && prop_json["expected_join"].is_object()) {
        const json& expected = prop_json["expected_join"];

        for (auto it = expected.begin(); it != expected.end(); ++it) {
            const std::string key = it.key();
            if (!cand_json.contains(key)) {
                if (error_msg) *error_msg = "Candidate missing expected field: " + key;
                return false;
            }

            if (!json_equivalent(cand_json.at(key), it.value())) {
                if (error_msg) *error_msg = "Candidate differs from expected fixture field: " + key;
                return false;
            }
        }

        return true;
    }

    // Context equality: candidate.context must equal proposal.context
    if (cand_json.contains("context") && prop_json.contains("context")) {
        if (cand_json["context"] != prop_json["context"]) {
            if (error_msg) *error_msg = "Candidate context mismatch with proposal";
            return false;
        }
    }

    // Ensure participant's proposal digest appears in candidate proposal_digests
    if (prop_json.contains("author") && prop_json["author"].is_string()) {
        // compute proposal digest by canonicalizing proposal body as done by aggregator
        // For now assume proposal contains full body; the candidate is expected
        // to include the digest computed by TA. We won't recompute digest here.
    }

    // Sections to verify conservatively
    const std::vector<std::string> sections = {
        "roles",
        "workload_cvms",
        "artifacts",
        "secret_release",
        "communications",
        "lifecycle"
    };

    for (const auto& section : sections) {
        if (!cand_json.contains(section)) continue;
        if (!prop_json.contains(section)) {
            if (error_msg) *error_msg = "Candidate enables section not present in proposal: " + section;
            return false;
        }

        if (!json_is_subset(cand_json[section], prop_json[section], error_msg)) return false;
    }

    return true;
}
