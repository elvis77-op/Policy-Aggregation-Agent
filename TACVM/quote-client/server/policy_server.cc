#include <iostream>
#include <string>
#include <unordered_map>
#include <filesystem>
#include <array>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <sys/wait.h>
#include <unistd.h>

#include <grpcpp/grpcpp.h>

#include "policy.grpc.pb.h"

#include "quote_verifier.h"

#include "../utils/sha256_utils.h"
#include "../utils/sha384_utils.h"
#include "../utils/canonical_json.h"
#include "../utils/crypto_utils.h"

#include <nlohmann/json.hpp>

using json = nlohmann::json;


namespace {

struct SessionInfo {
    std::string ta_public_key;
    std::string client_id;
    // SHA-256(policy) reported during remote attestation reply.
    std::string policy_hash;
    // Local policy identifier and body (as read from policy directory)
    std::string policy_id;
    std::string policy_body;
};


bool EncryptReply(
    const std::string& message_type,
    const std::string& plaintext,
    const std::string& ta_public_key,
    tacvm::v1::EncryptedPayload* output,
    std::string* error_msg
) {
    std::string encrypted_key;
    std::string nonce;
    std::string ciphertext;
    std::string tag;

    if (!attestation::utils::CryptoUtils::HybridEncrypt(
            plaintext,
            ta_public_key,
            &encrypted_key,
            &nonce,
            &ciphertext,
            &tag,
            error_msg
        )) {
        return false;
    }

    output->set_message_type(message_type);
    output->set_encrypted_key(encrypted_key);
    output->set_nonce(nonce);
    output->set_ciphertext(ciphertext);
    output->set_authentication_tag(tag);

    return true;
}

bool VerifyQuoteForParticipant(
    const std::string& quote,
    const std::string& expected_nonce,
    const std::string& ta_public_key,
    std::string* error_msg
) {
    if (error_msg) {
        error_msg->clear();
    }

    if (quote.empty()) {
        if (error_msg) {
            *error_msg = "Quote is empty";
        }
        return false;
    }

    if (expected_nonce.size() != 32) {
        if (error_msg) {
            *error_msg = "Expected nonce must be 32 bytes";
        }
        return false;
    }

    if (ta_public_key.empty()) {
        if (error_msg) {
            *error_msg = "TA public key is empty";
        }
        return false;
    }

    /*
     * Step 1:
     * Verify the TDX Quote using QVL/Appraisal.
     */
    std::vector<uint8_t> quote_bytes(
        quote.begin(),
        quote.end()
    );

    std::string qvl_error;

    if (!tacvm::attestation::VerifyQuoteWithQVL(
            quote_bytes,
            &qvl_error
        )) {

        if (error_msg) {
            *error_msg =
                qvl_error.empty()
                    ? "QVL quote verification failed"
                    : qvl_error;
        }

        return false;
    }

    /*
     * Step 2:
     * Calculate SHA256(PK2).
     */
    std::string expected_public_key_hash;

    if (!attestation::utils::CryptoUtils::Sha256(
            ta_public_key,
            &expected_public_key_hash,
            error_msg
        )) {

        return false;
    }

    if (expected_public_key_hash.size() != 32) {
        if (error_msg) {
            *error_msg =
                "SHA256(PK2) does not have 32 bytes";
        }

        return false;
    }

    /*
     * Step 3:
     * Extract REPORTDATA from the TDX Quote.
     *
     * Current quote layout used by your previous
     * Python verifier:
     *
     * report_data offset = 0x170
     * report_data size   = 0x40
     */
    constexpr size_t kReportDataOffset = 0x170;
    constexpr size_t kReportDataSize = 0x40;

    if (quote_bytes.size()
        < kReportDataOffset + kReportDataSize) {

        if (error_msg) {
            *error_msg =
                "Quote is too small to contain REPORTDATA";
        }

        return false;
    }

    const uint8_t* report_data =
        quote_bytes.data() + kReportDataOffset;

    /*
     * REPORTDATA:
     *
     * bytes [0..31]   = N_att
     * bytes [32..63]  = SHA256(PK2)
     */
    const std::string quote_nonce(
        reinterpret_cast<const char*>(
            report_data
        ),
        32
    );

    const std::string quote_public_key_hash(
        reinterpret_cast<const char*>(
            report_data + 32
        ),
        32
    );

    /*
     * Step 4:
     * Verify N_att binding.
     */
    if (quote_nonce != expected_nonce) {

        if (error_msg) {
            *error_msg =
                "Quote REPORTDATA nonce mismatch";
        }

        return false;
    }

    /*
     * Step 5:
     * Verify PK2 binding.
     */
    if (quote_public_key_hash
        != expected_public_key_hash) {

        if (error_msg) {
            *error_msg =
                "Quote REPORTDATA TA public-key hash mismatch";
        }

        return false;
    }

    return true;
}

bool LoadPolicy(
    const std::string& policy_directory,
    const std::string& policy_id,
    std::string* policy,
    std::string* error_msg
) {
    if (!policy) {
        if (error_msg) {
            *error_msg = "policy output is null";
        }

        return false;
    }

    if (policy_id.empty()) {
        if (error_msg) {
            *error_msg = "policy_id is empty";
        }

        return false;
    }

    /*
     * Basic path traversal protection.
     */
    if (policy_id.find("..") != std::string::npos
        || policy_id.find('/') != std::string::npos
        || policy_id.find('\\') != std::string::npos) {

        if (error_msg) {
            *error_msg = "Invalid policy_id";
        }

        return false;
    }

    const std::string policy_path =
        policy_directory
        + "/"
        + policy_id;

    return attestation::utils::CryptoUtils::ReadFile(
        policy_path,
        policy,
        error_msg
    );
}

} // anonymous namespace


class ParticipantServiceImpl final
    : public tacvm::v1::ParticipantService::Service {

public:

    ParticipantServiceImpl(
        const std::string& participant_id,
        const std::string& policy_directory
    )
        : participant_id_(participant_id),
          policy_directory_(policy_directory) {
    }


    grpc::Status Challenge(
        grpc::ServerContext* context,
        const tacvm::v1::ChallengeRequest* request,
        tacvm::v1::ChallengeReply* reply
    ) override {
        (void)context;

        if (request->client_id().empty()) {
            return grpc::Status(
                grpc::StatusCode::INVALID_ARGUMENT,
                "client_id is empty"
            );
        }

        std::string nonce;
        std::string error_msg;

        if (!attestation::utils::CryptoUtils::GenerateNonce(
                &nonce,
                32,
                &error_msg
            )) {

            return grpc::Status(
                grpc::StatusCode::INTERNAL,
                error_msg
            );
        }

        /*
         * Store one outstanding challenge per client.
         */
        pending_challenges_[
            request->client_id()
        ] = nonce;

        reply->set_nonce(nonce);

        std::cout
            << "[RA] Challenge generated for "
            << request->client_id()
            << "\n";

        return grpc::Status::OK;
    }

    grpc::Status VerifyQuote(
        grpc::ServerContext* context,
        const tacvm::v1::QuoteVerificationRequest* request,
        tacvm::v1::EncryptedPayload* response
    ) override {
        (void)context;

        if (request->client_id().empty()
            || request->quote().empty()
            || request->attestation_public_key().empty()
            || request->nonce().empty()
            || request->policy_id().empty()) {

            return grpc::Status(
                grpc::StatusCode::INVALID_ARGUMENT,
                "Incomplete QuoteVerificationRequest"
            );
        }

        auto challenge_it =
            pending_challenges_.find(
                request->client_id()
            );

        if (challenge_it == pending_challenges_.end()) {

            return grpc::Status(
                grpc::StatusCode::FAILED_PRECONDITION,
                "No pending challenge for client"
            );
        }

        const std::string expected_nonce =
            challenge_it->second;

        tacvm::v1::QuoteVerificationReply reply;

        std::string error_msg;

        /*
        * ----------------------------------------------------
        * Step 1:
        * Verify that the request nonce is the nonce we issued.
        * ----------------------------------------------------
        */
        if (request->nonce() != expected_nonce) {

            reply.set_accepted(false);
            reply.set_error_message(
                "Attestation nonce mismatch"
            );

        } else {

            /*
            * ------------------------------------------------
            * Step 2:
            * Verify Quote + REPORTDATA binding.
            * ------------------------------------------------
            */
            if (!VerifyQuoteForParticipant(
                    request->quote(),
                    expected_nonce,
                    request->attestation_public_key(),
                    &error_msg
                )) {

                reply.set_accepted(false);
                reply.set_error_message(
                    error_msg.empty()
                        ? "Quote verification failed"
                        : error_msg
                );

            } else {

                /*
                * --------------------------------------------
                * Step 3:
                * Load the requested policy.
                * --------------------------------------------
                */
                std::string policy;

                if (!LoadPolicy(
                        policy_directory_,
                        request->policy_id(),
                        &policy,
                        &error_msg
                    )) {

                    reply.set_accepted(false);
                    reply.set_error_message(
                        error_msg.empty()
                            ? "Failed to load policy"
                            : error_msg
                    );

                } else {

                    /*
                    * ----------------------------------------
                    * Step 4:
                    * Calculate H(policy).
                    * ----------------------------------------
                    */
                    std::string policy_hash;

                    if (!attestation::utils::CryptoUtils::Sha256(
                            policy,
                            &policy_hash,
                            &error_msg
                        )) {

                        reply.set_accepted(false);
                        reply.set_error_message(
                            error_msg.empty()
                                ? "Failed to hash policy"
                                : error_msg
                        );

                    } else {

                        /*
                        * ------------------------------------
                        * Step 5:
                        * Generate session_id.
                        * ------------------------------------
                        */
                        std::string session_id;

                        if (!attestation::utils::CryptoUtils::
                                GenerateNonce(
                                    &session_id,
                                    32,
                                    &error_msg
                                )) {

                            return grpc::Status(
                                grpc::StatusCode::INTERNAL,
                                error_msg
                            );
                        }

                        /*
                        * ------------------------------------
                        * Step 6:
                        * Store successful session.
                        * ------------------------------------
                        */
                        SessionInfo session;

                        session.client_id =
                            request->client_id();

                        session.ta_public_key =
                            request->attestation_public_key();

                        // Store the SHA-256(policy) and policy id/body so later
                        // confirmation checks can verify the candidate against
                        // this participant's locally proposed policy.
                        session.policy_hash = policy_hash;
                        session.policy_id = request->policy_id();
                        session.policy_body = policy;

                        sessions_[session_id] = session;

                        /*
                        * Challenge is one-time use.
                        */
                        pending_challenges_.erase(
                            challenge_it
                        );

                        /*
                        * ------------------------------------
                        * Step 7:
                        * Build successful reply.
                        * ------------------------------------
                        */
                        reply.set_accepted(true);

                        reply.set_participant_id(
                            participant_id_
                        );

                        reply.set_policy(
                            policy
                        );

                        reply.set_policy_hash(
                            policy_hash
                        );

                        reply.set_session_id(
                            session_id
                        );

                        std::cout
                            << "[RA] Quote verified successfully\n";

                        std::cout
                            << "[RA] Policy loaded: "
                            << request->policy_id()
                            << "\n";

                        std::cout
                            << "[RA] Session established\n";
                    }
                }
            }
        }

        /*
        * ----------------------------------------------------
        * Step 8:
        * Serialize QuoteVerificationReply.
        * ----------------------------------------------------
        */
        std::string serialized;

        if (!reply.SerializeToString(
                &serialized
            )) {

            return grpc::Status(
                grpc::StatusCode::INTERNAL,
                "Failed to serialize QuoteVerificationReply"
            );
        }

        /*
        * ----------------------------------------------------
        * Step 9:
        * Encrypt reply with PK2 received from TA.
        *
        * Even rejection replies are encrypted with PK2.
        * ----------------------------------------------------
        */
        if (!EncryptReply(
                "QuoteVerificationReply",
                serialized,
                request->attestation_public_key(),
                response,
                &error_msg
            )) {

            return grpc::Status(
                grpc::StatusCode::INTERNAL,
                error_msg
            );
        }

        return grpc::Status::OK;
    }

    grpc::Status VerifyAggregatedPolicy(
        grpc::ServerContext* context,
        const tacvm::v1::AggregatedPolicyRequest* request,
        tacvm::v1::EncryptedPayload* response
    ) override {
        (void)context;

        auto session_it =
            sessions_.find(
                request->session_id()
            );

        if (session_it == sessions_.end()) {
            return grpc::Status(
                grpc::StatusCode::UNAUTHENTICATED,
                "Unknown session"
            );
        }

        std::string error_msg;

        std::string calculated_hash;

        if (!attestation::utils::CryptoUtils::Sha256(
                request->aggregated_policy(),
                &calculated_hash,
                &error_msg
            )) {

            return grpc::Status(
                grpc::StatusCode::INTERNAL,
                error_msg
            );
        }

        if (calculated_hash != request->policy_hash()) {
            return grpc::Status(
                grpc::StatusCode::INVALID_ARGUMENT,
                "Aggregated policy hash mismatch"
            );
        }

        // Parse and verify candidate_digest using canonical JSON + SHA-384.
        const std::string& aggregated_policy = request->aggregated_policy();

        std::string canonical_text;

        if (!canonical_json_string_from_text(
                aggregated_policy,
                &canonical_text,
                &error_msg
            )) {

            return grpc::Status(
                grpc::StatusCode::INVALID_ARGUMENT,
                std::string("Failed to canonicalize aggregated policy: ") + (error_msg.empty() ? "" : error_msg)
            );
        }

        // Parse canonical text into JSON structure
        json parsed;
        try {
            parsed = json::parse(canonical_text);
        } catch (const std::exception& e) {
            return grpc::Status(
                grpc::StatusCode::INVALID_ARGUMENT,
                std::string("Aggregated policy is not a valid JSON/YAML bundle: ") + e.what()
            );
        }

        // Extract candidate object and supplied digest. Support both wrapped
        // bundles {"candidate": {...}, "candidate_digest": "..."}
        // and unwrapped candidate objects that include "candidate_digest".
        json candidate_obj;
        std::string supplied_digest;

        if (parsed.contains("candidate") && parsed.contains("candidate_digest")) {
            candidate_obj = parsed["candidate"];
            supplied_digest = parsed["candidate_digest"].get<std::string>();
        } else if (parsed.contains("candidate_digest") && parsed.is_object()) {
            // candidate_digest may be a top-level field while the rest are
            // candidate fields.
            supplied_digest = parsed["candidate_digest"].get<std::string>();
            candidate_obj = parsed;
        } else if (parsed.contains("candidate")) {
            candidate_obj = parsed["candidate"];
            // try to find digest inside candidate
            if (candidate_obj.contains("candidate_digest")) {
                supplied_digest = candidate_obj["candidate_digest"].get<std::string>();
            }
        }

        if (supplied_digest.empty()) {
            return grpc::Status(
                grpc::StatusCode::INVALID_ARGUMENT,
                "Aggregated candidate missing candidate_digest"
            );
        }

        // Compute canonical JSON for the candidate without the candidate_digest
        // field (the canonical digest is computed over the candidate body
        // before candidate_digest is inserted).
        json candidate_for_digest = candidate_obj;
        if (candidate_for_digest.contains("candidate_digest")) {
            candidate_for_digest.erase("candidate_digest");
        }

        std::string canonical_candidate;

        if (!canonical_json_string_from_json(
                candidate_for_digest,
                &canonical_candidate,
                &error_msg
            )) {

            return grpc::Status(
                grpc::StatusCode::INVALID_ARGUMENT,
                std::string("Failed to canonicalize candidate: ") + (error_msg.empty() ? "" : error_msg)
            );
        }

        // Compute SHA-384 hex and compare with supplied digest (format: sha384:<hex>)
        std::string computed_hex = sha384_hex(canonical_candidate);
        std::string computed_digest = std::string("sha384:") + computed_hex;

        if (computed_digest != supplied_digest) {
            return grpc::Status(
                grpc::StatusCode::INVALID_ARGUMENT,
                "Candidate digest mismatch"
            );
        }

        // Ensure candidate semantics respect this participant's proposal.
        if (session_it->second.policy_body.empty()) {
            return grpc::Status(
                grpc::StatusCode::FAILED_PRECONDITION,
                "Participant policy body not recorded for session"
            );
        }

        if (!verify_candidate_against_proposal(
                participant_id_,
                session_it->second.policy_body,
                canonical_candidate,
                &error_msg
            )) {

            return grpc::Status(
                grpc::StatusCode::INVALID_ARGUMENT,
                std::string("Candidate semantic verification failed: ") + (error_msg.empty() ? "" : error_msg)
            );
        }

        std::string signed_data =
            attestation::utils::CryptoUtils::
                BuildAggregatedPolicyRequestSignedData(
                    request->client_id(),
                    request->session_id(),
                    request->policy_hash(),
                    request->roster_hash(),
                    request->request_nonce()
                );

        if (!attestation::utils::CryptoUtils::
                VerifySignatureWithPublicKey(
                    signed_data,
                    request->signature(),
                    session_it->second.ta_public_key,
                    &error_msg
                )) {

            return grpc::Status(
                grpc::StatusCode::UNAUTHENTICATED,
                "TA signature verification failed: "
                + error_msg
            );
        }

        /*
         * Participant policy verification is intentionally omitted.
         *
         * Current behavior:
         */
        const bool accepted = true;

        tacvm::v1::AggregatedPolicyReply reply;

        reply.set_participant_id(
            participant_id_
        );

        reply.set_accepted(
            accepted
        );

        reply.set_request_nonce(
            request->request_nonce()
        );

        reply.set_policy_hash(
            request->policy_hash()
        );

        reply.set_roster_hash(
            request->roster_hash()
        );

        std::string serialized;

        if (!reply.SerializeToString(
                &serialized
            )) {

            return grpc::Status(
                grpc::StatusCode::INTERNAL,
                "Failed to serialize AggregatedPolicyReply"
            );
        }

        if (!EncryptReply(
                "AggregatedPolicyReply",
                serialized,
                session_it->second.ta_public_key,
                response,
                &error_msg
            )) {

            return grpc::Status(
                grpc::StatusCode::INTERNAL,
                error_msg
            );
        }

        std::cout
            << "[CONFIRM] Aggregated policy accepted\n";

        return grpc::Status::OK;
    }


private:

    std::string participant_id_;

    std::string policy_directory_;

    std::unordered_map<
        std::string,
        std::string
    > pending_challenges_;

    std::unordered_map<
        std::string,
        SessionInfo
    > sessions_;
};


void RunServer(
    const std::string& address,
    const std::string& participant_id,
    const std::string& server_cert_path,
    const std::string& server_key_path,
    const std::string& policy_directory
) {
    std::string cert;
    std::string key;
    std::string error_msg;

    if (!attestation::utils::CryptoUtils::ReadFile(
            server_cert_path,
            &cert,
            &error_msg
        )) {
        std::cerr << error_msg << "\n";
        return;
    }

    if (!attestation::utils::CryptoUtils::ReadFile(
            server_key_path,
            &key,
            &error_msg
        )) {
        std::cerr << error_msg << "\n";
        return;
    }

    grpc::SslServerCredentialsOptions::PemKeyCertPair pair;

    pair.private_key = key;
    pair.cert_chain = cert;

    grpc::SslServerCredentialsOptions ssl_options;

    ssl_options.pem_key_cert_pairs.push_back(
        pair
    );

    auto credentials =
        grpc::SslServerCredentials(
            ssl_options
        );

    ParticipantServiceImpl service(
        participant_id,
        policy_directory
    );

    grpc::ServerBuilder builder;

    builder.AddListeningPort(
        address,
        credentials
    );

    builder.RegisterService(
        &service
    );

    std::unique_ptr<grpc::Server> server(
        builder.BuildAndStart()
    );

    if (!server) {
        std::cerr
            << "Failed to start server\n";
        return;
    }

    std::cout
        << "Participant Server started\n"
        << "Participant ID: "
        << participant_id
        << "\nListening on: "
        << address
        << "\n";

    server->Wait();
}


int main(
    int argc,
    char** argv
) {
    /*
     * ./policy_server
     *
     * <address>
     * <participant_id>
     * <server_cert>
     * <server_key>
     * <policy_directory>
     */

    if (argc != 6) {

        std::cerr
            << "Usage: "
            << argv[0]
            << " <address>"
            << " <participant_id>"
            << " <server_cert>"
            << " <server_key>"
            << " <policy_directory>\n";

        return 1;
    }

    RunServer(
        argv[1],
        argv[2],
        argv[3],
        argv[4],
        argv[5]
    );

    return 0;
}