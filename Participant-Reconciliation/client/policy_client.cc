#include <grpcpp/grpcpp.h>

#include <yaml-cpp/yaml.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "policy.grpc.pb.h"
#include "crypto_utils.h"

using json = nlohmann::json;


/*
 * ============================================================
 * External TDX quote function
 *
 * Implemented elsewhere.
 * ============================================================
 */

int GetQuote(
    const std::string& nonce,
    const std::string& pubkey_hash,
    std::vector<uint8_t>& quote_data
);


/*
 * ============================================================
 * Server configuration
 * ============================================================
 */

struct ServerConfig {

    std::string id;

    std::string address;

    std::string cert;
};


/*
 * ============================================================
 * State established after successful remote attestation.
 *
 * PK3 has been removed.
 *
 * session_id identifies the successful:
 *
 * TA <-> Participant
 *
 * attestation session.
 * ============================================================
 */

struct ParticipantState {

    ServerConfig server;

    std::string participant_id;

    std::string session_id;
};


/*
 * ============================================================
 * Verified policy result.
 *
 * Contains both:
 *
 * policy data
 * participant session information
 * ============================================================
 */

struct PolicyResult {

    std::string server_id;

    std::string policy;

    std::string policy_hash;

    ParticipantState participant;
};


/*
 * ============================================================
 * Load server list.
 *
 * JSON format:
 *
 * [
 *   {
 *     "address": "...",
 *     "cert": "..."
 *   }
 * ]
 *
 * IDs are generated locally:
 *
 * server_0
 * server_1
 * ...
 * ============================================================
 */

bool LoadServerList(
    const std::string& path,
    std::vector<ServerConfig>* servers
) {
    if (!servers) {
        return false;
    }

    servers->clear();

    std::ifstream input(path);

    if (!input.is_open()) {

        std::cerr
            << "Cannot open server list: "
            << path
            << "\n";

        return false;
    }

    json config;

    try {

        input >> config;

    } catch (const std::exception& e) {

        std::cerr
            << "Failed to parse server list: "
            << e.what()
            << "\n";

        return false;
    }

    if (!config.is_array()) {

        std::cerr
            << "Server list must be a JSON array\n";

        return false;
    }

    for (size_t i = 0; i < config.size(); ++i) {

        if (!config[i].contains("address")
            || !config[i].contains("cert")) {

            std::cerr
                << "Invalid server entry at index "
                << i
                << "\n";

            return false;
        }

        ServerConfig server;

        server.id =
            "server_"
            + std::to_string(i);

        server.address =
            config[i]["address"].get<std::string>();

        server.cert =
            config[i]["cert"].get<std::string>();

        servers->push_back(
            server
        );
    }

    return true;
}


/*
 * ============================================================
 * TLS channel.
 *
 * Key 1:
 *
 * Participant server certificate.
 *
 * Used only for TLS authentication.
 * ============================================================
 */

std::shared_ptr<grpc::Channel> CreateParticipantChannel(
    const ServerConfig& server
) {
    std::string cert;
    std::string error_msg;

    if (!attestation::utils::CryptoUtils::ReadFile(
            server.cert,
            &cert,
            &error_msg
        )) {

        std::cerr
            << "Failed to read certificate: "
            << error_msg
            << "\n";

        return nullptr;
    }

    grpc::SslCredentialsOptions ssl_options;

    ssl_options.pem_root_certs =
        cert;

    auto credentials =
        grpc::SslCredentials(
            ssl_options
        );

    return grpc::CreateChannel(
        server.address,
        credentials
    );
}


/*
 * ============================================================
 * Decrypt EncryptedPayload using TA SK2.
 *
 * Participant encrypts replies using PK2.
 *
 * TA decrypts using SK2.
 * ============================================================
 */

bool DecryptPayload(
    const tacvm::v1::EncryptedPayload& payload,
    const std::string& ta_private_key_path,
    std::string* plaintext
) {
    if (!plaintext) {
        return false;
    }

    std::string error_msg;

    if (!attestation::utils::CryptoUtils::HybridDecrypt(
            payload.encrypted_key(),
            payload.nonce(),
            payload.ciphertext(),
            payload.authentication_tag(),
            ta_private_key_path,
            plaintext,
            &error_msg
        )) {

        std::cerr
            << "Hybrid decrypt failed: "
            << error_msg
            << "\n";

        return false;
    }

    return true;
}


/*
 * ============================================================
 * Remote Attestation + Get Policy
 *
 * One complete cycle:
 *
 * Challenge
 *      ↓
 * N_att
 *      ↓
 * H(PK2)
 *      ↓
 * GetQuote(N_att || H(PK2))
 *      ↓
 * VerifyQuote(policy_id)
 *      ↓
 * QuoteVerificationReply encrypted using PK2
 *      ↓
 * Decrypt using SK2
 *      ↓
 * Verify:
 *
 * accepted
 * participant_id
 * policy
 * H(policy)
 * session_id
 * ============================================================
 */

bool RemoteAttestAndGetPolicy(
    const ServerConfig& server,
    const std::string& client_id,
    const std::string& ta_public_key_pem,
    const std::string& ta_private_key_path,
    const std::string& policy_id,
    PolicyResult* result
) {
    if (!result) {
        return false;
    }

    std::cout
        << "\n====================================\n";

    std::cout
        << "[RA] Connecting to "
        << server.id
        << "\n";

    std::cout
        << "Address: "
        << server.address
        << "\n";


    /*
     * --------------------------------------------------------
     * Create channel and stub.
     * --------------------------------------------------------
     */

    auto channel =
        CreateParticipantChannel(
            server
        );

    if (!channel) {
        return false;
    }

    auto stub =
        tacvm::v1::ParticipantService::NewStub(
            channel
        );


    /*
     * --------------------------------------------------------
     * Step 1
     *
     * ChallengeRequest
     * --------------------------------------------------------
     */

    tacvm::v1::ChallengeRequest
        challenge_request;

    challenge_request.set_client_id(
        client_id
    );


    tacvm::v1::ChallengeReply
        challenge_reply;


    grpc::ClientContext
        challenge_context;


    grpc::Status challenge_status =
        stub->Challenge(
            &challenge_context,
            challenge_request,
            &challenge_reply
        );


    if (!challenge_status.ok()) {

        std::cerr
            << "[RA] Challenge RPC failed: "
            << challenge_status.error_message()
            << "\n";

        return false;
    }


    const std::string attestation_nonce =
        challenge_reply.nonce();


    if (attestation_nonce.empty()) {

        std::cerr
            << "[RA] Received empty challenge nonce\n";

        return false;
    }


    std::cout
        << "[RA] Received challenge nonce: "
        << attestation_nonce.size()
        << " bytes\n";


    /*
     * --------------------------------------------------------
     * Step 2
     *
     * Calculate H(PK2).
     *
     * PK2 is the TA public key.
     * --------------------------------------------------------
     */

    std::string ta_public_key_hash;
    std::string error_msg;


    if (!attestation::utils::CryptoUtils::Sha256(
            ta_public_key_pem,
            &ta_public_key_hash,
            &error_msg
        )) {

        std::cerr
            << "[RA] Failed to hash PK2: "
            << error_msg
            << "\n";

        return false;
    }


    /*
     * GetQuote() expects hexadecimal strings.
     */

    std::string nonce_hex =
        attestation::utils::CryptoUtils::
            BytesToHex(
                reinterpret_cast<
                    const uint8_t*
                >(
                    attestation_nonce.data()
                ),
                attestation_nonce.size()
            );


    std::string public_key_hash_hex =
        attestation::utils::CryptoUtils::
            BytesToHex(
                reinterpret_cast<
                    const uint8_t*
                >(
                    ta_public_key_hash.data()
                ),
                ta_public_key_hash.size()
            );


    /*
     * --------------------------------------------------------
     * Step 3
     *
     * Generate TDX Quote.
     *
     * report_data:
     *
     * [ N_att (32 bytes) || H(PK2) (32 bytes) ]
     * --------------------------------------------------------
     */

    std::vector<uint8_t>
        quote_data;


    if (!GetQuote(
            nonce_hex,
            public_key_hash_hex,
            quote_data
        ) != 0) {

        std::cerr
            << "[RA] Failed to generate TDX quote\n";

        return false;
    }


    if (quote_data.empty()) {

        std::cerr
            << "[RA] Generated empty quote\n";

        return false;
    }


    std::cout
        << "[RA] Quote generated: "
        << quote_data.size()
        << " bytes\n";


    /*
     * --------------------------------------------------------
     * Step 4
     *
     * VerifyQuote.
     *
     * policy_id is now included here because:
     *
     * VerifyQuoteReply directly returns the policy.
     * --------------------------------------------------------
     */

    tacvm::v1::QuoteVerificationRequest
        verify_request;


    verify_request.set_client_id(
        client_id
    );


    verify_request.set_quote(
        quote_data.data(),
        quote_data.size()
    );


    verify_request.set_attestation_public_key(
        ta_public_key_pem
    );


    verify_request.set_nonce(
        attestation_nonce
    );


    verify_request.set_policy_id(
        policy_id
    );


    tacvm::v1::EncryptedPayload
        encrypted_reply;


    grpc::ClientContext
        verify_context;


    grpc::Status verify_status =
        stub->VerifyQuote(
            &verify_context,
            verify_request,
            &encrypted_reply
        );


    if (!verify_status.ok()) {

        std::cerr
            << "[RA] VerifyQuote RPC failed: "
            << verify_status.error_message()
            << "\n";

        return false;
    }


    if (encrypted_reply.message_type()
        != "QuoteVerificationReply") {

        std::cerr
            << "[RA] Unexpected encrypted message type: "
            << encrypted_reply.message_type()
            << "\n";

        return false;
    }


    /*
     * --------------------------------------------------------
     * Step 5
     *
     * HybridDecrypt using SK2.
     * --------------------------------------------------------
     */

    std::string plaintext;


    if (!DecryptPayload(
            encrypted_reply,
            ta_private_key_path,
            &plaintext
        )) {

        return false;
    }


    tacvm::v1::QuoteVerificationReply
        verify_reply;


    if (!verify_reply.ParseFromString(
            plaintext
        )) {

        std::cerr
            << "[RA] Failed to parse QuoteVerificationReply\n";

        return false;
    }


    /*
     * --------------------------------------------------------
     * Step 6
     *
     * Check Remote Attestation result.
     * --------------------------------------------------------
     */

    if (!verify_reply.accepted()) {

        std::cerr
            << "[RA] Participant rejected attestation: "
            << verify_reply.error_message()
            << "\n";

        return false;
    }


    /*
     * A successful reply must contain:
     *
     * participant_id
     * policy
     * policy_hash
     * session_id
     */

    if (verify_reply.participant_id().empty()
        || verify_reply.policy().empty()
        || verify_reply.policy_hash().empty()
        || verify_reply.session_id().empty()) {

        std::cerr
            << "[RA] Incomplete successful reply\n";

        return false;
    }


    /*
     * --------------------------------------------------------
     * Step 7
     *
     * Verify H(policy).
     * --------------------------------------------------------
     */

    std::string calculated_hash;


    if (!attestation::utils::CryptoUtils::Sha256(
            verify_reply.policy(),
            &calculated_hash,
            &error_msg
        )) {

        std::cerr
            << "[RA] Failed to hash policy: "
            << error_msg
            << "\n";

        return false;
    }


    if (calculated_hash
        != verify_reply.policy_hash()) {

        std::cerr
            << "[RA] Policy hash mismatch\n";

        return false;
    }


    std::cout
        << "[RA] Policy hash verified\n";


    /*
     * --------------------------------------------------------
     * Step 8
     *
     * Build PolicyResult directly.
     *
     * There is no PK3 and no second GetPolicy phase.
     * --------------------------------------------------------
     */

    result->server_id =
        verify_reply.participant_id();


    result->policy =
        verify_reply.policy();


    result->policy_hash =
        verify_reply.policy_hash();


    result->participant.server =
        server;


    result->participant.participant_id =
        verify_reply.participant_id();


    result->participant.session_id =
        verify_reply.session_id();


    std::cout
        << "[RA] SUCCESS\n";

    std::cout
        << "Participant ID: "
        << result->participant.participant_id
        << "\n";

    std::cout
        << "Session established: "
        << result->participant.session_id.size()
        << " bytes\n";

    std::cout
        << "Policy received: "
        << result->policy.size()
        << " bytes\n";


    return true;
}


/*
 * ============================================================
 * PAA
 * ============================================================
 */

bool RunPAA(
    const std::string& paa_script,
    const std::string& input_path,
    const std::string& output_path
) {
    std::ostringstream cmd;

    cmd
        << "ruby "
        << paa_script
        << " join "
        << input_path
        << " "
        << output_path;


    std::cout
        << "[PAA] "
        << cmd.str()
        << "\n";


    int status =
        std::system(
            cmd.str().c_str()
        );


    if (status != 0) {

        std::cerr
            << "PAA execution failed\n";

        return false;
    }


    if (!std::filesystem::exists(
            output_path
        )) {

        std::cerr
            << "PAA output file not created\n";

        return false;
    }


    return true;
}


/*
 * ============================================================
 * Build PAA input.
 *
 * One participant provides one proposal.
 * ============================================================
 */

bool BuildPAAInput(
    const std::vector<PolicyResult>& results,
    const std::string& output_path
) {
    if (results.empty()) {

        std::cerr
            << "No verified policies\n";

        return false;
    }


    YAML::Node output;

    YAML::Node all_proposals(
        YAML::NodeType::Sequence
    );


    bool first_policy =
        true;


    for (const auto& result : results) {

        YAML::Node input;


        try {

            input =
                YAML::Load(
                    result.policy
                );

        } catch (
            const YAML::Exception& e
        ) {

            std::cerr
                << "Failed to parse YAML from "
                << result.server_id
                << ": "
                << e.what()
                << "\n";

            return false;
        }


        if (!input["fixture_schema"]) {

            std::cerr
                << result.server_id
                << ": missing fixture_schema\n";

            return false;
        }


        if (!input["shared_context"]) {

            std::cerr
                << result.server_id
                << ": missing shared_context\n";

            return false;
        }


        if (!input["shared_roles"]) {

            std::cerr
                << result.server_id
                << ": missing shared_roles\n";

            return false;
        }


        if (!input["proposals"]
            || !input["proposals"].IsSequence()) {

            std::cerr
                << result.server_id
                << ": proposals missing or invalid\n";

            return false;
        }


        if (input["proposals"].size()
            != 1) {

            std::cerr
                << result.server_id
                << ": expected exactly 1 proposal\n";

            return false;
        }


        if (first_policy) {

            output["fixture_schema"] =
                input["fixture_schema"];

            output["shared_context"] =
                input["shared_context"];

            output["shared_roles"] =
                input["shared_roles"];

            first_policy =
                false;

        } else {

            if (YAML::Dump(
                    output["shared_context"]
                )
                != YAML::Dump(
                    input["shared_context"]
                )) {

                std::cerr
                    << "shared_context mismatch from "
                    << result.server_id
                    << "\n";

                return false;
            }


            if (YAML::Dump(
                    output["shared_roles"]
                )
                != YAML::Dump(
                    input["shared_roles"]
                )) {

                std::cerr
                    << "shared_roles mismatch from "
                    << result.server_id
                    << "\n";

                return false;
            }
        }


        YAML::Node proposal =
            input["proposals"][0];


        if (!proposal["author"]) {

            std::cerr
                << result.server_id
                << ": proposal has no author\n";

            return false;
        }


        all_proposals.push_back(
            proposal
        );
    }


    output["proposals"] =
        all_proposals;


    // Regression runs may query any subset of the full roster; restrict shared_roles
    // to just the participants actually queried so the roster matches the proposals.
    std::set<std::string> queried_authors;
    for (const auto& proposal : all_proposals) {
        queried_authors.insert(proposal["author"].as<std::string>());
    }

    YAML::Node trimmed_roles(
        YAML::NodeType::Map
    );

    for (const auto& entry : output["shared_roles"]) {
        const std::string slot =
            entry.first.as<std::string>();

        if (queried_authors.count(slot)) {
            trimmed_roles[slot] =
                entry.second;
        }
    }

    output["shared_roles"] =
        trimmed_roles;


    std::ofstream out(
        output_path
    );


    if (!out.is_open()) {

        std::cerr
            << "Cannot open "
            << output_path
            << "\n";

        return false;
    }


    out << output;


    if (!out.good()) {

        std::cerr
            << "Failed writing "
            << output_path
            << "\n";

        return false;
    }


    std::cout
        << "[OK] Built PAA input: "
        << output_path
        << "\n";


    return true;
}


/*
 * ============================================================
 * Build roster hash.
 *
 * Bind aggregated-policy confirmation to the exact
 * participants that contributed policies.
 * ============================================================
 */

bool BuildRosterHash(
    const std::vector<PolicyResult>& results,
    std::string* roster_hash
) {
    if (!roster_hash) {
        return false;
    }

    std::string roster;


    for (const auto& result : results) {

        roster +=
            result.server_id;

        roster +=
            "\n";
    }


    std::string error_msg;


    if (!attestation::utils::CryptoUtils::Sha256(
            roster,
            roster_hash,
            &error_msg
        )) {

        std::cerr
            << "Failed to hash roster: "
            << error_msg
            << "\n";

        return false;
    }


    return true;
}


/*
 * ============================================================
 * Phase 3
 *
 * Send aggregated policy back to participant.
 *
 * TA:
 *
 * generates N_conf
 * signs request using SK2
 *
 * Participant:
 *
 * verifies using PK2 associated with session_id
 * currently returns accepted = true
 * encrypts reply using PK2
 *
 * TA:
 *
 * decrypts reply using SK2
 * checks all bindings
 *
 * PK3 does not exist anymore.
 * ============================================================
 */

bool ConfirmAggregatedPolicy(
    const PolicyResult& participant_result,
    const std::string& client_id,
    const std::string& aggregated_policy,
    const std::string& aggregated_policy_hash,
    const std::string& roster_hash,
    const std::string& ta_private_key_path
) {
    const ParticipantState& participant =
        participant_result.participant;


    std::cout
        << "\n------------------------------------\n";

    std::cout
        << "[CONFIRM] Sending aggregated policy to "
        << participant.participant_id
        << "\n";


    auto channel =
        CreateParticipantChannel(
            participant.server
        );


    if (!channel) {
        return false;
    }


    auto stub =
        tacvm::v1::ParticipantService::NewStub(
            channel
        );


    /*
     * --------------------------------------------------------
     * Fresh N_conf.
     * --------------------------------------------------------
     */

    std::string request_nonce;
    std::string error_msg;


    if (!attestation::utils::CryptoUtils::GenerateNonce(
            &request_nonce,
            32,
            &error_msg
        )) {

        std::cerr
            << "[CONFIRM] Failed to generate nonce: "
            << error_msg
            << "\n";

        return false;
    }


    /*
     * --------------------------------------------------------
     * TA signs request using SK2.
     * --------------------------------------------------------
     */

    std::string signed_data =
        attestation::utils::CryptoUtils::
            BuildAggregatedPolicyRequestSignedData(
                client_id,
                participant.session_id,
                aggregated_policy_hash,
                roster_hash,
                request_nonce
            );


    std::string signature;


    if (!attestation::utils::CryptoUtils::SignData(
            signed_data,
            ta_private_key_path,
            &signature,
            &error_msg
        )) {

        std::cerr
            << "[CONFIRM] Failed to sign request: "
            << error_msg
            << "\n";

        return false;
    }


    /*
     * --------------------------------------------------------
     * Build request.
     * --------------------------------------------------------
     */

    tacvm::v1::AggregatedPolicyRequest
        request;


    request.set_client_id(
        client_id
    );


    request.set_session_id(
        participant.session_id
    );


    request.set_aggregated_policy(
        aggregated_policy
    );


    request.set_policy_hash(
        aggregated_policy_hash
    );


    request.set_roster_hash(
        roster_hash
    );


    request.set_request_nonce(
        request_nonce
    );


    request.set_signature(
        signature
    );


    /*
     * --------------------------------------------------------
     * Send request.
     * --------------------------------------------------------
     */

    tacvm::v1::EncryptedPayload
        encrypted_reply;


    grpc::ClientContext
        context;


    grpc::Status status =
        stub->VerifyAggregatedPolicy(
            &context,
            request,
            &encrypted_reply
        );


    if (!status.ok()) {

        std::cerr
            << "[CONFIRM] RPC failed: "
            << status.error_message()
            << "\n";

        return false;
    }


    if (encrypted_reply.message_type()
        != "AggregatedPolicyReply") {

        std::cerr
            << "[CONFIRM] Unexpected reply type: "
            << encrypted_reply.message_type()
            << "\n";

        return false;
    }


    /*
     * --------------------------------------------------------
     * Decrypt reply using SK2.
     * --------------------------------------------------------
     */

    std::string plaintext;


    if (!DecryptPayload(
            encrypted_reply,
            ta_private_key_path,
            &plaintext
        )) {

        return false;
    }


    tacvm::v1::AggregatedPolicyReply
        reply;


    if (!reply.ParseFromString(
            plaintext
        )) {

        std::cerr
            << "[CONFIRM] Failed to parse reply\n";

        return false;
    }


    /*
     * --------------------------------------------------------
     * Verify reply bindings.
     *
     * No PK3 signature verification anymore.
     * --------------------------------------------------------
     */

    if (reply.participant_id()
        != participant.participant_id) {

        std::cerr
            << "[CONFIRM] Participant ID mismatch\n";

        return false;
    }


    if (reply.request_nonce()
        != request_nonce) {

        std::cerr
            << "[CONFIRM] Nonce mismatch\n";

        return false;
    }


    if (reply.policy_hash()
        != aggregated_policy_hash) {

        std::cerr
            << "[CONFIRM] Policy hash mismatch\n";

        return false;
    }


    if (reply.roster_hash()
        != roster_hash) {

        std::cerr
            << "[CONFIRM] Roster hash mismatch\n";

        return false;
    }


    if (!reply.accepted()) {

        std::cerr
            << "[CONFIRM] Participant rejected "
            << "aggregated policy\n";

        return false;
    }


    std::cout
        << "[CONFIRM] ACCEPTED and verified\n";


    return true;
}


/*
 * ============================================================
 * Main
 * ============================================================
 */

int main(
    int argc,
    char** argv
) {
    /*
     * Usage:
     *
     * ./policy_client
     *
     * <server_list.json>
     * <policy_id>
     * <client_id>
     * <paa_script>
     * <ta_private_key>
     * <ta_public_key>
     */

    if (argc != 7) {

        std::cerr
            << "Usage: "
            << argv[0]
            << " <server_list.json>"
            << " <policy_id>"
            << " <client_id>"
            << " <paa_script>"
            << " <ta_private_key>"
            << " <ta_public_key>\n";

        return 1;
    }


    const std::string server_list_path =
        argv[1];

    const std::string policy_id =
        argv[2];

    const std::string client_id =
        argv[3];

    const std::string paa_script =
        argv[4];


    /*
     * Key 2:
     *
     * TA SK2
     * TA PK2
     */

    const std::string ta_private_key_path =
        argv[5];

    const std::string ta_public_key_path =
        argv[6];


    /*
     * --------------------------------------------------------
     * Load PK2.
     * --------------------------------------------------------
     */

    std::string ta_public_key_pem;
    std::string error_msg;


    if (!attestation::utils::CryptoUtils::LoadPublicKeyPem(
            ta_public_key_path,
            &ta_public_key_pem,
            &error_msg
        )) {

        std::cerr
            << "Failed to load TA public key: "
            << error_msg
            << "\n";

        return 1;
    }


    /*
     * --------------------------------------------------------
     * Load server list.
     * --------------------------------------------------------
     */

    std::vector<ServerConfig>
        servers;


    if (!LoadServerList(
            server_list_path,
            &servers
        )) {

        return 1;
    }


    if (servers.empty()) {

        std::cerr
            << "Server list is empty\n";

        return 1;
    }


    std::cout
        << "Loaded "
        << servers.size()
        << " participants\n";


    /*
     * ========================================================
     * Phase 1
     *
     * Remote Attestation + Policy Collection.
     *
     * There is now only ONE loop.
     * ========================================================
     */

    std::vector<PolicyResult>
        results;


    for (const auto& server : servers) {

        PolicyResult result;


        if (!RemoteAttestAndGetPolicy(
                server,
                client_id,
                ta_public_key_pem,
                ta_private_key_path,
                policy_id,
                &result
            )) {

            std::cerr
                << "Remote attestation/policy collection failed for "
                << server.id
                << "\n";

            return 1;
        }


        results.push_back(
            result
        );
    }


    std::cout
        << "\n====================================\n";

    std::cout
        << "All participants remotely attested\n";

    std::cout
        << "All policy proposals verified\n";


    /*
     * ========================================================
     * Build PAA input.
     * ========================================================
     */

    const std::string paa_input =
        "paa_input.yaml";

    const std::string paa_output =
        "paa_output.yaml";


    if (!BuildPAAInput(
            results,
            paa_input
        )) {

        std::cerr
            << "Failed to build PAA input\n";

        return 1;
    }


    /*
     * ========================================================
     * Measure PAA join.
     *
     * Timing boundary:
     *
     * immediately before RunPAA()
     * immediately after RunPAA()
     * ========================================================
     */

    auto join_start =
        std::chrono::steady_clock::now();


    if (!RunPAA(
            paa_script,
            paa_input,
            paa_output
        )) {

        std::cerr
            << "Policy aggregation FAILED\n";

        return 1;
    }


    auto join_end =
        std::chrono::steady_clock::now();


    auto join_us =
        std::chrono::duration_cast<
            std::chrono::microseconds
        >(
            join_end - join_start
        ).count();


    std::cout
        << "[OK] Policy aggregation SUCCESS\n";

    std::cout
        << "PAA join time: "
        << join_us
        << " us\n";


    /*
     * ========================================================
     * Read aggregated policy.
     * ========================================================
     */

    std::string aggregated_policy;


    if (!attestation::utils::CryptoUtils::ReadFile(
            paa_output,
            &aggregated_policy,
            &error_msg
        )) {

        std::cerr
            << "Failed to read PAA output: "
            << error_msg
            << "\n";

        return 1;
    }


    std::string aggregated_policy_hash;


    if (!attestation::utils::CryptoUtils::Sha256(
            aggregated_policy,
            &aggregated_policy_hash,
            &error_msg
        )) {

        std::cerr
            << "Failed to hash aggregated policy: "
            << error_msg
            << "\n";

        return 1;
    }


    /*
     * ========================================================
     * Hash participant roster.
     * ========================================================
     */

    std::string roster_hash;


    if (!BuildRosterHash(
            results,
            &roster_hash
        )) {

        std::cerr
            << "Failed to build roster hash\n";

        return 1;
    }


    /*
     * ========================================================
     * Phase 2
     *
     * Send aggregated policy to every participant.
     * ========================================================
     */

    for (const auto& result : results) {

        if (!ConfirmAggregatedPolicy(
                result,
                client_id,
                aggregated_policy,
                aggregated_policy_hash,
                roster_hash,
                ta_private_key_path
            )) {

            std::cerr
                << "Aggregated policy confirmation failed for "
                << result.server_id
                << "\n";

            return 1;
        }
    }


    /*
     * ========================================================
     * SUCCESS
     * ========================================================
     */

    std::cout
        << "\n====================================\n";

    std::cout
        << "TACVM POLICY ATTESTATION SUCCESS\n";

    std::cout
        << "Participants: "
        << results.size()
        << "\n";

    std::cout
        << "PAA join time: "
        << join_us
        << " us\n";


    return 0;
}