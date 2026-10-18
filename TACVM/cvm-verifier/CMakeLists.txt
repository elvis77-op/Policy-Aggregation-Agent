cmake_minimum_required(VERSION 3.16)

project(policy_attestation)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_POLICY_CLIENT "Build the policy_client executable" ON)


# ==========================================
# Dependencies
# ==========================================

find_package(Protobuf REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(yaml-cpp REQUIRED)

pkg_check_modules(GRPCPP REQUIRED IMPORTED_TARGET grpc++)

set(
    TDX_LIB_DIR
    /lib/x86_64-linux-gnu
)

link_directories(
    ${TDX_LIB_DIR}
)


find_program(
    GRPC_CPP_PLUGIN
    NAMES grpc_cpp_plugin
    REQUIRED
)


message(STATUS "Protobuf protoc: ${Protobuf_PROTOC_EXECUTABLE}")
message(STATUS "gRPC C++ plugin: ${GRPC_CPP_PLUGIN}")


# ==========================================
# Proto
# ==========================================

set(
    PROTO_FILE
    ${CMAKE_CURRENT_SOURCE_DIR}/proto/policy.proto
)

get_filename_component(
    PROTO_DIR
    ${PROTO_FILE}
    DIRECTORY
)


set(
    PROTO_SRCS
    ${CMAKE_CURRENT_BINARY_DIR}/policy.pb.cc
)

set(
    PROTO_HDRS
    ${CMAKE_CURRENT_BINARY_DIR}/policy.pb.h
)

set(
    GRPC_SRCS
    ${CMAKE_CURRENT_BINARY_DIR}/policy.grpc.pb.cc
)

set(
    GRPC_HDRS
    ${CMAKE_CURRENT_BINARY_DIR}/policy.grpc.pb.h
)


add_custom_command(
    OUTPUT
        ${PROTO_SRCS}
        ${PROTO_HDRS}
        ${GRPC_SRCS}
        ${GRPC_HDRS}

    COMMAND
        ${Protobuf_PROTOC_EXECUTABLE}

    ARGS
        --proto_path=${PROTO_DIR}
        --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
        --grpc_out=${CMAKE_CURRENT_BINARY_DIR}
        --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN}
        ${PROTO_FILE}

    DEPENDS
        ${PROTO_FILE}
)


add_library(
    policy_proto
    ${PROTO_SRCS}
    ${GRPC_SRCS}
)


target_include_directories(
    policy_proto
    PUBLIC
        ${CMAKE_CURRENT_BINARY_DIR}
)


target_link_libraries(
    policy_proto
    PUBLIC
        protobuf::libprotobuf
        PkgConfig::GRPCPP
)


# ==========================================
# Utilities
# ==========================================

add_library(
    policy_utils
    utils/sha256_utils.cc
    utils/sha384_utils.cc
    utils/canonical_json.cc
    utils/crypto_utils.cc
    utils/policy_verifier.cc
)


target_include_directories(
    policy_utils
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/utils
)


target_link_libraries(
    policy_utils
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    yaml-cpp
)


# ==========================================
# Quote Verifier
# ==========================================

add_library(
    quote_verifier
    QuoteAppraisal/quote_verifier.cc
)


target_include_directories(
    quote_verifier
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/QuoteAppraisal
        ${CMAKE_CURRENT_SOURCE_DIR}/QuoteAppraisal/jwt-cpp/include
)


target_link_libraries(
    quote_verifier
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        pthread
        dl

        # Intel DCAP Quote Verification Library
        sgx_dcap_quoteverify
)


# ==========================================
# Server
# ==========================================

add_executable(
    policy_server
    server/policy_server.cc
)


target_include_directories(
    policy_server
    PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/QuoteAppraisal
)


target_link_libraries(
    policy_server
    PRIVATE
        policy_proto
        policy_utils
        quote_verifier
        PkgConfig::GRPCPP
        OpenSSL::SSL
        OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    yaml-cpp
)


# ==========================================
# Client
# ==========================================

if(BUILD_POLICY_CLIENT)
    add_executable(
        policy_client
        client/policy_client.cc
        client/tdx_quote.cc
    )


    target_include_directories(
        policy_client
        PRIVATE
            ${CMAKE_CURRENT_BINARY_DIR}
    )


    target_link_libraries(
        policy_client
        PRIVATE
            policy_proto
            policy_utils
            tdx_attest
            PkgConfig::GRPCPP
            OpenSSL::SSL
            OpenSSL::Crypto
        nlohmann_json::nlohmann_json
        yaml-cpp
    )
endif()