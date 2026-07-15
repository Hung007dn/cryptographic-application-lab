cmake_minimum_required(VERSION 3.16)

# =========================
# Lab 5 - Classical Digital Signatures
# Tool: sigtool
#
# Expected source location:
#   Vũ Trọng Hưng/lab5/lab5
#
# Expected bundled folders:
#   Vũ Trọng Hưng/openssl
#   Vũ Trọng Hưng/cryptopp
#   Vũ Trọng Hưng/nlohmann
# =========================

project(SignatureTool LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PROJECT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
get_filename_component(BUNDLE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)

message(STATUS "PROJECT_DIR = ${PROJECT_DIR}")
message(STATUS "BUNDLE_ROOT = ${BUNDLE_ROOT}")

# =========================
# nlohmann-json bundled header
# =========================

if(NOT EXISTS "${BUNDLE_ROOT}/nlohmann/json.hpp")
    message(FATAL_ERROR
        "nlohmann/json.hpp not found.\n"
        "Expected: ${BUNDLE_ROOT}/nlohmann/json.hpp"
    )
endif()

message(STATUS "Using bundled nlohmann/json.hpp: ${BUNDLE_ROOT}/nlohmann/json.hpp")

# =========================
# Crypto++ bundled library
# Required by ManualRSAPSS.cpp and ModularArithmetic.cpp
# =========================

set(CRYPTOPP_INCLUDE_DIR "${BUNDLE_ROOT}/cryptopp/include")

if(WIN32)
    set(CRYPTOPP_LIBRARY "${BUNDLE_ROOT}/cryptopp/lib/windows/libcryptopp.a")
else()
    set(CRYPTOPP_LIBRARY "${BUNDLE_ROOT}/cryptopp/lib/linux/libcryptopp.a")
endif()

if(NOT EXISTS "${CRYPTOPP_INCLUDE_DIR}/cryptopp/sha.h")
    message(FATAL_ERROR
        "Crypto++ headers not found.\n"
        "Expected: ${CRYPTOPP_INCLUDE_DIR}/cryptopp/sha.h"
    )
endif()

if(NOT EXISTS "${CRYPTOPP_LIBRARY}")
    message(FATAL_ERROR
        "Crypto++ library not found.\n"
        "Expected: ${CRYPTOPP_LIBRARY}"
    )
endif()

message(STATUS "Using Crypto++ include: ${CRYPTOPP_INCLUDE_DIR}")
message(STATUS "Using Crypto++ library: ${CRYPTOPP_LIBRARY}")

# =========================
# OpenSSL
# Windows uses bundled OpenSSL.
# Linux uses system OpenSSL.
# =========================

set(OPENSSL_BUNDLED_ROOT "${BUNDLE_ROOT}/openssl")

if(WIN32)
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_BUNDLED_ROOT}/include")
    set(OPENSSL_CRYPTO_LIB "${OPENSSL_BUNDLED_ROOT}/lib64/libcrypto.a")
    set(OPENSSL_SSL_LIB "${OPENSSL_BUNDLED_ROOT}/lib64/libssl.a")

    if(NOT EXISTS "${OPENSSL_INCLUDE_DIR}/openssl/evp.h")
        message(FATAL_ERROR
            "Bundled OpenSSL headers not found.\n"
            "Expected: ${OPENSSL_INCLUDE_DIR}/openssl/evp.h"
        )
    endif()

    if(NOT EXISTS "${OPENSSL_CRYPTO_LIB}")
        message(FATAL_ERROR
            "Bundled OpenSSL libcrypto.a not found.\n"
            "Expected: ${OPENSSL_CRYPTO_LIB}"
        )
    endif()

    if(NOT EXISTS "${OPENSSL_SSL_LIB}")
        message(FATAL_ERROR
            "Bundled OpenSSL libssl.a not found.\n"
            "Expected: ${OPENSSL_SSL_LIB}"
        )
    endif()

    message(STATUS "Using bundled OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "Using bundled OpenSSL crypto: ${OPENSSL_CRYPTO_LIB}")
    message(STATUS "Using bundled OpenSSL ssl: ${OPENSSL_SSL_LIB}")

else()
    find_package(OpenSSL REQUIRED)
endif()

# =========================
# Main executable
# =========================

add_executable(sigtool
    main.cpp

    SigConfig.cpp
    SigKeyManager.cpp

    ECDSAEngine.cpp
    RSAPSSEngine.cpp

    NegativeTests.cpp
    BatchVerifier.cpp
    SigBenchmarker.cpp
    SigKAT.cpp
    ManualRSAPSS.cpp
    ModularArithmetic.cpp
)

target_include_directories(sigtool PRIVATE
    ${PROJECT_DIR}
    ${BUNDLE_ROOT}
    ${CRYPTOPP_INCLUDE_DIR}
)

if(WIN32)
    target_include_directories(sigtool PRIVATE
        "${OPENSSL_INCLUDE_DIR}"
    )

    target_link_libraries(sigtool PRIVATE
        "${OPENSSL_CRYPTO_LIB}"
        "${OPENSSL_SSL_LIB}"
        "${CRYPTOPP_LIBRARY}"
        ws2_32
        crypt32
        advapi32
        user32
        bcrypt
    )
else()
    target_link_libraries(sigtool PRIVATE
        OpenSSL::Crypto
        OpenSSL::SSL
        "${CRYPTOPP_LIBRARY}"
        pthread
    )
endif()

# =========================
# Compiler warnings
# =========================

if(MSVC)
    target_compile_options(sigtool PRIVATE /W4)
else()
    target_compile_options(sigtool PRIVATE -Wall -Wextra)
endif()

# =========================
# CTest
# =========================

enable_testing()

add_test(
    NAME help_test
    COMMAND sigtool --help
)
add_test(
    NAME kat_tests
    COMMAND sigtool --kat ${PROJECT_DIR}/test_vectors.json
)
add_test(
    NAME negative_tests
    COMMAND sigtool --negative-tests
)
# =========================
# Unit tests with bundled Catch2
#
# Expected:
#   Vũ Trọng Hưng/catch2/catch.hpp
# =========================

if(EXISTS "${PROJECT_DIR}/tests/unit_tests.cpp")
    message(STATUS "Found tests/unit_tests.cpp")

    if(NOT EXISTS "${BUNDLE_ROOT}/catch2/catch.hpp")
        message(FATAL_ERROR
            "Bundled Catch2 header not found.\n"
            "Expected: ${BUNDLE_ROOT}/catch2/catch.hpp"
        )
    endif()

    add_executable(unit_tests
        tests/unit_tests.cpp

        SigConfig.cpp
        SigKeyManager.cpp

        ECDSAEngine.cpp
        RSAPSSEngine.cpp

        BatchVerifier.cpp
        ManualRSAPSS.cpp
        ModularArithmetic.cpp
    )

    target_include_directories(unit_tests PRIVATE
        ${PROJECT_DIR}
        ${BUNDLE_ROOT}
        ${CRYPTOPP_INCLUDE_DIR}
    )

    if(WIN32)
        target_include_directories(unit_tests PRIVATE
            "${OPENSSL_INCLUDE_DIR}"
        )

        target_link_libraries(unit_tests PRIVATE
            "${OPENSSL_CRYPTO_LIB}"
            "${OPENSSL_SSL_LIB}"
            "${CRYPTOPP_LIBRARY}"
            ws2_32
            crypt32
            advapi32
            user32
            bcrypt
        )
    else()
        target_link_libraries(unit_tests PRIVATE
            OpenSSL::Crypto
            OpenSSL::SSL
            "${CRYPTOPP_LIBRARY}"
            pthread
        )
    endif()

    add_test(
        NAME unit_tests
        COMMAND unit_tests
    )
else()
    message(WARNING "tests/unit_tests.cpp not found. Unit tests will not be built.")
endif()