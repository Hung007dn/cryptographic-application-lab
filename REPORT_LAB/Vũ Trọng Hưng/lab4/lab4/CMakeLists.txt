
cmake_minimum_required(VERSION 3.16)

# =========================
# Lab 4 - Hashing, PKI, and Practical Attacks
#
# Expected source location:
#   Vũ Trọng Hưng/lab4/lab4
#
# Expected bundled folders:
#   Vũ Trọng Hưng/nlohmann
#   Vũ Trọng Hưng/openssl
#   Vũ Trọng Hưng/catch2
#
# Lab 4 uses OpenSSL for:
#   - SHA-2
#   - SHA-3
#   - SHAKE
#   - MD5/SHA-256 collision verification
#   - X.509 certificate parsing
#
# CustomSHA256Extend.cpp is manually implemented for the
# SHA-256 length-extension bonus.
# =========================

project(Lab4_HashTool LANGUAGES CXX)

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
# OpenSSL
#
# Windows bundled OpenSSL expected:
#   Vũ Trọng Hưng/openssl/bin/openssl.exe
#   Vũ Trọng Hưng/openssl/include/openssl/x509.h
#   Vũ Trọng Hưng/openssl/lib64/libcrypto.a
#   Vũ Trọng Hưng/openssl/lib64/libssl.a
#
# Linux:
#   Prefer system OpenSSL package:
#   sudo apt install openssl libssl-dev
# =========================

set(OPENSSL_BUNDLED_ROOT "${BUNDLE_ROOT}/openssl")

if(WIN32)
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_BUNDLED_ROOT}/include")
    set(OPENSSL_CRYPTO_LIB "${OPENSSL_BUNDLED_ROOT}/lib64/libcrypto.a")
    set(OPENSSL_SSL_LIB "${OPENSSL_BUNDLED_ROOT}/lib64/libssl.a")

    if(NOT EXISTS "${OPENSSL_INCLUDE_DIR}/openssl/x509.h")
        message(FATAL_ERROR
            "Bundled OpenSSL headers not found.\n"
            "Expected: ${OPENSSL_INCLUDE_DIR}/openssl/x509.h"
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

add_executable(hashtool
    main.cpp

    HashConfig.cpp
    HashEngine.cpp
    HashValidator.cpp
    HashBenchmarker.cpp

    NegativeTests.cpp
    CertificateAnalyzer.cpp
    MD5CollisionDemo.cpp

    CustomSHA256Extend.cpp
)

target_include_directories(hashtool PRIVATE
    ${PROJECT_DIR}
    ${BUNDLE_ROOT}
)

if(WIN32)
    target_include_directories(hashtool PRIVATE
        "${OPENSSL_INCLUDE_DIR}"
    )

    target_link_libraries(hashtool PRIVATE
        "${OPENSSL_CRYPTO_LIB}"
        "${OPENSSL_SSL_LIB}"
        ws2_32
        crypt32
        advapi32
        user32
        bcrypt
    )
else()
    target_link_libraries(hashtool PRIVATE
        OpenSSL::Crypto
        OpenSSL::SSL
        pthread
    )
endif()

# =========================
# Compiler warnings
# =========================

if(MSVC)
    target_compile_options(hashtool PRIVATE /W4)
else()
    target_compile_options(hashtool PRIVATE -Wall -Wextra)
endif()

# =========================
# CTest CLI tests
# =========================

enable_testing()

add_test(
    NAME help_test
    COMMAND hashtool --help
)

add_test(
    NAME kat_tests
    COMMAND hashtool --kat ${PROJECT_DIR}/test_vectors.json
)

add_test(
    NAME negative_tests
    COMMAND hashtool --negative-tests
)

# =========================
# Unit tests with bundled Catch2
#
# Expected:
#   Vũ Trọng Hưng/catch2/catch.hpp
#
# Supported:
#   #include <catch2/catch.hpp>
# =========================

if(EXISTS "${PROJECT_DIR}/tests/unit_tests.cpp")
    message(STATUS "Found tests/unit_tests.cpp")

    if(NOT EXISTS "${BUNDLE_ROOT}/catch2/catch.hpp")
        message(FATAL_ERROR
            "Bundled Catch2 header not found.\n"
            "Expected:\n"
            "  ${BUNDLE_ROOT}/catch2/catch.hpp"
        )
    endif()

    message(STATUS "Using bundled Catch2 header: ${BUNDLE_ROOT}/catch2/catch.hpp")

    add_executable(unit_tests
        tests/unit_tests.cpp
    )

    target_include_directories(unit_tests PRIVATE
        ${PROJECT_DIR}
        ${BUNDLE_ROOT}
    )

    target_compile_definitions(unit_tests PRIVATE
        CATCH_CONFIG_MAIN
        TEST_VECTOR_PATH="${PROJECT_DIR}/test_vectors.json"
    )

    add_test(
        NAME unit_tests
        COMMAND unit_tests
    )

else()
    message(WARNING "tests/unit_tests.cpp not found. Unit tests will not be built.")
endif()
