cmake_minimum_required(VERSION 3.16)

# =========================
# Project paths
#
# CMakeLists.txt is inside:
#   Vũ Trọng Hưng/lab6/lab6
#
# Bundled dependency folders are inside:
#   Vũ Trọng Hưng/openssl     (OpenSSL 4.0, includes ML-DSA and ML-KEM)
#   Vũ Trọng Hưng/nlohmann    (nlohmann/json.hpp)
#   Vũ Trọng Hưng/catch2      (Catch2 single-header)
# =========================

set(PROJECT_DIR  ${CMAKE_CURRENT_SOURCE_DIR})
get_filename_component(BUNDLE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)

message(STATUS "PROJECT_DIR = ${PROJECT_DIR}")
message(STATUS "BUNDLE_ROOT = ${BUNDLE_ROOT}")

project(Lab6_PQC LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# =========================
# OpenSSL 4.0 (bundled)
# =========================
set(OPENSSL_ROOT "${BUNDLE_ROOT}/openssl")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT}/include")
set(OPENSSL_LIBCRYPTO    "${OPENSSL_ROOT}/lib64/libcrypto.dll.a")
set(OPENSSL_LIBSSL       "${OPENSSL_ROOT}/lib64/libssl.dll.a")
set(OPENSSL_BIN_DIR      "${OPENSSL_ROOT}/bin")

if(NOT EXISTS "${OPENSSL_INCLUDE_DIR}/openssl/evp.h")
    message(FATAL_ERROR
        "Bundled OpenSSL headers not found.\n"
        "Expected: ${OPENSSL_INCLUDE_DIR}/openssl/evp.h"
    )
endif()
if(NOT EXISTS "${OPENSSL_LIBCRYPTO}")
    message(FATAL_ERROR
        "Bundled OpenSSL libcrypto not found.\n"
        "Expected: ${OPENSSL_LIBCRYPTO}"
    )
endif()

message(STATUS "Using bundled OpenSSL 4.0 from: ${OPENSSL_ROOT}")

# =========================
# nlohmann/json (bundled)
# =========================
if(NOT EXISTS "${BUNDLE_ROOT}/nlohmann/json.hpp")
    message(FATAL_ERROR "Bundled nlohmann/json.hpp not found.")
endif()
message(STATUS "Using bundled nlohmann/json.hpp")

# =========================
# Catch2 (bundled)
# =========================
if(NOT EXISTS "${BUNDLE_ROOT}/catch2/catch.hpp")
    message(FATAL_ERROR "Bundled catch2/catch.hpp not found.")
endif()
message(STATUS "Using bundled Catch2 header")

# =========================
# Core library sources
# =========================
set(PQ_CORE_SOURCES
    PQConfig.hpp
    PQKeyManager.cpp
    MLDSAEngine.cpp
    MLKEMEngine.cpp
    PQCertificate.cpp
    PQBenchmarker.cpp
    PQNegativeTests.cpp
)

add_library(pq_core STATIC ${PQ_CORE_SOURCES})

target_include_directories(pq_core PUBLIC
    ${PROJECT_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${BUNDLE_ROOT}          # for <nlohmann/json.hpp>
)

target_link_libraries(pq_core PUBLIC
    "${OPENSSL_LIBCRYPTO}"
    "${OPENSSL_LIBSSL}"
    ws2_32
    crypt32
)

# =========================
# Main executable: pqtool
# =========================
add_executable(pqtool main.cpp)

target_include_directories(pqtool PRIVATE
    ${PROJECT_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${BUNDLE_ROOT}
)

target_link_libraries(pqtool PRIVATE pq_core)

# Copy DLLs next to the executable on Windows
if(WIN32)
    add_custom_command(TARGET pqtool POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${OPENSSL_BIN_DIR}/libcrypto-4.dll"
            "$<TARGET_FILE_DIR:pqtool>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${OPENSSL_BIN_DIR}/libssl-4.dll"
            "$<TARGET_FILE_DIR:pqtool>"
        COMMENT "Copying OpenSSL DLLs to output directory"
    )
endif()

# =========================
# Unit tests (Catch2)
# =========================
if(EXISTS "${PROJECT_DIR}/tests/unit_tests.cpp")
    add_executable(unit_tests tests/unit_tests.cpp)

    target_include_directories(unit_tests PRIVATE
        ${PROJECT_DIR}
        ${OPENSSL_INCLUDE_DIR}
        ${BUNDLE_ROOT}
    )

    target_link_libraries(unit_tests PRIVATE pq_core)

    if(WIN32)
        add_custom_command(TARGET unit_tests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${OPENSSL_BIN_DIR}/libcrypto-4.dll"
                "$<TARGET_FILE_DIR:unit_tests>"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${OPENSSL_BIN_DIR}/libssl-4.dll"
                "$<TARGET_FILE_DIR:unit_tests>"
            COMMENT "Copying OpenSSL DLLs for unit_tests"
        )
    endif()

    enable_testing()
    add_test(NAME PQCUnitTests COMMAND unit_tests)
    message(STATUS "Found tests/unit_tests.cpp — unit test target added")
endif()
