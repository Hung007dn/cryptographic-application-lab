cmake_minimum_required(VERSION 3.16)

# =========================
# Project paths
#
# CMakeLists.txt is inside:
#   Vũ Trọng Hưng/lab3/lab3
#
# Bundled dependency folders are inside:
#   Vũ Trọng Hưng/cryptopp
#   Vũ Trọng Hưng/catch2
#   Vũ Trọng Hưng/nlohmann
#
# This version DOES NOT use vcpkg.
# =========================

set(PROJECT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
get_filename_component(BUNDLE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)

message(STATUS "PROJECT_DIR = ${PROJECT_DIR}")
message(STATUS "BUNDLE_ROOT = ${BUNDLE_ROOT}")

project(Lab3_RSAHybridEncryption LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# =========================
# Core source files
# Do not put main.cpp here
# =========================

set(RSA_CORE_SOURCES
    RSAConfig.cpp
    RSAKeyManager.cpp
    RSAEngine.cpp
    HybridEncryptor.cpp
    RSAValidator.cpp
    RSABenchmarker.cpp
    NegativeTests.cpp
    ManualOAEP.cpp
    OAEPValidator.cpp
)

add_library(rsa_core STATIC ${RSA_CORE_SOURCES})

target_include_directories(rsa_core PUBLIC
    ${PROJECT_DIR}
)

# =========================
# nlohmann-json bundled only
#
# Expected:
#   Vũ Trọng Hưng/nlohmann/json.hpp
#
# Supports:
#   #include <nlohmann/json.hpp>
# =========================

if(EXISTS "${BUNDLE_ROOT}/nlohmann/json.hpp")
    message(STATUS "Using bundled nlohmann/json.hpp from: ${BUNDLE_ROOT}/nlohmann/json.hpp")

    target_include_directories(rsa_core PUBLIC
        ${BUNDLE_ROOT}
    )
else()
    message(FATAL_ERROR
        "Bundled nlohmann/json.hpp not found.\n"
        "Expected:\n"
        "  ${BUNDLE_ROOT}/nlohmann/json.hpp"
    )
endif()

# =========================
# Crypto++ bundled only
#
# Expected headers:
#   Vũ Trọng Hưng/cryptopp/include/cryptopp/rsa.h
#
# Expected libraries:
#
# Windows / MinGW:
#   Vũ Trọng Hưng/cryptopp/lib/windows/libcryptopp.a
#
# Linux:
#   Vũ Trọng Hưng/cryptopp/lib/linux/libcryptopp.a
# or:
#   Vũ Trọng Hưng/cryptopp/lib/linux/libcryptopp.so
#
# Important:
#   Do not use Windows/MinGW libcryptopp.a on Linux.
#   Do not use Linux libcryptopp.a on Windows.
# =========================

set(CRYPTOPP_INCLUDE_DIR "${BUNDLE_ROOT}/cryptopp/include")

if(NOT EXISTS "${CRYPTOPP_INCLUDE_DIR}/cryptopp/rsa.h")
    message(FATAL_ERROR
        "Bundled Crypto++ headers not found.\n"
        "Expected:\n"
        "  ${CRYPTOPP_INCLUDE_DIR}/cryptopp/rsa.h"
    )
endif()

target_include_directories(rsa_core PUBLIC
    ${CRYPTOPP_INCLUDE_DIR}
)

if(WIN32)
    set(CRYPTOPP_WINDOWS_STATIC "${BUNDLE_ROOT}/cryptopp/lib/cryptopp/gcc/libcryptopp.a")

    if(NOT EXISTS "${CRYPTOPP_WINDOWS_STATIC}")
        message(FATAL_ERROR
            "Bundled Windows/MinGW Crypto++ library not found.\n"
            "Expected:\n"
            "  ${CRYPTOPP_WINDOWS_STATIC}\n"
            "Important: this library must be built with the same MinGW compiler used for this project."
        )
    endif()

    message(STATUS "Using bundled Windows Crypto++ static library: ${CRYPTOPP_WINDOWS_STATIC}")

    target_link_libraries(rsa_core PUBLIC
        "${CRYPTOPP_WINDOWS_STATIC}"
    )

    if(MINGW)
        target_link_libraries(rsa_core PUBLIC
            ws2_32
            advapi32
        )
    endif()

else()
    set(CRYPTOPP_LINUX_STATIC "${BUNDLE_ROOT}/cryptopp/lib/linux/libcryptopp.a")
    set(CRYPTOPP_LINUX_SHARED "${BUNDLE_ROOT}/cryptopp/lib/linux/libcryptopp.so")

    if(EXISTS "${CRYPTOPP_LINUX_STATIC}")
        message(STATUS "Using bundled Linux Crypto++ static library: ${CRYPTOPP_LINUX_STATIC}")
        target_link_libraries(rsa_core PUBLIC "${CRYPTOPP_LINUX_STATIC}")

    elseif(EXISTS "${CRYPTOPP_LINUX_SHARED}")
        message(STATUS "Using bundled Linux Crypto++ shared library: ${CRYPTOPP_LINUX_SHARED}")
        target_link_libraries(rsa_core PUBLIC "${CRYPTOPP_LINUX_SHARED}")

    else()
        message(FATAL_ERROR
            "Bundled Linux Crypto++ library not found.\n"
            "Expected one of:\n"
            "  ${CRYPTOPP_LINUX_STATIC}\n"
            "  ${CRYPTOPP_LINUX_SHARED}\n"
            "Important: do not use Windows/MinGW libcryptopp.a on Linux."
        )
    endif()

    target_link_libraries(rsa_core PUBLIC
        pthread
    )
endif()

# =========================
# Main executable
# =========================

add_executable(rsatool
    main.cpp
)

target_link_libraries(rsatool PRIVATE
    rsa_core
)

# =========================
# Compiler warnings
# =========================

if(MSVC)
    target_compile_options(rsa_core PRIVATE /W4)
    target_compile_options(rsatool PRIVATE /W4)
else()
    target_compile_options(rsa_core PRIVATE -Wall -Wextra)
    target_compile_options(rsatool PRIVATE -Wall -Wextra)
endif()

# =========================
# CTest
# =========================

enable_testing()

add_test(
    NAME help_test
    COMMAND rsatool --help
)

# =========================
# Unit tests with bundled Catch2 v2 single header
#
# Expected:
#   Vũ Trọng Hưng/catch2/catch.hpp
#
# Recommended tests/unit_tests.cpp:
#   #define CATCH_CONFIG_MAIN
#   #include <catch2/catch.hpp>
#
# If unit_tests.cpp already defines CATCH_CONFIG_MAIN,
# do NOT define it again in CMake.
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

    target_link_libraries(unit_tests PRIVATE
        rsa_core
    )

    add_test(
        NAME unit_tests
        COMMAND unit_tests
    )

else()
    message(WARNING "tests/unit_tests.cpp not found. Unit tests will not be built.")
endif()