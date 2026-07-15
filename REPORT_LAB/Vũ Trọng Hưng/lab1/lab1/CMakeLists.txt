cmake_minimum_required(VERSION 3.16)

# =========================
# Auto-detect project paths
#
# This CMakeLists.txt is usually inside:
#   Vũ Trọng Hưng/lab1/lab1
#
# Bundled dependency folders are expected at:
#   Vũ Trọng Hưng/cryptopp
#   Vũ Trọng Hưng/catch2
#   Vũ Trọng Hưng/nlohmann
#
# This version DOES NOT use vcpkg.
# =========================

set(PROJECT_DIR ${CMAKE_CURRENT_SOURCE_DIR})

set(BUNDLE_ROOT "")

foreach(candidate
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/.."
    "${CMAKE_CURRENT_SOURCE_DIR}/../.."
)
    if(EXISTS "${candidate}/cryptopp"
       OR EXISTS "${candidate}/catch2"
       OR EXISTS "${candidate}/nlohmann")
        get_filename_component(BUNDLE_ROOT "${candidate}" ABSOLUTE)
        break()
    endif()
endforeach()

if(BUNDLE_ROOT STREQUAL "")
    message(FATAL_ERROR
        "Cannot find bundled dependency root.\n"
        "Expected cryptopp, catch2, or nlohmann near the lab1 folder."
    )
endif()

message(STATUS "PROJECT_DIR = ${PROJECT_DIR}")
message(STATUS "BUNDLE_ROOT = ${BUNDLE_ROOT}")

project(AESToolCryptoPP LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# =========================
# Source files
# =========================

add_executable(encrypt_tool
    main.cpp
    CryptoConfig.cpp
    FileEncryptor.cpp
    KATRunner.cpp
    NISTValidator.cpp
    NegativeTests.cpp
    Benchmarker.cpp
)

target_include_directories(encrypt_tool PRIVATE
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

    target_include_directories(encrypt_tool PRIVATE
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
#   Vũ Trọng Hưng/cryptopp/include/cryptopp/aes.h
#
# Expected libraries, one of:
#
# Windows / MinGW:
#   Vũ Trọng Hưng/cryptopp/lib/windows/libcryptopp.a
#   Vũ Trọng Hưng/cryptopp/lib/mingw/libcryptopp.a
#   Vũ Trọng Hưng/cryptopp/lib/cryptopp/gcc/libcryptopp.a
#   Vũ Trọng Hưng/cryptopp/lib/libcryptopp.a
#
# Linux:
#   Vũ Trọng Hưng/cryptopp/lib/linux/libcryptopp.a
#   Vũ Trọng Hưng/cryptopp/lib/linux/libcryptopp.so
#   Vũ Trọng Hưng/cryptopp/lib/libcryptopp.a
# =========================

set(CRYPTOPP_INCLUDE_DIR "${BUNDLE_ROOT}/cryptopp/include")

if(NOT EXISTS "${CRYPTOPP_INCLUDE_DIR}/cryptopp/aes.h")
    message(FATAL_ERROR
        "Bundled Crypto++ headers not found.\n"
        "Expected:\n"
        "  ${CRYPTOPP_INCLUDE_DIR}/cryptopp/aes.h"
    )
endif()

target_include_directories(encrypt_tool PRIVATE
    ${CRYPTOPP_INCLUDE_DIR}
)

if(WIN32)
    set(CRYPTOPP_WINDOWS_CANDIDATES
        "${BUNDLE_ROOT}/cryptopp/lib/windows/libcryptopp.a"
        "${BUNDLE_ROOT}/cryptopp/lib/mingw/libcryptopp.a"
        "${BUNDLE_ROOT}/cryptopp/lib/cryptopp/gcc/libcryptopp.a"
        "${BUNDLE_ROOT}/cryptopp/lib/libcryptopp.a"
        "${BUNDLE_ROOT}/cryptopp/x64/Output/Release/libcryptopp.a"
    )

    set(CRYPTOPP_LIBRARY "")

    foreach(candidate ${CRYPTOPP_WINDOWS_CANDIDATES})
        if(EXISTS "${candidate}")
            set(CRYPTOPP_LIBRARY "${candidate}")
            break()
        endif()
    endforeach()

    if(CRYPTOPP_LIBRARY STREQUAL "")
        message(FATAL_ERROR
            "Bundled Windows/MinGW Crypto++ library not found.\n"
            "Expected one of:\n"
            "  ${BUNDLE_ROOT}/cryptopp/lib/windows/libcryptopp.a\n"
            "  ${BUNDLE_ROOT}/cryptopp/lib/mingw/libcryptopp.a\n"
            "  ${BUNDLE_ROOT}/cryptopp/lib/cryptopp/gcc/libcryptopp.a\n"
            "  ${BUNDLE_ROOT}/cryptopp/lib/libcryptopp.a\n"
            "Important: the library must be built with the same MinGW compiler used for this project."
        )
    endif()

    message(STATUS "Using bundled Windows Crypto++ library: ${CRYPTOPP_LIBRARY}")

    target_link_libraries(encrypt_tool PRIVATE
        "${CRYPTOPP_LIBRARY}"
    )

    if(MINGW)
        target_link_libraries(encrypt_tool PRIVATE
            ws2_32
            advapi32
        )
    endif()

else()
    set(CRYPTOPP_LINUX_CANDIDATES
        "${BUNDLE_ROOT}/cryptopp/lib/linux/libcryptopp.a"
        "${BUNDLE_ROOT}/cryptopp/lib/linux/libcryptopp.so"
        "${BUNDLE_ROOT}/cryptopp/lib/libcryptopp.a"
        "${BUNDLE_ROOT}/cryptopp/lib/libcryptopp.so"
    )

    set(CRYPTOPP_LIBRARY "")

    foreach(candidate ${CRYPTOPP_LINUX_CANDIDATES})
        if(EXISTS "${candidate}")
            set(CRYPTOPP_LIBRARY "${candidate}")
            break()
        endif()
    endforeach()

    if(CRYPTOPP_LIBRARY STREQUAL "")
        message(FATAL_ERROR
            "Bundled Linux Crypto++ library not found.\n"
            "Expected one of:\n"
            "  ${BUNDLE_ROOT}/cryptopp/lib/linux/libcryptopp.a\n"
            "  ${BUNDLE_ROOT}/cryptopp/lib/linux/libcryptopp.so\n"
            "  ${BUNDLE_ROOT}/cryptopp/lib/libcryptopp.a\n"
            "  ${BUNDLE_ROOT}/cryptopp/lib/libcryptopp.so\n"
            "Important: do not use Windows/MinGW libcryptopp.a on Linux."
        )
    endif()

    message(STATUS "Using bundled Linux Crypto++ library: ${CRYPTOPP_LIBRARY}")

    target_link_libraries(encrypt_tool PRIVATE
        "${CRYPTOPP_LIBRARY}"
        pthread
    )
endif()

# =========================
# Compiler warnings
# =========================

if(MSVC)
    target_compile_options(encrypt_tool PRIVATE /W4)
else()
    target_compile_options(encrypt_tool PRIVATE -Wall -Wextra)
endif()

# =========================
# CTest CLI tests
# =========================

enable_testing()

add_test(
    NAME help_test
    COMMAND encrypt_tool --help
)

add_test(
    NAME kat_vectors_test
    COMMAND encrypt_tool --kat ${PROJECT_DIR}/test_vectors.json
)

add_test(
    NAME negative_tests
    COMMAND encrypt_tool --negative-tests
)

# =========================
# Unit testing with bundled Catch2 header
#
# Expected:
#   Vũ Trọng Hưng/catch2/catch.hpp
#
# Recommended tests/unit_tests.cpp:
#   #include <catch2/catch.hpp>
#
# This CMakeLists defines CATCH_CONFIG_MAIN.
# Therefore, unit_tests.cpp should NOT define:
#   #define CATCH_CONFIG_MAIN
# =========================

if(EXISTS "${PROJECT_DIR}/tests/unit_tests.cpp")
    message(STATUS "Found tests/unit_tests.cpp")

    if(EXISTS "${BUNDLE_ROOT}/catch2/catch.hpp")
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
            ENCRYPT_TOOL_PATH="$<TARGET_FILE:encrypt_tool>"
            TEST_VECTOR_PATH="${PROJECT_DIR}/test_vectors.json"
        )

        add_dependencies(unit_tests encrypt_tool)

        add_test(
            NAME unit_tests
            COMMAND unit_tests
        )

    else()
        message(WARNING
            "Bundled Catch2 header not found. Unit tests will not be built.\n"
            "Expected:\n"
            "  ${BUNDLE_ROOT}/catch2/catch.hpp\n"
            "CLI CTest tests will still run."
        )
    endif()

else()
    message(WARNING
        "tests/unit_tests.cpp not found. Unit tests will not be built. "
        "CLI CTest tests will still run."
    )
endif()