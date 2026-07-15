cmake_minimum_required(VERSION 3.16)
project(PQTool LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PROJECT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
get_filename_component(BUNDLE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)

# ===== liboqs paths =====
set(LIBOQS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../liboqs")

if(WIN32)
    # Windows liboqs build folder
    set(LIBOQS_INCLUDE_DIR "${LIBOQS_ROOT}/build/include")

    set(LIBOQS_LIB_CANDIDATES
        "${LIBOQS_ROOT}/build/Release/oqs.lib"
        "${LIBOQS_ROOT}/build/lib/Release/oqs.lib"
        "${LIBOQS_ROOT}/build/liboqs.dll.a"
        "${LIBOQS_ROOT}/build/lib/liboqs.dll.a"
        "${LIBOQS_ROOT}/build/liboqs.a"
        "${LIBOQS_ROOT}/build/lib/liboqs.a"
    )
else()
    # Linux liboqs build folder
    set(LIBOQS_INCLUDE_DIR "${LIBOQS_ROOT}/build_linux/include")

    set(LIBOQS_LIB_CANDIDATES
        "${LIBOQS_ROOT}/build_linux/lib/liboqs.so"
        "${LIBOQS_ROOT}/build_linux/lib/liboqs.a"
        "${LIBOQS_ROOT}/build_linux/liboqs.so"
        "${LIBOQS_ROOT}/build_linux/liboqs.a"
    )
endif()

set(LIBOQS_LIBRARY "")

foreach(candidate ${LIBOQS_LIB_CANDIDATES})
    if(EXISTS "${candidate}")
        set(LIBOQS_LIBRARY "${candidate}")
        break()
    endif()
endforeach()

if(NOT EXISTS "${LIBOQS_INCLUDE_DIR}/oqs/oqs.h")
    message(FATAL_ERROR "liboqs header not found: ${LIBOQS_INCLUDE_DIR}/oqs/oqs.h")
endif()

if(LIBOQS_LIBRARY STREQUAL "")
    message(FATAL_ERROR "liboqs library not found. Check liboqs build output folder.")
endif()

message(STATUS "Using liboqs include: ${LIBOQS_INCLUDE_DIR}")
message(STATUS "Using liboqs library: ${LIBOQS_LIBRARY}")

# ===== nlohmann/json bundled header =====
# Source files include <nlohmann/json.hpp>, so include Vũ Trọng Hưng.
set(NLOHMANN_ROOT "${BUNDLE_ROOT}")

if(NOT EXISTS "${NLOHMANN_ROOT}/nlohmann/json.hpp")
    message(FATAL_ERROR "nlohmann/json.hpp not found: ${NLOHMANN_ROOT}/nlohmann/json.hpp")
endif()

message(STATUS "Using nlohmann/json.hpp: ${NLOHMANN_ROOT}/nlohmann/json.hpp")

set(PQTOOL_SOURCES
    PQConfig.cpp
    PQKeyManager.cpp
    MLDSAEngine.cpp
    MLKEMEngine.cpp
    PQCertificate.cpp
    PQNegativeTests.cpp
    PQBatchTools.cpp
    PQKAT.cpp
)

# ===== Main executable =====
add_executable(pqtool
    main.cpp
    ${PQTOOL_SOURCES}
)

target_include_directories(pqtool PRIVATE
    ${PROJECT_DIR}
    ${LIBOQS_INCLUDE_DIR}
    ${NLOHMANN_ROOT}
)

target_link_libraries(pqtool PRIVATE
    "${LIBOQS_LIBRARY}"
)

if(WIN32)
    target_link_libraries(pqtool PRIVATE ws2_32 bcrypt advapi32)
endif()

# ===== CTest =====
enable_testing()

add_test(NAME help_test COMMAND pqtool --help)
add_test(NAME kat_tests COMMAND pqtool --kat ${PROJECT_DIR}/test_vectors.json)
add_test(NAME negative_tests COMMAND pqtool --negative-tests)
add_test(NAME batch_verify_demo COMMAND pqtool --batch-verify-demo --algo mldsa-44 --count 5)
add_test(NAME batch_decaps_bench COMMAND pqtool --batch-decaps-bench --algo mlkem-512 --count 5)

# ===== Optional Catch2 unit tests =====
if(EXISTS "${PROJECT_DIR}/tests/unit_tests.cpp")
    if(EXISTS "${BUNDLE_ROOT}/catch2/catch.hpp")
        add_executable(unit_tests
            tests/unit_tests.cpp
            ${PQTOOL_SOURCES}
        )

        target_include_directories(unit_tests PRIVATE
            ${PROJECT_DIR}
            ${LIBOQS_INCLUDE_DIR}
            ${NLOHMANN_ROOT}
            ${BUNDLE_ROOT}
        )

        target_link_libraries(unit_tests PRIVATE
            "${LIBOQS_LIBRARY}"
        )

        if(WIN32)
            target_link_libraries(unit_tests PRIVATE ws2_32 bcrypt advapi32)
        endif()

        add_test(NAME unit_tests COMMAND unit_tests)
    else()
        message(WARNING "catch2/catch.hpp not found at ${BUNDLE_ROOT}/catch2/catch.hpp. Unit tests will not be built.")
    endif()
else()
    message(WARNING "tests/unit_tests.cpp not found. Unit tests will not be built.")
endif()
# ===== Auto-copy liboqs.dll next to pqtool.exe on Windows =====
if(WIN32)
    file(GLOB_RECURSE LIBOQS_DLL_CANDIDATES
        "${LIBOQS_ROOT}/build/liboqs.dll"
        "${LIBOQS_ROOT}/build/bin/liboqs.dll"
        "${LIBOQS_ROOT}/build/bin/Release/liboqs.dll"
        "${LIBOQS_ROOT}/build/bin/Debug/liboqs.dll"
    )

    list(LENGTH LIBOQS_DLL_CANDIDATES LIBOQS_DLL_COUNT)

    if(LIBOQS_DLL_COUNT GREATER 0)
        list(GET LIBOQS_DLL_CANDIDATES 0 LIBOQS_DLL)

        message(STATUS "Using liboqs DLL: ${LIBOQS_DLL}")

        add_custom_command(TARGET pqtool POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${LIBOQS_DLL}"
            "$<TARGET_FILE_DIR:pqtool>"
            COMMENT "Copying liboqs.dll next to pqtool.exe"
        )

        if(TARGET unit_tests)
            add_custom_command(TARGET unit_tests POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${LIBOQS_DLL}"
                "$<TARGET_FILE_DIR:unit_tests>"
                COMMENT "Copying liboqs.dll next to unit_tests.exe"
            )
        endif()
    else()
        message(WARNING "liboqs.dll not found. pqtool.exe may fail at runtime.")
    endif()
endif()