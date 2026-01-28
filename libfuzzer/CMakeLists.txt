# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: Apache-2.0

include("${CMAKE_SOURCE_DIR}/cmake/test_support.cmake")

if (UBPF_SKIP_EXTERNAL)
    message(WARNING "Skipping configuration of tests that require external package support.")
    return()
endif()

if (PLATFORM_WINDOWS)
set(Boost_INCLUDE_DIRS ${CMAKE_BINARY_DIR}/packages/boost/lib/native/include)
set(Boost_LIBRARY_DIRS ${CMAKE_BINARY_DIR}/packages/boost_filesystem-vc143/lib/native)
endif()

# Extend base test includes with fuzzer-specific includes
set(UBPF_FUZZER_INCLUDES 
    ${UBPF_TEST_INCLUDES}
    "${CMAKE_BINARY_DIR}/_deps/gsl-src/include"
    "${CMAKE_SOURCE_DIR}/ubpf_plugin"
    "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src"
    "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src/crab"
    "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src/crab_utils"
    "${CMAKE_CURRENT_BINARY_DIR}"
    "${Boost_INCLUDE_DIRS}")

# Extend base test libs with fuzzer-specific libs
set(UBPF_FUZZER_LIBS
    ${UBPF_TEST_LIBS}
    ebpfverifier)

set(CMAKE_REQUIRED_INCLUDES ${UBPF_FUZZER_INCLUDES})

set(CMAKE_CXX_STANDARD 20)

configure_file(
    libfuzzer_config.h.inc
    "${CMAKE_CURRENT_BINARY_DIR}/libfuzzer_config.h"
)

add_executable(
    ubpf_fuzzer
    libfuzz_harness.cc
)

target_include_directories("ubpf_fuzzer" PRIVATE ${UBPF_FUZZER_INCLUDES})

if (PLATFORM_WINDOWS)
  set(CMAKE_EXE_LINKER_FLAGS_FUZZERDEBUG libsancov.lib clang_rt.fuzzer_MDd-x86_64.lib)
endif()

target_link_libraries(ubpf_fuzzer PRIVATE ${UBPF_FUZZER_LIBS})
