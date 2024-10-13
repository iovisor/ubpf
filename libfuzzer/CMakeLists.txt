# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: Apache-2.0

if (UBPF_SKIP_EXTERNAL)
    message(WARNING "Skipping configuration of tests that require external package support.")
    return()
endif()

set(UBPF_FUZZER_INCLUDES "${CMAKE_SOURCE_DIR}/vm"
    "${CMAKE_BINARY_DIR}/vm"
    "${CMAKE_BINARY_DIR}/_deps/gsl-src/include"
    "${CMAKE_SOURCE_DIR}/vm/inc"
    "${CMAKE_BINARY_DIR}/vm/inc"
    "${CMAKE_SOURCE_DIR}/ubpf_plugin"
    "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src"
    "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src/crab"
    "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src/crab_utils"
    "${CMAKE_CURRENT_BINARY_DIR}")

set(UBPF_FUZZER_LIBS
    ubpf
    ubpf_settings
    ebpfverifier)

# include(CheckCXXSymbolExists)

set(CMAKE_REQUIRED_INCLUDES ${UBPF_FUZZER_INCLUDES})

# check_cxx_symbol_exists(ebpf_verifier_options_t::store_pre_invariants "config.hpp" HAVE_EBPF_CHECK_CONSTRAINTS_AT_LABEL)

include(CheckCXXSourceCompiles)

set(CHECK_CONFIG_STORE_PRE_INVARIANTS "
#include <config.hpp>
int main() {
    ebpf_verifier_options_t options;
    options.store_pre_invariants = true;
    return 0;
}
")

check_cxx_source_compiles("${CHECK_CONFIG_STORE_PRE_INVARIANTS}" HAVE_EBPF_VERIFIER_CHECK_CONSTRAINTS_AT_LABEL)

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

target_link_libraries(ubpf_fuzzer PRIVATE ${UBPF_FUZZER_LIBS})

