# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: Apache-2.0

if (UBPF_SKIP_EXTERNAL)
    message(WARNING "Skipping configuration of tests that require external package support.")
    return()
endif()

set(CMAKE_CXX_STANDARD 20)

add_executable(
    ubpf_fuzzer
    libfuzz_harness.cc
)

target_include_directories("ubpf_fuzzer" PRIVATE
    "${CMAKE_SOURCE_DIR}/vm"
    "${CMAKE_BINARY_DIR}/vm"
    "${CMAKE_SOURCE_DIR}/vm/inc"
    "${CMAKE_BINARY_DIR}/vm/inc"
    "${CMAKE_SOURCE_DIR}/ubpf_plugin"
)

target_link_libraries(
    ubpf_fuzzer
    ubpf
    ubpf_settings
)

