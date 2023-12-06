# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: Apache-2.0

if (UBPF_SKIP_EXTERNAL)
    message(WARNING "Skipping configuration of tests that require external package support.")
    return()
endif()

set(CMAKE_CXX_STANDARD 20)

file(COPY ${CMAKE_SOURCE_DIR}/tests DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

add_executable(
    ubpf_plugin
    ubpf_plugin.cc
)

add_dependencies(ubpf_plugin Conformance-build)

target_include_directories("ubpf_plugin" PRIVATE
    "${CMAKE_SOURCE_DIR}/vm"
    "${CMAKE_BINARY_DIR}/vm"
    "${CMAKE_SOURCE_DIR}/vm/inc"
    "${CMAKE_BINARY_DIR}/vm/inc"
)

target_link_libraries(
    ubpf_plugin
    ubpf
    ubpf_settings
)

file(GLOB external_files ${CMAKE_SOURCE_DIR}/external/bpf_conformance/tests/*.data)
file(GLOB local_files ${CMAKE_SOURCE_DIR}/tests/*.data)

set(files ${external_files} ${local_files})

if(NOT BPF_CONFORMANCE_RUNNER)
    set(BPF_CONFORMANCE_RUNNER ${CMAKE_BINARY_DIR}/external/bpf_conformance/bin/bpf_conformance_runner)
else()
    message(STATUS "Using custom bpf_conformance_runner: ${BPF_CONFORMANCE_RUNNER}")
endif()

if(CMAKE_SYSTEM_PROCESSOR STREQUAL aarch64 AND (NOT CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL aarch64))
    set(PLUGIN_JIT --plugin_path ${CMAKE_BINARY_DIR}/bin/run-jit.sh)
    set(PLUGIN_INTERPRET --plugin_path ${CMAKE_BINARY_DIR}/bin/run-interpret.sh)
else()
    if(PLATFORM_WINDOWS)
        set(PLATFORM_EXECUTABLE_EXTENSION ".exe")
    else()
        set(PLATFORM_EXECUTABLE_EXTENSION "")
    endif()
    set(PLUGIN_JIT --plugin_path ${CMAKE_BINARY_DIR}/bin/ubpf_plugin${PLATFORM_EXECUTABLE_EXTENSION} --plugin_options --jit)
    set(PLUGIN_INTERPRET --plugin_path ${CMAKE_BINARY_DIR}/bin/ubpf_plugin${PLATFORM_EXECUTABLE_EXTENSION} --plugin_options --interpret)
endif()

# Add all names of tests that are expected to fail to the TESTS_EXPECTED_TO_FAIL list
list(APPEND TESTS_EXPECTED_TO_FAIL "duplicate_label")
# TODO: remove this once we have a proper implementation of interlocked operations
# and support for calling local functions.
list(APPEND TESTS_EXPECTED_TO_FAIL "lock")

foreach(file ${files})
    unset(EXPECT_FAILURE)
    foreach(to_fail ${TESTS_EXPECTED_TO_FAIL})
        if(NOT EXPECT_FAILURE)
            string(REGEX MATCH "${to_fail}" EXPECT_FAILURE "${file}")
            if(EXPECT_FAILURE)
                message(STATUS "Expecting ${file} test to fail.")
            endif()
        endif()
    endforeach()
    add_test(
        NAME ${file}-JIT
        COMMAND ${BPF_CONFORMANCE_RUNNER} --test_file_path ${file} ${PLUGIN_JIT}
    )

    if(EXPECT_FAILURE)
        set_tests_properties(${file}-JIT PROPERTIES WILL_FAIL TRUE)
    endif()

    add_test(
        NAME ${file}-Interpreter
        COMMAND ${BPF_CONFORMANCE_RUNNER} --test_file_path ${file} ${PLUGIN_INTERPRET}
    )

    if(EXPECT_FAILURE)
        set_tests_properties(${file}-Interpreter PROPERTIES WILL_FAIL TRUE)
    endif()
endforeach()
