# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: Apache-2.0

set(CMAKE_CXX_STANDARD 20)

file(COPY ${CMAKE_SOURCE_DIR}/tests DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

add_executable(
    ubpf_plugin
    ubpf_plugin.cc
)

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

if(CMAKE_SYSTEM_PROCESSOR STREQUAL aarch64)
    set(PLUGIN_JIT --plugin_path ${CMAKE_BINARY_DIR}/bin/run-jit.sh)
    set(PLUGIN_INTERPRET --plugin_path ${CMAKE_BINARY_DIR}/bin/run-interpret.sh)
else()
    set(PLUGIN_JIT --plugin_path ${CMAKE_BINARY_DIR}/bin/ubpf_plugin --plugin_options --jit)
    set(PLUGIN_INTERPRET --plugin_path ${CMAKE_BINARY_DIR}/bin/ubpf_plugin --plugin_options --interpret)
endif()

foreach(file ${files})
    # TODO: remove this once we have a proper implementation of interlocked operations
    # and support for calling local functions.
    string(REGEX MATCH "(lock|call_local)" EXPECT_FAILURE "${file}")
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
