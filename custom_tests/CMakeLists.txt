# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: Apache-2.0

set(CMAKE_CXX_STANDARD 20)

file(GLOB test_descr_files ${CMAKE_SOURCE_DIR}/custom_tests/descrs/*.md)

add_library(ubpf_custom_test_support srcs/ubpf_custom_test_support.cc)

target_link_libraries(
    ubpf_custom_test_support
    ubpf
    ubpf_settings
)

target_include_directories(ubpf_custom_test_support PUBLIC ".srcs/")
target_include_directories(ubpf_custom_test_support PRIVATE
    "${CMAKE_SOURCE_DIR}/vm"
    "${CMAKE_BINARY_DIR}/vm"
    "${CMAKE_SOURCE_DIR}/vm/inc"
    "${CMAKE_BINARY_DIR}/vm/inc"
)

set(QEMU_RUNNER "")
if(CMAKE_SYSTEM_PROCESSOR STREQUAL aarch64 AND (NOT CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL aarch64))
	set(QEMU_RUNNER qemu-aarch64 -L /usr/aarch64-linux-gnu)
endif()

foreach(test_file ${test_descr_files})
    get_filename_component(test_name ${test_file} NAME_WE)
    set(test_source_path "${CMAKE_SOURCE_DIR}/custom_tests/srcs/${test_name}.cc")

    add_executable(
        ${test_name}
        ${test_source_path}
    )
    target_include_directories(${test_name} PRIVATE
        "${CMAKE_SOURCE_DIR}/vm"
        "${CMAKE_BINARY_DIR}/vm"
        "${CMAKE_SOURCE_DIR}/vm/inc"
        "${CMAKE_BINARY_DIR}/vm/inc"
    )
    target_link_libraries(
        ${test_name}
        ubpf
        ubpf_custom_test_support
        ubpf_settings
    )
    set(potential_input_file ${CMAKE_SOURCE_DIR}/custom_tests/data/${test_name}.input)
    if (EXISTS ${potential_input_file})
        list(JOIN QEMU_RUNNER " " QEMU_RUNNER_STR)
        add_test(
            NAME ${test_name}-Custom
	    COMMAND sh -c "cat ${potential_input_file} | ${QEMU_RUNNER_STR} $<TARGET_FILE:${test_name}>"
        )
    else()
        add_test(
            NAME ${test_name}-Custom
	    COMMAND ${QEMU_RUNNER} $<TARGET_FILE:${test_name}>
        )
    endif()
endforeach()
