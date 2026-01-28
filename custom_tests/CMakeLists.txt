# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: Apache-2.0

include("${CMAKE_SOURCE_DIR}/cmake/test_support.cmake")

set(CMAKE_CXX_STANDARD 20)

file(GLOB test_descr_files ${CMAKE_SOURCE_DIR}/custom_tests/descrs/*.md)

add_library(ubpf_custom_test_support srcs/ubpf_custom_test_support.cc)

target_link_libraries(
    ubpf_custom_test_support
    ${UBPF_TEST_LIBS}
)

target_include_directories(ubpf_custom_test_support PUBLIC ".srcs/")
target_include_directories(ubpf_custom_test_support PRIVATE ${UBPF_TEST_INCLUDES})

set(QEMU_RUNNER "")
# Only use QEMU when cross-compiling for ARM64 (building on x86_64 for ARM64)
# On native ARM64 systems, CMAKE_HOST_SYSTEM_PROCESSOR will also be aarch64
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
    target_include_directories(${test_name} PRIVATE ${UBPF_TEST_INCLUDES})
    target_link_libraries(
        ${test_name}
        ${UBPF_TEST_LIBS}
        ubpf_custom_test_support
    )
    set(potential_input_file ${CMAKE_SOURCE_DIR}/custom_tests/data/${test_name}.input)
    if (EXISTS ${potential_input_file})
        list(JOIN QEMU_RUNNER " " QEMU_RUNNER_STR)
        if(PLATFORM_WINDOWS)
            set(test_exe ${CMAKE_BINARY_DIR}\\bin\\$<$<CONFIG:Debug>:Debug>$<$<CONFIG:RelWithDebInfo>:RelWithDebInfo>\\${test_name}.exe)
            # Replace forward slashes with backslashes in the path to the input file
            string(REPLACE "/" "\\" potential_input_file ${potential_input_file})
            # Replace forward slashes with backslashes in the path to the test executable
            string(REPLACE "/" "\\" test_exe ${test_exe})
            add_test(
                NAME ${test_name}-Custom
            COMMAND ${test_exe} --program ${potential_input_file}
            )
        else()
            add_test(
                NAME ${test_name}-Custom
            COMMAND sh -c "cat ${potential_input_file} | ${QEMU_RUNNER_STR} $<TARGET_FILE:${test_name}>"
            )
        endif()
    else()
        add_test(
            NAME ${test_name}-Custom
	    COMMAND ${QEMU_RUNNER} $<TARGET_FILE:${test_name}>
        )
    endif()
endforeach()
