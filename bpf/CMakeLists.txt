# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: Apache-2.0

function(clang_validator correct clang_path)
    execute_process(
        COMMAND echo "int main() { return 0;}"
        COMMAND ${clang_path} --target=bpf -x c - -c -o /dev/null
        ERROR_QUIET OUTPUT_QUIET
        RESULT_VARIABLE CLANG_RETURN_CODE
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if (CLANG_RETURN_CODE EQUAL 0)
        set(${correct} true PARENT_SCOPE)
    else()
        set(${correct} false PARENT_SCOPE)
    endif()

endfunction()

find_program(clang_path "clang" VALIDATOR clang_validator NO_CACHE HINTS ${UBPF_ALTERNATE_LLVM_PATH})

if(CMAKE_SYSTEM_PROCESSOR STREQUAL aarch64 AND (NOT CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL aarch64))
    set(PREFIX qemu-aarch64 -L /usr/aarch64-linux-gnu)
else()
    set(PREFIX)
endif()

function(build_bpf file_name expected_result optimize)
    message(STATUS "Building BPF ${file_name}")

    set(optimize_flags "-O0")
    if(${optimize})
        set(optimize_flags "-O2")
    endif()

    # An optional parameter sets the name of the section containing main()
    # The test program assumes that it is in .text unless otherwise specified.
    set(main_section_name_param)
    if(${ARGC} EQUAL 4)
        list(APPEND main_section_name_param "--main-function" "${ARGV3}")
    endif()

    set(bpf_file_name ${file_name}.bpf.c)
    set(bpf_file_path ${CMAKE_CURRENT_SOURCE_DIR}/${bpf_file_name})
    set(bpf_obj_file_name ${file_name}.bpf.o)
    set(bpf_obj_file_path ${CMAKE_CURRENT_BINARY_DIR}/${bpf_obj_file_name})

    if (NOT EXISTS ${bpf_file_path})
        message(FATAL_ERROR "BPF file ${bpf_file_path} does not exist")
    endif()

    add_custom_command(
        OUTPUT ${bpf_obj_file_path}
        COMMAND ${clang_path} -g ${optimize_flags} -target bpf -c ${bpf_file_path} -o ${bpf_obj_file_path}
        DEPENDS ${bpf_file_path}
        COMMENT "Building BPF object ${bpf_obj_file_path}"
    )

    add_custom_target(${file_name}_ELF ALL DEPENDS ${bpf_obj_file_path} SOURCES ${bpf_file_path})

    add_test(NAME ${file_name}_TEST_INTERPRET COMMAND ${PREFIX} "${CMAKE_BINARY_DIR}/bin/ubpf_test" ${main_section_name_param} "${bpf_obj_file_path}")
    set_tests_properties(${file_name}_TEST_INTERPRET PROPERTIES PASS_REGULAR_EXPRESSION ${expected_result})
    add_test(NAME ${file_name}_TEST_JIT COMMAND ${PREFIX} "${CMAKE_BINARY_DIR}/bin/ubpf_test" ${main_section_name_param} "${bpf_obj_file_path}")
    set_tests_properties(${file_name}_TEST_JIT PROPERTIES PASS_REGULAR_EXPRESSION ${expected_result})
endfunction()

if (NOT ${clang_path} STREQUAL "clang_path-NOTFOUND")
    message(WARNING "Clang supports BPF target")
    # Note that the regular expressions test whether the final bit of outcome matches
    # the expected values. That is because the loader may give warnings about unhandled
    # relocation types.
    # Also note: We use this odd regex (instead of [\n\r]{1,2}) because CMake does not
    # appear to like that syntax.
    build_bpf(map "0x0[\n\r]*[\n\r]*$" true)
    build_bpf(rel_64_32 "0xe[\n\r]*[\n\r]*$" false "main")
else()
    message(WARNING "Clang does not support BPF target, skipping BPF tests")
endif()
