// Copyright (c) Will Hawkins
// SPDX-License-Identifier: Apache-2.0

#include "ubpf_int.h"
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdint.h>
#include <string>

extern "C"
{
#include "ubpf.h"
}

#include "ubpf_custom_test_support.h"

int
main(int argc, char** argv)
{
    std::string program_string{};
    std::string error{};
    ubpf_jit_fn jit_fn;
    uint64_t jit_result{};
    uint64_t interp_result{};

    if (!get_program_string(argc, argv, program_string, error)) {
        std::cerr << error << std::endl;
        return 1;
    }

    const size_t stack_size{8192};

    uint8_t expected_result[8192] = {
        0,
    };

    expected_result[stack_size - 1 - 0] = 0x1;
    expected_result[stack_size - 1 - 1] = 0x2;
    expected_result[stack_size - 1 - 2] = 0x3;
    expected_result[stack_size - 1 - 3] = 0x4;


    expected_result[stack_size - UBPF_EBPF_LOCAL_FUNCTION_STACK_SIZE - 1 - 0] = 0x11;
    expected_result[stack_size - UBPF_EBPF_LOCAL_FUNCTION_STACK_SIZE - 1 - 1] = 0x12;
    expected_result[stack_size - UBPF_EBPF_LOCAL_FUNCTION_STACK_SIZE - 1 - 2] = 0x13;
    expected_result[stack_size - UBPF_EBPF_LOCAL_FUNCTION_STACK_SIZE - 1 - 3] = 0x14;

    bool success = true;

    std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
    if (!ubpf_setup_custom_test(
            vm,
            program_string,
            [](ubpf_vm_up& vm, std::string& error) {
                UNUSED_PARAMETER(vm);
                UNUSED_PARAMETER(error);
                return true;
            },
            jit_fn,
            error)) {
        std::cerr << "Problem setting up custom test: " << error << std::endl;
        return 1;
    }

    char* ex_jit_compile_error = nullptr;
    auto jit_ex_fn = ubpf_compile_ex(vm.get(), &ex_jit_compile_error, ExtendedJitMode);
    uint8_t external_stack[stack_size] = {
        0,
    };
    jit_result = jit_ex_fn(nullptr, 0, external_stack, stack_size);

    if (jit_result) {
        std::cerr << "Execution of the JIT'd program gave a non-0 result.\n";
        return 1;
    }

    for (size_t i = 0; i < stack_size; i++) {
        if (external_stack[i] != expected_result[i]) {
            std::cerr << "Byte 0x" << std::hex << i << " different between expected (0x" << (uint32_t)expected_result[i]
                      << ") and actual (0x" << (uint32_t)external_stack[i] << ")\n";
            success = false;
        }
    }

    if (!success) {
        return !success;
    }

    std::memset(external_stack, 0x0, sizeof(external_stack));
    int interp_success{ubpf_exec_ex(vm.get(), nullptr, 0, &interp_result, external_stack, stack_size)};

    if (interp_success < 0) {
        std::cerr << "There was an error interpreting the program: " << success << "\n";
        return 1;
    }

    if (interp_result) {
        std::cerr << "Execution of the interpreted program gave a non-0 result.\n";
        return 1;
    }

    for (size_t i = 0; i < stack_size; i++) {
        if (external_stack[i] != expected_result[i]) {
            std::cerr << "Byte 0x" << std::hex << i << " different between expected (0x" << (uint32_t)expected_result[i]
                      << ") and actual (0x" << (uint32_t)external_stack[i] << ")\n";
            success = false;
        }
    }

    if (!success) {
        return !success;
    }

    return 0;
}
