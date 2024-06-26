// Copyright (c) Will Hawkins
// SPDX-License-Identifier: Apache-2.0

#include <cstdint>
#include <iostream>
#include <memory>
#include <stdint.h>
#include <vector>
#include <string>

extern "C"
{
#include "ubpf.h"
}

#include "ubpf_custom_test_support.h"

int
stack_usage_calculator(const struct ubpf_vm* vm, uint16_t pc, void* cookie)
{
    UNREFERENCED_PARAMETER(vm);
    UNREFERENCED_PARAMETER(pc);
    UNREFERENCED_PARAMETER(cookie);
    return 16;
}

int
main(int argc, char** argv)
{
    std::string program_string{};
    std::string error{};
    ubpf_jit_fn jit_fn;

    if (!get_program_string(argc, argv, program_string, error)) {
        std::cerr << error << std::endl;
        return 1;
    }

    const size_t stack_size{32};
    uint8_t expected_result[] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4,
    };

    bool success = true;

    std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
    if (!ubpf_setup_custom_test(
            vm,
            program_string,
            [](ubpf_vm_up& vm, std::string& error) {
                if (ubpf_register_stack_usage_calculator(vm.get(), stack_usage_calculator, nullptr) < 0) {
                    error = "Failed to register stack usage calculator.";
                    return false;
                }
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
    jit_ex_fn(nullptr, 0, external_stack, stack_size);

    for (size_t i = 0; i < stack_size; i++) {
        if (external_stack[i] != expected_result[i]) {
            success = false;
        }
    }
    return !success;
}
