// Copyright (c) Will Hawkins
// SPDX-License-Identifier: Apache-2.0

#include "ubpf_int.h"
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdint.h>
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
    return 17;
}

int
main(int argc, char** argv)
{
    UNUSED_PARAMETER(argc);
    UNUSED_PARAMETER(argv);

    std::string error{};
    ubpf_jit_fn jit_fn;

    std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
    if (!ubpf_setup_custom_test(
            vm,
            "",
            [](ubpf_vm_up& vm, std::string& error) {
                if (ubpf_register_stack_usage_calculator(vm.get(), stack_usage_calculator, nullptr) < 0) {
                    error = "Failed to register stack usage calculator.";
                    return false;
                }
                return true;
            },
            jit_fn,
            error)) {
        if (error != "Failed to load program: local function "
                     "(at PC 0) has improperly sized stack use (17)") {
            std::cerr << "Did not get the expected error regarding unaligned stack size for local function: " << error
                      << "\n";
            return 1;
        }
    }

    return 0;
}
