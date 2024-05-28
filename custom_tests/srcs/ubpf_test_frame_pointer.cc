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
overwrite_stack_usage_calculator(const struct ubpf_vm* vm, uint16_t pc, void* cookie)
{
    UNREFERENCED_PARAMETER(vm);
    UNREFERENCED_PARAMETER(pc);
    UNREFERENCED_PARAMETER(cookie);
    return 0;
}

int
main(int argc, char** argv)
{
    std::vector<std::string> args(argv, argv + argc);
    std::string program_string{};
    ubpf_jit_fn jit_fn;

    std::getline(std::cin, program_string);

    uint64_t no_overwrite_interp_result = 0;
    uint64_t no_overwrite_jit_result = 0;
    uint64_t overwrite_interp_result = 0;
    uint64_t overwrite_jit_result = 0;

    {

        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        std::string error{};
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

        no_overwrite_jit_result = jit_fn(nullptr, 0);
        [[maybe_unused]] auto exec_result = ubpf_exec(vm.get(), NULL, 0, &no_overwrite_interp_result);
    }

    {

        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        std::string error{};
        if (!ubpf_setup_custom_test(
                vm,
                program_string,
                [](ubpf_vm_up& vm, std::string& error) {
                    if (ubpf_register_stack_usage_calculator(vm.get(), overwrite_stack_usage_calculator, nullptr) < 0) {
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

        overwrite_jit_result = jit_fn(nullptr, 0);

        [[maybe_unused]] auto exec_result = ubpf_exec(vm.get(), NULL, 0, &overwrite_interp_result);
    }
    // ... because of the semantics of external_dispatcher, the result of the eBPF
    // program execution should point to the same place to which &memory points.
    return !(
        no_overwrite_interp_result == no_overwrite_jit_result && no_overwrite_interp_result == 0x5 &&
        overwrite_interp_result == overwrite_jit_result && overwrite_interp_result == 0x37);
}
