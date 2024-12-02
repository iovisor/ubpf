// Copyright (c) Will Hawkins
// SPDX-License-Identifier: Apache-2.0

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
main(int argc, char** argv)
{
    std::string program_string{};
    std::string error{};
    ubpf_jit_fn jit_fn;

    if (!get_program_string(argc, argv, program_string, error)) {
        std::cerr << error << std::endl;
        return 1;
    }

    uint64_t memory_expected{0x123456789};
    uint64_t memory{0x123456789};

    std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
    if (!ubpf_setup_custom_test(
            vm, program_string, [](ubpf_vm_up&, std::string&) { return true; }, jit_fn, error)) {
        if (error == "Failed to load program: Invalid immediate value 66 for opcode DB.") {
            return 0;
        }

        return 1;
    }

    return 1;

    uint64_t bpf_return_value;
    if (ubpf_exec(vm.get(), &memory, sizeof(memory), &bpf_return_value)) {
        std::cerr << "Problem executing program" << std::endl;
        return 1;
    }

    return !(memory == memory_expected);
}
