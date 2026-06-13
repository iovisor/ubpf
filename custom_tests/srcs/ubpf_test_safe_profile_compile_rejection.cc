// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: Apache-2.0

#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>

extern "C"
{
#include "ebpf.h"
#include "ubpf.h"
}

static bool
load_program(ubpf_vm* vm, const ebpf_inst* program, size_t program_size)
{
    char* errmsg = nullptr;
    if (ubpf_load(vm, program, static_cast<uint32_t>(program_size), &errmsg) != 0) {
        std::cerr << "load failed: " << (errmsg ? errmsg : "unknown") << std::endl;
        free(errmsg);
        return false;
    }
    free(errmsg);
    return true;
}

int
main()
{
    const ebpf_inst program[] = {
        {.opcode = EBPF_OP_MOV64_IMM, .dst = 0, .src = 0, .offset = 0, .imm = 7},
        {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0},
    };

    std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
    if (!vm) {
        std::cerr << "Failed to create VM" << std::endl;
        return 1;
    }

    if (ubpf_set_execution_profile(vm.get(), UBPF_EXECUTION_PROFILE_SAFE) != 0) {
        std::cerr << "Failed to enable safe execution profile" << std::endl;
        return 1;
    }

    if (!load_program(vm.get(), program, sizeof(program))) {
        return 1;
    }

    if (ubpf_set_execution_profile(vm.get(), UBPF_EXECUTION_PROFILE_LEGACY) == 0) {
        std::cerr << "Execution profile unexpectedly changed after load" << std::endl;
        return 1;
    }

    char* errmsg = nullptr;
    if (ubpf_compile(vm.get(), &errmsg) != nullptr) {
        std::cerr << "Safe profile unexpectedly compiled" << std::endl;
        free(errmsg);
        return 1;
    }

    if (errmsg == nullptr || std::strstr(errmsg, "interpreter-only") == nullptr) {
        std::cerr << "Missing compile rejection message" << std::endl;
        free(errmsg);
        return 1;
    }
    free(errmsg);

    uint64_t return_value = 0;
    if (ubpf_exec(vm.get(), nullptr, 0, &return_value) != 0 || return_value != 7) {
        std::cerr << "Safe profile execution failed" << std::endl;
        return 1;
    }

    return 0;
}
