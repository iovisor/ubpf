// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: Apache-2.0

#include <cstdint>
#include <iostream>
#include <memory>

extern "C"
{
#include "ebpf.h"
#include "ubpf.h"
}

static bool
load_safe_program(ubpf_vm* vm, const ebpf_inst* program, size_t program_size)
{
    char* errmsg = nullptr;
    if (ubpf_set_execution_profile(vm, UBPF_EXECUTION_PROFILE_SAFE) != 0) {
        std::cerr << "Failed to enable safe profile" << std::endl;
        return false;
    }
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
    uint64_t memory = 0;

    const ebpf_inst pointer_plus_pointer_program[] = {
        {.opcode = EBPF_OP_MOV64_REG, .dst = 2, .src = 10, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_ADD64_IMM, .dst = 2, .src = 0, .offset = 0, .imm = -8},
        {.opcode = EBPF_OP_ADD64_REG, .dst = 1, .src = 2, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0},
    };

    const ebpf_inst scalar_minus_pointer_program[] = {
        {.opcode = EBPF_OP_MOV64_IMM, .dst = 1, .src = 0, .offset = 0, .imm = 8},
        {.opcode = EBPF_OP_MOV64_REG, .dst = 2, .src = 10, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_ADD64_IMM, .dst = 2, .src = 0, .offset = 0, .imm = -8},
        {.opcode = EBPF_OP_SUB64_REG, .dst = 1, .src = 2, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0},
    };

    const ebpf_inst pointer_minus_pointer_same_region_program[] = {
        {.opcode = EBPF_OP_MOV64_REG, .dst = 1, .src = 10, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_ADD64_IMM, .dst = 1, .src = 0, .offset = 0, .imm = -8},
        {.opcode = EBPF_OP_MOV64_REG, .dst = 2, .src = 10, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_ADD64_IMM, .dst = 2, .src = 0, .offset = 0, .imm = -16},
        {.opcode = EBPF_OP_SUB64_REG, .dst = 1, .src = 2, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_MOV64_REG, .dst = 0, .src = 1, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0},
    };

    const ebpf_inst pointer_minus_pointer_different_region_program[] = {
        {.opcode = EBPF_OP_MOV64_REG, .dst = 2, .src = 10, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_ADD64_IMM, .dst = 2, .src = 0, .offset = 0, .imm = -8},
        {.opcode = EBPF_OP_SUB64_REG, .dst = 1, .src = 2, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0},
    };

    const ebpf_inst alu32_clears_pointer_program[] = {
        {.opcode = EBPF_OP_MOV64_REG, .dst = 1, .src = 10, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_ADD_IMM, .dst = 1, .src = 0, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_LDXDW, .dst = 0, .src = 1, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0},
    };

    {
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        if (!vm || !load_safe_program(vm.get(), pointer_plus_pointer_program, sizeof(pointer_plus_pointer_program))) {
            return 1;
        }
        uint64_t return_value = 0;
        if (ubpf_exec(vm.get(), &memory, sizeof(memory), &return_value) == 0) {
            std::cerr << "pointer + pointer unexpectedly succeeded" << std::endl;
            return 1;
        }
    }

    {
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        if (!vm || !load_safe_program(vm.get(), scalar_minus_pointer_program, sizeof(scalar_minus_pointer_program))) {
            return 1;
        }
        uint64_t return_value = 0;
        if (ubpf_exec(vm.get(), &memory, sizeof(memory), &return_value) == 0) {
            std::cerr << "scalar - pointer unexpectedly succeeded" << std::endl;
            return 1;
        }
    }

    {
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        if (!vm || !load_safe_program(
                       vm.get(), pointer_minus_pointer_same_region_program, sizeof(pointer_minus_pointer_same_region_program))) {
            return 1;
        }
        uint64_t return_value = 0;
        if (ubpf_exec(vm.get(), nullptr, 0, &return_value) != 0 || return_value != 8) {
            std::cerr << "same-region pointer subtraction failed" << std::endl;
            return 1;
        }
    }

    {
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        if (!vm || !load_safe_program(
                       vm.get(),
                       pointer_minus_pointer_different_region_program,
                       sizeof(pointer_minus_pointer_different_region_program))) {
            return 1;
        }
        uint64_t return_value = 0;
        if (ubpf_exec(vm.get(), &memory, sizeof(memory), &return_value) == 0) {
            std::cerr << "different-region pointer subtraction unexpectedly succeeded" << std::endl;
            return 1;
        }
    }

    {
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        if (!vm || !load_safe_program(vm.get(), alu32_clears_pointer_program, sizeof(alu32_clears_pointer_program))) {
            return 1;
        }
        uint64_t return_value = 0;
        if (ubpf_exec(vm.get(), nullptr, 0, &return_value) == 0) {
            std::cerr << "ALU32 tag clearing test unexpectedly succeeded" << std::endl;
            return 1;
        }
    }

    return 0;
}
