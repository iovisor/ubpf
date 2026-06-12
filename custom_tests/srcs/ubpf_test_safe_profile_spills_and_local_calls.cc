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
load_program(ubpf_vm* vm, const ebpf_inst* program, size_t program_size)
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
    const ebpf_inst spill_restore_program[] = {
        {.opcode = EBPF_OP_MOV64_REG, .dst = 1, .src = 10, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_ADD64_IMM, .dst = 1, .src = 0, .offset = 0, .imm = -16},
        {.opcode = EBPF_OP_STXDW, .dst = 10, .src = 1, .offset = -8, .imm = 0},
        {.opcode = EBPF_OP_LDXDW, .dst = 2, .src = 10, .offset = -8, .imm = 0},
        {.opcode = EBPF_OP_MOV64_IMM, .dst = 3, .src = 0, .offset = 0, .imm = 42},
        {.opcode = EBPF_OP_STXDW, .dst = 2, .src = 3, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_LDXDW, .dst = 0, .src = 10, .offset = -16, .imm = 0},
        {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0},
    };

    const ebpf_inst spill_invalidation_program[] = {
        {.opcode = EBPF_OP_MOV64_REG, .dst = 1, .src = 10, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_ADD64_IMM, .dst = 1, .src = 0, .offset = 0, .imm = -16},
        {.opcode = EBPF_OP_STXDW, .dst = 10, .src = 1, .offset = -8, .imm = 0},
        {.opcode = EBPF_OP_STW, .dst = 10, .src = 0, .offset = -8, .imm = 0},
        {.opcode = EBPF_OP_LDXDW, .dst = 2, .src = 10, .offset = -8, .imm = 0},
        {.opcode = EBPF_OP_MOV64_IMM, .dst = 3, .src = 0, .offset = 0, .imm = 42},
        {.opcode = EBPF_OP_STXDW, .dst = 2, .src = 3, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_MOV64_IMM, .dst = 0, .src = 0, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0},
    };

    const ebpf_inst local_call_program[] = {
        {.opcode = EBPF_OP_MOV64_REG, .dst = 1, .src = 10, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_ADD64_IMM, .dst = 1, .src = 0, .offset = 0, .imm = -8},
        {.opcode = EBPF_OP_CALL, .dst = 0, .src = 1, .offset = 0, .imm = 2},
        {.opcode = EBPF_OP_LDXDW, .dst = 0, .src = 1, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_MOV64_IMM, .dst = 2, .src = 0, .offset = 0, .imm = 7},
        {.opcode = EBPF_OP_STXDW, .dst = 1, .src = 2, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_MOV64_IMM, .dst = 0, .src = 0, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0},
    };

    {
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        if (!vm || !load_program(vm.get(), spill_restore_program, sizeof(spill_restore_program))) {
            return 1;
        }

        uint64_t return_value = 0;
        if (ubpf_exec(vm.get(), nullptr, 0, &return_value) != 0 || return_value != 42) {
            std::cerr << "Spill restore test failed" << std::endl;
            return 1;
        }
    }

    {
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        if (!vm || !load_program(vm.get(), spill_invalidation_program, sizeof(spill_invalidation_program))) {
            return 1;
        }

        uint64_t return_value = 0;
        if (ubpf_exec(vm.get(), nullptr, 0, &return_value) == 0) {
            std::cerr << "Spill invalidation test unexpectedly succeeded" << std::endl;
            return 1;
        }
    }

    {
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        if (!vm || !load_program(vm.get(), local_call_program, sizeof(local_call_program))) {
            return 1;
        }

        uint64_t return_value = 0;
        if (ubpf_exec(vm.get(), nullptr, 0, &return_value) == 0) {
            std::cerr << "Caller-saved provenance test unexpectedly succeeded" << std::endl;
            return 1;
        }
    }

    return 0;
}
