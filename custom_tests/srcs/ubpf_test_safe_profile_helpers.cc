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

static uint64_t helper_region = 0;

static uint64_t
return_helper_region(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t)
{
    return (uint64_t)(uintptr_t)&helper_region;
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
        {.opcode = EBPF_OP_CALL, .dst = 0, .src = 0, .offset = 0, .imm = 1},
        {.opcode = EBPF_OP_MOV64_IMM, .dst = 1, .src = 0, .offset = 0, .imm = 99},
        {.opcode = EBPF_OP_STXDW, .dst = 0, .src = 1, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_LDXDW, .dst = 0, .src = 0, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0},
    };
    const ebpf_inst handle_program[] = {
        {.opcode = EBPF_OP_CALL, .dst = 0, .src = 0, .offset = 0, .imm = 2},
        {.opcode = EBPF_OP_LDXDW, .dst = 0, .src = 0, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0},
    };
    const ebpf_inst pointer_handle_mismatch_program[] = {
        {.opcode = EBPF_OP_CALL, .dst = 0, .src = 0, .offset = 0, .imm = 3},
        {.opcode = EBPF_OP_LDXDW, .dst = 0, .src = 0, .offset = 0, .imm = 0},
        {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0},
    };

    helper_region = 0;

    {
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        if (!vm) {
            std::cerr << "Failed to create VM" << std::endl;
            return 1;
        }

        if (ubpf_set_execution_profile(vm.get(), UBPF_EXECUTION_PROFILE_SAFE) != 0) {
            std::cerr << "Failed to enable safe profile" << std::endl;
            return 1;
        }

        const ubpf_safe_region region = {
            .id = 1,
            .base = &helper_region,
            .size = sizeof(helper_region),
            .kind = UBPF_SAFE_REGION_POINTER,
            .permissions = UBPF_SAFE_REGION_READ | UBPF_SAFE_REGION_WRITE,
        };
        if (ubpf_register_safe_region(vm.get(), &region) != 0) {
            std::cerr << "Failed to register safe region" << std::endl;
            return 1;
        }

        const ubpf_safe_helper_descriptor helper = {
            .index = 1,
            .name = "return_helper_region",
            .fn = return_helper_region,
            .result_kind = UBPF_SAFE_HELPER_RESULT_POINTER,
            .region_id = 1,
            .region_size = sizeof(helper_region),
        };
        if (ubpf_register_safe_helper(vm.get(), &helper) != 0) {
            std::cerr << "Failed to register safe helper" << std::endl;
            return 1;
        }

        const ubpf_safe_helper_descriptor handle_helper = {
            .index = 2,
            .name = "return_helper_handle",
            .fn = return_helper_region,
            .result_kind = UBPF_SAFE_HELPER_RESULT_HANDLE,
            .region_id = 1,
            .region_size = sizeof(helper_region),
        };
        if (ubpf_register_safe_helper(vm.get(), &handle_helper) != 0) {
            std::cerr << "Failed to register safe handle helper" << std::endl;
            return 1;
        }

        const ubpf_safe_region handle_region = {
            .id = 2,
            .base = &helper_region,
            .size = sizeof(helper_region),
            .kind = UBPF_SAFE_REGION_HANDLE,
            .permissions = UBPF_SAFE_REGION_READ,
        };
        if (ubpf_register_safe_region(vm.get(), &handle_region) != 0) {
            std::cerr << "Failed to register safe handle region" << std::endl;
            return 1;
        }

        const ubpf_safe_helper_descriptor pointer_handle_mismatch_helper = {
            .index = 3,
            .name = "return_pointer_from_handle_region",
            .fn = return_helper_region,
            .result_kind = UBPF_SAFE_HELPER_RESULT_POINTER,
            .region_id = 2,
            .region_size = sizeof(helper_region),
        };
        if (ubpf_register_safe_helper(vm.get(), &pointer_handle_mismatch_helper) != 0) {
            std::cerr << "Failed to register mismatched safe helper" << std::endl;
            return 1;
        }

        if (!load_program(vm.get(), program, sizeof(program))) {
            return 1;
        }

        uint64_t return_value = 0;
        if (ubpf_exec(vm.get(), nullptr, 0, &return_value) != 0 || return_value != 99 || helper_region != 99) {
            std::cerr << "Safe helper execution failed" << std::endl;
            return 1;
        }

        ubpf_unload_code(vm.get());
        if (!load_program(vm.get(), handle_program, sizeof(handle_program))) {
            return 1;
        }

        if (ubpf_exec(vm.get(), nullptr, 0, &return_value) == 0) {
            std::cerr << "Handle dereference unexpectedly succeeded" << std::endl;
            return 1;
        }

        ubpf_unload_code(vm.get());
        if (!load_program(vm.get(), pointer_handle_mismatch_program, sizeof(pointer_handle_mismatch_program))) {
            return 1;
        }

        if (ubpf_exec(vm.get(), nullptr, 0, &return_value) == 0) {
            std::cerr << "Pointer/helper region kind mismatch unexpectedly succeeded" << std::endl;
            return 1;
        }
    }

    {
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        if (!vm) {
            std::cerr << "Failed to create VM" << std::endl;
            return 1;
        }

        if (ubpf_set_execution_profile(vm.get(), UBPF_EXECUTION_PROFILE_SAFE) != 0) {
            std::cerr << "Failed to enable safe profile for negative test" << std::endl;
            return 1;
        }

        if (ubpf_register(vm.get(), 1, "return_helper_region", return_helper_region) != 0) {
            std::cerr << "Failed to register legacy helper" << std::endl;
            return 1;
        }

        if (!load_program(vm.get(), program, sizeof(program))) {
            return 1;
        }

        uint64_t return_value = 0;
        if (ubpf_exec(vm.get(), nullptr, 0, &return_value) == 0) {
            std::cerr << "Safe execution unexpectedly allowed helper without metadata" << std::endl;
            return 1;
        }
    }

    {
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        if (!vm) {
            std::cerr << "Failed to create VM" << std::endl;
            return 1;
        }

        if (ubpf_set_execution_profile(vm.get(), UBPF_EXECUTION_PROFILE_SAFE) != 0) {
            std::cerr << "Failed to enable safe profile for registration checks" << std::endl;
            return 1;
        }

        const ubpf_safe_region reserved_region = {
            .id = 0xffffffffu,
            .base = &helper_region,
            .size = sizeof(helper_region),
            .kind = UBPF_SAFE_REGION_POINTER,
            .permissions = UBPF_SAFE_REGION_READ,
        };
        if (ubpf_register_safe_region(vm.get(), &reserved_region) == 0) {
            std::cerr << "Reserved safe region ID unexpectedly succeeded" << std::endl;
            return 1;
        }

        const ubpf_safe_region invalid_permissions_region = {
            .id = 3,
            .base = &helper_region,
            .size = sizeof(helper_region),
            .kind = UBPF_SAFE_REGION_POINTER,
            .permissions = 8,
        };
        if (ubpf_register_safe_region(vm.get(), &invalid_permissions_region) == 0) {
            std::cerr << "Invalid safe region permissions unexpectedly succeeded" << std::endl;
            return 1;
        }

        const ubpf_safe_helper_descriptor reserved_helper = {
            .index = 7,
            .name = "reserved_helper_region",
            .fn = return_helper_region,
            .result_kind = UBPF_SAFE_HELPER_RESULT_POINTER,
            .region_id = 0xfffffffeu,
            .region_size = sizeof(helper_region),
        };
        if (ubpf_register_safe_helper(vm.get(), &reserved_helper) == 0) {
            std::cerr << "Reserved safe helper region ID unexpectedly succeeded" << std::endl;
            return 1;
        }
    }

    return 0;
}
