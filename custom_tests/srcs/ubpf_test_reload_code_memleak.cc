// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: Apache-2.0

#include <iostream>
#include <cstdint>

extern "C"
{
#include "ubpf.h"
}

// Simple program that just returns 0
static uint64_t program[] = {
    0x00000000000000b7,         /* r0 = 0 */
    0x0000000000000095,         /* exit */
};

int main()
{
    struct ubpf_vm *vm;
    char *errmsg = NULL;

    vm = ubpf_create();
    if (!vm) {
        std::cerr << "Failed to create VM" << std::endl;
        return 1;
    }

    // First load
    if (ubpf_load(vm, program, sizeof(program), &errmsg) != 0)
    {
        std::cerr << "Failed to load code: " << errmsg << std::endl;
        free(errmsg);
        ubpf_destroy(vm);
        return 1;
    }

    // Unload the code
    ubpf_unload_code(vm);

    // Reload the code - this should not leak memory
    errmsg = NULL;
    if (ubpf_load(vm, program, sizeof(program), &errmsg) != 0)
    {
        std::cerr << "Failed to reload code: " << errmsg << std::endl;
        free(errmsg);
        ubpf_destroy(vm);
        return 1;
    }

    ubpf_unload_code(vm);
    ubpf_destroy(vm);

    return 0;
}
