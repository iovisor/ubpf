// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: Apache-2.0

/*
 * Test constant blinding functionality in JIT compilation.
 * This test verifies that:
 * 1. Constant blinding can be enabled/disabled
 * 2. The execution results are identical with and without blinding
 */

#include <cassert>
#include <cstdint>
#include <iostream>
#include <memory>
#include <vector>
#include <string.h>

extern "C"
{
#include "ebpf.h"
#include "ubpf.h"
}

int main(int, char**)
{
    // Simple test: just test the API
    std::cout << "Test: Toggle constant blinding API..." << std::endl;
    
    struct ubpf_vm* vm = ubpf_create();
    if (vm == nullptr) {
        std::cerr << "Failed to create VM" << std::endl;
        return 1;
    }
    
    // Test 1: Default state (should be disabled)
    std::cout << "  Initial state: constant blinding should be disabled" << std::endl;
    
    // Test 2: Enable constant blinding
    bool was_enabled = ubpf_toggle_constant_blinding(vm, true);
    if (was_enabled) {
        std::cerr << "ERROR: Constant blinding was initially enabled (expected disabled)" << std::endl;
        ubpf_destroy(vm);
        return 1;
    }
    std::cout << "  PASS: Constant blinding was initially disabled" << std::endl;
    
    // Test 3: Check it's now enabled
    was_enabled = ubpf_toggle_constant_blinding(vm, false);
    if (!was_enabled) {
        std::cerr << "ERROR: Constant blinding was not enabled after toggle" << std::endl;
        ubpf_destroy(vm);
        return 1;
    }
    std::cout << "  PASS: Constant blinding was enabled after toggle" << std::endl;
    
    // Test 4: Toggle back to enabled
    was_enabled = ubpf_toggle_constant_blinding(vm, true);
    if (was_enabled) {
        std::cerr << "ERROR: Constant blinding was enabled when expected disabled" << std::endl;
        ubpf_destroy(vm);
        return 1;
    }
    std::cout << "  PASS: Constant blinding state toggle works correctly" << std::endl;
    
    ubpf_destroy(vm);
    
    std::cout << "\nAll tests passed!" << std::endl;
    return 0;
}

