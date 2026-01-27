// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: Apache-2.0

/*
 * Test constant blinding functionality in JIT compilation.
 * This test verifies that:
 * 1. Constant blinding can be enabled/disabled via the API
 * 2. JIT compilation succeeds with and without blinding
 * 3. Execution results are identical with and without blinding
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
    std::cout << "Test 1: API toggle functionality..." << std::endl;
    
    struct ubpf_vm* vm = ubpf_create();
    if (vm == nullptr) {
        std::cerr << "Failed to create VM" << std::endl;
        return 1;
    }
    
    // Test 1: Default state (should be disabled)
    bool was_enabled = ubpf_toggle_constant_blinding(vm, true);
    if (was_enabled) {
        std::cerr << "ERROR: Constant blinding was initially enabled (expected disabled)" << std::endl;
        ubpf_destroy(vm);
        return 1;
    }
    std::cout << "  PASS: Constant blinding was initially disabled" << std::endl;
    
    // Test 2: Check it's now enabled
    was_enabled = ubpf_toggle_constant_blinding(vm, false);
    if (!was_enabled) {
        std::cerr << "ERROR: Constant blinding was not enabled after toggle" << std::endl;
        ubpf_destroy(vm);
        return 1;
    }
    std::cout << "  PASS: Constant blinding toggle works correctly" << std::endl;
    
    ubpf_destroy(vm);
    
    // Test 2: JIT compilation with and without blinding
    std::cout << "\nTest 2: JIT compilation and execution..." << std::endl;
    
    // Simple program: MOV r0, 0x12345678; ADD r0, 0x11111111; EXIT
    // Expected result: 0x12345678 + 0x11111111 = 0x23456789
    struct ebpf_inst program[] = {
        {.opcode = 0xb7, .dst = 0, .src = 0, .offset = 0, .imm = 0x12345678}, // MOV r0, imm
        {.opcode = 0x07, .dst = 0, .src = 0, .offset = 0, .imm = 0x11111111}, // ADD r0, imm
        {.opcode = 0x95, .dst = 0, .src = 0, .offset = 0, .imm = 0}           // EXIT
    };
    
    // Test without blinding
    struct ubpf_vm* vm1 = ubpf_create();
    if (vm1 == nullptr) {
        std::cerr << "Failed to create VM1" << std::endl;
        return 1;
    }
    
    char* errmsg1 = nullptr;
    int result = ubpf_load(vm1, program, sizeof(program), &errmsg1);
    if (result != 0) {
        std::cerr << "Failed to load program without blinding: " << (errmsg1 ? errmsg1 : "unknown") << std::endl;
        free(errmsg1);
        ubpf_destroy(vm1);
        return 1;
    }
    
    ubpf_jit_fn fn1 = ubpf_compile(vm1, &errmsg1);
    if (fn1 == nullptr) {
        std::cerr << "Failed to compile without blinding: " << (errmsg1 ? errmsg1 : "unknown") << std::endl;
        free(errmsg1);
        ubpf_destroy(vm1);
        return 1;
    }
    
    uint64_t result1 = fn1(nullptr, 0);
    uint64_t expected = 0x23456789ULL;
    if (result1 != expected) {
        std::cerr << "ERROR: Wrong result without blinding. Expected 0x" << std::hex << expected 
                  << " but got 0x" << result1 << std::endl;
        ubpf_destroy(vm1);
        return 1;
    }
    std::cout << "  PASS: Compilation without blinding works (result: 0x" << std::hex << result1 << ")" << std::endl;
    
    ubpf_destroy(vm1);
    
    // Test with blinding
    struct ubpf_vm* vm2 = ubpf_create();
    if (vm2 == nullptr) {
        std::cerr << "Failed to create VM2" << std::endl;
        return 1;
    }
    
    ubpf_toggle_constant_blinding(vm2, true);
    
    char* errmsg2 = nullptr;
    result = ubpf_load(vm2, program, sizeof(program), &errmsg2);
    if (result != 0) {
        std::cerr << "Failed to load program with blinding: " << (errmsg2 ? errmsg2 : "unknown") << std::endl;
        free(errmsg2);
        ubpf_destroy(vm2);
        return 1;
    }
    
    ubpf_jit_fn fn2 = ubpf_compile(vm2, &errmsg2);
    if (fn2 == nullptr) {
        std::cerr << "Failed to compile with blinding: " << (errmsg2 ? errmsg2 : "unknown") << std::endl;
        free(errmsg2);
        ubpf_destroy(vm2);
        return 1;
    }
    
    uint64_t result2 = fn2(nullptr, 0);
    if (result2 != expected) {
        std::cerr << "ERROR: Wrong result with blinding. Expected 0x" << std::hex << expected 
                  << " but got 0x" << result2 << std::endl;
        ubpf_destroy(vm2);
        return 1;
    }
    std::cout << "  PASS: Compilation with blinding works (result: 0x" << std::hex << result2 << ")" << std::endl;
    
    ubpf_destroy(vm2);
    
    std::cout << "\nAll tests passed!" << std::endl;
    return 0;
}

