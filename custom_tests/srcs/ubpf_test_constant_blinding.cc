// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: Apache-2.0

/*
 * Test constant blinding functionality in JIT compilation.
 * This test verifies that:
 * 1. Constant blinding can be enabled/disabled via the API
 * 2. JIT compilation succeeds with and without blinding
 * 3. Execution results are identical with and without blinding
 * 4. Blinding produces different code each time (randomness verification)
 * 5. All immediate ALU operations work correctly with blinding
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

// Helper function to test an immediate operation
static bool test_imm_operation(const char* name, uint8_t opcode, int32_t imm, uint64_t initial, uint64_t expected)
{
    struct ebpf_inst program[] = {
        {.opcode = EBPF_OP_MOV64_IMM, .dst = 0, .src = 0, .offset = 0, .imm = (int32_t)initial}, // MOV r0, initial
        {.opcode = opcode, .dst = 0, .src = 0, .offset = 0, .imm = imm},                          // OP r0, imm
        {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0}                       // EXIT
    };
    
    // Test without blinding
    struct ubpf_vm* vm1 = ubpf_create();
    char* errmsg1 = nullptr;
    if (ubpf_load(vm1, program, sizeof(program), &errmsg1) != 0) {
        std::cerr << "  " << name << ": Failed to load without blinding" << std::endl;
        free(errmsg1);
        ubpf_destroy(vm1);
        return false;
    }
    
    ubpf_jit_fn fn1 = ubpf_compile(vm1, &errmsg1);
    if (fn1 == nullptr) {
        std::cerr << "  " << name << ": Failed to compile without blinding" << std::endl;
        free(errmsg1);
        ubpf_destroy(vm1);
        return false;
    }
    
    uint64_t result1 = fn1(nullptr, 0);
    ubpf_destroy(vm1);
    
    // Test with blinding
    struct ubpf_vm* vm2 = ubpf_create();
    ubpf_toggle_constant_blinding(vm2, true);
    
    char* errmsg2 = nullptr;
    if (ubpf_load(vm2, program, sizeof(program), &errmsg2) != 0) {
        std::cerr << "  " << name << ": Failed to load with blinding" << std::endl;
        free(errmsg2);
        ubpf_destroy(vm2);
        return false;
    }
    
    ubpf_jit_fn fn2 = ubpf_compile(vm2, &errmsg2);
    if (fn2 == nullptr) {
        std::cerr << "  " << name << ": Failed to compile with blinding" << std::endl;
        free(errmsg2);
        ubpf_destroy(vm2);
        return false;
    }
    
    uint64_t result2 = fn2(nullptr, 0);
    ubpf_destroy(vm2);
    
    // Verify both produce expected result
    if (result1 != expected || result2 != expected) {
        std::cerr << "  " << name << ": FAIL - Expected 0x" << std::hex << expected 
                  << ", got without=0x" << result1 << ", with=0x" << result2 << std::endl;
        return false;
    }
    
    std::cout << "  " << name << ": PASS (0x" << std::hex << result1 << ")" << std::endl;
    return true;
}

int main(int, char**)
{
    bool all_passed = true;
    
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
    
    // Test 2: Randomness verification - same program compiled twice with blinding
    std::cout << "\nTest 2: Randomness verification..." << std::endl;
    
    struct ebpf_inst test_program[] = {
        {.opcode = EBPF_OP_MOV64_IMM, .dst = 0, .src = 0, .offset = 0, .imm = 0x12345678},
        {.opcode = EBPF_OP_ADD64_IMM, .dst = 0, .src = 0, .offset = 0, .imm = 0x11111111},
        {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0}
    };
    
    // Compile twice with blinding and get raw JIT code
    uint8_t buffer1[65536];
    uint8_t buffer2[65536];
    size_t size1 = sizeof(buffer1);
    size_t size2 = sizeof(buffer2);
    
    struct ubpf_vm* vm_rand1 = ubpf_create();
    ubpf_toggle_constant_blinding(vm_rand1, true);
    char* err_rand1 = nullptr;
    ubpf_load(vm_rand1, test_program, sizeof(test_program), &err_rand1);
    int translate_result1 = ubpf_translate(vm_rand1, buffer1, &size1, &err_rand1);
    
    struct ubpf_vm* vm_rand2 = ubpf_create();
    ubpf_toggle_constant_blinding(vm_rand2, true);
    char* err_rand2 = nullptr;
    ubpf_load(vm_rand2, test_program, sizeof(test_program), &err_rand2);
    int translate_result2 = ubpf_translate(vm_rand2, buffer2, &size2, &err_rand2);
    
    if (translate_result1 != 0 || translate_result2 != 0) {
        std::cerr << "  FAIL: Failed to translate programs" << std::endl;
        all_passed = false;
    } else {
        // Compare the code - should be different due to random blinding values
        bool code_different = (memcmp(buffer1, buffer2, std::min(size1, size2)) != 0);
        
        if (code_different) {
            std::cout << "  PASS: JIT code differs between compilations (random blinding working)" << std::endl;
        } else {
            std::cerr << "  FAIL: JIT code is identical - randomness not working" << std::endl;
            all_passed = false;
        }
    }
    
    ubpf_destroy(vm_rand1);
    ubpf_destroy(vm_rand2);
    free(err_rand1);
    free(err_rand2);
    
    // Test 3: 32-bit ALU immediate operations
    std::cout << "\nTest 3: 32-bit ALU immediate operations..." << std::endl;
    
    all_passed &= test_imm_operation("ADD_IMM", EBPF_OP_ADD_IMM, 0x11111111, 0x12345678, 0x23456789ULL);
    all_passed &= test_imm_operation("SUB_IMM", EBPF_OP_SUB_IMM, 0x11111111, 0x23456789, 0x12345678ULL);
    all_passed &= test_imm_operation("OR_IMM", EBPF_OP_OR_IMM, 0x0F0F0F0F, 0xF0F0F0F0, 0xFFFFFFFFULL);
    all_passed &= test_imm_operation("AND_IMM", EBPF_OP_AND_IMM, 0x0F0F0F0F, 0xFFFFFFFF, 0x0F0F0F0FULL);
    all_passed &= test_imm_operation("XOR_IMM", EBPF_OP_XOR_IMM, 0xFFFFFFFF, 0x12345678, 0xEDCBA987ULL);
    all_passed &= test_imm_operation("MOV_IMM", EBPF_OP_MOV_IMM, 0xDEADBEEF, 0x00000000, 0xDEADBEEFULL);
    
    // Test 4: 64-bit ALU immediate operations
    std::cout << "\nTest 4: 64-bit ALU immediate operations..." << std::endl;
    
    all_passed &= test_imm_operation("ADD64_IMM", EBPF_OP_ADD64_IMM, 0x11111111, 0x12345678, 0x23456789ULL);
    all_passed &= test_imm_operation("SUB64_IMM", EBPF_OP_SUB64_IMM, 0x11111111, 0x23456789, 0x12345678ULL);
    all_passed &= test_imm_operation("OR64_IMM", EBPF_OP_OR64_IMM, 0x0F0F0F0F, 0x70707070, 0x7F7F7F7FULL);
    all_passed &= test_imm_operation("AND64_IMM", EBPF_OP_AND64_IMM, 0x0F0F0F0F, 0x7FFFFFFF, 0x0F0F0F0FULL);
    all_passed &= test_imm_operation("XOR64_IMM", EBPF_OP_XOR64_IMM, 0xFFFFFFFF, 0x12345678, 0xFFFFFFFFEDCBA987ULL);
    all_passed &= test_imm_operation("MOV64_IMM", EBPF_OP_MOV64_IMM, 0x7EADBEEF, 0x00000000, 0x7EADBEEFULL);
    
    // Test 5: Edge case - large immediates
    std::cout << "\nTest 5: Edge case - large immediates..." << std::endl;
    
    struct ebpf_inst large_imm_program[] = {
        {.opcode = EBPF_OP_MOV64_IMM, .dst = 0, .src = 0, .offset = 0, .imm = 0x7FFFFFFF}, // Max positive int32
        {.opcode = EBPF_OP_ADD64_IMM, .dst = 0, .src = 0, .offset = 0, .imm = 0x7FFFFFFF}, // Add max int32
        {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0}
    };
    
    struct ubpf_vm* vm_large1 = ubpf_create();
    char* err_large1 = nullptr;
    ubpf_load(vm_large1, large_imm_program, sizeof(large_imm_program), &err_large1);
    ubpf_jit_fn fn_large1 = ubpf_compile(vm_large1, &err_large1);
    uint64_t result_large1 = fn_large1(nullptr, 0);
    
    struct ubpf_vm* vm_large2 = ubpf_create();
    ubpf_toggle_constant_blinding(vm_large2, true);
    char* err_large2 = nullptr;
    ubpf_load(vm_large2, large_imm_program, sizeof(large_imm_program), &err_large2);
    ubpf_jit_fn fn_large2 = ubpf_compile(vm_large2, &err_large2);
    uint64_t result_large2 = fn_large2(nullptr, 0);
    
    uint64_t expected_large = 0xFFFFFFFEULL;
    if (result_large1 == expected_large && result_large2 == expected_large) {
        std::cout << "  PASS: Large immediates (0x" << std::hex << result_large1 << ")" << std::endl;
    } else {
        std::cerr << "  FAIL: Large immediates - Expected 0x" << std::hex << expected_large 
                  << ", got without=0x" << result_large1 << ", with=0x" << result_large2 << std::endl;
        all_passed = false;
    }
    
    ubpf_destroy(vm_large1);
    ubpf_destroy(vm_large2);
    free(err_large1);
    free(err_large2);
    
    if (all_passed) {
        std::cout << "\nAll tests passed!" << std::endl;
        return 0;
    } else {
        std::cerr << "\nSome tests failed!" << std::endl;
        return 1;
    }
}

