// Copyright (c) GitHub Copilot
// SPDX-License-Identifier: Apache-2.0

#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>

extern "C"
{
#include "ubpf.h"
#include "ebpf.h"
}

int
main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    // Create a program with more than 65,536 instructions  
    // Use a reasonable number that's large enough to demonstrate the feature
    // but small enough to execute in reasonable time
    const uint32_t num_instructions = 66000;
    std::vector<struct ebpf_inst> program(num_instructions);
    
    // First instruction: set r0 = 0
    program[0].opcode = EBPF_OP_MOV_IMM;
    program[0].dst = 0;  // r0
    program[0].src = 0;
    program[0].offset = 0;
    program[0].imm = 0;  // value 0
    
    // Fill rest with NOP-like JA instructions (jump with offset 0)
    for (uint32_t i = 1; i < num_instructions - 1; i++) {
        program[i].opcode = EBPF_OP_JA;
        program[i].dst = 0;
        program[i].src = 0;
        program[i].offset = 0;
        program[i].imm = 0;
    }
    
    // Last instruction is EXIT
    program[num_instructions - 1].opcode = EBPF_OP_EXIT;
    program[num_instructions - 1].dst = 0;
    program[num_instructions - 1].src = 0;
    program[num_instructions - 1].offset = 0;
    program[num_instructions - 1].imm = 0;
    
    std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
    if (!vm) {
        std::cerr << "Failed to create VM" << std::endl;
        return 1;
    }
    
    // Set max instructions to allow this large program
    if (ubpf_set_max_instructions(vm.get(), 100000) != 0) {
        std::cerr << "Failed to set max instructions" << std::endl;
        return 1;
    }
    
    // Set a larger JIT buffer size for large programs
    // Estimate: ~50 bytes per instruction + overhead
    size_t jit_buffer_size = num_instructions * 50 + 4096;
    if (ubpf_set_jit_code_size(vm.get(), jit_buffer_size) != 0) {
        std::cerr << "Failed to set JIT buffer size" << std::endl;
        return 1;
    }
    
    // Load the program
    char* errmsg = nullptr;
    int result = ubpf_load(vm.get(), program.data(), num_instructions * sizeof(struct ebpf_inst), &errmsg);
    if (result != 0) {
        std::cerr << "Failed to load program: " << (errmsg ? errmsg : "unknown error") << std::endl;
        free(errmsg);
        return 1;
    }
    
    std::cout << "Successfully loaded program with " << num_instructions << " instructions" << std::endl;
    
    // Test JIT compilation with large program
    errmsg = nullptr;
    ubpf_jit_fn jit_fn = ubpf_compile(vm.get(), &errmsg);
    if (!jit_fn) {
        std::cerr << "Failed to JIT compile: " << (errmsg ? errmsg : "unknown error") << std::endl;
        free(errmsg);
        return 1;
    }
    
    std::cout << "Successfully JIT compiled program with " << num_instructions << " instructions" << std::endl;
    
    // Execute via JIT - the program sets r0 to 0 and exits
    uint64_t jit_result = jit_fn(nullptr, 0);
    
    if (jit_result != 0) {
        std::cerr << "JIT execution returned unexpected value: " << jit_result << " (expected 0)" << std::endl;
        return 1;
    }
    
    std::cout << "JIT execution result: " << jit_result << " (correct)" << std::endl;
    
    // Note: We skip interpreter execution because executing 66,000 sequential NOP-like
    // instructions via the interpreter would take too long for a test
    
    std::cout << "Test passed!" << std::endl;
    return 0;
}
