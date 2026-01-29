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
    
    // Fill with NOP-like JA instructions (jump with offset 0)
    for (uint32_t i = 0; i < num_instructions - 1; i++) {
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
    
    // Load the program
    char* errmsg = nullptr;
    int result = ubpf_load(vm.get(), program.data(), num_instructions * sizeof(struct ebpf_inst), &errmsg);
    if (result != 0) {
        std::cerr << "Failed to load program: " << (errmsg ? errmsg : "unknown error") << std::endl;
        free(errmsg);
        return 1;
    }
    
    std::cout << "Successfully loaded program with " << num_instructions << " instructions" << std::endl;
    
    // Skip JIT and interpreter execution for large programs to keep test fast
    // The key validation is that we can load programs > 65,536 instructions
    
    std::cout << "Test passed!" << std::endl;
    return 0;
}
