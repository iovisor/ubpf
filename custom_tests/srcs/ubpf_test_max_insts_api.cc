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

static std::vector<struct ebpf_inst>
generate_program(uint32_t num_instructions)
{
    std::vector<struct ebpf_inst> program(num_instructions);
    
    // Fill with NOP-like JA instructions
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
    
    return program;
}

int
main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    // Test 1: 65,535 instructions (just under default limit) should work
    {
        std::cout << "Test 1: Loading 65,535 instructions (just under default limit)..." << std::endl;
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        auto program = generate_program(65535);
        
        char* errmsg = nullptr;
        int result = ubpf_load(vm.get(), program.data(), program.size() * sizeof(struct ebpf_inst), &errmsg);
        if (result != 0) {
            std::cerr << "Test 1 FAILED: Could not load 65,535 instructions: " 
                      << (errmsg ? errmsg : "unknown error") << std::endl;
            free(errmsg);
            return 1;
        }
        std::cout << "Test 1 PASSED" << std::endl;
    }

    // Test 2: 65,536 instructions (at default limit) should fail
    {
        std::cout << "Test 2: Loading 65,536 instructions (at default limit - should fail)..." << std::endl;
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        auto program = generate_program(65536);
        
        char* errmsg = nullptr;
        int result = ubpf_load(vm.get(), program.data(), program.size() * sizeof(struct ebpf_inst), &errmsg);
        if (result == 0) {
            std::cerr << "Test 2 FAILED: Should not be able to load 65,536 instructions with default limit" << std::endl;
            return 1;
        }
        
        // Check that error message mentions instruction limit
        if (errmsg == nullptr || strstr(errmsg, "too many instructions") == nullptr) {
            std::cerr << "Test 2 FAILED: Expected 'too many instructions' error, got: " 
                      << (errmsg ? errmsg : "null") << std::endl;
            free(errmsg);
            return 1;
        }
        free(errmsg);
        std::cout << "Test 2 PASSED" << std::endl;
    }

    // Test 3: ubpf_set_max_instructions() allows loading larger programs
    {
        std::cout << "Test 3: Loading 70,000 instructions after setting max to 100,000..." << std::endl;
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        
        if (ubpf_set_max_instructions(vm.get(), 100000) != 0) {
            std::cerr << "Test 3 FAILED: Could not set max instructions" << std::endl;
            return 1;
        }
        
        auto program = generate_program(70000);
        char* errmsg = nullptr;
        int result = ubpf_load(vm.get(), program.data(), program.size() * sizeof(struct ebpf_inst), &errmsg);
        if (result != 0) {
            std::cerr << "Test 3 FAILED: Could not load 70,000 instructions: " 
                      << (errmsg ? errmsg : "unknown error") << std::endl;
            free(errmsg);
            return 1;
        }
        std::cout << "Test 3 PASSED" << std::endl;
    }

    // Test 4: ubpf_set_max_instructions() fails if code is already loaded
    {
        std::cout << "Test 4: Setting max instructions after loading code (should fail)..." << std::endl;
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        
        auto program = generate_program(100);
        char* errmsg = nullptr;
        int result = ubpf_load(vm.get(), program.data(), program.size() * sizeof(struct ebpf_inst), &errmsg);
        if (result != 0) {
            std::cerr << "Test 4 FAILED: Could not load program: " 
                      << (errmsg ? errmsg : "unknown error") << std::endl;
            free(errmsg);
            return 1;
        }
        
        // Now try to set max instructions - should fail
        result = ubpf_set_max_instructions(vm.get(), 200000);
        if (result == 0) {
            std::cerr << "Test 4 FAILED: Should not be able to set max instructions after loading code" << std::endl;
            return 1;
        }
        std::cout << "Test 4 PASSED" << std::endl;
    }

    // Test 5: Setting a lower limit than default
    {
        std::cout << "Test 5: Setting max instructions to 1,000 and loading 1,001 instructions (should fail)..." << std::endl;
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        
        if (ubpf_set_max_instructions(vm.get(), 1000) != 0) {
            std::cerr << "Test 5 FAILED: Could not set max instructions" << std::endl;
            return 1;
        }
        
        auto program = generate_program(1001);
        char* errmsg = nullptr;
        int result = ubpf_load(vm.get(), program.data(), program.size() * sizeof(struct ebpf_inst), &errmsg);
        if (result == 0) {
            std::cerr << "Test 5 FAILED: Should not be able to load 1,001 instructions with limit of 1,000" << std::endl;
            return 1;
        }
        
        if (errmsg == nullptr || strstr(errmsg, "too many instructions") == nullptr) {
            std::cerr << "Test 5 FAILED: Expected 'too many instructions' error" << std::endl;
            free(errmsg);
            return 1;
        }
        free(errmsg);
        std::cout << "Test 5 PASSED" << std::endl;
    }

    // Test 6: Setting max_insts to 0 uses default
    {
        std::cout << "Test 6: Setting max instructions to 0 (should use default 65536)..." << std::endl;
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        
        if (ubpf_set_max_instructions(vm.get(), 0) != 0) {
            std::cerr << "Test 6 FAILED: Could not set max instructions to 0" << std::endl;
            return 1;
        }
        
        // Should be able to load just under default limit
        auto program = generate_program(65535);
        char* errmsg = nullptr;
        int result = ubpf_load(vm.get(), program.data(), program.size() * sizeof(struct ebpf_inst), &errmsg);
        if (result != 0) {
            std::cerr << "Test 6 FAILED: Could not load 65,535 instructions with default limit: " 
                      << (errmsg ? errmsg : "unknown error") << std::endl;
            free(errmsg);
            return 1;
        }
        std::cout << "Test 6 PASSED" << std::endl;
    }

    std::cout << "All tests passed!" << std::endl;
    return 0;
}
