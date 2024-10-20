// Copyright (c) Will Hawkins
// SPDX-License-Identifier: Apache-2.0

#include <cstdint>
#include <iostream>
#include <memory>
#include <stdint.h>
#include <vector>
#include <string>

extern "C"
{
#include "ubpf.h"
}

#include "ubpf_custom_test_support.h"

typedef struct _vm_state {
    int pc;
    std::vector<uint64_t> registers;
    std::vector<uint8_t> stack;
} vm_state_t;

void
debug_callout(void* context, int program_counter, const uint64_t registers[16], const uint8_t* stack_start, size_t stack_length, uint64_t register_mask, const uint8_t* stack_mask)
{
    UNREFERENCED_PARAMETER(register_mask);
    UNREFERENCED_PARAMETER(stack_mask);
    std::vector<vm_state_t>* vm_states = static_cast<std::vector<vm_state_t>*>(context);
    vm_state_t vm_state{};

    vm_state.pc = program_counter;
    for (int i = 0; i < 16; i++) {
        vm_state.registers.push_back(registers[i]);
    }
    for (size_t i = 0; i < stack_length; i++) {
        vm_state.stack.push_back(stack_start[i]);
    }

    vm_states->push_back(vm_state);
}

uint64_t test_function_1(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5)
{
    return r1 + r2 + r3 + r4 + r5;
}

int
main(int argc, char** argv)
{
    std::string program_string{};
    std::string error{};
    ubpf_jit_fn jit_fn;

    std::vector<vm_state_t> vm_states;

    if (!get_program_string(argc, argv, program_string, error)) {
        std::cerr << error << std::endl;
        return 1;
    }

    uint64_t memory{0x123456789};

    std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
    if (!ubpf_setup_custom_test(
            vm,
            program_string,
            [](ubpf_vm_up& vm, std::string& error) {
                int retval = ubpf_register(vm.get(), 1, "test_function_1", test_function_1);
                if (retval < 0) {
                    error = "Problem registering test function retval=" + std::to_string(retval);
                    return false;
                }
                return true;
            },
            jit_fn,
            error)) {
        std::cerr << "Problem setting up custom test: " << error << std::endl;
        return 1;
    }

    if (ubpf_register_debug_fn(vm.get(), &vm_states, debug_callout) < 0) {
        std::cerr << "Problem registering debug function" << std::endl;
        return 1;
    }

    uint64_t bpf_return_value;
    if (ubpf_exec(vm.get(), &memory, sizeof(memory), &bpf_return_value)) {
        std::cerr << "Problem executing program" << std::endl;
        return 1;
    }

    if (vm_states.empty()) {
        std::cerr << "No debug callouts were made" << std::endl;
        return 1;
    }

    for (auto& vm_state : vm_states) {
        std::cout << "Program Counter: " << vm_state.pc << std::endl;
        for (int i = 0; i < 16; i++) {
            std::cout << "Register " << i << ": " << vm_state.registers[i] << std::endl;
        }
        std::cout << "Stack: ";
        for (auto& stack_byte : vm_state.stack) {
            std::cout << std::hex << static_cast<int>(stack_byte) << " ";
        }
        std::cout << std::endl;
    }
}
