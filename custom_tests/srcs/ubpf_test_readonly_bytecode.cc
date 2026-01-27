// Copyright (c) uBPF contributors
// SPDX-License-Identifier: Apache-2.0

#include <cstdint>
#include <iostream>
#include <memory>
#include <string>

extern "C"
{
#include "ubpf.h"
}

#include "ubpf_custom_test_support.h"

/**
 * @brief Test that bytecode can be loaded and executed with read-only protection enabled.
 * 
 * This test verifies that:
 * 1. Bytecode can be loaded successfully when read-only mode is enabled (default)
 * 2. The VM can execute the bytecode correctly
 * 3. Toggling read-only mode works correctly
 */
int
main(int argc, char** argv)
{
    std::string program_string{};
    std::string error{};
    ubpf_jit_fn jit_fn;

    if (!get_program_string(argc, argv, program_string, error)) {
        std::cerr << error << std::endl;
        return 1;
    }

    // Test 1: Load and execute with read-only bytecode enabled (default)
    {
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        if (!vm) {
            std::cerr << "Failed to create VM" << std::endl;
            return 1;
        }

        // Read-only bytecode should be enabled by default
        if (!ubpf_setup_custom_test(
                vm, program_string, [](ubpf_vm_up&, std::string&) { return true; }, jit_fn, error)) {
            std::cerr << "Failed to load program with read-only bytecode: " << error << std::endl;
            return 1;
        }

        // Execute the program to ensure read-only bytecode doesn't break execution
        uint64_t memory = 0x123456789;
        uint64_t bpf_return_value;
        if (ubpf_exec(vm.get(), &memory, sizeof(memory), &bpf_return_value)) {
            std::cerr << "Failed to execute program with read-only bytecode" << std::endl;
            return 1;
        }

        std::cout << "Test 1 PASSED: Bytecode loaded and executed with read-only protection" << std::endl;
    }

    // Test 2: Toggle read-only bytecode off and verify it can still load
    {
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        if (!vm) {
            std::cerr << "Failed to create VM" << std::endl;
            return 1;
        }

        // Disable read-only bytecode
        bool was_enabled = ubpf_toggle_readonly_bytecode(vm.get(), false);
        if (!was_enabled) {
            std::cerr << "Read-only bytecode was not enabled by default" << std::endl;
            return 1;
        }

        if (!ubpf_setup_custom_test(
                vm, program_string, [](ubpf_vm_up&, std::string&) { return true; }, jit_fn, error)) {
            std::cerr << "Failed to load program without read-only bytecode: " << error << std::endl;
            return 1;
        }

        // Execute the program
        uint64_t memory = 0x123456789;
        uint64_t bpf_return_value;
        if (ubpf_exec(vm.get(), &memory, sizeof(memory), &bpf_return_value)) {
            std::cerr << "Failed to execute program without read-only bytecode" << std::endl;
            return 1;
        }

        std::cout << "Test 2 PASSED: Bytecode loaded and executed without read-only protection" << std::endl;
    }

    // Test 3: Toggle read-only bytecode back on
    {
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        if (!vm) {
            std::cerr << "Failed to create VM" << std::endl;
            return 1;
        }

        // Verify it's enabled by default
        bool was_enabled = ubpf_toggle_readonly_bytecode(vm.get(), false);
        if (!was_enabled) {
            std::cerr << "Read-only bytecode was not enabled by default" << std::endl;
            return 1;
        }

        // Re-enable it
        was_enabled = ubpf_toggle_readonly_bytecode(vm.get(), true);
        if (was_enabled) {
            std::cerr << "Read-only bytecode should have been disabled" << std::endl;
            return 1;
        }

        if (!ubpf_setup_custom_test(
                vm, program_string, [](ubpf_vm_up&, std::string&) { return true; }, jit_fn, error)) {
            std::cerr << "Failed to load program after re-enabling read-only: " << error << std::endl;
            return 1;
        }

        std::cout << "Test 3 PASSED: Toggle functionality works correctly" << std::endl;
    }

    std::cout << "All tests PASSED!" << std::endl;
    return 0;
}
