// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: Apache-2.0

// This program reads BPF instructions from stdin and memory contents from
// the first agument. It then executes the BPF program and prints the
// value of %r0 at the end of execution.
// The program is intended to be used with the bpf conformance test suite.

#include <iostream>
#include <memory>
#include <vector>
#include <string>
#include <sstream>
#include <sys/mman.h>
#include "ubpf_int.h"

extern "C"
{
#include "ebpf.h"
#include "ubpf.h"
}

#include "test_helpers.h"

uint64_t test_helpers_dispatcher(uint64_t p0, uint64_t p1,uint64_t p2,uint64_t p3, uint64_t p4, unsigned int idx, void* cookie) {
    UNREFERENCED_PARAMETER(cookie);
    return helper_functions[idx](p0, p1, p2, p3, p4);
}

bool test_helpers_validater(unsigned int idx, const struct ubpf_vm *vm) {
    UNREFERENCED_PARAMETER(vm);
    return helper_functions.contains(idx);
}

/**
 * @brief Read in a string of hex bytes and return a vector of bytes.
 *
 * @param[in] input String containing hex bytes.
 * @return Vector of bytes.
 */
std::vector<uint8_t>
base16_decode(const std::string &input)
{
    std::vector<uint8_t> output;
    std::stringstream ss(input);
    std::string value;
    output.reserve(input.size() / 3);
    while (std::getline(ss, value, ' '))
    {
        try
        {
            output.push_back(static_cast<uint8_t>(std::stoi(value, nullptr, 16)));
        }
        catch (...)
        {
            // Ignore invalid values.
        }
    }
    return output;
}

/**
 * @brief Convert a vector of bytes to a vector of ebpf_inst.
 *
 * @param[in] bytes Vector of bytes.
 * @return Vector of ebpf_inst.
 */
std::vector<ebpf_inst>
bytes_to_ebpf_inst(std::vector<uint8_t> bytes)
{
    std::vector<ebpf_inst> instructions(bytes.size() / sizeof(ebpf_inst));
    memcpy(instructions.data(), bytes.data(), bytes.size());
    return instructions;
}

/**
 * @brief This program reads BPF instructions from stdin and memory contents from
 * the first agument. It then executes the BPF program and prints the
 * value of %r0 at the end of execution.
 */
int main(int argc, char **argv)
{
    bool jit = false; // JIT == true, interpreter == false
    std::vector<std::string> args(argv, argv + argc);
    std::string program_string;
    std::string memory_string;

    // Remove the first argument which is the program name.
    args.erase(args.begin());

    // First parameter is optional memory contents.
    if (args.size() > 0 && !args[0].starts_with("--"))
    {
        memory_string = args[0];
        args.erase(args.begin());
    }
    if (args.size() > 0 && args[0] == "--program")
    {
        args.erase(args.begin());
        if (args.size() > 0)
        {
            program_string = args[0];
            args.erase(args.begin());
        }
    }
    if (args.size() > 0 && args[0] == "--jit")
    {
        jit = true;
        args.erase(args.begin());
    }
    if (args.size() > 0 && args[0] == "--interpret")
    {
        jit = false;
        args.erase(args.begin());
    }

    if (args.size() > 0 && args[0].size() > 0)
    {
        std::cerr << "Invalid arguments: " << args[0] << std::endl;
        return 1;
    }

    if (program_string.empty()) {
        std::getline(std::cin, program_string);
    }

    std::vector<ebpf_inst> program = bytes_to_ebpf_inst(base16_decode(program_string));
    std::vector<uint8_t> memory = base16_decode(memory_string);

    std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
    char* error = nullptr;

    if (vm == nullptr)
    {
        std::cerr << "Failed to create VM" << std::endl;
        return 1;
    }

    ubpf_register_external_dispatcher(vm.get(), test_helpers_dispatcher, test_helpers_validater);

    if (ubpf_set_unwind_function_index(vm.get(), 5) != 0)
    {
        std::cerr << "Failed to set unwind function index" << std::endl;
        return 1;
    }

    if (ubpf_load(vm.get(), program.data(), static_cast<uint32_t>(program.size() * sizeof(ebpf_inst)), &error) != 0)
    {
        std::cout << "Failed to load code: " << error << std::endl;
        free(error);
        return 1;
    }

    uint64_t external_dispatcher_result;
    if (jit)
    {
        // Compile the program ...
        ubpf_jit_fn fn = ubpf_compile(vm.get(), &error);
        if (fn == nullptr)
        {
            std::cerr << "Failed to compile program: " << error << std::endl;
            free(error);
            return 1;
        }

        // ... keep the original program memory safe from being trashed by test program so that
        // it can be run again ...
        std::vector<uint8_t> usable_program_memory{memory};
        uint8_t *usable_program_memory_pointer{nullptr};
        if (usable_program_memory.size() != 0) {
            usable_program_memory_pointer = usable_program_memory.data();
        }

        // ... execute the original copy of the JIT'd code ...
        external_dispatcher_result = fn(usable_program_memory_pointer, usable_program_memory.size());


        // ... execute original code but with indexed dispatcher to helper functions ...
        ubpf_register_external_dispatcher(vm.get(), nullptr, test_helpers_validater);
        for (auto& [key, value] : helper_functions) {
            if (ubpf_register(vm.get(), key, "unnamed", value) != 0) {
                std::cerr << "Failed to register helper function" << std::endl;
                return 1;
            }
        }

        uint64_t index_helper_result;
        usable_program_memory = memory;
        usable_program_memory_pointer = nullptr;
        if (usable_program_memory.size() != 0) {
            usable_program_memory_pointer = usable_program_memory.data();
        }
        index_helper_result = fn(usable_program_memory_pointer, usable_program_memory.size());

        // ... copy the JIT'd program ...
        auto fn_copy_size = vm->jitted_size * sizeof(char);
        void *fn_copy = mmap(0, fn_copy_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        fn = ubpf_copy_jit(vm.get(), fn_copy, fn_copy_size, &error);
        if (fn == nullptr) {
            std::cerr << "Failed to copy JIT'd program: " << error << std::endl;
            free(error);
            return 1;
        }
        mprotect(fn_copy, fn_copy_size, PROT_READ | PROT_EXEC);

        // ... execute the copy of the JIT'd code ...
        uint64_t copy_result;
        usable_program_memory = memory;
        usable_program_memory_pointer = nullptr;
        if (usable_program_memory.size() != 0) {
            usable_program_memory_pointer = usable_program_memory.data();
        }
        copy_result = fn(usable_program_memory_pointer, usable_program_memory.size());

        // ... and make sure the results are the same.
        if (external_dispatcher_result != index_helper_result || index_helper_result != copy_result) {
            std::cerr << "Execution of the JIT'd code (with external and indexed helpers) and a copy of "
                         "the JIT'd code gave different results: 0x" << std::hex << external_dispatcher_result 
                      << " vs 0x" << std::hex << index_helper_result 
                      << " vs 0x" << std::hex << copy_result << "." << std::endl;
            return 1;
        }
    }
    else
    {
        // Keep the original program memory safe from being trashed by test program so that
        // it can be run again ...
        std::vector<uint8_t> usable_program_memory{memory};
        uint8_t *usable_program_memory_pointer{nullptr};
        if (usable_program_memory.size() != 0) {
            usable_program_memory_pointer = usable_program_memory.data();
        }

        if (ubpf_exec(vm.get(), usable_program_memory_pointer, usable_program_memory.size(), &external_dispatcher_result) != 0)
        {
            std::cerr << "Failed to execute program" << std::endl;
            return 1;
        }

        // ... execute original code but with indexed dispatcher to helper functions ...
        ubpf_register_external_dispatcher(vm.get(), nullptr, test_helpers_validater);
        for (auto& [key, value] : helper_functions) {
            if (ubpf_register(vm.get(), key, "unnamed", value) != 0) {
                std::cerr << "Failed to register helper function" << std::endl;
                return 1;
            }
        }

        // ... but first reset program memory.
        usable_program_memory = memory;
        usable_program_memory_pointer = nullptr;
        if (usable_program_memory.size() != 0) {
            usable_program_memory_pointer = usable_program_memory.data();
        }

        uint64_t index_helper_result;
        if (ubpf_exec(vm.get(), usable_program_memory_pointer, usable_program_memory.size(), &index_helper_result) != 0)
        {
            std::cerr << "Failed to execute program" << std::endl;
            return 1;
        }

        // ... and make sure the results are the same.
        if (external_dispatcher_result != index_helper_result) {
            std::cerr << "Execution of the interpreted code with external and indexed helpers gave difference results: 0x"
                      << std::hex << external_dispatcher_result 
                      << " vs 0x" << std::hex << index_helper_result << "." << std::endl;
            return 1;
        }

    }
    std::cout << std::hex << external_dispatcher_result << std::endl;
    return 0;
}
