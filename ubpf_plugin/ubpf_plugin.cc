// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: Apache-2.0

// This program reads BPF instructions from stdin and memory contents from
// the first agument. It then executes the BPF program and prints the
// value of %r0 at the end of execution.
// The program is intended to be used with the bpf conformance test suite.

#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>
#include <string>
#include <sstream>

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

bool test_helpers_validater(unsigned int idx, void *cookie) {
    UNREFERENCED_PARAMETER(cookie);
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
    uint8_t *memory_ptr{nullptr};

    if (memory.size() != 0) {
        memory_ptr = memory.data();
    }

    std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
    char* error = nullptr;

    if (vm == nullptr)
    {
        std::cerr << "Failed to create VM" << std::endl;
        return 1;
    }

/*
    for (auto &[key, value] : helper_functions)
    {
        if (ubpf_register(vm.get(), key, "unnamed", value) != 0)
        {
            std::cerr << "Failed to register helper function" << std::endl;
            return 1;
        }
    }
*/

    ubpf_register_external_dispatcher(vm.get(), test_helpers_dispatcher, test_helpers_validater, NULL);

    if (ubpf_set_unwind_function_index(vm.get(), 5) != 0)
    {
        std::cerr << "Failed to set unwind function index" << std::endl;
        return 1;
    }

    if (ubpf_load(vm.get(), program.data(), static_cast<uint32_t>(program.size() * sizeof(ebpf_inst)), &error) != 0)
    {
        std::cerr << "Failed to load program: " << error << std::endl;
        std::cout << "Failed to load code: " << error << std::endl;
        free(error);
        return 1;
    }

    uint64_t actual_result;
    if (jit)
    {
        ubpf_jit_fn fn = ubpf_compile(vm.get(), &error);
        if (fn == nullptr)
        {
            std::cerr << "Failed to compile program: " << error << std::endl;
            std::cout << "Failed to load code: " << error << std::endl;
            free(error);
            return 1;
        }
        actual_result = fn(memory_ptr, memory.size());
    }
    else
    {
        if (ubpf_exec(vm.get(), memory_ptr, memory.size(), &actual_result) != 0)
        {
            std::cerr << "Failed to execute program" << std::endl;
            return 1;
        }
    }
    std::cout << std::hex << actual_result << std::endl;
    return 0;
}
