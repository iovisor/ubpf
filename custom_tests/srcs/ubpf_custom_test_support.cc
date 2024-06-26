// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: Apache-2.0

#include <cassert>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <optional>

extern "C"
{
#include "ebpf.h"
#include "ubpf.h"
}


#include "ubpf_custom_test_support.h"

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

std::vector<ebpf_inst>
bytes_to_ebpf_inst(std::vector<uint8_t> bytes)
{
    std::vector<ebpf_inst> instructions(bytes.size() / sizeof(ebpf_inst));
    memcpy(instructions.data(), bytes.data(), bytes.size());
    return instructions;
}


bool ubpf_setup_custom_test(ubpf_vm_up &vm,
                       const std::string program_string,
                       std::optional<custom_test_fixup_cb> fixup_f,
                       ubpf_jit_fn &jit_fn,
                       std::string &error)
{
    jit_fn = nullptr;
    std::vector<ebpf_inst> program = bytes_to_ebpf_inst(base16_decode(program_string));
    char *error_s{nullptr};

    if (vm == nullptr)
    {
        error = "VM not provided";
        return false;
    }

    if (ubpf_set_unwind_function_index(vm.get(), 5) != 0)
    {
        error = "Failed to set unwind function index";
        return false;
    }

    if (fixup_f.has_value())
    {
        if (!(fixup_f.value())(vm, error)) {
            return false;
        }
    }

    if (ubpf_load(vm.get(), program.data(), static_cast<uint32_t>(program.size() * sizeof(ebpf_inst)), &error_s) != 0)
    {
        error = "Failed to load program: " + std::string{error_s};
        free(error_s);
        return false;
    }

    jit_fn = ubpf_compile(vm.get(), &error_s);
    if (jit_fn == nullptr)
    {
        error = "Failed to compile: " + std::string{error_s};
        free(error_s);
        return false;
    }

    assert(error_s == nullptr);
    free(error_s);
    return true;
}

bool get_program_string(int argc, char **argv, std::string &program_string, std::string &error)
{
    std::vector<std::string> args(argv, argv + argc);

    if (args.size() == 1)
    {
        std::string line;
        while (std::getline(std::cin, line))
        {
            program_string += line;
        }
    }
    else if (args.size() == 3 && args[1] == "--program")
    {
        std::ifstream file(args[2]);
        if (file.is_open())
        {
            std::string line;
            while (std::getline(file, line))
            {
                program_string += line;
            }
            file.close();
        }
        else
        {
            error = "Failed to open file: " + args[2];
            return false;
        }
    }
    else
    {
        error = "Usage: " + args[0] + " [program]";
        return false;
    }

    return true;
}
