// Copyright (c) 2022-present, IO Visor Project
// SPDX-License-Identifier: Apache-2.0

#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

#include "bpf_assembler.h"
#include "test_helpers.h"
extern "C"
{
#include "ubpf.h"
}

std::map<std::string, std::string> unsupported_tests {
#if defined(__aarch64__)
    {"mod-by-zero-reg.data", "JIT"},
    {"div-by-zero-reg.data", "JIT"},
    {"div-by-zero-imm.data", "JIT"},
    {"mod-by-zero-reg.data", "JIT"},
    {"mod-by-zero-reg.data", "JIT"},
    { "mod-by-zero-reg.data", "JIT"}, 
    {"div-by-zero-reg.data", "JIT"}, 
    {"div-by-zero-imm.data", "JIT"}, 
    {"div64-by-zero-imm.data", "JIT"}, 
    {"mod64-by-zero-imm.data", "JIT"}, 
    {"mod-by-zero-imm.data", "JIT"}, 
    {"div64-by-zero-reg.data", "JIT"}, 
    {"mod64-by-zero-reg.data", "JIT"}, 
#else
#endif
};

std::tuple<std::vector<uint8_t>, uint64_t, std::string, std::vector<ebpf_inst>>
parse_test_file(const std::filesystem::path &data_file)
{
    enum class _state
    {
        state_ignore,
        state_assembly,
        state_raw,
        state_result,
        state_memory,
        state_error,
    } state = _state::state_ignore;

    std::stringstream data_out;
    std::ifstream data_in(data_file);

    std::string result_string;
    std::string mem;
    std::string line;
    std::string expected_error;
    while (std::getline(data_in, line))
    {
        if (line.find("--") != std::string::npos)
        {
            if (line.find("asm") != std::string::npos)
            {
                state = _state::state_assembly;
                continue;
            }
            else if (line.find("result") != std::string::npos)
            {
                state = _state::state_result;
                continue;
            }
            else if (line.find("mem") != std::string::npos)
            {
                state = _state::state_memory;
                continue;
            }
            else if (line.find("raw") != std::string::npos)
            {
                state = _state::state_ignore;
                continue;
            }
            else if (line.find("result") != std::string::npos)
            {
                state = _state::state_result;
                continue;
            }
            else if (line.find("no register offset") != std::string::npos)
            {
                state = _state::state_ignore;
                continue;
            }
            else if (line.find(" c") != std::string::npos)
            {
                state = _state::state_ignore;
                continue;
            }
            else if (line.find("error") != std::string::npos)
            {
                state = _state::state_error;
                continue;
            }
            else
            {
                std::cout << "Unknown directive " << line << std::endl;
                return {};
                continue;
            }
        }
        if (line.empty())
        {
            continue;
        }

        switch (state)
        {
        case _state::state_assembly:
            if (line.find("#") != std::string::npos)
            {
                line = line.substr(0, line.find("#"));
            }
            data_out << line << std::endl;
            break;
        case _state::state_result:
            result_string = line;
            break;
        case _state::state_memory:
            mem += std::string(" ") + line;
            break;
        case _state::state_error:
            expected_error = line;
            break;
        default:
            continue;
        }
    }

    uint64_t result_value;
    if (result_string.empty())
    {
        result_value = 0;
        return {};
    } else if (result_string.find("0x") != std::string::npos)
    {
        result_value = std::stoull(result_string, nullptr, 16);
    }
    else
    {
        result_value = std::stoull(result_string);
    }

    data_out.seekg(0);
    auto instructions = bpf_assembler(data_out);

    std::vector<uint8_t> input_buffer;

    if (!mem.empty())
    {
        std::stringstream ss(mem);
        uint32_t value;
        while (ss >> std::hex >> value)
        {
            input_buffer.push_back(static_cast<uint8_t>(value));
        }
    }

    return {input_buffer, result_value, expected_error, instructions};
}

ubpf_vm *
prepare_ubpf_vm(const std::vector<ebpf_inst> instructions, const std::string& expected_error)
{
    ubpf_vm *vm = ubpf_create();
    if (vm == nullptr)
        throw std::runtime_error("Failed to create VM");

    char *error = nullptr;
    for (auto &[key, value] : helper_functions)
    {
        if (ubpf_register(vm, key, "unnamed", reinterpret_cast<void*>(value)) != 0)
            throw std::runtime_error("Failed to register helper function");
    }

    if (ubpf_set_unwind_function_index(vm, 5) != 0)
        throw std::runtime_error("Failed to set unwind function index");

    auto result = ubpf_load(vm, instructions.data(), static_cast<uint32_t>(instructions.size() * sizeof(ebpf_inst)), &error);
    if (expected_error.empty())
    {
        if (result != 0)
            throw std::runtime_error("Failed to load program: " + std::string(error));
    }
    else
    {
        if (result == 0)
            throw std::runtime_error("Expected error but program loaded successfully");
        if (expected_error.find(error) == std::string::npos)
            throw std::runtime_error("Expected error '" + expected_error + "' but got '" + error + "'");
        ubpf_destroy(vm);
        vm = nullptr;
    }

    return vm;
}

void run_ubpf_jit_test(const std::filesystem::path &data_file)
{
    auto unsupported = unsupported_tests.find(data_file.filename().string());
    if (unsupported != unsupported_tests.end() && unsupported->second == "JIT")
    {
        std::cout << "Skipping " << data_file << " because it is unsupported on " << unsupported->second << std::endl;
        GTEST_SKIP();
        return;
    }

    auto [mem, expected_result, expected_error, instructions] = parse_test_file(data_file);
    if (instructions.empty())
    {
        std::cout << "Skipping " << data_file << " because it is not supported" << std::endl;
        GTEST_SKIP();
        return;
    }

    char *error = nullptr;
    ubpf_vm *vm = prepare_ubpf_vm(instructions, expected_error);
    if (vm == nullptr)
        return;

    ubpf_jit_fn jit = ubpf_compile(vm, &error);
    if (jit == nullptr)
        throw std::runtime_error("Failed to compile program: " + std::string(error));

    uint64_t actual_result = jit(mem.data(), mem.size());

    if (actual_result != expected_result) {
        std::cout << "Expected: " << expected_result << " Actual: " << actual_result << std::endl;
        throw std::runtime_error("Result mismatch");
    }

    ubpf_destroy(vm);
}

void run_ubpf_interpret_test(const std::filesystem::path &data_file)
{
    auto unsupported = unsupported_tests.find(data_file.filename().string());
    if (unsupported != unsupported_tests.end() && unsupported->second == "INTERPRET")
    {
        std::cout << "Skipping " << data_file << " because it is unsupported on " << unsupported->second << std::endl;
        GTEST_SKIP();
        return;
    }

    auto [mem, expected_result, expected_error, instructions] = parse_test_file(data_file);
    if (instructions.empty())
    {
        std::cout << "Skipping " << data_file << " because it is not supported" << std::endl;
        GTEST_SKIP();
        return;
    }

    ubpf_vm *vm = prepare_ubpf_vm(instructions, expected_error);
    if (vm == nullptr)
        return;

    uint64_t actual_result = 0;
    if (ubpf_exec(vm, mem.data(), mem.size(), &actual_result) != 0)
        throw std::runtime_error("Failed to execute program");

    if (actual_result != expected_result) {
        std::cout << "Expected: " << expected_result << " Actual: " << actual_result << std::endl;
        throw std::runtime_error("Result mismatch");
    }

    ubpf_destroy(vm);
}

class ubpf_test : public ::testing::TestWithParam<std::filesystem::path>
{
};

TEST_P(ubpf_test, jit)
{
    run_ubpf_jit_test(GetParam());
}

TEST_P(ubpf_test, interpret)
{
    run_ubpf_interpret_test(GetParam());
}

std::vector<std::filesystem::path> get_test_files()
{
    std::vector<std::filesystem::path> result;
    for (auto &p : std::filesystem::directory_iterator("tests/"))
    {
        if (p.path().extension() == ".data")
        {
            result.push_back(p.path());
        }
    }
    return result;
}

INSTANTIATE_TEST_SUITE_P(ubpf_tests, ubpf_test, ::testing::ValuesIn(get_test_files()));
