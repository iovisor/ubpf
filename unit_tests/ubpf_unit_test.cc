// Copyright (c) 2022-present, IO Visor Project
// SPDX-License-Identifier: Apache-2.0

#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <filesystem>
#include <string>

#include <gtest/gtest.h>

#include "bpf_conformance.h"

#if defined(_WIN32)
#define PLUGIN_PATH "ubpf_plugin.exe"
#else
#define PLUGIN_PATH "ubpf_plugin"
#endif

#define TEST_PATH "tests"

class ubpf_test : public ::testing::TestWithParam<std::filesystem::path>
{
};

TEST_P(ubpf_test, jit)
{
    std::cout << "Running JIT test " << GetParam() << std::endl;
    
    // Get the path to the program
    auto program_path = boost::dll::program_location();
    auto plugin_path = program_path.parent_path() / PLUGIN_PATH;

    auto test_result = bpf_conformance({GetParam()}, plugin_path.string(), "--jit", false);
    auto [result, output] = test_result.begin()->second;

    switch (result)
    {
    case bpf_conformance_test_result_t::TEST_RESULT_PASS:
        break;
    case bpf_conformance_test_result_t::TEST_RESULT_FAIL:
        GTEST_FAIL() << output;
        break;
    case bpf_conformance_test_result_t::TEST_RESULT_SKIP:
        GTEST_SKIP() << output;
        break;
    case bpf_conformance_test_result_t::TEST_RESULT_ERROR:
        GTEST_FAIL() << output;
        break;
    default:
        GTEST_FAIL() << "Unknown test result";
    }
}

TEST_P(ubpf_test, interpret)
{
    std::cout << "Running interpret test " << GetParam() << std::endl;
    // Get the path to the program
    auto program_path = boost::dll::program_location();
    auto plugin_path = program_path.parent_path() / PLUGIN_PATH;

    auto test_result = bpf_conformance({GetParam()}, plugin_path.string(), "", false);
    auto [result, output] = test_result.begin()->second;
    switch (result)
    {
    case bpf_conformance_test_result_t::TEST_RESULT_PASS:
        break;
    case bpf_conformance_test_result_t::TEST_RESULT_FAIL:
        GTEST_FAIL() << output;
        break;
    case bpf_conformance_test_result_t::TEST_RESULT_SKIP:
        GTEST_SKIP() << output;
        break;
    case bpf_conformance_test_result_t::TEST_RESULT_ERROR:
        GTEST_FAIL() << output;
        break;
    case bpf_conformance_test_result_t::TEST_RESULT_UNKNOWN:
        GTEST_FAIL() << "Unknown test result";
        break;
    default:
        GTEST_FAIL() << "Unknown test result";
        break;
    }
}

std::vector<std::filesystem::path> get_test_files()
{
    std::vector<std::filesystem::path> result;
    for (auto &p : std::filesystem::directory_iterator(TEST_PATH))
    {
        if (p.path().extension() == ".data")
        {
            result.push_back(p.path());
        }
    }
    return result;
}

INSTANTIATE_TEST_SUITE_P(ubpf_tests, ubpf_test, ::testing::ValuesIn(get_test_files()));
