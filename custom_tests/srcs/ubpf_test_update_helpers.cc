// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: Apache-2.0

// This program reads BPF instructions from stdin and memory contents from
// the first agument. It then executes the BPF program and prints the
// value of %r0 at the end of execution.
// The program is intended to be used with the bpf conformance test suite.

#include "ubpf_int.h"
#include <cstdint>
#include <iostream>
#include <memory>
#include <vector>
#include <string>

extern "C"
{
#include "ubpf.h"
}

#include "ubpf_custom_test_support.h"
#include "test_helpers.h"

struct HelperTestCase {
    const char *testcase_name;
    external_function_t helper_function1;
    external_function_t helper_function2;
    int index;
    uint64_t result1;
    uint64_t result2;
};

/**
 * @brief This program reads BPF instructions from stdin and memory contents from
 * the first agument. It then executes the BPF program and prints the
 * value of %r0 at the end of execution.
 */
int main(int argc, char **argv)
{
    std::vector<std::string> args(argv, argv + argc);
    std::string program_string{};
    bool success{true};

    const char memfrob_testcase_name[] = "memfrob";
    const char gather_bytes_testcase_name[] = "gather bytes";
    const char sqrti_testcase_name[] = "sqrti";
    const char no_op_testcase_name[] = "no op";
    const char strcmp_testcase_name[] = "strcmp";
    const char unwind_testcase_name[] = "unwind";

    std::vector<HelperTestCase> test_cases{
        {
            .testcase_name = memfrob_testcase_name,
            .helper_function1 = dispatcher_test_memfrob,
            .helper_function2 = updated_dispatcher_test_memfrob,
            .index = 1,
            .result1 = 42,
            .result2 = 43
        },
        {
            .testcase_name = gather_bytes_testcase_name,
            .helper_function1 = dispatcher_gather_bytes,
            .helper_function2 = updated_dispatcher_gather_bytes,
            .index = 1,
            .result1 = 44,
            .result2 = 45
        },
        {
            .testcase_name = no_op_testcase_name,
            .helper_function1 = dispatcher_no_op,
            .helper_function2 = updated_dispatcher_no_op,
            .index = 1,
            .result1 = 46,
            .result2 = 47
        },
        {
            .testcase_name = sqrti_testcase_name,
            .helper_function1 = dispatcher_sqrti,
            .helper_function2 = updated_dispatcher_sqrti,
            .index = 1,
            .result1 = 48,
            .result2 = 49
        },
        {
            .testcase_name = strcmp_testcase_name,
            .helper_function1 = dispatcher_strcmp_ext,
            .helper_function2 = updated_dispatcher_strcmp_ext,
            .index = 1,
            .result1 = 50,
            .result2 = 51
        },
        {
            .testcase_name = unwind_testcase_name,
            .helper_function1 = dispatcher_unwind,
            .helper_function2 = updated_dispatcher_unwind,
            .index = 1,
            .result1 = 52,
            .result2 = 53
        }
    };

    std::getline(std::cin, program_string);

    for (auto testcase : test_cases) {
        ubpf_jit_fn jit_fn;
        uint64_t memory{0x123456789};
        std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
        std::string error{};
        if (!ubpf_setup_custom_test(
                vm,
                program_string,
                [&testcase](ubpf_vm_up& vm, std::string& error) {
                        if (ubpf_register(vm.get(), testcase.index, "unnamed", testcase.helper_function1) != 0) {
                            error = "Failed to register helper function";
                            return false;
                        }
                    return true;
                },
                jit_fn,
                error)) {
            std::cerr << "Problem setting up custom test: " << error << std::endl;
            return 1;
        }

        [[maybe_unused]] auto first_result = jit_fn(&memory, sizeof(uint64_t));

        if (ubpf_register(vm.get(), testcase.index, "unnamed", testcase.helper_function2) != 0) {
            std::cout << "Failed to register helper function\n";
            return 1;
        }

        [[maybe_unused]] auto second_result = jit_fn(&memory, sizeof(uint64_t));

        auto current_success{(first_result == testcase.result1 && second_result == testcase.result2)};
        if (!current_success) {
            std::cout << "There was a failure with test " << testcase.testcase_name << ": " <<
            testcase.result1 << " != " << first_result << " or "  <<
            testcase.result2 << " != " << second_result << "!\n";
        }
        success &= current_success;
    }
    return success ? 0 : 1;
}
