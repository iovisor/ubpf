// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: Apache-2.0

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

const uint64_t dispatcher_test_dispatcher_failure{40};
const uint64_t dispatcher_test_dispatcher_success{42};
const uint64_t updated_dispatcher_test_dispatcher_failure{41};
const uint64_t updated_dispatcher_test_dispatcher_success{43};

uint64_t
dispatcher_test_dispatcher(
    uint64_t p0, uint64_t p1, uint64_t p2, uint64_t p3, uint64_t p4, unsigned int idx, void* cookie)
{
    UNREFERENCED_PARAMETER(p0);
    UNREFERENCED_PARAMETER(p1);
    UNREFERENCED_PARAMETER(p2);
    UNREFERENCED_PARAMETER(p3);
    UNREFERENCED_PARAMETER(p4);
    UNREFERENCED_PARAMETER(cookie);
    if (idx != 1) {
        return dispatcher_test_dispatcher_failure;
    }
    return dispatcher_test_dispatcher_success;
}

uint64_t
updated_dispatcher_test_dispatcher(
    uint64_t p0, uint64_t p1, uint64_t p2, uint64_t p3, uint64_t p4, unsigned int idx, void* cookie)
{
    UNREFERENCED_PARAMETER(p0);
    UNREFERENCED_PARAMETER(p1);
    UNREFERENCED_PARAMETER(p2);
    UNREFERENCED_PARAMETER(p3);
    UNREFERENCED_PARAMETER(p4);
    UNREFERENCED_PARAMETER(cookie);
    if (idx != 1) {
        return updated_dispatcher_test_dispatcher_failure;
    }
    return updated_dispatcher_test_dispatcher_success;
}

bool
test_helpers_validater(unsigned int idx, const struct ubpf_vm* vm)
{
    UNREFERENCED_PARAMETER(idx);
    UNREFERENCED_PARAMETER(vm);
    return true;
}

int
main(int argc, char** argv)
{
    std::vector<std::string> args(argv, argv + argc);
    std::string program_string;
    std::string memory_string;

    std::getline(std::cin, program_string);

    ubpf_jit_fn jit_fn;
    uint64_t memory{0x123456789};
    std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
    std::string error{};
    if (!ubpf_setup_custom_test(
            vm,
            program_string,
            [](ubpf_vm_up& vm, std::string& error) {
                if (ubpf_register_external_dispatcher(vm.get(), dispatcher_test_dispatcher, test_helpers_validater)) {
                    error = "Failed to register the external dispatcher function";
                    return false;
                }
                return true;
            },
            jit_fn,
            error)) {
        std::cerr << "Problem setting up custom test: " << error << std::endl;
        return 1;
    }

    auto first_result = jit_fn(&memory, sizeof(uint64_t));

    if (ubpf_register_external_dispatcher(vm.get(), updated_dispatcher_test_dispatcher, test_helpers_validater)) {
        std::cout << "Failed to register updated dispatcher function\n";
        return 1;
    }

    auto second_result = jit_fn(&memory, sizeof(uint64_t));

    auto current_success{
        (first_result == dispatcher_test_dispatcher_success &&
         second_result == updated_dispatcher_test_dispatcher_success)};
    return current_success ? 0 : 1;
}
