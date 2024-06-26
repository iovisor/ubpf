// Copyright (c) Will Hawkins
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

uint64_t
test_helper(uint64_t p0, uint64_t p1, uint64_t p2, uint64_t p3, uint64_t p4, void* cookie)
{
    UNREFERENCED_PARAMETER(p0);
    UNREFERENCED_PARAMETER(p1);
    UNREFERENCED_PARAMETER(p2);
    UNREFERENCED_PARAMETER(p3);
    UNREFERENCED_PARAMETER(p4);
    //UNREFERENCED_PARAMETER(index);
    uint64_t* ccookie = (uint64_t*)cookie;
    return *ccookie;
}

int main(int argc, char **argv)
{
    std::string program_string{};
    std::string error{};
    ubpf_jit_fn jit_fn;
    uint64_t memory{0x123456789};

    // The test program invokes an external function (which is invoked via the registered
    // external helper dispatcher). The result of that external function is given as the
    // result of the eBPF's program execution. Therefore, ...
    if (!get_program_string(argc, argv, program_string, error)) {
        std::cerr << error << std::endl;
        return 1;
    }

    std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
    if (!ubpf_setup_custom_test(
            vm,
            program_string,
            [](ubpf_vm_up& vm, std::string &error) {
                if (ubpf_register(vm.get(), 1, "test_helper", reinterpret_cast<external_function_t>(test_helper)) < 0) {
                    error = "Failed to register test_helper.";
                    return false;
                }
                return true;
            },
            jit_fn,
            error)) {
        std::cerr << "Problem setting up custom test: " << error << std::endl;
        return 1;
    }

    [[maybe_unused]] auto result = jit_fn(&memory, sizeof(uint64_t));

    // ... because of the semantics of default dispatcher, the result of the eBPF
    // program execution should point to the same place to which &memory points.
    return !(result == memory);
}
