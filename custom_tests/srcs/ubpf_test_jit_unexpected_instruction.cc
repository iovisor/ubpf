// Copyright (c) Will Hawkins
// SPDX-License-Identifier: Apache-2.0

#include <vector>
#include <string>
#include <iostream>

extern "C"
{
#include "ebpf.h"
#include "ubpf.h"
}

#include "ubpf_custom_test_support.h"

int main()
{
    std::string expected_error{"Failed to load program: unknown opcode 0x8f at PC 0" };
    ubpf_jit_fn jit_fn;
    std::string program_string;

    // The program's first instruction contains an invalid opcode. Attempting to load this
    // program should elicit an error alerting the user to an unknown opcode (see above).
    std::getline(std::cin, program_string);

    std::vector<ebpf_inst> program = bytes_to_ebpf_inst(base16_decode(program_string));

    ubpf_vm_up vm(ubpf_create(), ubpf_destroy);
    std::string error{};

    if (!ubpf_setup_custom_test(
            vm,
            program_string,
            custom_test_fixup_cb{[](ubpf_vm_up&, std::string& ) {
                return true;
            }},
            jit_fn,
            error)) {

        // Only if the error matches exactly what we expect should this test pass.
        if (jit_fn == nullptr && expected_error == error)
            return 0;
    }

    return 1;
}
