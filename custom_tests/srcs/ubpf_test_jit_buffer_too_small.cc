// Copyright (c) Will Hawkins
// SPDX-License-Identifier: Apache-2.0

#include <vector>
#include <string>

extern "C"
{
#include "ebpf.h"
#include "ubpf.h"
}

#include "ubpf_custom_test_support.h"

/**
 * @brief This program reads BPF instructions from stdin and memory contents from
 * the first agument. It then executes the BPF program and prints the
 * value of %r0 at the end of execution.
 */
int main()
{
    std::string expected_error{"Failed to compile: Target buffer too small"};
    std::string program_string{"95 00 00 00 00 00 00 00"};
    ubpf_jit_fn jit_fn;

    std::vector<ebpf_inst> program = bytes_to_ebpf_inst(base16_decode(program_string));

    ubpf_vm_up vm(ubpf_create(), ubpf_destroy);
    std::string error{};
    char *error_s{nullptr};

    if (!ubpf_setup_custom_test(
            vm,
            program_string,
            custom_test_fixup_cb{[](ubpf_vm_up& vm, std::string& error) {
                if (ubpf_set_jit_code_size(vm.get(), 1) < 0) {
                    error = "Could not set the jit code size.";
                    return false;
                }
                return true;
            }},
            jit_fn,
            error)) {
        free(error_s);

        // Only if the error is that the buffer was too small does this test pass.
        if (jit_fn == nullptr && expected_error == error)
            return 0;
    }

    free(error_s);
    return 1;
}
