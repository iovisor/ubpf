// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: Apache-2.0

#include <cstdint>
#include <memory>
#include <vector>
#include <string>
#include <optional>
#include <functional>

extern "C"
{
#include "ebpf.h"
#include "ubpf.h"
}

#define UNREFERENCED_PARAMETER (void)

/**
 * @brief Read in a string of hex bytes and return a vector of bytes.
 *
 * @param[in] input String containing hex bytes.
 * @return Vector of bytes.
 */
std::vector<uint8_t>
base16_decode(const std::string &input);


/**
 * @brief Convert a vector of bytes to a vector of ebpf_inst.
 *
 * @param[in] bytes Vector of bytes.
 * @return Vector of ebpf_inst.
 */
std::vector<ebpf_inst>
bytes_to_ebpf_inst(std::vector<uint8_t> bytes);


using ubpf_vm_up = std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)>;
using custom_test_fixup_cb = std::function<bool(ubpf_vm_up &, std::string &error)>;


/**
 * @brief Do the common necessary work to setup a custom test.
 *
 * @param[in] vm The VM for which to prepare the test.
 * @param[in] program_string A string of raw bytes that make up the eBPF program to execute under this test.
 * @param[in] fixup_f A function that will be invoked after the program is loaded and before it is compiled.
 * @param[out] jit_fn A function that can be invoked to run the jit'd program.
 * @param[out] error A string containing the error message (if any) generated during custom test configuration.
 * @return True or false depending on whether setting up the custom test succeeded.
 */
bool ubpf_setup_custom_test(ubpf_vm_up &vm,
                       const std::string program_string,
                       std::optional<custom_test_fixup_cb> fixup_f,
                       ubpf_jit_fn &jit_fn,
                       std::string &error);

