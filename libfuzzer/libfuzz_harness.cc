// Copyright (c) uBPF contributors
// SPDX-License-Identifier: MIT

#include <cstdint>
#include <cstddef>
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

bool test_helpers_validator(unsigned int idx, const struct ubpf_vm *vm) {
    UNREFERENCED_PARAMETER(vm);
    return helper_functions.contains(idx);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size);

int null_printf(FILE* stream, const char* format, ...)
{
    if (!stream) {
        return 0;
    }
    if (!format) {
        return 0;
    }
    return 0;
}

/**
 * @brief Accept an input buffer and size.
 *
 * @param[in] data Pointer to the input buffer.
 * @param[in] size Size of the input buffer.
 * @return -1 if the input is invalid
 * @return 0 if the input is valid and processed.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size)
{
    // Assume the fuzzer input is as follows:
    // 32-bit program length
    // program byte
    // test data

    // Copy memory into a writable buffer.
    std::vector<uint8_t> memory;

    if (size < 4)
        return -1;

    uint32_t program_length = *reinterpret_cast<const uint32_t*>(data);
    uint32_t memory_length = size - 4 - program_length;
    const uint8_t* program_start = data + 4;
    const uint8_t* memory_start = data + 4 + program_length;

    if (program_length > size) {
        // The program length is larger than the input size.
        // This is not interesting, as the fuzzer input is invalid.
        // Do not add it to the corpus.
        return -1;
    }

    if (program_length == 0) {
        // The program length is zero.
        // This is not interesting, as the fuzzer input is invalid.
        // Do not add it to the corpus.
        return -1;
    }

    if (program_length + 4u > size) {
        // The program length is larger than the input size.
        // This is not interesting, as the fuzzer input is invalid.
        // Do not add it to the corpus.
        return -1;
    }

    // Copy any input memory into a writable buffer.
    if (memory_length > 0) {
        memory.resize(memory_length);
        std::memcpy(memory.data(), memory_start, memory_length);
    }

    // Automatically free the VM when it goes out of scope.
    std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);

    if (vm == nullptr) {
        // Failed to create the VM.
        // This is not interesting, as the fuzzer input is invalid.
        // Do not add it to the corpus.
        return -1;
    }

    char* error_message = nullptr;

    if (ubpf_load(vm.get(), program_start, program_length, &error_message) != 0) {
        // The program failed to load, due to a validation error.
        // This is not interesting, as the fuzzer input is invalid.
        // Do not add it to the corpus.
        free(error_message);
        return -1;
    }

    ubpf_set_error_print(vm.get(), null_printf);

    ubpf_toggle_bounds_check(vm.get(), true);

    if (ubpf_register_external_dispatcher(vm.get(), test_helpers_dispatcher, test_helpers_validator) != 0) {
        // Failed to register the external dispatcher.
        // This is not interesting, as the fuzzer input is invalid.
        // Do not add it to the corpus.
        return -1;
    }

    if (ubpf_set_instruction_limit(vm.get(), 10000, nullptr) != 0) {
        // Failed to set the instruction limit.
        // This is not interesting, as the fuzzer input is invalid.
        // Do not add it to the corpus.
        return -1;
    }

    uint64_t result = 0;

    // Execute the program using the input memory.
    if (ubpf_exec(vm.get(), memory.data(), memory.size(), &result) != 0) {
        // The program passed validation during load, but failed during execution.
        // due to a runtime error. Add it to the corpus as it may be interesting.
        return 0;
    }

    // Program executed successfully.
    // Add it to the corpus as it may be interesting.
    return 0;
}
