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

typedef std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> ubpf_vm_ptr;

ubpf_vm_ptr create_ubpf_vm(const std::vector<uint8_t>& program_code)
{
    // Automatically free the VM when it goes out of scope.
    std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);

    if (vm == nullptr) {
        // Failed to create the VM.
        // This is not interesting, as the fuzzer input is invalid.
        // Do not add it to the corpus.
        return vm;
    }

    ubpf_toggle_undefined_behavior_check(vm.get(), true);

    char* error_message = nullptr;

    ubpf_set_error_print(vm.get(), null_printf);

    if (ubpf_load(vm.get(), program_code.data(), program_code.size(), &error_message) != 0) {
        // The program failed to load, due to a validation error.
        // This is not interesting, as the fuzzer input is invalid.
        // Do not add it to the corpus.
        free(error_message);
        vm.reset();
        return vm;
    }

    ubpf_toggle_bounds_check(vm.get(), true);

    if (ubpf_register_external_dispatcher(vm.get(), test_helpers_dispatcher, test_helpers_validator) != 0) {
        // Failed to register the external dispatcher.
        // This is not interesting, as the fuzzer input is invalid.
        // Do not add it to the corpus.
        vm.reset();
        return vm;
    }

    if (ubpf_set_instruction_limit(vm.get(), 10000, nullptr) != 0) {
        // Failed to set the instruction limit.
        // This is not interesting, as the fuzzer input is invalid.
        // Do not add it to the corpus.
        vm.reset();
        return vm;
    }

    return vm;
}

bool call_ubpf_interpreter(const std::vector<uint8_t>& program_code, std::vector<uint8_t>& memory, std::vector<uint8_t>& ubpf_stack, uint64_t& interpreter_result)
{
    auto vm = create_ubpf_vm(program_code);

    if (vm == nullptr) {
        // VM creation failed.
        return false;
    }

    // Execute the program using the input memory.
    if (ubpf_exec_ex(vm.get(), memory.data(), memory.size(), &interpreter_result, ubpf_stack.data(), ubpf_stack.size()) != 0) {
        // VM execution failed.
        return false;
    }

    // VM execution succeeded.
    return true;
}

bool call_ubpf_jit(const std::vector<uint8_t>& program_code, std::vector<uint8_t>& memory, std::vector<uint8_t>& ubpf_stack, uint64_t& jit_result)
{
    auto vm = create_ubpf_vm(program_code);

    char* error_message = nullptr;

    if (vm == nullptr) {
        // VM creation failed.
        return false;
    }

    auto fn = ubpf_compile_ex(vm.get(), &error_message, JitMode::ExtendedJitMode);

    if (fn == nullptr) {
        free(error_message);

        // Compilation failed.
        return false;
    }

    jit_result = fn(memory.data(), memory.size(), ubpf_stack.data(), ubpf_stack.size());

    // Compilation succeeded.
    return true;
}

bool call_linux_jit(const std::vector<uint8_t>& program_code, std::vector<uint8_t>& memory, std::vector<uint8_t> ubpf_stack, uint64_t& linux_jit_result);

bool split_input(const uint8_t* data, std::size_t size, std::vector<uint8_t>& program, std::vector<uint8_t>& memory)
{
    if (size < 4)
        return false;

    uint32_t program_length = *reinterpret_cast<const uint32_t*>(data);
    uint32_t memory_length = size - 4 - program_length;
    const uint8_t* program_start = data + 4;
    const uint8_t* memory_start = data + 4 + program_length;

    if (program_length > size) {
        // The program length is larger than the input size.
        // This is not interesting, as the fuzzer input is invalid.
        return false;
    }

    if (program_length == 0) {
        // The program length is zero.
        // This is not interesting, as the fuzzer input is invalid.
        return false;
    }

    if (program_length + 4u > size) {
        // The program length is larger than the input size.
        // This is not interesting, as the fuzzer input is invalid.
        return false;
    }

    if ((program_length % sizeof(ebpf_inst)) != 0) {
        // The program length needs to be a multiple of sizeof(ebpf_inst_t).
        // This is not interesting, as the fuzzer input is invalid.
        return false;
    }

    // Copy any input memory into a writable buffer.
    if (memory_length > 0) {
        memory.resize(memory_length);
        std::memcpy(memory.data(), memory_start, memory_length);
    }

    program.resize(program_length);
    std::memcpy(program.data(), program_start, program_length);

    return true;
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

    std::vector<uint8_t> program;
    std::vector<uint8_t> memory;
    std::vector<uint8_t> ubpf_stack(3*4096);

    if (!split_input(data, size, program, memory)) {
        // The input is invalid. Not interesting.
        return -1;
    }

    uint64_t interpreter_result = 0;
    uint64_t jit_result = 0;

    if (!call_ubpf_interpreter(program, memory, ubpf_stack, interpreter_result)) {
        // Failed to load or execute the program in the interpreter.
        // This is not interesting, as the fuzzer input is invalid.
        return 0;
    }

    if (!split_input(data, size, program, memory)) {
        // The input is invalid. Not interesting.
        return -1;
    }

    if (!call_ubpf_jit(program, memory, ubpf_stack, jit_result)) {
        // Failed to load or execute the program in the JIT.
        // This is not interesting, as the fuzzer input is invalid.
        return 0;
    }

    // If interpreter_result is not equal to jit_result, raise a fatal signal
    if (interpreter_result != jit_result) {
        printf("%lx ubpf_stack\n", reinterpret_cast<uintptr_t>(ubpf_stack.data()) + ubpf_stack.size());
        printf("interpreter_result: %lx\n", interpreter_result);
        printf("jit_result: %lx\n", jit_result);
        throw std::runtime_error("interpreter_result != jit_result");
    }

    // Program executed successfully.
    // Add it to the corpus as it may be interesting.
    return 0;
}
