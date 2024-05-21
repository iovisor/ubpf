// Copyright (c) 2015 Big Switch Networks, Inc
// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2015 Big Switch Networks, Inc
 * Copyright 2022 Linaro Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UBPF_INT_H
#define UBPF_INT_H

#include <stdint.h>
#include <ubpf.h>
#include "ebpf.h"

#define UNUSED_PARAMETER(x) ((void)x)

struct ebpf_inst;
typedef uint64_t (*ext_func)(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);

typedef enum
{
    UBPF_JIT_COMPILE_SUCCESS,
    UBPF_JIT_COMPILE_FAILURE,
} upbf_jit_result_t;

struct ubpf_jit_result
{
    uint32_t external_dispatcher_offset;
    uint32_t external_helper_offset;
    upbf_jit_result_t compile_result;
    enum JitMode jit_mode;
    char* errmsg;
};

struct ubpf_stack_usage
{
    bool stack_usage_calculated;
    uint16_t stack_usage;
};

#define MAX_EXT_FUNCS 64

struct ubpf_vm
{
    struct ebpf_inst* insts;
    uint16_t num_insts;
    ubpf_jit_ex_fn jitted;
    size_t jitted_size;
    size_t jitter_buffer_size;
    struct ubpf_jit_result jitted_result;

    ext_func* ext_funcs;
    bool* int_funcs;
    const char** ext_func_names;

    struct ubpf_stack_usage* local_func_stack_usage;
    void* stack_usage_calculator_cookie;
    stack_usage_calculator_t stack_usage_calculator;

    external_function_dispatcher_t dispatcher;
    external_function_validate_t dispatcher_validate;

    bool bounds_check_enabled;
    bool undefined_behavior_check_enabled;
    int (*error_printf)(FILE* stream, const char* format, ...);
    struct ubpf_jit_result (*jit_translate)(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, enum JitMode jit_mode);
    bool (*jit_update_dispatcher)(
        struct ubpf_vm* vm,
        external_function_dispatcher_t new_dispatcher,
        uint8_t* buffer,
        size_t size,
        uint32_t offset);
    bool (*jit_update_helper)(
        struct ubpf_vm* vm, ext_func new_helper, unsigned int idx, uint8_t* buffer, size_t size, uint32_t offset);
    int unwind_stack_extension_index;
    uint64_t pointer_secret;
    ubpf_data_relocation data_relocation_function;
    void* data_relocation_user_data;
    ubpf_bounds_check bounds_check_function;
    void* bounds_check_user_data;
    int instruction_limit;
#ifdef DEBUG
    uint64_t* regs;
#endif
};

struct ubpf_stack_frame
{
    uint16_t stack_usage;
    uint16_t return_address;
    uint64_t saved_registers[5];
};

/* The various JIT targets.  */

// arm64
struct ubpf_jit_result
ubpf_translate_arm64(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, enum JitMode jit_mode);
bool
ubpf_jit_update_dispatcher_arm64(
    struct ubpf_vm* vm, external_function_dispatcher_t new_dispatcher, uint8_t* buffer, size_t size, uint32_t offset);
bool
ubpf_jit_update_helper_arm64(
    struct ubpf_vm* vm, ext_func new_helper, unsigned int idx, uint8_t* buffer, size_t size, uint32_t offset);

// x86_64
struct ubpf_jit_result
ubpf_translate_x86_64(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, enum JitMode jit_mode);
bool
ubpf_jit_update_dispatcher_x86_64(
    struct ubpf_vm* vm, external_function_dispatcher_t new_dispatcher, uint8_t* buffer, size_t size, uint32_t offset);
bool
ubpf_jit_update_helper_x86_64(
    struct ubpf_vm* vm, ext_func new_helper, unsigned int idx, uint8_t* buffer, size_t size, uint32_t offset);

// uhm, hello?
struct ubpf_jit_result
ubpf_translate_null(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, enum JitMode jit_mode);
bool
ubpf_jit_update_dispatcher_null(
    struct ubpf_vm* vm, external_function_dispatcher_t new_dispatcher, uint8_t* buffer, size_t size, uint32_t offset);
bool
ubpf_jit_update_helper_null(
    struct ubpf_vm* vm, ext_func new_helper, unsigned int idx, uint8_t* buffer, size_t size, uint32_t offset);

char*
ubpf_error(const char* fmt, ...);
unsigned int
ubpf_lookup_registered_function(struct ubpf_vm* vm, const char* name);
uint64_t
ubpf_dispatch_to_external_helper(
    uint64_t p0, uint64_t p1, uint64_t p2, uint64_t p3, uint64_t p4, const struct ubpf_vm* vm, unsigned int idx);

/**
 * @brief Fetch the instruction at the given index.
 *
 * @param[in] vm The VM to fetch the instruction from.
 * @param[in] pc The index of the instruction to fetch.
 * @return The instruction.
 */
struct ebpf_inst
ubpf_fetch_instruction(const struct ubpf_vm* vm, uint16_t pc);

/**
 * @brief Store the given instruction at the given index.
 *
 * @param[in] vm The VM to store the instruction in.
 * @param[in] pc The index of the instruction to store.
 * @param[in] inst The instruction to store.
 */
void
ubpf_store_instruction(const struct ubpf_vm* vm, uint16_t pc, struct ebpf_inst inst);

uint16_t
ubpf_stack_usage_for_local_func(const struct ubpf_vm* vm, uint16_t pc);

bool
ubpf_calculate_stack_usage_for_local_func(const struct ubpf_vm* vm, uint16_t pc, char** errmsg);

#endif
