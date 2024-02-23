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

#include <ubpf.h>
#include "ebpf.h"

struct ebpf_inst;
typedef uint64_t (*ext_func)(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);

struct ubpf_vm
{
    struct ebpf_inst* insts;
    uint16_t num_insts;
    ubpf_jit_fn jitted;
    size_t jitted_size;

    ext_func* ext_funcs;
    bool* int_funcs;
    const char** ext_func_names;

    external_function_dispatcher_t dispatcher;
    external_function_validate_t dispatcher_validate;
    void* dispatcher_cookie;

    bool bounds_check_enabled;
    int (*error_printf)(FILE* stream, const char* format, ...);
    int (*translate)(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg);
    int unwind_stack_extension_index;
    uint64_t pointer_secret;
    ubpf_data_relocation data_relocation_function;
    void* data_relocation_user_data;
    ubpf_bounds_check bounds_check_function;
    void* bounds_check_user_data;
#ifdef DEBUG
    uint64_t* regs;
#endif
};

struct ubpf_stack_frame
{
    uint16_t return_address;
    uint64_t saved_registers[4];
};

/* The various JIT targets.  */
int
ubpf_translate_arm64(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg);
int
ubpf_translate_x86_64(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg);
int
ubpf_translate_null(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg);

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

#endif
