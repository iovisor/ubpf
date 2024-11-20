// Copyright (c) Will Hawkins
// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2015 Big Switch Networks, Inc
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

/*
 * Generic x86-64 code generation functions
 */

#ifndef UBPF_JIT_SUPPORT_H
#define UBPF_JIT_SUPPORT_H

#include <stdint.h>
#include <sys/types.h>
#include "ubpf_int.h"

enum JitProgress
{
    NoError,
    TooManyJumps,
    TooManyLoads,
    TooManyLeas,
    TooManyLocalCalls,
    NotEnoughSpace,
    UnexpectedInstruction,
    UnknownInstruction
};

struct patchable_relative
{
    /* Where in the instruction stream should this relative address be patched. */
    uint32_t offset_loc;
    /* Which PC should this target. The ultimate offset will be determined
     * automatically unless ... */
    uint32_t target_pc;
    /* ... the target_offset is set which overrides the automatic lookup. */
    uint32_t target_offset;
    /* Whether or not this patchable relative is _near_. */
    bool near;
};

/* Special values for target_pc in struct jump */
#define TARGET_PC_EXIT (~UINT32_C(0) & 0xF0000000)
#define TARGET_PC_ENTER (~UINT32_C(0) & 0xF0000001)
#define TARGET_PC_RETPOLINE (~UINT32_C(0) & 0xF0000101)
#define TARGET_PC_EXTERNAL_DISPATCHER (~UINT32_C(0) & 0xF0010101)
#define TARGET_LOAD_HELPER_TABLE (~UINT32_C(0) & 0xF1010101)

struct jit_state
{
    uint8_t* buf;
    uint32_t offset;
    uint32_t size;
    uint32_t* pc_locs;
    uint32_t exit_loc;
    uint32_t entry_loc;
    uint32_t unwind_loc;
    /* The offset (from the start of the JIT'd code) to the location
     * of the retpoline (if retpoline support is enabled).
     */
    uint32_t retpoline_loc;
    /* The offset (from the start of the JIT'd code) to the location
     * of the address of the external helper dispatcher. The address
     * at that location during execution may be null if no external
     * helper dispatcher is registered. See commentary in ubpf_jit_x86_64.c.
     */
    uint32_t dispatcher_loc;
    /* The offset (from the start of the JIT'd code) to the location
     * of a consecutive series of XXXX addresses that contain pointers
     * to external helper functions. The address' position in the sequence
     * corresponds to the index of the helper function. Addresses may
     * be null but validation guarantees that (at the time the eBPF program
     * is loaded), if a helper function is called, there is an appropriately
     * registered handler. See commentary in ubpf_jit_x86_64.c.
     */
    uint32_t helper_table_loc;
    enum JitProgress jit_status;
    enum JitMode jit_mode;
    struct patchable_relative* jumps;
    struct patchable_relative* loads;
    struct patchable_relative* leas;
    struct patchable_relative* local_calls;
    int num_jumps;
    int num_loads;
    int num_leas;
    int num_local_calls;
    uint32_t stack_size;
    size_t bpf_function_prolog_size; // Count of bytes emitted at the start of the function.
};

int
initialize_jit_state_result(
    struct jit_state* state,
    struct ubpf_jit_result* compile_result,
    uint8_t* buffer,
    uint32_t size,
    enum JitMode jit_mode,
    char** errmsg);

void
release_jit_state_result(struct jit_state* state, struct ubpf_jit_result* compile_result);

/** @brief Add an entry to the given patchable relative table.
 *
 * Emitting an entry into the patchable relative table means that resolution of the target
 * address can be postponed until all the instructions are emitted. Note: This function does
 * not emit any instructions -- it simply updates metadata to guide resolution after code generation.
 * _target_pc_ is in eBPF instruction units and _manual_target_offset_ is in JIT'd instruction
 * units. In other words, setting _target_pc_ instead of _manual_target_offset_ will guide
 * the resolution algorithm to find the JIT'd code that corresponds to the eBPF instruction
 * (as the jump target); alternatively, setting _manual_target_offset_ will direct the
 * resolution algorithm to find the JIT'd instruction at that offset (as the target).
 *
 * @param[in] offset The offset in the JIT'd code where the to-be-resolved target begins.
 * @param[in] target_pc The offset of the eBPF instruction targeted by the jump.
 * @param[in] manual_target_offset The offset of the JIT'd instruction targeted by the jump.
 *                                 A non-zero value for this parameter overrides _target_pc_`.
 * @param[in] table The relative patchable table to update.
 * @param[in] index A spot in the _table_ to add/update according to the given parameters.
 * @param[in] near Whether the target is relatively near the jump.
 */
void
emit_patchable_relative_ex(
    uint32_t offset,
    uint32_t target_pc,
    uint32_t manual_target_offset,
    struct patchable_relative* table,
    size_t index,
    bool near);

/** @brief Add an entry to the given patchable relative table.
 *
 * See emit_patchable_relative_ex. emit_patchable_relative's parameters have the same meaning
 * but fixes the _near_ argument to false.
 */
void
emit_patchable_relative(
    uint32_t offset, uint32_t target_pc, uint32_t manual_target_offset, struct patchable_relative* table, size_t index);

void
note_load(struct jit_state* state, uint32_t target_pc);

void
note_lea(struct jit_state* state, uint32_t offset);

void
emit_jump_target(struct jit_state* state, uint32_t jump_src);

void
fixup_jump_target(struct patchable_relative* table, size_t table_size, uint32_t src_offset, uint32_t dest_offset);
#endif
