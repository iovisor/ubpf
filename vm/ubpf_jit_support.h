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
};

/* Special values for target_pc in struct jump */
#define TARGET_PC_EXIT ~UINT32_C(0)
#define TARGET_PC_ENTER (~UINT32_C(0) & 0x01)
#define TARGET_PC_RETPOLINE (~UINT32_C(0) & 0x0101)
#define TARGET_PC_EXTERNAL_DISPATCHER (~UINT32_C(0) & 0x010101)
#define TARGET_LOAD_HELPER_TABLE (~UINT32_C(0) & 0x01010101)

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
    int num_jumps;
    int num_loads;
    int num_leas;
    uint32_t stack_size;
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
