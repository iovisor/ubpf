// Copyright (c) Will Hawkins
// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright Will Hawkins
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

#include "ubpf_jit_support.h"
#include <stdlib.h>
#include "ubpf_int.h"

int
initialize_jit_state_result(struct jit_state *state, struct ubpf_jit_result *compile_result, uint8_t *buffer, uint32_t size, char **errmsg) {
    compile_result->compile_result = UBPF_JIT_COMPILE_FAILURE;
    compile_result->errmsg = NULL;
    compile_result->external_dispatcher_offset = 0;

    state->offset = 0;
    state->size = size;
    state->buf = buffer;
    state->pc_locs = calloc(UBPF_MAX_INSTS + 1, sizeof(state->pc_locs[0]));
    state->jumps = calloc(UBPF_MAX_INSTS, sizeof(state->jumps[0]));
    state->loads = calloc(UBPF_MAX_INSTS, sizeof(state->loads[0]));
    state->leas = calloc(UBPF_MAX_INSTS, sizeof(state->leas[0]));
    state->num_jumps = 0;
    state->num_loads = 0;
    state->num_leas = 0;
    state->jit_status = NoError;

    if (!state->pc_locs || !state->jumps || !state->loads || !state->leas) {
        *errmsg = ubpf_error("Could not allocate space needed to JIT compile eBPF program");
        return -1;
    }

    return 0;
}

void
release_jit_state_result(struct jit_state *state, struct ubpf_jit_result *compile_result)
{
    UNUSED_PARAMETER(compile_result);
    free(state->pc_locs);
    state->pc_locs = NULL;
    free(state->jumps);
    state->jumps = NULL;
    free(state->loads);
    state->loads = NULL;
    free(state->leas);
    state->leas = NULL;
}

void
emit_patchable_relative(uint32_t offset, uint32_t target_pc, uint32_t manual_target_offset, struct patchable_relative *table, size_t index)
{
    struct patchable_relative* jump = &table[index];
    jump->offset_loc = offset;
    jump->target_pc = target_pc;
    jump->target_offset = manual_target_offset;
}

void
note_load(struct jit_state* state, uint32_t target_pc)
{
    emit_patchable_relative(state->offset, target_pc, 0, state->loads, state->num_loads++);
}

void
note_lea(struct jit_state* state, uint32_t offset)
{
    emit_patchable_relative(state->offset, offset, 0, state->leas, state->num_leas++);
}


void
fixup_jump_target(struct patchable_relative *table, size_t table_size, uint32_t src_offset, uint32_t dest_offset)
{
    for (size_t index = 0; index < table_size; index++) {
        if (table[index].offset_loc == src_offset) {
            table[index].target_offset = dest_offset;
        }
    }
}

void
emit_jump_target(struct jit_state* state, uint32_t jump_src)
{
    fixup_jump_target(state->jumps, state->num_jumps, jump_src, state->offset);
}