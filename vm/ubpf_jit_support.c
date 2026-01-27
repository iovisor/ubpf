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
#include "ubpf.h"
#include "ubpf_int.h"
#include <memory.h>

#if defined(_WIN32)
#define _CRT_RAND_S
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#elif defined(__unix__) || defined(__APPLE__)
#include <fcntl.h>
#include <unistd.h>
#endif

int
initialize_jit_state_result(
    struct jit_state* state,
    struct ubpf_jit_result* compile_result,
    uint8_t* buffer,
    uint32_t size,
    enum JitMode jit_mode,
    char** errmsg)
{
    compile_result->compile_result = UBPF_JIT_COMPILE_FAILURE;
    compile_result->errmsg = NULL;
    compile_result->external_dispatcher_offset = 0;
    compile_result->jit_mode = jit_mode;

    state->offset = 0;
    state->size = size;
    state->buf = buffer;
    state->pc_locs = calloc(UBPF_MAX_INSTS + 1, sizeof(state->pc_locs[0]));
    state->jumps = calloc(UBPF_MAX_INSTS, sizeof(state->jumps[0]));
    state->loads = calloc(UBPF_MAX_INSTS, sizeof(state->loads[0]));
    state->leas = calloc(UBPF_MAX_INSTS, sizeof(state->leas[0]));
    state->local_calls = calloc(UBPF_MAX_INSTS, sizeof(state->local_calls[0]));
    state->num_jumps = 0;
    state->num_loads = 0;
    state->num_leas = 0;
    state->num_local_calls = 0;
    state->jit_status = NoError;
    state->jit_mode = jit_mode;
    state->bpf_function_prolog_size = 0;

    if (!state->pc_locs || !state->jumps || !state->loads || !state->leas) {
        *errmsg = ubpf_error("Could not allocate space needed to JIT compile eBPF program");
        return -1;
    }

    return 0;
}

void
release_jit_state_result(struct jit_state* state, struct ubpf_jit_result* compile_result)
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
    free(state->local_calls);
    state->local_calls = NULL;
}

void
emit_patchable_relative(struct patchable_relative* table,
    uint32_t offset, struct PatchableTarget target, size_t index)
{
    struct patchable_relative* jump = &table[index];
    jump->offset_loc = offset;
    jump->target = target;
}

void
note_load(struct jit_state* state, struct PatchableTarget target)
{
    emit_patchable_relative(state->loads, state->offset, target, state->num_loads++);
}

void
note_lea(struct jit_state* state, struct PatchableTarget target)
{
    emit_patchable_relative(state->leas, state->offset, target, state->num_leas++);
}

void
modify_patchable_relatives_target(struct patchable_relative* table, size_t table_size, uint32_t patchable_relative_src, struct PatchableTarget target)
{
    for (size_t index = 0; index < table_size; index++) {
        if (table[index].offset_loc == patchable_relative_src) {
            table[index].target = target;
        }
    }
}

void
emit_jump_target(struct jit_state* state, uint32_t jump_src)
{
    DECLARE_PATCHABLE_TARGET(pt);
    pt.is_special = false;
    pt.target.regular.jit_target_pc = state->offset;

    modify_patchable_relatives_target(state->jumps, state->num_jumps, jump_src, pt);
}

/**
 * @brief Generate a cryptographically secure random 64-bit value for constant blinding.
 *
 * This function uses platform-specific secure random number generators:
 * - Windows: BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG
 * - Unix/Linux/macOS: /dev/urandom
 *
 * @return A 64-bit random value.
 */
uint64_t
ubpf_generate_blinding_constant(void)
{
    uint64_t random_value = 0;

#if defined(_WIN32)
    // Windows: Use BCryptGenRandom for cryptographically secure random
    BCryptGenRandom(NULL, (PUCHAR)&random_value, sizeof(random_value), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#elif defined(__unix__) || defined(__APPLE__)
    // Unix/Linux/macOS: Use /dev/urandom for cryptographically secure random
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t result = read(fd, &random_value, sizeof(random_value));
        close(fd);
        if (result != sizeof(random_value)) {
            // Fallback: use time-based random if read fails
            random_value = (uint64_t)rand() ^ ((uint64_t)rand() << 32);
        }
    } else {
        // Fallback: use time-based random if open fails
        random_value = (uint64_t)rand() ^ ((uint64_t)rand() << 32);
    }
#else
    // Generic fallback: use standard rand (not cryptographically secure)
    random_value = (uint64_t)rand() ^ ((uint64_t)rand() << 32);
#endif

    return random_value;
}
