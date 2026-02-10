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
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#elif defined(__linux__)
#include <sys/random.h>
#endif

// Thread-safe initialization for fallback random seeding
#if defined(_WIN32)
static INIT_ONCE g_seed_init_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK
init_seed_once(PINIT_ONCE InitOnce, PVOID Parameter, PVOID* lpContext)
{
    (void)InitOnce;
    (void)Parameter;
    (void)lpContext;
    srand((unsigned int)time(NULL));
    return TRUE;
}
#elif defined(__GNUC__) || defined(__clang__)
static void
init_seed(void) __attribute__((constructor));
static void
init_seed(void)
{
    srand((unsigned int)time(NULL));
}
#else
// For other platforms, accept potential race condition on first use
static volatile int seed_initialized = 0;
static void
ensure_seed_initialized(void)
{
    if (!seed_initialized) {
        srand((unsigned int)time(NULL));
        seed_initialized = 1;
    }
}
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
emit_patchable_relative(struct patchable_relative* table, uint32_t offset, struct PatchableTarget target, size_t index)
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
modify_patchable_relatives_target(
    struct patchable_relative* table, size_t table_size, uint32_t patchable_relative_src, struct PatchableTarget target)
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
 * - Linux: getrandom() system call
 * - macOS: arc4random()
 *
 * Thread safety: This function is thread-safe. Platform RNGs are thread-safe,
 * and fallback rand() uses thread-safe initialization where available.
 *
 * @return A 64-bit random value.
 */
uint64_t
ubpf_generate_blinding_constant(void)
{
    uint64_t random_value = 0;

#if defined(_WIN32)
    // Windows: Use BCryptGenRandom for cryptographically secure random
    NTSTATUS status =
        BCryptGenRandom(NULL, (PUCHAR)&random_value, sizeof(random_value), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        // Fallback on error - use thread-safe initialization
        InitOnceExecuteOnce(&g_seed_init_once, init_seed_once, NULL, NULL);
        random_value = ((uint64_t)rand() << 32) | (uint64_t)rand();
    }
#elif defined(__linux__)
    // Linux: Use getrandom() system call (available since kernel 3.17)
    // This doesn't require opening /dev/urandom and is more efficient
    ssize_t result = getrandom(&random_value, sizeof(random_value), 0);
    if (result != sizeof(random_value)) {
        // Fallback: use time-based random if getrandom fails
        // Seed is initialized at program start via constructor
        random_value = ((uint64_t)rand() << 32) | (uint64_t)rand();
    }
#elif defined(__APPLE__)
    // macOS: Use arc4random_buf which is available and doesn't need seeding
    arc4random_buf(&random_value, sizeof(random_value));
#else
    // Generic fallback: use standard rand (not cryptographically secure)
    ensure_seed_initialized();
    random_value = ((uint64_t)rand() << 32) | (uint64_t)rand();
#endif

    return random_value;
}
