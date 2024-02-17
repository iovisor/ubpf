// Copyright (c) 2015 Big Switch Networks, Inc
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

#ifndef UBPF_JIT_X86_64_H
#define UBPF_JIT_X86_64_H

#include "ubpf.h"
#include "ubpf_int.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

#define RAX 0
#define RCX 1
#define RDX 2
#define RBX 3
#define RSP 4
#define RBP 5
#define RIP 5
#define RSI 6
#define RDI 7
#define R8 8
#define R9 9
#define R10 10
#define R11 11
#define R12 12
#define R13 13
#define R14 14
#define R15 15

enum operand_size
{
    S8,
    S16,
    S32,
    S64,
};

struct jump
{
    uint32_t offset_loc;
    uint32_t target_pc;
    uint32_t target_offset;
};

struct load
{
    uint32_t offset_loc;
    uint32_t target_pc;
    uint32_t target_offset;
};

/* Special values for target_pc in struct jump */
#define TARGET_PC_EXIT -1
#define TARGET_PC_RETPOLINE -3
#define TARGET_PC_HELPERS -4

struct jit_state
{
    uint8_t* buf;
    uint32_t offset;
    uint32_t size;
    uint32_t* pc_locs;
    uint32_t exit_loc;
    uint32_t unwind_loc;
    uint32_t retpoline_loc;
    uint32_t helper_trampoline_loc;
    struct jump* jumps;
    struct load* loads;
    int num_jumps;
    int num_loads;
};

#endif
