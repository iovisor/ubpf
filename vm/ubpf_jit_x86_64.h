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

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "ubpf.h"
#include "ubpf_int.h"

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

struct patchable_relative
{
    uint32_t offset_loc;
    uint32_t target_pc;
    uint32_t target_offset;
};

/* Special values for target_pc in struct jump */
#define TARGET_PC_EXIT -1
#define TARGET_PC_RETPOLINE -3
#define TARGET_PC_EXTERNAL_DISPATCHER -4

struct jit_state
{
    uint8_t* buf;
    uint32_t offset;
    uint32_t size;
    uint32_t* pc_locs;
    uint32_t exit_loc;
    uint32_t unwind_loc;
    uint32_t retpoline_loc;
    uint32_t dispatcher_loc;
    struct patchable_relative* jumps;
    struct patchable_relative* loads;
    int num_jumps;
    int num_loads;
};

static inline void
emit_bytes(struct jit_state* state, void* data, uint32_t len)
{
    assert(state->offset <= state->size - len);
    if ((state->offset + len) > state->size) {
        state->offset = state->size;
        return;
    }
    memcpy(state->buf + state->offset, data, len);
    state->offset += len;
}

static inline void
emit1(struct jit_state* state, uint8_t x)
{
    emit_bytes(state, &x, sizeof(x));
}

static inline void
emit2(struct jit_state* state, uint16_t x)
{
    emit_bytes(state, &x, sizeof(x));
}

static inline void
emit4(struct jit_state* state, uint32_t x)
{
    emit_bytes(state, &x, sizeof(x));
}

static inline void
emit8(struct jit_state* state, uint64_t x)
{
    emit_bytes(state, &x, sizeof(x));
}

static inline void
emit_jump_target_address(struct jit_state* state, int32_t target_pc)
{
    if (state->num_jumps == UBPF_MAX_INSTS) {
        return;
    }
    struct patchable_relative* jump = &state->jumps[state->num_jumps++];
    jump->offset_loc = state->offset;
    jump->target_pc = target_pc;
    emit4(state, 0);
}

static inline void
emit_jump_target_offset(struct jit_state* state, uint32_t jump_loc, uint32_t jump_state_offset)
{
    if (state->num_jumps == UBPF_MAX_INSTS) {
        return;
    }
    struct patchable_relative* jump = &state->jumps[state->num_jumps++];
    jump->offset_loc = jump_loc;
    jump->target_offset = jump_state_offset;
}

static inline void
emit_modrm(struct jit_state* state, int mod, int r, int m)
{
    assert(!(mod & ~0xc0));
    emit1(state, (mod & 0xc0) | ((r & 7) << 3) | (m & 7));
}

static inline void
emit_modrm_reg2reg(struct jit_state* state, int r, int m)
{
    emit_modrm(state, 0xc0, r, m);
}

static inline void
emit_modrm_and_displacement(struct jit_state* state, int r, int m, int32_t d)
{
    if (d == 0 && (m & 7) != RBP) {
        emit_modrm(state, 0x00, r, m);
    } else if (d >= -128 && d <= 127) {
        emit_modrm(state, 0x40, r, m);
        emit1(state, d);
    } else {
        emit_modrm(state, 0x80, r, m);
        emit4(state, d);
    }
}

static inline void
emit_rex(struct jit_state* state, int w, int r, int x, int b)
{
    assert(!(w & ~1));
    assert(!(r & ~1));
    assert(!(x & ~1));
    assert(!(b & ~1));
    emit1(state, 0x40 | (w << 3) | (r << 2) | (x << 1) | b);
}

/*
 * Emits a REX prefix with the top bit of src and dst.
 * Skipped if no bits would be set.
 */
static inline void
emit_basic_rex(struct jit_state* state, int w, int src, int dst)
{
    if (w || (src & 8) || (dst & 8)) {
        emit_rex(state, w, !!(src & 8), 0, !!(dst & 8));
    }
}

static inline void
emit_push(struct jit_state* state, int r)
{
    emit_basic_rex(state, 0, 0, r);
    emit1(state, 0x50 | (r & 7));
}

static inline void
emit_pop(struct jit_state* state, int r)
{
    emit_basic_rex(state, 0, 0, r);
    emit1(state, 0x58 | (r & 7));
}

/* REX prefix and ModRM byte */
/* We use the MR encoding when there is a choice */
/* 'src' is often used as an opcode extension */
static inline void
emit_alu32(struct jit_state* state, int op, int src, int dst)
{
    emit_basic_rex(state, 0, src, dst);
    emit1(state, op);
    emit_modrm_reg2reg(state, src, dst);
}

/* REX prefix, ModRM byte, and 32-bit immediate */
static inline void
emit_alu32_imm32(struct jit_state* state, int op, int src, int dst, int32_t imm)
{
    emit_alu32(state, op, src, dst);
    emit4(state, imm);
}

/* REX prefix, ModRM byte, and 8-bit immediate */
static inline void
emit_alu32_imm8(struct jit_state* state, int op, int src, int dst, int8_t imm)
{
    emit_alu32(state, op, src, dst);
    emit1(state, imm);
}

/* REX.W prefix and ModRM byte */
/* We use the MR encoding when there is a choice */
/* 'src' is often used as an opcode extension */
static inline void
emit_alu64(struct jit_state* state, int op, int src, int dst)
{
    emit_basic_rex(state, 1, src, dst);
    emit1(state, op);
    emit_modrm_reg2reg(state, src, dst);
}

/* REX.W prefix, ModRM byte, and 32-bit immediate */
static inline void
emit_alu64_imm32(struct jit_state* state, int op, int src, int dst, int32_t imm)
{
    emit_alu64(state, op, src, dst);
    emit4(state, imm);
}

/* REX.W prefix, ModRM byte, and 8-bit immediate */
static inline void
emit_alu64_imm8(struct jit_state* state, int op, int src, int dst, int8_t imm)
{
    emit_alu64(state, op, src, dst);
    emit1(state, imm);
}

/* Register to register mov */
static inline void
emit_mov(struct jit_state* state, int src, int dst)
{
    emit_alu64(state, 0x89, src, dst);
}

static inline void
emit_cmp_imm32(struct jit_state* state, int dst, int32_t imm)
{
    emit_alu64_imm32(state, 0x81, 7, dst, imm);
}

static inline void
emit_cmp32_imm32(struct jit_state* state, int dst, int32_t imm)
{
    emit_alu32_imm32(state, 0x81, 7, dst, imm);
}

static inline void
emit_cmp(struct jit_state* state, int src, int dst)
{
    emit_alu64(state, 0x39, src, dst);
}

static inline void
emit_cmp32(struct jit_state* state, int src, int dst)
{
    emit_alu32(state, 0x39, src, dst);
}

static inline void
emit_jcc(struct jit_state* state, int code, int32_t target_pc)
{
    emit1(state, 0x0f);
    emit1(state, code);
    emit_jump_target_address(state, target_pc);
}

/* Load [src + offset] into dst */
static inline void
emit_load(struct jit_state* state, enum operand_size size, int src, int dst, int32_t offset)
{
    emit_basic_rex(state, size == S64, dst, src);

    if (size == S8 || size == S16) {
        /* movzx */
        emit1(state, 0x0f);
        emit1(state, size == S8 ? 0xb6 : 0xb7);
    } else if (size == S32 || size == S64) {
        /* mov */
        emit1(state, 0x8b);
    }

    emit_modrm_and_displacement(state, dst, src, offset);
}

/* Load sign-extended immediate into register */
static inline void
emit_load_imm(struct jit_state* state, int dst, int64_t imm)
{
    if (imm >= INT32_MIN && imm <= INT32_MAX) {
        emit_alu64_imm32(state, 0xc7, 0, dst, imm);
    } else {
        /* movabs $imm,dst */
        emit_basic_rex(state, 1, 0, dst);
        emit1(state, 0xb8 | (dst & 7));
        emit8(state, imm);
    }
}

/* Load sign-extended immediate into register */
static inline void
emit_load_relative(struct jit_state* state, int target_pc)
{
    if (state->num_loads == UBPF_MAX_INSTS) {
        return;
    }
    emit1(state, 0x48);
    emit1(state, 0x8b);
    emit1(state, 0x05);
    struct patchable_relative* load = &state->loads[state->num_loads++];
    load->offset_loc = state->offset;
    load->target_pc = target_pc;
    emit4(state, 0);
}

/* Store register src to [dst + offset] */
static inline void
emit_store(struct jit_state* state, enum operand_size size, int src, int dst, int32_t offset)
{
    if (size == S16) {
        emit1(state, 0x66); /* 16-bit override */
    }
    int rexw = size == S64;
    if (rexw || src & 8 || dst & 8 || size == S8) {
        emit_rex(state, rexw, !!(src & 8), 0, !!(dst & 8));
    }
    emit1(state, size == S8 ? 0x88 : 0x89);
    emit_modrm_and_displacement(state, src, dst, offset);
}

/* Store immediate to [dst + offset] */
static inline void
emit_store_imm32(struct jit_state* state, enum operand_size size, int dst, int32_t offset, int32_t imm)
{
    if (size == S16) {
        emit1(state, 0x66); /* 16-bit override */
    }
    emit_basic_rex(state, size == S64, 0, dst);
    emit1(state, size == S8 ? 0xc6 : 0xc7);
    emit_modrm_and_displacement(state, 0, dst, offset);
    if (size == S32 || size == S64) {
        emit4(state, imm);
    } else if (size == S16) {
        emit2(state, imm);
    } else if (size == S8) {
        emit1(state, imm);
    }
}

static inline void
emit_ret(struct jit_state* state)
{
    emit1(state, 0xc3);
}

static inline void
emit_jmp(struct jit_state* state, uint32_t target_pc)
{
    emit1(state, 0xe9);
    emit_jump_target_address(state, target_pc);
}

static inline void
emit_dispatched_external_helper_call(struct jit_state* state, const struct ubpf_vm* vm, unsigned int idx)
{
    /*
     * When we enter here, our stack is 16-byte aligned. Keep
     * it that way!
     */

#if defined(_WIN32)
    /* We have to create a little space to keep our 16-byte
     * alignment happy
     */
    emit_alu64_imm32(state, 0x81, 5, RSP, sizeof(uint64_t));

    emit_load_imm(state, RAX, (uint64_t)vm->dispatcher_cookie);
    emit_push(state, RAX);

    emit_load_imm(state, RAX, idx);
    emit_push(state, RAX);

    /* Windows x64 ABI spills 5th parameter to stack */
    emit_push(state, map_register(5));

    /* Windows x64 ABI requires home register space.
     * Allocate home register space - 4 registers.
     */
    emit_alu64_imm32(state, 0x81, 5, RSP, 4 * sizeof(uint64_t));
#else
    // Save r9 -- I need it for a parameter!
    emit_push(state, R9);

    // Before it's a parameter, use it for a push.
    emit_load_imm(state, R9, (uint64_t)vm->dispatcher_cookie);
    emit_push(state, R9);

    emit_load_imm(state, R9, (uint64_t)idx);
#endif

    emit_load_relative(state, TARGET_PC_EXTERNAL_DISPATCHER);

#ifndef UBPF_DISABLE_RETPOLINES
    emit1(state, 0xe8); // e8 is the opcode for a CALL
    emit_jump_target_address(state, TARGET_PC_RETPOLINE);
#else
    /* TODO use direct call when possible */
    /* callq *%rax */
    emit1(state, 0xff);
    // ModR/M byte: b11010000b = xd
    //               ^
    //               register-direct addressing.
    //                 ^
    //                 opcode extension (2)
    //                    ^
    //                    rax is register 0
    emit1(state, 0xd0);
#endif

    // The result is in RAX. Nothing to do there.
    // Just rationalize the stack!

#if defined(_WIN32)
    /* Deallocate home register space + 3 spilled parameters + alignment space */
    emit_alu64_imm32(state, 0x81, 0, RSP, (4 + 3 + 1) * sizeof(uint64_t));
#else
    emit_pop(state, R9); // First one is a throw away (it's where our parameter was!)
    emit_pop(state, R9); // This one is real!
#endif
}

#endif
