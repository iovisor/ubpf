// Copyright (c) 2015 Big Switch Networks, Inc
// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2015 Big Switch Networks, Inc
 * Copyright 2017 Google Inc.
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

#include "ubpf.h"
#include "ubpf_jit_support.h"
#define _GNU_SOURCE

#include "ebpf.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/mman.h>
#include <memory.h>
#include <assert.h>
#include "ubpf_int.h"

#if !defined(_countof)
#define _countof(array) (sizeof(array) / sizeof(array[0]))
#endif

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

#define VOLATILE_CTXT 11

enum operand_size
{
    S8,
    S16,
    S32,
    S64,
};

#define REGISTER_MAP_SIZE 11

/*
 * There are two common x86-64 calling conventions, as discussed at
 * https://en.wikipedia.org/wiki/X86_calling_conventions#x86-64_calling_conventions
 *
 * Please Note: R12 is special and we are *not* using it. As a result, it is omitted
 * from the list of non-volatile registers for both platforms (even though it is, in
 * fact, non-volatile).
 *
 * BPF R0-R4 are "volatile"
 * BPF R5-R10 are "non-volatile"
 * In general, we attempt to map BPF volatile registers to x64 volatile and BPF non-
 * volatile to x64 non-volatile.
 */

// Because of this designation and the way that the registers are mapped
// between native and BPF, the value in native R10 is always something
// the BPF program has to consider trashed across external function calls.
// Therefore, during invocation of external function calls, we can use
// native R10 for free.
#define RCX_ALT R10

#if defined(_WIN32)
static int platform_nonvolatile_registers[] = {RBP, RBX, RDI, RSI, R12, R13, R14, R15}; // Callee-saved registers.
static int platform_volatile_registers[] = {RAX, RDX, RCX, R8, R9, R10, R11}; // Caller-saved registers (if needed).
static int platform_parameter_registers[] = {RCX, RDX, R8, R9};
static int register_map[REGISTER_MAP_SIZE] = {
    // Scratch registers
    RAX,
    R10,
    RDX,
    R8,
    R9,
    R12,
    // Non-volatile registers
    RBX,
    RDI,
    RSI,
    R14,
    R15, // Until further notice, r15 must be mapped to eBPF register r10
};
#else
static int platform_nonvolatile_registers[] = {RBP, RBX, R12, R13, R14, R15}; // Callee-saved registers.
static int platform_volatile_registers[] = {
    RAX, RDI, RSI, RDX, RCX, R8, R9, R10, R11}; // Caller-saved registers (if needed).
static int platform_parameter_registers[] = {RDI, RSI, RDX, RCX, R8, R9};
static int register_map[REGISTER_MAP_SIZE] = {
    // Scratch registers
    RAX,
    RDI,
    RSI,
    RDX,
    R10,
    R8,
    // Non-volatile registers
    RBX,
    R12,
    R13,
    R14,
    R15, // Until further notice, r15 must be mapped to eBPF register r10
};
#endif

/* Return the x86 register for the given eBPF register */
static int
map_register(int r)
{
    assert(r < _BPF_REG_MAX);
    return register_map[r % _BPF_REG_MAX];
}

static inline void
emit_bytes(struct jit_state* state, void* data, uint32_t len)
{
    // Never emit any bytes if there is an error!
    if (state->jit_status != NoError) {
        return;
    }

    // If we are trying to emit bytes to a spot outside the buffer,
    // then there is not enough space!
    if ((state->offset + len) > state->size) {
        state->jit_status = NotEnoughSpace;
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

static void
emit_4byte_offset_placeholder(struct jit_state* state)
{
    emit4(state, 0);
}

static uint32_t
emit_jump_address_reloc(struct jit_state* state, struct PatchableTarget target)
{
    if (state->num_jumps == state->max_insts) {
        state->jit_status = TooManyJumps;
        return 0;
    }
    uint32_t target_address_offset = state->offset;
    emit_patchable_relative(state->jumps, state->offset, target, state->num_jumps++);
    emit_4byte_offset_placeholder(state);
    return target_address_offset;
}

static uint32_t
emit_local_call_address_reloc(struct jit_state* state, struct PatchableTarget target)
{
    if (state->num_local_calls == state->max_insts) {
        state->jit_status = TooManyLocalCalls;
        return 0;
    }
    uint32_t target_address_offset = state->offset;
    emit_patchable_relative(state->local_calls, state->offset, target, state->num_local_calls++);
    emit_4byte_offset_placeholder(state);
    return target_address_offset;
}

static inline void
emit_modrm(struct jit_state* state, int mod, int r, int m)
{
    // Only the top 2 bits of the mod should be used.
    assert(!(mod & ~0xc0));
    emit1(state, (mod & 0xc0) | ((r & 7) << 3) | (m & 7));
}

static inline void
emit_modrm_reg2reg(struct jit_state* state, int r, int m)
{
    emit_modrm(state, 0xc0, r, m);
}

/**
 * @brief Emit an ModRM byte and accompanying displacement.
 * Special case for the situation where the displacement is 0.
 *
 * @param[in] state The JIT state in which to emit this instruction.
 * @param[in] reg The value for the reg of the ModRM byte.
 * @param[in] rm The value for the rm of the ModRM byte.
 * @param[in] d The displacement value
 */
static inline void
emit_modrm_and_displacement(struct jit_state* state, int reg, int rm, int32_t d)
{
    rm &= 0xf;
    reg &= 0xf;

    // Handle 0 displacement special (where we can!).
    if (d == 0 && rm != RSP && rm != RBP && rm != R12 && rm != R13) {
        emit_modrm(state, 0x00, reg, rm);
        return;
    }

    uint32_t near_disp = (d >= -128 && d <= 127);
    uint8_t mod = near_disp ? 0x40 : 0x80;

    emit_modrm(state, mod, reg, rm);
    if (rm == R12) {
        // When using R12 as the rm in (rm + disp), the actual
        // rm has to be put in an SIB. SIB value of 0x24 means:
        // scale (of index): N/A (see below)
        // index: no index
        // base: R12
        // A SIB byte with this value means that the resulting
        // encoded instruction will mimic the semantics when
        // using any other register.
        emit1(state, 0x24);
    }

    if (near_disp)
        emit1(state, d);
    else
        emit4(state, d);
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

static inline void
emit_truncate_u32(struct jit_state* state, int destination)
{
    emit_alu32_imm32(state, 0x81, 4, destination, UINT32_MAX);
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

static inline uint32_t
emit_jcc(struct jit_state* state, int code, struct PatchableTarget target)
{
    emit1(state, 0x0f);
    emit1(state, code);
    return emit_jump_address_reloc(state, target);
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

/* Load sign-extended [src + offset] into dst */
static inline void
emit_load_sx(struct jit_state* state, enum operand_size size, int src, int dst, int32_t offset)
{
    if (size == S8 || size == S16) {
        /* movsx for 8/16-bit */
        emit_basic_rex(state, 1, dst, src); /* REX.W for 64-bit result */
        emit1(state, 0x0f);
        if (size == S8) {
            emit1(state, 0xbe); /* movsx byte */
        } else {
            emit1(state, 0xbf); /* movsx word */
        }
        emit_modrm_and_displacement(state, dst, src, offset);
    } else if (size == S32) {
        /* For 32-bit sign extension, we need movsxd (REX.W + 0x63) */
        emit_basic_rex(state, 1, dst, src);
        emit1(state, 0x63);
        emit_modrm_and_displacement(state, dst, src, offset);
    }
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

/* Load sign-extended immediate into register with constant blinding */
static inline void
emit_load_imm_blinded(struct jit_state* state, int dst, int64_t imm)
{
    /* Generate random blinding constant */
    uint64_t random = ubpf_generate_blinding_constant();
    uint64_t blinded_imm = (uint64_t)imm ^ random;
    
    /* Load blinded constant: mov dst, (imm ^ random) */
    if ((int64_t)blinded_imm >= INT32_MIN && (int64_t)blinded_imm <= INT32_MAX) {
        emit_alu64_imm32(state, 0xc7, 0, dst, blinded_imm);
    } else {
        /* movabs $blinded_imm,dst */
        emit_basic_rex(state, 1, 0, dst);
        emit1(state, 0xb8 | (dst & 7));
        emit8(state, blinded_imm);
    }
    
    /* XOR with random to recover original: xor dst, random */
    if ((int64_t)random >= INT32_MIN && (int64_t)random <= INT32_MAX) {
        emit_alu64_imm32(state, 0x81, 6, dst, random);
    } else {
        /* Use R11 as temporary register for large random values (safe - it's volatile) */
        int temp_reg = (dst == R11) ? R10 : R11;
        /* mov temp_reg, random */
        emit_basic_rex(state, 1, 0, temp_reg);
        emit1(state, 0xb8 | (temp_reg & 7));
        emit8(state, random);
        /* xor dst, temp_reg */
        emit_alu64(state, 0x31, temp_reg, dst);
    }
}

/* Blinded version of emit_alu64_imm32 
 * Note: The 'src' parameter is kept to match the signature of emit_alu64_imm32,
 * but is unused because blinding loads the immediate into a temp register first.
 */
static inline void
emit_alu64_imm32_blinded(struct jit_state* state, int op, int src, int dst, int32_t imm)
{
    /* Generate random blinding constant (32-bit) */
    uint32_t random = (uint32_t)ubpf_generate_blinding_constant();
    /* Cast imm to unsigned to avoid sign extension issues during XOR */
    uint32_t imm_unsigned = (uint32_t)imm;
    int32_t blinded_imm = (int32_t)(imm_unsigned ^ random);
    
    /* Use R11 as temporary for blinded operations (safe - it's volatile) */
    int temp_reg = (dst == R11) ? R10 : R11;
    
    /* Load blinded immediate into temp register */
    /* Note: Direct call to emit_alu64_imm32 bypasses the EMIT_ALU64_IMM32 macro,
     * so these internal immediates are NOT recursively blinded */
    emit_alu64_imm32(state, 0xc7, 0, temp_reg, blinded_imm);
    /* XOR with random to recover original value */
    emit_alu64_imm32(state, 0x81, 6, temp_reg, (int32_t)random);
    
    /* Now apply the operation using the recovered value in temp_reg as source */
    /* Convert immediate opcode+extension to register-register opcode */
    int reg_op;
    if (op == 0x81) {
        /* Immediate ALU operations - map src extension to register opcode */
        switch (src) {
            case 0: reg_op = 0x01; break;  /* ADD */
            case 1: reg_op = 0x09; break;  /* OR */
            case 4: reg_op = 0x21; break;  /* AND */
            case 5: reg_op = 0x29; break;  /* SUB */
            case 6: reg_op = 0x31; break;  /* XOR */
            case 7: reg_op = 0x39; break;  /* CMP */
            default: reg_op = 0x01; break; /* Fallback to ADD */
        }
        emit_alu64(state, reg_op, temp_reg, dst);
    } else if (op == 0xc7) {
        /* MOV dst, imm becomes MOV dst, temp_reg */
        emit_alu64(state, 0x89, temp_reg, dst);  // MOV r/m64, r64
    } else {
        /* For other operations, use the opcode directly with temp_reg */
        emit_alu64(state, op, temp_reg, dst);
    }
}

/* Blinded version of emit_alu32_imm32 
 * Note: The 'src' parameter is kept to match the signature of emit_alu32_imm32,
 * but is unused because blinding loads the immediate into a temp register first.
 */
static inline void
emit_alu32_imm32_blinded(struct jit_state* state, int op, int src, int dst, int32_t imm)
{
    /* Generate random blinding constant (32-bit) */
    uint32_t random = (uint32_t)ubpf_generate_blinding_constant();
    /* Cast imm to unsigned to avoid sign extension issues during XOR */
    uint32_t imm_unsigned = (uint32_t)imm;
    int32_t blinded_imm = (int32_t)(imm_unsigned ^ random);
    
    /* Use R11 as temporary for blinded operations (safe - it's volatile) */
    int temp_reg = (dst == R11) ? R10 : R11;
    
    /* Load blinded immediate into temp register */
    /* Note: Direct call to emit_alu32_imm32 bypasses the EMIT_ALU32_IMM32 macro,
     * so these internal immediates are NOT recursively blinded */
    emit_alu32_imm32(state, 0xc7, 0, temp_reg, blinded_imm);
    /* XOR with random to recover original value */
    emit_alu32_imm32(state, 0x81, 6, temp_reg, (int32_t)random);
    
    /* Now apply the operation using the recovered value in temp_reg as source */
    /* Convert immediate opcode+extension to register-register opcode */
    int reg_op;
    if (op == 0x81) {
        /* Immediate ALU operations - map src extension to register opcode */
        switch (src) {
            case 0: reg_op = 0x01; break;  /* ADD */
            case 1: reg_op = 0x09; break;  /* OR */
            case 4: reg_op = 0x21; break;  /* AND */
            case 5: reg_op = 0x29; break;  /* SUB */
            case 6: reg_op = 0x31; break;  /* XOR */
            case 7: reg_op = 0x39; break;  /* CMP */
            default: reg_op = 0x01; break; /* Fallback to ADD */
        }
        emit_alu32(state, reg_op, temp_reg, dst);
    } else if (op == 0xc7) {
        /* MOV dst, imm becomes MOV dst, temp_reg */
        emit_alu32(state, 0x89, temp_reg, dst);  // MOV r/m32, r32
    } else {
        /* For other operations, use the opcode directly with temp_reg */
        emit_alu32(state, op, temp_reg, dst);
    }
}

/* Forward declaration for emit_store (defined later) */
static inline void
emit_store(struct jit_state* state, enum operand_size size, int src, int dst, int32_t offset);

/* Blinded version of emit_cmp_imm32 (64-bit compare with immediate) */
static inline void
emit_cmp_imm32_blinded(struct jit_state* state, int dst, int32_t imm)
{
    /* Generate random blinding constant (32-bit) */
    uint32_t random = (uint32_t)ubpf_generate_blinding_constant();
    uint32_t imm_unsigned = (uint32_t)imm;
    int32_t blinded_imm = (int32_t)(imm_unsigned ^ random);
    
    /* Use R11 as temporary for blinded operations (safe - it's volatile) */
    int temp_reg = (dst == R11) ? R10 : R11;
    
    /* Load blinded immediate into temp register */
    emit_alu64_imm32(state, 0xc7, 0, temp_reg, blinded_imm);
    /* XOR with random to recover original value */
    emit_alu64_imm32(state, 0x81, 6, temp_reg, (int32_t)random);
    /* CMP dst, temp_reg */
    emit_alu64(state, 0x39, temp_reg, dst);
}

/* Blinded version of emit_cmp32_imm32 (32-bit compare with immediate) */
static inline void
emit_cmp32_imm32_blinded(struct jit_state* state, int dst, int32_t imm)
{
    /* Generate random blinding constant (32-bit) */
    uint32_t random = (uint32_t)ubpf_generate_blinding_constant();
    uint32_t imm_unsigned = (uint32_t)imm;
    int32_t blinded_imm = (int32_t)(imm_unsigned ^ random);
    
    /* Use R11 as temporary for blinded operations (safe - it's volatile) */
    int temp_reg = (dst == R11) ? R10 : R11;
    
    /* Load blinded immediate into temp register (32-bit) */
    emit_alu32_imm32(state, 0xc7, 0, temp_reg, blinded_imm);
    /* XOR with random to recover original value */
    emit_alu32_imm32(state, 0x81, 6, temp_reg, (int32_t)random);
    /* CMP dst, temp_reg (32-bit) */
    emit_alu32(state, 0x39, temp_reg, dst);
}

/* Blinded version of TEST instruction (for JSET) - 64-bit */
static inline void
emit_test_imm32_blinded(struct jit_state* state, int dst, int32_t imm)
{
    /* Generate random blinding constant (32-bit) */
    uint32_t random = (uint32_t)ubpf_generate_blinding_constant();
    uint32_t imm_unsigned = (uint32_t)imm;
    int32_t blinded_imm = (int32_t)(imm_unsigned ^ random);
    
    /* Use R11 as temporary for blinded operations (safe - it's volatile) */
    int temp_reg = (dst == R11) ? R10 : R11;
    
    /* Load blinded immediate into temp register */
    emit_alu64_imm32(state, 0xc7, 0, temp_reg, blinded_imm);
    /* XOR with random to recover original value */
    emit_alu64_imm32(state, 0x81, 6, temp_reg, (int32_t)random);
    /* TEST dst, temp_reg */
    emit_alu64(state, 0x85, temp_reg, dst);
}

/* Blinded version of TEST instruction (for JSET32) - 32-bit */
static inline void
emit_test32_imm32_blinded(struct jit_state* state, int dst, int32_t imm)
{
    /* Generate random blinding constant (32-bit) */
    uint32_t random = (uint32_t)ubpf_generate_blinding_constant();
    uint32_t imm_unsigned = (uint32_t)imm;
    int32_t blinded_imm = (int32_t)(imm_unsigned ^ random);
    
    /* Use R11 as temporary for blinded operations (safe - it's volatile) */
    int temp_reg = (dst == R11) ? R10 : R11;
    
    /* Load blinded immediate into temp register (32-bit) */
    emit_alu32_imm32(state, 0xc7, 0, temp_reg, blinded_imm);
    /* XOR with random to recover original value */
    emit_alu32_imm32(state, 0x81, 6, temp_reg, (int32_t)random);
    /* TEST dst, temp_reg (32-bit) */
    emit_alu32(state, 0x85, temp_reg, dst);
}

/* Blinded version of emit_store_imm32 */
static inline void
emit_store_imm32_blinded(struct jit_state* state, enum operand_size size, int dst, int32_t offset, int32_t imm)
{
    /* Generate random blinding constant (32-bit) */
    uint32_t random = (uint32_t)ubpf_generate_blinding_constant();
    uint32_t imm_unsigned = (uint32_t)imm;
    int32_t blinded_imm = (int32_t)(imm_unsigned ^ random);
    
    /* Use R11 as temporary for blinded operations (safe - it's volatile) */
    int temp_reg = R11;
    
    /* Load blinded immediate into temp register */
    if (size == S64) {
        emit_alu64_imm32(state, 0xc7, 0, temp_reg, blinded_imm);
        emit_alu64_imm32(state, 0x81, 6, temp_reg, (int32_t)random);
    } else {
        emit_alu32_imm32(state, 0xc7, 0, temp_reg, blinded_imm);
        emit_alu32_imm32(state, 0x81, 6, temp_reg, (int32_t)random);
    }
    
    /* Store temp_reg to [dst + offset] using the register store function */
    emit_store(state, size, temp_reg, dst, offset);
}

/* Helper macro for constant blinding - defined early so emit_muldivmod can use it */
#define EMIT_LOAD_IMM(vm, state, dst, imm) \
    do { \
        if ((vm)->constant_blinding_enabled) { \
            emit_load_imm_blinded(state, dst, imm); \
        } else { \
            emit_load_imm(state, dst, imm); \
        } \
    } while (0)


static uint32_t
emit_rip_relative_load(struct jit_state* state, int dst, struct PatchableTarget load_tgt)
{
    if (state->num_loads == state->max_insts) {
        state->jit_status = TooManyLoads;
        return 0;
    }

    emit_rex(state, 1, 0, 0, 0);
    emit1(state, 0x8b);
    emit_modrm(state, 0, dst, 0x05);

    uint32_t load_target_offset = state->offset;
    note_load(state, load_tgt);
    emit_4byte_offset_placeholder(state);

    return load_target_offset;
}

static void
emit_rip_relative_lea(struct jit_state* state, int lea_dst_reg, struct PatchableTarget lea_tgt)
{
    if (state->num_leas == state->max_insts) {
        state->jit_status = TooManyLeas;
        return;
    }

    // lea dst, [rip + HELPER TABLE ADDRESS]
    emit_rex(state, 1, 1, 0, 0);
    emit1(state, 0x8d);
    emit_modrm(state, 0, lea_dst_reg, 0x05);
    note_lea(state, lea_tgt);
    emit_4byte_offset_placeholder(state);
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

/** @brief Emit a (32-bit) jump.
 *
 * @param[in] state The JIT state.
 * @param[in] target_pc The PC to which to jump when this near
 *                      jump is executed.
 * @return The offset in the JIT'd code where the jump offset starts.
 */
static inline uint32_t
emit_jmp(struct jit_state* state, struct PatchableTarget target)
{
    if (!target.is_special && target.target.regular.near) {
        emit1(state, 0xeb);
        return emit_jump_address_reloc(state, target);
    }
    emit1(state, 0xe9);
    return emit_jump_address_reloc(state, target);
}

static inline uint32_t
emit_call(struct jit_state* state, struct PatchableTarget target)
{
    emit1(state, 0xe8);
    uint32_t call_src = state->offset;
    emit_jump_address_reloc(state, target);
    return call_src;
}

static inline void
emit_pause(struct jit_state* state)
{
    emit1(state, 0xf3);
    emit1(state, 0x90);
}

static inline void
emit_dispatched_external_helper_call(struct jit_state* state, unsigned int idx)
{
    /*
     * Note: We do *not* have to preserve any x86-64 registers here ...
     * ... according to the SystemV ABI: rbx (eBPF6),
     *                                   r13 (eBPF7),
     *                                   r14 (eBPF8),
     *                                   r15 (eBPF9), and
     *                                   rbp (eBPF10) are all preserved.
     * ... according to the Windows ABI: r15 (eBPF6)
     *                                   rdi (eBPF7),
     *                                   rsi (eBPF8),
     *                                   rbx (eBPF9), and
     *                                   rbp (eBPF10) are all preserved.
     *
     * When we enter here, our stack is 16-byte aligned. Keep
     * it that way!
     */

    /*
     * There are two things that could happen:
     * 1. The user has registered an external dispatcher and we need to
     *    send control there to invoke an external helper.
     * 2. The user is relying on the default dispatcher to pass control
     *    to the registered external helper.
     * To determine which action to take, we will first consider the 8
     * bytes at TARGET_PC_EXTERNAL_DISPATCHER. If those 8 bytes have an
     * address, that represents the address of the user-registered external
     * dispatcher and we pass control there. That function signature looks like
     * uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, unsigned int index, void* cookie
     * so we make sure that the arguments are done properly depending on the abi.
     *
     * If there is no external dispatcher registered, the user is expected
     * to have registered a handler with us for the helper with index idx.
     * There is a table of MAX_ function pointers starting at TARGET_LOAD_HELPER_TABLE.
     * Each of those functions has a signature that looks like
     * uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, void* cookie
     * We load the appropriate function pointer by using idx to index it and then
     * make sure that the arguments are set properly depending on the abi.
     */

    // Save register where volatile context is stored.
    emit_push(state, VOLATILE_CTXT);
    emit_push(state, VOLATILE_CTXT);
    // ^^ Stack is aligned here.

#if defined(_WIN32)
    /* Because we may need 24 bytes on the stack but at least 16, we have to take 32
     * to keep alignment happy. We may ultimately need it all, but we certainly
     * need 16! Later, though, there is a push that always happens (MARKER2), so
     * we only allocate 24 here.
     */
    emit_alu64_imm32(state, 0x81, 5, RSP, 3 * sizeof(uint64_t));
#endif

    DECLARE_PATCHABLE_TARGET(rip_rel_tgt);
    rip_rel_tgt.is_special = true;
    rip_rel_tgt.target.special = ExternalDispatcher;
    emit_rip_relative_load(state, RAX, rip_rel_tgt);

    // cmp rax, 0
    emit_cmp_imm32(state, RAX, 0);
    // jne skip_default_dispatcher_label
    DECLARE_PATCHABLE_TARGET(default_jmp_tgt);
    default_jmp_tgt.is_special = false;
    default_jmp_tgt.target.regular.ebpf_target_pc = 0;
    uint32_t skip_default_dispatcher_source = emit_jcc(state, 0x85, default_jmp_tgt);

    // Default dispatcher:

    // Load the address of the helper function from the table.
    // mov rax, idx
    emit_alu32(state, 0xc7, 0, RAX);
    emit4(state, idx);
    // shl rax, 3 (i.e., multiply the index by 8 because addresses are that size on x86-64)
    emit_alu64_imm8(state, 0xc1, 4, RAX, 3);

    // lea r10, [rip + HELPER TABLE ADDRESS]
    DECLARE_PATCHABLE_TARGET(rip_rel_load_helper_tgt);
    rip_rel_load_helper_tgt.is_special = true;
    rip_rel_load_helper_tgt.target.special = LoadHelperTable;
    // emit_rip_relative_lea(state, R10, TARGET_LOAD_HELPER_TABLE);
    emit_rip_relative_lea(state, R10, rip_rel_load_helper_tgt);

    // add rax, r10
    emit_alu64(state, 0x01, R10, RAX);
    // load rax, [rax]
    emit_load(state, S64, RAX, RAX, 0);

    // There is no index for the registered helper function. They just get
    // 5 arguments and a context, which becomes the 6th argument to the function ...
#if defined(_WIN32)
    // and spills to the stack on Windows.
    // mov qword [rsp], VOLATILE_CTXT
    emit1(state, 0x4c);
    emit1(state, 0x89);
    emit1(state, 0x5c);
    emit1(state, 0x24);
    emit1(state, 0x00);
#else
    // and goes in R9 on SystemV.
    emit_mov(state, VOLATILE_CTXT, R9);
#endif

    // jmp call_label
    uint32_t skip_external_dispatcher_source = emit_jmp(state, default_jmp_tgt);

    // External dispatcher:

    // skip_default_dispatcher_label:
    emit_jump_target(state, skip_default_dispatcher_source);

    // Using an external dispatcher. They get a total of 7 arguments. The
    // 6th argument is the index of the function to call which ...

#if defined(_WIN32)
    // and spills to the stack on Windows.

    // mov qword [rsp + 8], VOLATILE_CTXT
    emit1(state, 0x4c);
    emit1(state, 0x89);
    emit1(state, 0x5c);
    emit1(state, 0x24);
    emit1(state, 0x08);

    // To make it easier on ourselves, let's just use
    // VOLATILE_CTXT register to load the immediate
    // and push to the stack.
    emit_load_imm(state, VOLATILE_CTXT, (uint64_t)idx);

    // mov qword [rsp + 0], VOLATILE_CTXT
    emit1(state, 0x4c);
    emit1(state, 0x89);
    emit1(state, 0x5c);
    emit1(state, 0x24);
    emit1(state, 0x00);
#else
    // and goes in R9 on SystemV.
    emit_load_imm(state, R9, (uint64_t)idx);
    // And the 7th is already spilled to the stack in the right spot because
    // we wanted to save it -- cool (see MARKER1, above).

    // Intentional no-op for 7th argument.
#endif

    // Control flow converges for call:

    // call_label:
    emit_jump_target(state, skip_external_dispatcher_source);

#if defined(_WIN32)
    /* Windows x64 ABI spills 5th parameter to stack (MARKER2) */
    emit_push(state, map_register(5));

    /* Windows x64 ABI requires home register space.
     * Allocate home register space - 4 registers.
     */
    emit_alu64_imm32(state, 0x81, 5, RSP, 4 * sizeof(uint64_t));
#endif

#ifndef UBPF_DISABLE_RETPOLINES
    DECLARE_PATCHABLE_TARGET(retpoline_tgt);
    retpoline_tgt.is_special = true;
    retpoline_tgt.target.special = Retpoline;
    // emit_call(state, TARGET_PC_RETPOLINE);
    emit_call(state, retpoline_tgt);
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
    /* Deallocate home register space + (up to ) 3 spilled parameters + alignment space */
    emit_alu64_imm32(state, 0x81, 0, RSP, (4 + 3 + 1) * sizeof(uint64_t));
#endif

    emit_pop(state, VOLATILE_CTXT); // Restore register where volatile context is stored.
    emit_pop(state, VOLATILE_CTXT); // Restore register where volatile context is stored.
}

#define X64_ALU_ADD 0x01
#define X64_ALU_OR 0x09
#define X64_ALU_AND 0x21
#define X64_ALU_XOR 0x31

#define IS_64BIT 1
#define IS_32BIT 0

/**
 * @brief Emit an atomic ALU operation without fetch.
 *
 * This applies the operation to the memory location identified by the destination register and offset, using the source
 * register as the operand.
 *
 * @param[in,out] state The JIT state
 * @param[in] opcode The x64 opcode for the ALU operation
 * @param[in] is_64bit Whether the operation is 64-bit or 32-bit
 * @param[in] src Source register
 * @param[in] dst Destination register
 * @param[in] offset Offset from the destination register
 */
static inline void
emit_atomic_alu(struct jit_state* state, int opcode, int is_64bit, int src, int dst, int offset)
{
    emit1(state, 0xf0); // lock prefix
    emit_basic_rex(state, is_64bit, src, dst);
    emit1(state, opcode);
    emit_modrm_and_displacement(state, src, dst, offset);
}

/**
 * @brief Atomically compare and exchange.
 * This writes the value stored in src into the memory location identified by dst and offset, if the value at that
 * location is equal to the value in RAX.
 *
 * @param[in,out] state The JIT state
 * @param[in] is_64bit Whether the operation is 64-bit or 32-bit
 * @param[in] src The value to write.
 * @param[in] dst The base address of the destination memory location.
 * @param[in] offset The offset from dst.
 * @note This implicitly uses RAX as the original value to compare against and stores the original value in [destination
 * + offset] into RAX.
 */
static inline void
emit_atomic_cmp_exch_with_rax(struct jit_state* state, int is_64bit, int src, int dst, int offset)
{
    emit1(state, 0xf0); // lock prefix
    emit_basic_rex(state, is_64bit, src, dst);
    emit1(state, 0x0f);
    emit1(state, 0xb1);
    emit_modrm_and_displacement(state, src, dst, offset);
}

/**
 * @brief Atomically swaps the value of src into the memory location identified by dst and offset and sets src to the
 * original value at that location.
 *
 * @param[in,out] state The JIT state
 * @param[in] is_64bit Whether the operation is 64-bit or 32-bit
 * @param[in] src The value to write.
 * @param[in] dst The base address of the destination memory location.
 * @param[in] offset The offset from the destination memory location.
 */
static inline void
emit_atomic_exchange(struct jit_state* state, int is_64bit, int src, int dst, int offset)
{
    emit1(state, 0xf0); // lock prefix
    emit_basic_rex(state, is_64bit, src, dst);
    emit1(state, 0x87);
    emit_modrm_and_displacement(state, src, dst, offset);
}

/**
 * @brief Perform an ALU operation atomically and fetch the result.
 *
 * @param[in,out] state The JIT state
 * @param[in] is_64bit Whether the operation is 64-bit or 32-bit
 * @param[in] opcode The x64 opcode for the ALU operation
 * @param[in] src The source register, used as the operand for the ALU operation.
 * @param[in] dst The base address of the destination memory location.
 * @param[in] offset The offset from the destination memory location.
 * @note This operation stores the original value in [destination + offset] into RAX.
 * @note This operation is emulated on x64 for 64-bit and 32-bit operations as the x64 architecture does not have an
 * atomic fetch-and, fetch-or, fetch-xor, or fetch-add instruction.
 */
static inline void
emit_atomic_fetch_alu(struct jit_state* state, int is_64bit, int opcode, int src, int dst, int offset)
{
    // x64 lacks a 64-bit atomic version of some alu-fetch instruction, so we emulate it with a compare-exchange.
    // This is not a problem because the compare-exchange instruction is a full memory barrier.

    // The atomic compare exchange instruction overwrites RAX. If RAX is the source register, then save the original
    // value in R10 or R11, depending on which one is not the destination.
    int actual_src = src == RAX ? (dst == R10 ? R11 : R10) : src;

    if (src != RAX) {
        // Compare exchange overwrites RAX, so we need to save it.
        emit_push(state, RAX);
    } else {
        // Save the original value in actual_src (r10 or r11).
        emit_push(state, actual_src);

        // Move src into actual_src.
        emit_mov(state, src, actual_src);
    }

    // Load the original value at the destination into RAX.
    emit_load(state, is_64bit ? S64 : S32, dst, RAX, offset);

    // Loop until we successfully update the value.
    uint32_t loop_start = state->offset;

    // Copy RAX to RCX (required to preserve the original value of RAX for the comparison).
    emit_mov(state, RAX, RCX);

    // Perform the ALU operation into RCX.
    emit_alu64(state, opcode, actual_src, RCX);

    // Attempt to compare-exchange the value.
    // Atomic compare exchange compares the value at [dst + offset] with RAX and if they are equal, it stores RCX into
    // [dst + offset]. It always store the original value at [dst + offset] into RAX.
    emit_atomic_cmp_exch_with_rax(state, is_64bit, RCX, dst, offset);

    // If the compare-exchange failed, loop.
    emit1(state, 0x75);
    emit1(state, loop_start - state->offset - 1);

    if (src != RAX) {
        // Move RAX into the src register.
        emit_mov(state, RAX, src);

        // Restore RAX
        emit_pop(state, RAX);
    } else {
        // Restore the original value of actual_src.
        emit_pop(state, actual_src);
    }
}

static inline void
emit_atomic_add64(struct jit_state* state, int src, int dst, int offset)
{
    emit_atomic_alu(state, X64_ALU_ADD, IS_64BIT, src, dst, offset);
}

static inline void
emit_atomic_add32(struct jit_state* state, int src, int dst, int offset)
{
    emit_atomic_alu(state, X64_ALU_ADD, IS_32BIT, src, dst, offset);
}

static inline void
emit_atomic_and64(struct jit_state* state, int src, int dst, int offset)
{
    emit_atomic_alu(state, X64_ALU_AND, IS_64BIT, src, dst, offset);
}

static inline void
emit_atomic_and32(struct jit_state* state, int src, int dst, int offset)
{
    emit_atomic_alu(state, X64_ALU_AND, IS_32BIT, src, dst, offset);
}

static inline void
emit_atomic_or64(struct jit_state* state, int src, int dst, int offset)
{
    emit_atomic_alu(state, X64_ALU_OR, IS_64BIT, src, dst, offset);
}

static inline void
emit_atomic_or32(struct jit_state* state, int src, int dst, int offset)
{
    emit_atomic_alu(state, X64_ALU_OR, IS_32BIT, src, dst, offset);
}

static inline void
emit_atomic_xor64(struct jit_state* state, int src, int dst, int offset)
{
    emit_atomic_alu(state, X64_ALU_XOR, IS_64BIT, src, dst, offset);
}

static inline void
emit_atomic_xor32(struct jit_state* state, int src, int dst, int offset)
{
    emit_atomic_alu(state, X64_ALU_XOR, IS_32BIT, src, dst, offset);
}

static inline void
emit_atomic_compare_exchange64(struct jit_state* state, int src, int dst, int offset)
{
    emit_atomic_cmp_exch_with_rax(state, IS_64BIT, src, dst, offset);
}

static inline void
emit_atomic_compare_exchange32(struct jit_state* state, int src, int dst, int offset)
{
    emit_atomic_cmp_exch_with_rax(state, IS_32BIT, src, dst, offset);
}

static inline void
emit_atomic_exchange64(struct jit_state* state, int src, int dst, int offset)
{
    emit_atomic_exchange(state, IS_64BIT, src, dst, offset);
}

static inline void
emit_atomic_exchange32(struct jit_state* state, int src, int dst, int offset)
{
    emit_atomic_exchange(state, IS_32BIT, src, dst, offset);
}

static inline void
emit_atomic_fetch_add64(struct jit_state* state, int src, int dst, int offset)
{
    emit_atomic_fetch_alu(state, IS_64BIT, X64_ALU_ADD, src, dst, offset);
}

static inline void
emit_atomic_fetch_add32(struct jit_state* state, int src, int dst, int offset)
{
    emit_atomic_fetch_alu(state, IS_32BIT, X64_ALU_ADD, src, dst, offset);
}

static inline void
emit_atomic_fetch_and64(struct jit_state* state, int src, int dst, int offset)
{
    emit_atomic_fetch_alu(state, IS_64BIT, X64_ALU_AND, src, dst, offset);
}

static inline void
emit_atomic_fetch_and32(struct jit_state* state, int src, int dst, int offset)
{
    emit_atomic_fetch_alu(state, IS_32BIT, X64_ALU_AND, src, dst, offset);
}

static inline void
emit_atomic_fetch_or64(struct jit_state* state, int src, int dst, int offset)
{
    emit_atomic_fetch_alu(state, IS_64BIT, X64_ALU_OR, src, dst, offset);
}

static inline void
emit_atomic_fetch_or32(struct jit_state* state, int src, int dst, int offset)
{
    emit_atomic_fetch_alu(state, IS_32BIT, X64_ALU_OR, src, dst, offset);
}

static inline void
emit_atomic_fetch_xor64(struct jit_state* state, int src, int dst, int offset)
{
    emit_atomic_fetch_alu(state, IS_64BIT, X64_ALU_XOR, src, dst, offset);
}

static inline void
emit_atomic_fetch_xor32(struct jit_state* state, int src, int dst, int offset)
{
    emit_atomic_fetch_alu(state, IS_32BIT, X64_ALU_XOR, src, dst, offset);
}

static void
emit_muldivmod(struct ubpf_vm* vm, struct jit_state* state, uint8_t opcode, int src, int dst, int32_t imm, int16_t offset)
{
    bool mul = (opcode & EBPF_ALU_OP_MASK) == (EBPF_OP_MUL_IMM & EBPF_ALU_OP_MASK);
    bool div = (opcode & EBPF_ALU_OP_MASK) == (EBPF_OP_DIV_IMM & EBPF_ALU_OP_MASK);
    bool mod = (opcode & EBPF_ALU_OP_MASK) == (EBPF_OP_MOD_IMM & EBPF_ALU_OP_MASK);
    bool is64 = (opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU64;
    bool reg = (opcode & EBPF_SRC_REG) == EBPF_SRC_REG;
    bool is_signed = (offset == 1);

    // Short circuit for imm == 0.
    if (!reg && imm == 0) {
        if (div || mul) {
            // For division and multiplication, set result to zero.
            emit_alu32(state, 0x31, dst, dst);
        } else {
            // For modulo, set result to dividend.
            emit_mov(state, dst, dst);
        }
        return;
    }

    if (dst != RAX) {
        emit_push(state, RAX);
    }

    if (dst != RDX) {
        emit_push(state, RDX);
    }

    // Load the divisor into RCX.
    if (!reg) {
        EMIT_LOAD_IMM(vm, state, RCX, imm);
    } else {
        emit_mov(state, src, RCX);
    }

    // Load the dividend into RAX.
    emit_mov(state, dst, RAX);

    // BPF has two different semantics for division and modulus. For division
    // if the divisor is zero, the result is zero.  For modulus, if the divisor
    // is zero, the result is the dividend. To handle this we set the divisor
    // to 1 if it is zero and then set the result to zero if the divisor was
    // zero (for division) or set the result to the dividend if the divisor was
    // zero (for modulo).

    if (div || mod) {
        // Check if divisor is zero.
        if (is64) {
            emit_alu64(state, 0x85, RCX, RCX);
        } else {
            emit_alu32(state, 0x85, RCX, RCX);
        }

        // Save the dividend for the modulo case.
        if (mod) {
            emit_push(state, RAX); // Save dividend.
        }

        // Save the result of the test.
        emit1(state, 0x9c); /* pushfq */

        // Set the divisor to 1 if it is zero.
        emit_load_imm(state, RDX, 1);
        emit1(state, 0x48);
        emit1(state, 0x0f);
        emit1(state, 0x44);
        emit1(state, 0xca); /* cmove rcx,rdx */

        if (is_signed) {
            // For signed division, sign-extend RAX into RDX:RAX.
            if (is64) {
                emit1(state, 0x48); /* REX.W prefix for CQO */
                emit1(state, 0x99); /* cqo: sign-extend RAX into RDX:RAX (64-bit) */
            } else {
                emit1(state, 0x99); /* cdq: sign-extend EAX into EDX:EAX (32-bit) */
            }
        } else {
            /* xor %edx,%edx */
            emit_alu32(state, 0x31, RDX, RDX);
        }
    }

    // Handle signed division overflow case: INT_MIN / -1.
    // On x86-64, IDIV with INT_MIN / -1 causes a divide error exception.
    // Per RFC 9669, the result should be INT_MIN (overflow wraps).
    uint32_t overflow_jump_source = 0;
    if ((div || mod) && is_signed) {
        // Check if divisor (RCX) == -1.
        if (is64) {
            // cmp rcx, -1
            emit1(state, 0x48);
            emit1(state, 0x83);
            emit1(state, 0xf9);
            emit1(state, 0xff);
        } else {
            // cmp ecx, -1
            emit1(state, 0x83);
            emit1(state, 0xf9);
            emit1(state, 0xff);
        }
        // jne skip_overflow_check (short jump, patched later)
        emit1(state, 0x75);
        uint32_t jne_source = state->offset;
        emit1(state, 0x00); // placeholder for jump offset

        // Check if dividend (RAX) == INT_MIN.
        if (is64) {
            // mov r11, 0x8000000000000000
            emit1(state, 0x49);
            emit1(state, 0xbb);
            emit8(state, 0x8000000000000000ULL);
            // cmp rax, r11
            emit1(state, 0x4c);
            emit1(state, 0x39);
            emit1(state, 0xd8);
        } else {
            // cmp eax, 0x80000000
            emit1(state, 0x3d);
            emit4(state, 0x80000000);
        }
        // jne skip_overflow_handling (short jump, patched later)
        emit1(state, 0x75);
        uint32_t jne2_source = state->offset;
        emit1(state, 0x00); // placeholder

        // INT_MIN / -1 case: set result directly without IDIV.
        if (div) {
            // For division, result is INT_MIN (already in RAX), so nothing to do.
        } else {
            // For modulo, result is 0.
            // xor rdx, rdx (or edx, edx for 32-bit)
            emit_alu32(state, 0x31, RDX, RDX);
        }
        // Jump over the IDIV instruction.
        emit1(state, 0xeb); // jmp short
        overflow_jump_source = state->offset;
        emit1(state, 0x00); // placeholder

        // Patch the jne jumps to land here.
        state->buf[jne_source] = state->offset - jne_source - 1;
        state->buf[jne2_source] = state->offset - jne2_source - 1;
    }

    if (is64) {
        emit_rex(state, 1, 0, 0, 0);
    }

    // Multiply or divide.
    // For multiplication: opcode /4 (MUL)
    // For unsigned division: opcode /6 (DIV)
    // For signed division: opcode /7 (IDIV)
    int modrm_reg = mul ? 4 : (is_signed ? 7 : 6);
    emit_alu32(state, 0xf7, modrm_reg, RCX);

    // Patch the overflow jump to land here (after IDIV).
    if ((div || mod) && is_signed && overflow_jump_source != 0) {
        state->buf[overflow_jump_source] = state->offset - overflow_jump_source - 1;
    }

    // Division operation stores the remainder in RDX and the quotient in RAX.
    if (div || mod) {
        // Restore the result of the test.
        emit1(state, 0x9d); /* popfq */

        // If zero flag is set, then the divisor was zero.

        if (div) {
            // Set the dividend to zero if the divisor was zero.
            emit_load_imm(state, RCX, 0);

            // Store 0 in RAX if the divisor was zero.
            // Use conditional move to avoid a branch.
            emit1(state, 0x48);
            emit1(state, 0x0f);
            emit1(state, 0x44);
            emit1(state, 0xc1); /* cmove rax,rcx */
        } else {
            // Restore dividend to RCX.
            emit_pop(state, RCX);

            // Store the dividend in RAX if the divisor was zero.
            // Use conditional move to avoid a branch.
            emit1(state, 0x48);
            emit1(state, 0x0f);
            emit1(state, 0x44);
            emit1(state, 0xd1); /* cmove rdx,rcx */
        }
    }

    if (dst != RDX) {
        if (mod) {
            emit_mov(state, RDX, dst);
        }
        emit_pop(state, RDX);
    }
    if (dst != RAX) {
        if (div || mul) {
            emit_mov(state, RAX, dst);
        }
        emit_pop(state, RAX);
    }
}
static inline void
emit_local_call(struct ubpf_vm* vm, struct jit_state* state, uint32_t ebpf_target_pc)
{
    UNUSED_PARAMETER(vm);
    // Invariant: The top of the host stack always holds the amount of space needed
    // by the currently-executing eBPF function.

    // Because the top of the host stack holds the stack usage of the currently-executing
    // function, we adjust the eBPF base pointer down by that value!
    // sub r15, [rsp]
    emit1(state, 0x4c);
    emit1(state, 0x2B);
    emit1(state, 0x3C); // Mod: 00b Reg: 111b RM: 100b
    emit1(state, 0x24); // Scale: 00b Index: 100b Base: 100b

    emit_push(state, map_register(BPF_REG_6));
    emit_push(state, map_register(BPF_REG_7));
    emit_push(state, map_register(BPF_REG_8));
    emit_push(state, map_register(BPF_REG_9));

#if defined(_WIN32)
    /* Windows x64 ABI requires home register space */
    /* Allocate home register space - 4 registers */
    emit_alu64_imm32(state, 0x81, 5, RSP, 4 * sizeof(uint64_t));
#endif
    emit1(state, 0xe8); // e8 is the opcode for a CALL
    DECLARE_PATCHABLE_REGULAR_EBPF_TARGET(target_pt, ebpf_target_pc);
    emit_local_call_address_reloc(state, target_pt);

#if defined(_WIN32)
    /* Deallocate home register space - 4 registers */
    emit_alu64_imm32(state, 0x81, 0, RSP, 4 * sizeof(uint64_t));
#endif
    emit_pop(state, map_register(BPF_REG_9));
    emit_pop(state, map_register(BPF_REG_8));
    emit_pop(state, map_register(BPF_REG_7));
    emit_pop(state, map_register(BPF_REG_6));

    // Because the top of the host stack holds the stack usage of the currently-executing
    // function, we adjust the eBPF base pointer back up by that value!
    // add r15, [rsp]
    emit1(state, 0x4c);
    emit1(state, 0x03);
    emit1(state, 0x3C); // Mod: 00b Reg: 111b RM: 100b
    emit1(state, 0x24); // Scale: 00b Index: 100b Base: 100b
}

static uint32_t
emit_dispatched_external_helper_address(struct jit_state* state, struct ubpf_vm* vm)
{
    uint32_t external_helper_address_target = state->offset;
    emit8(state, (uint64_t)vm->dispatcher);
    return external_helper_address_target;
}

static uint32_t
emit_helper_table(struct jit_state* state, struct ubpf_vm* vm)
{

    uint32_t helper_table_address_target = state->offset;
    for (int i = 0; i < MAX_EXT_FUNCS; i++) {
        emit8(state, (uint64_t)vm->ext_funcs[i]);
    }
    return helper_table_address_target;
}

static uint32_t
emit_retpoline(struct jit_state* state)
{

    /*
     * Using retpolines to mitigate spectre/meltdown. Adapting the approach
     * from
     * https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/retpoline-branch-target-injection-mitigation.html
     */

    /* label0: */
    /* call label1 */
    uint32_t retpoline_target = state->offset;
    DECLARE_PATCHABLE_REGULAR_EBPF_TARGET(default_call_tgt, 0);
    uint32_t label1_call_offset = emit_call(state, default_call_tgt);

    /* capture_ret_spec: */
    /* pause */
    uint32_t capture_ret_spec = state->offset;
    emit_pause(state);
    /* jmp  capture_ret_spec */
    DECLARE_PATCHABLE_REGULAR_JIT_TARGET(capture_ret_tgt, capture_ret_spec);
    emit_jmp(state, capture_ret_tgt);

    /* label1: */
    /* mov rax, (rsp) */
    uint32_t label1 = state->offset;
    emit1(state, 0x48);
    emit1(state, 0x89);
    emit1(state, 0x04); // Mod: 00b Reg: 000b RM: 100b
    emit1(state, 0x24); // Scale: 00b Index: 100b Base: 100b

    /* ret */
    emit_ret(state);

    DECLARE_PATCHABLE_REGULAR_JIT_TARGET(label1_tgt, label1);
    modify_patchable_relatives_target(state->jumps, state->num_jumps, label1_call_offset, label1_tgt);

    return retpoline_target;
}

/* For testing, this changes the mapping between x86 and eBPF registers */
void
ubpf_set_register_offset(int x)
{
    int i;
    if (x < REGISTER_MAP_SIZE) {
        int tmp[REGISTER_MAP_SIZE];
        memcpy(tmp, register_map, sizeof(register_map));
        for (i = 0; i < REGISTER_MAP_SIZE; i++) {
            register_map[i] = tmp[(i + x) % REGISTER_MAP_SIZE];
        }
    } else {
        /* Shuffle array */
        unsigned int seed = x;
        for (i = 0; i < REGISTER_MAP_SIZE - 1; i++) {
            int j = i + (rand_r(&seed) % (REGISTER_MAP_SIZE - i));
            int tmp = register_map[j];
            register_map[j] = register_map[i];
            register_map[i] = tmp;
        }
    }
}

/*
 * JIT'd Code Layout & Invariants:
 *
 * 1. Layout of external dispatcher/helpers pointers
 * In order to make it so that the generated code is completely standalone, all the necessary
 * function pointers for external helpers are embedded in the jitted code. The layout looks like:
 *
 *                 state->buffer: CODE
 *                                CODE
 *                                CODE
 *                                ...
 *                                CODE
 *                                External Helper External Dispatcher Function Pointer (8 bytes, maybe NULL)
 *                                External Helper Function Pointer Idx 0 (8 bytes, maybe NULL)
 *                                External Helper Function Pointer Idx 1 (8 bytes, maybe NULL)
 *                                ...
 *                                External Helper Function Pointer Idx MAX_EXT_FUNCS-1 (8 bytes, maybe NULL)
 * state->buffer + state->offset:
 *
 * 2. Invariants
 *    a. The top of the host stack always contains an 8-byte value which is the size
 *       of the eBPF stack usage of currently-executing eBPF function. The invariant
 *       is maintained in the code generated for the EXIT, and CALL opcodes and in the
 *       code generated for the first instruction in an eBPF function.
 *
 * The layout and invariants are identical for code JIT compiled for Arm.
 */

/* Helper macros to conditionally use blinded versions */
/* Note: EMIT_LOAD_IMM is defined earlier in the file (after blinded functions)
 * so that emit_muldivmod can use it */

#define EMIT_ALU64_IMM32(vm, state, op, src, dst, imm) \
    do { \
        if ((vm)->constant_blinding_enabled) { \
            emit_alu64_imm32_blinded(state, op, src, dst, imm); \
        } else { \
            emit_alu64_imm32(state, op, src, dst, imm); \
        } \
    } while (0)

#define EMIT_ALU32_IMM32(vm, state, op, src, dst, imm) \
    do { \
        if ((vm)->constant_blinding_enabled) { \
            emit_alu32_imm32_blinded(state, op, src, dst, imm); \
        } else { \
            emit_alu32_imm32(state, op, src, dst, imm); \
        } \
    } while (0)

#define EMIT_CMP_IMM32(vm, state, dst, imm) \
    do { \
        if ((vm)->constant_blinding_enabled) { \
            emit_cmp_imm32_blinded(state, dst, imm); \
        } else { \
            emit_cmp_imm32(state, dst, imm); \
        } \
    } while (0)

#define EMIT_CMP32_IMM32(vm, state, dst, imm) \
    do { \
        if ((vm)->constant_blinding_enabled) { \
            emit_cmp32_imm32_blinded(state, dst, imm); \
        } else { \
            emit_cmp32_imm32(state, dst, imm); \
        } \
    } while (0)

#define EMIT_TEST_IMM32(vm, state, dst, imm) \
    do { \
        if ((vm)->constant_blinding_enabled) { \
            emit_test_imm32_blinded(state, dst, imm); \
        } else { \
            emit_alu64_imm32(state, 0xf7, 0, dst, imm); \
        } \
    } while (0)

#define EMIT_TEST32_IMM32(vm, state, dst, imm) \
    do { \
        if ((vm)->constant_blinding_enabled) { \
            emit_test32_imm32_blinded(state, dst, imm); \
        } else { \
            emit_alu32_imm32(state, 0xf7, 0, dst, imm); \
        } \
    } while (0)

#define EMIT_STORE_IMM32(vm, state, size, dst, offset, imm) \
    do { \
        if ((vm)->constant_blinding_enabled) { \
            emit_store_imm32_blinded(state, size, dst, offset, imm); \
        } else { \
            emit_store_imm32(state, size, dst, offset, imm); \
        } \
    } while (0)

static int
translate(struct ubpf_vm* vm, struct jit_state* state, char** errmsg)
{
    int i;

    (void)platform_volatile_registers;
    /* Save platform non-volatile registers */
    for (i = 0; i < _countof(platform_nonvolatile_registers); i++) {
        emit_push(state, platform_nonvolatile_registers[i]);
    }

    /* Move first platform parameter register into register 1 */
    if (map_register(1) != platform_parameter_registers[0]) {
        emit_mov(state, platform_parameter_registers[0], map_register(BPF_REG_1));
    }

    /* Move the first platform parameter register to the (volatile) register
     * that holds the pointer to the context.
     */
    emit_mov(state, platform_parameter_registers[0], VOLATILE_CTXT);

    /*
     * Assuming that the stack is 16-byte aligned right before
     * the call insn that brought us to this code, when
     * we start executing the jit'd code, we need to regain a 16-byte
     * alignment. The UBPF_EBPF_STACK_SIZE is guaranteed to be
     * divisible by 16. However, if we pushed an even number of
     * registers on the stack when we are saving state (see above),
     * then we have to add an additional 8 bytes to get back
     * to a 16-byte alignment.
     */
    if (!(_countof(platform_nonvolatile_registers) % 2)) {
        emit_alu64_imm32(state, 0x81, 5, RSP, 0x8);
    }

    /*
     * Let's set RBP to RSP so that we can restore RSP later!
     */
    emit_mov(state, RSP, RBP);

    /* Configure eBPF program stack space */
    if (state->jit_mode == BasicJitMode) {
        /*
         * Set BPF R10 (the way to access the frame in eBPF) the beginning
         * of the eBPF program's stack space.
         */
        emit_mov(state, RSP, map_register(BPF_REG_10));
        /* Allocate eBPF program stack space */
        emit_alu64_imm32(state, 0x81, 5, RSP, UBPF_EBPF_STACK_SIZE);
    } else {
        /* Use given eBPF program stack space */
        emit_mov(state, platform_parameter_registers[2], map_register(BPF_REG_10));
        emit_alu64(state, 0x01, platform_parameter_registers[3], map_register(BPF_REG_10));
    }

#if defined(_WIN32)
    /* Windows x64 ABI requires home register space */
    /* Allocate home register space - 4 registers */
    emit_alu64_imm32(state, 0x81, 5, RSP, 4 * sizeof(uint64_t));
#endif

    /*
     * Use a call to set up a place where we can land after eBPF program's
     * final EXIT call. This makes it appear to the ebpf programs
     * as if they are called like a function. It is their responsibility
     * to deal with the non-16-byte aligned stack pointer that goes along
     * with this pretense.
     */
    emit1(state, 0xe8);
    emit4(state, 5);
    /*
     * We jump over this instruction in the first place; return here
     * after the eBPF program is finished executing.
     */

    DECLARE_PATCHABLE_SPECIAL_TARGET(exit_tgt, Exit)
    emit_jmp(state, exit_tgt);

    for (i = 0; i < vm->num_insts; i++) {
        if (state->jit_status != NoError) {
            break;
        }

        struct ebpf_inst inst = ubpf_fetch_instruction(vm, i);

        int dst = map_register(inst.dst);
        int src = map_register(inst.src);

        // Use int64_t to avoid signed overflow with large immediates
        int64_t target_pc_64;
        if (inst.opcode == EBPF_OP_JA32) {
            target_pc_64 = (int64_t)i + (int64_t)inst.imm + 1;
        } else {
            target_pc_64 = (int64_t)i + (int64_t)inst.offset + 1;
        }
        uint32_t target_pc = (uint32_t)target_pc_64;

        DECLARE_PATCHABLE_REGULAR_EBPF_TARGET(tgt, target_pc);

        // If
        // a) the previous instruction in the eBPF program could fallthrough
        //    to this instruction and
        // b) the current instruction starts a local function,
        // then there has to be a means to "jump around" the code that
        // manipulates the stack when the program executes in the fallthrough
        // path.
        uint32_t fallthrough_jump_source = 0;
        bool fallthrough_jump_present = false;
        if (i != 0 && vm->int_funcs[i]) {
            struct ebpf_inst prev_inst = ubpf_fetch_instruction(vm, i - 1);
            if (ubpf_instruction_has_fallthrough(prev_inst)) {
                DECLARE_PATCHABLE_REGULAR_EBPF_TARGET(default_near_target, 0)
                default_near_target.target.regular.near = true;
                fallthrough_jump_source = emit_jmp(state, default_near_target);
                fallthrough_jump_present = true;
            }
        }

        /*
         * There is an invariant that the top of the host stack always contains
         * the amount of local space used by the currently-executing eBPF program.
         * So, if we are at the start of an eBPF function, we will need to put the
         * amount of its local space usage on the top of the host stack. It is safe
         * to adjust the stack by only 8 bytes here because the `call` pushed the
         * return address (8 bytes). In combination, there is a 16-byte change
         * to the stack pointer which maintains the 16-byte stack alignment.
         */
        if (i == 0 || vm->int_funcs[i]) {
            size_t prolog_start = state->offset;
            uint16_t stack_usage = ubpf_stack_usage_for_local_func(vm, i);
            // Move the stack pointer to make space for a 64-bit integer ...
            emit_alu64_imm32(state, 0x81, 5, RSP, 8);
            // ... that is filled with the amount of space needed for the local function.
            emit1(state, 0x48);
            emit1(state, 0xC7); // mov immediate to [rsp]
            emit1(state, 0x04); // Mod: 00b Reg: 000b RM: 100b
            emit1(state, 0x24); // Scale: 00b Index: 100b Base: 100b
            emit4(state, stack_usage);

            // Record the size of the prolog so that we can calculate offset when doing a local call.
            if (state->bpf_function_prolog_size == 0) {
                state->bpf_function_prolog_size = state->offset - prolog_start;
            } else {
                assert(state->bpf_function_prolog_size == state->offset - prolog_start);
            }
        }

        // If there was a jump inserted to bypass the host stack manipulation code,
        // we need to update its target.
        if (fallthrough_jump_present) {
            DECLARE_PATCHABLE_REGULAR_JIT_TARGET(fallthrough_jump_tgt, state->offset);
            fallthrough_jump_tgt.target.regular.near = true;
            modify_patchable_relatives_target(
                state->jumps, state->num_jumps, fallthrough_jump_source, fallthrough_jump_tgt);
        }
        state->pc_locs[i] = state->offset;

        switch (inst.opcode) {
        case EBPF_OP_ADD_IMM:
            EMIT_ALU32_IMM32(vm, state, 0x81, 0, dst, inst.imm);
            break;
        case EBPF_OP_ADD_REG:
            emit_alu32(state, 0x01, src, dst);
            break;
        case EBPF_OP_SUB_IMM:
            EMIT_ALU32_IMM32(vm, state, 0x81, 5, dst, inst.imm);
            break;
        case EBPF_OP_SUB_REG:
            emit_alu32(state, 0x29, src, dst);
            break;
        case EBPF_OP_MUL_IMM:
        case EBPF_OP_MUL_REG:
        case EBPF_OP_DIV_IMM:
        case EBPF_OP_DIV_REG:
        case EBPF_OP_MOD_IMM:
        case EBPF_OP_MOD_REG:
            emit_muldivmod(vm, state, inst.opcode, src, dst, inst.imm, inst.offset);
            break;
        case EBPF_OP_OR_IMM:
            EMIT_ALU32_IMM32(vm, state, 0x81, 1, dst, inst.imm);
            break;
        case EBPF_OP_OR_REG:
            emit_alu32(state, 0x09, src, dst);
            break;
        case EBPF_OP_AND_IMM:
            EMIT_ALU32_IMM32(vm, state, 0x81, 4, dst, inst.imm);
            break;
        case EBPF_OP_AND_REG:
            emit_alu32(state, 0x21, src, dst);
            break;
        case EBPF_OP_LSH_IMM:
            emit_alu32_imm8(state, 0xc1, 4, dst, inst.imm);
            break;
        case EBPF_OP_LSH_REG:
            emit_mov(state, src, RCX);
            emit_alu32(state, 0xd3, 4, dst);
            break;
        case EBPF_OP_RSH_IMM:
            emit_alu32_imm8(state, 0xc1, 5, dst, inst.imm);
            break;
        case EBPF_OP_RSH_REG:
            emit_mov(state, src, RCX);
            emit_alu32(state, 0xd3, 5, dst);
            break;
        case EBPF_OP_NEG:
            emit_alu32(state, 0xf7, 3, dst);
            break;
        case EBPF_OP_XOR_IMM:
            EMIT_ALU32_IMM32(vm, state, 0x81, 6, dst, inst.imm);
            break;
        case EBPF_OP_XOR_REG:
            emit_alu32(state, 0x31, src, dst);
            break;
        case EBPF_OP_MOV_IMM:
            EMIT_ALU32_IMM32(vm, state, 0xc7, 0, dst, inst.imm);
            break;
        case EBPF_OP_MOV_REG:
            emit_mov(state, src, dst);
            break;
        case EBPF_OP_ARSH_IMM:
            emit_alu32_imm8(state, 0xc1, 7, dst, inst.imm);
            break;
        case EBPF_OP_ARSH_REG:
            emit_mov(state, src, RCX);
            emit_alu32(state, 0xd3, 7, dst);
            break;

        case EBPF_OP_LE:
            /* x64 instruction set is already little-endian, so no-op except for truncation. */
            if (inst.imm == 16) {
                /* Truncate to 16 bits */
                emit_alu32_imm32(state, 0x81, 4, dst, 0xffff);
            } else if (inst.imm == 32) {
                /* Truncate to 32 bits */
                emit_alu32_imm32(state, 0x81, 4, dst, 0xffffffff);
            }
            break;
        case EBPF_OP_BE:
            if (inst.imm == 16) {
                /* rol */
                emit1(state, 0x66); /* 16-bit override */
                emit_alu32_imm8(state, 0xc1, 0, dst, 8);
                /* and */
                emit_alu32_imm32(state, 0x81, 4, dst, 0xffff);
            } else if (inst.imm == 32 || inst.imm == 64) {
                /* bswap */
                emit_basic_rex(state, inst.imm == 64, 0, dst);
                emit1(state, 0x0f);
                emit1(state, 0xc8 | (dst & 7));
            }
            break;

        case EBPF_OP_BSWAP:
            if (inst.imm == 16) {
                /* rol for 16-bit bswap */
                emit1(state, 0x66); /* 16-bit override */
                emit_alu32_imm8(state, 0xc1, 0, dst, 8);
                /* and to zero upper bits */
                emit_alu64_imm32(state, 0x81, 4, dst, 0xffff);
            } else if (inst.imm == 32) {
                /* bswap for 32-bit */
                emit_basic_rex(state, 0, 0, dst);
                emit1(state, 0x0f);
                emit1(state, 0xc8 | (dst & 7));
                /* Zero-extend to 64-bit */
                emit_alu32(state, 0x89, dst, dst);
            } else if (inst.imm == 64) {
                /* bswap for 64-bit */
                emit_basic_rex(state, 1, 0, dst);
                emit1(state, 0x0f);
                emit1(state, 0xc8 | (dst & 7));
            }
            break;

        case EBPF_OP_ADD64_IMM:
            EMIT_ALU64_IMM32(vm, state, 0x81, 0, dst, inst.imm);
            break;
        case EBPF_OP_ADD64_REG:
            emit_alu64(state, 0x01, src, dst);
            break;
        case EBPF_OP_SUB64_IMM:
            EMIT_ALU64_IMM32(vm, state, 0x81, 5, dst, inst.imm);
            break;
        case EBPF_OP_SUB64_REG:
            emit_alu64(state, 0x29, src, dst);
            break;
        case EBPF_OP_MUL64_IMM:
        case EBPF_OP_MUL64_REG:
        case EBPF_OP_DIV64_IMM:
        case EBPF_OP_DIV64_REG:
        case EBPF_OP_MOD64_IMM:
        case EBPF_OP_MOD64_REG:
            emit_muldivmod(vm, state, inst.opcode, src, dst, inst.imm, inst.offset);
            break;
        case EBPF_OP_OR64_IMM:
            EMIT_ALU64_IMM32(vm, state, 0x81, 1, dst, inst.imm);
            break;
        case EBPF_OP_OR64_REG:
            emit_alu64(state, 0x09, src, dst);
            break;
        case EBPF_OP_AND64_IMM:
            EMIT_ALU64_IMM32(vm, state, 0x81, 4, dst, inst.imm);
            break;
        case EBPF_OP_AND64_REG:
            emit_alu64(state, 0x21, src, dst);
            break;
        case EBPF_OP_LSH64_IMM:
            emit_alu64_imm8(state, 0xc1, 4, dst, inst.imm);
            break;
        case EBPF_OP_LSH64_REG:
            emit_mov(state, src, RCX);
            emit_alu64(state, 0xd3, 4, dst);
            break;
        case EBPF_OP_RSH64_IMM:
            emit_alu64_imm8(state, 0xc1, 5, dst, inst.imm);
            break;
        case EBPF_OP_RSH64_REG:
            emit_mov(state, src, RCX);
            emit_alu64(state, 0xd3, 5, dst);
            break;
        case EBPF_OP_NEG64:
            emit_alu64(state, 0xf7, 3, dst);
            break;
        case EBPF_OP_XOR64_IMM:
            EMIT_ALU64_IMM32(vm, state, 0x81, 6, dst, inst.imm);
            break;
        case EBPF_OP_XOR64_REG:
            emit_alu64(state, 0x31, src, dst);
            break;
        case EBPF_OP_MOV64_IMM:
            EMIT_LOAD_IMM(vm, state, dst, inst.imm);
            break;
        case EBPF_OP_MOV64_REG:
            emit_mov(state, src, dst);
            break;
        case EBPF_OP_ARSH64_IMM:
            emit_alu64_imm8(state, 0xc1, 7, dst, inst.imm);
            break;
        case EBPF_OP_ARSH64_REG:
            emit_mov(state, src, RCX);
            emit_alu64(state, 0xd3, 7, dst);
            break;

        /* TODO use 8 bit immediate when possible */
        case EBPF_OP_JA:
        case EBPF_OP_JA32:
            emit_jmp(state, tgt);
            break;
        case EBPF_OP_JEQ_IMM:
            EMIT_CMP_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x84, tgt);
            break;
        case EBPF_OP_JEQ_REG:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x84, tgt);
            break;
        case EBPF_OP_JGT_IMM:
            EMIT_CMP_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x87, tgt);
            break;
        case EBPF_OP_JGT_REG:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x87, tgt);
            break;
        case EBPF_OP_JGE_IMM:
            EMIT_CMP_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x83, tgt);
            break;
        case EBPF_OP_JGE_REG:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x83, tgt);
            break;
        case EBPF_OP_JLT_IMM:
            EMIT_CMP_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x82, tgt);
            break;
        case EBPF_OP_JLT_REG:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x82, tgt);
            break;
        case EBPF_OP_JLE_IMM:
            EMIT_CMP_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x86, tgt);
            break;
        case EBPF_OP_JLE_REG:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x86, tgt);
            break;
        case EBPF_OP_JSET_IMM:
            EMIT_TEST_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x85, tgt);
            break;
        case EBPF_OP_JSET_REG:
            emit_alu64(state, 0x85, src, dst);
            emit_jcc(state, 0x85, tgt);
            break;
        case EBPF_OP_JNE_IMM:
            EMIT_CMP_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x85, tgt);
            break;
        case EBPF_OP_JNE_REG:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x85, tgt);
            break;
        case EBPF_OP_JSGT_IMM:
            EMIT_CMP_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x8f, tgt);
            break;
        case EBPF_OP_JSGT_REG:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x8f, tgt);
            break;
        case EBPF_OP_JSGE_IMM:
            EMIT_CMP_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x8d, tgt);
            break;
        case EBPF_OP_JSGE_REG:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x8d, tgt);
            break;
        case EBPF_OP_JSLT_IMM:
            EMIT_CMP_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x8c, tgt);
            break;
        case EBPF_OP_JSLT_REG:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x8c, tgt);
            break;
        case EBPF_OP_JSLE_IMM:
            EMIT_CMP_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x8e, tgt);
            break;
        case EBPF_OP_JSLE_REG:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x8e, tgt);
            break;
        case EBPF_OP_JEQ32_IMM:
            EMIT_CMP32_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x84, tgt);
            break;
        case EBPF_OP_JEQ32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x84, tgt);
            break;
        case EBPF_OP_JGT32_IMM:
            EMIT_CMP32_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x87, tgt);
            break;
        case EBPF_OP_JGT32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x87, tgt);
            break;
        case EBPF_OP_JGE32_IMM:
            EMIT_CMP32_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x83, tgt);
            break;
        case EBPF_OP_JGE32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x83, tgt);
            break;
        case EBPF_OP_JLT32_IMM:
            EMIT_CMP32_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x82, tgt);
            break;
        case EBPF_OP_JLT32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x82, tgt);
            break;
        case EBPF_OP_JLE32_IMM:
            EMIT_CMP32_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x86, tgt);
            break;
        case EBPF_OP_JLE32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x86, tgt);
            break;
        case EBPF_OP_JSET32_IMM:
            EMIT_TEST32_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x85, tgt);
            break;
        case EBPF_OP_JSET32_REG:
            emit_alu32(state, 0x85, src, dst);
            emit_jcc(state, 0x85, tgt);
            break;
        case EBPF_OP_JNE32_IMM:
            EMIT_CMP32_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x85, tgt);
            break;
        case EBPF_OP_JNE32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x85, tgt);
            break;
        case EBPF_OP_JSGT32_IMM:
            EMIT_CMP32_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x8f, tgt);
            break;
        case EBPF_OP_JSGT32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x8f, tgt);
            break;
        case EBPF_OP_JSGE32_IMM:
            EMIT_CMP32_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x8d, tgt);
            break;
        case EBPF_OP_JSGE32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x8d, tgt);
            break;
        case EBPF_OP_JSLT32_IMM:
            EMIT_CMP32_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x8c, tgt);
            break;
        case EBPF_OP_JSLT32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x8c, tgt);
            break;
        case EBPF_OP_JSLE32_IMM:
            EMIT_CMP32_IMM32(vm, state, dst, inst.imm);
            emit_jcc(state, 0x8e, tgt);
            break;
        case EBPF_OP_JSLE32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x8e, tgt);
            break;
        case EBPF_OP_CALL:
            /* We reserve RCX for shifts */
            if (inst.src == 0) {
                emit_mov(state, RCX_ALT, RCX);
                emit_dispatched_external_helper_call(state, inst.imm);
                if (inst.imm == vm->unwind_stack_extension_index) {
                    emit_cmp_imm32(state, map_register(BPF_REG_0), 0);
                    DECLARE_PATCHABLE_TARGET(exit_tgt);
                    exit_tgt.is_special = true;
                    exit_tgt.target.special = Exit;
                    emit_jcc(state, 0x84, exit_tgt);
                }
            } else if (inst.src == 1) {
                target_pc = i + inst.imm + 1;
                emit_local_call(vm, state, target_pc);
            }
            break;
        case EBPF_OP_EXIT:
            /* There is an invariant that the top of the host stack contains
             * the amout of space used by the currently-executing eBPF function.
             * 8 bytes are required for the storage. So, anytime that we leave an
             * eBPF function, we must pop its local usage from the top of the
             * host stack.
             */
            emit_alu64_imm32(state, 0x81, 0, RSP, 8);
            emit_ret(state);
            break;

        case EBPF_OP_LDXW:
            emit_load(state, S32, src, dst, inst.offset);
            break;
        case EBPF_OP_LDXH:
            emit_load(state, S16, src, dst, inst.offset);
            break;
        case EBPF_OP_LDXB:
            emit_load(state, S8, src, dst, inst.offset);
            break;
        case EBPF_OP_LDXDW:
            emit_load(state, S64, src, dst, inst.offset);
            break;

        case EBPF_OP_LDXWSX:
            emit_load_sx(state, S32, src, dst, inst.offset);
            break;
        case EBPF_OP_LDXHSX:
            emit_load_sx(state, S16, src, dst, inst.offset);
            break;
        case EBPF_OP_LDXBSX:
            emit_load_sx(state, S8, src, dst, inst.offset);
            break;

        case EBPF_OP_STW:
            EMIT_STORE_IMM32(vm, state, S32, dst, inst.offset, inst.imm);
            break;
        case EBPF_OP_STH:
            EMIT_STORE_IMM32(vm, state, S16, dst, inst.offset, inst.imm);
            break;
        case EBPF_OP_STB:
            EMIT_STORE_IMM32(vm, state, S8, dst, inst.offset, inst.imm);
            break;
        case EBPF_OP_STDW:
            EMIT_STORE_IMM32(vm, state, S64, dst, inst.offset, inst.imm);
            break;

        case EBPF_OP_STXW:
            emit_store(state, S32, src, dst, inst.offset);
            break;
        case EBPF_OP_STXH:
            emit_store(state, S16, src, dst, inst.offset);
            break;
        case EBPF_OP_STXB:
            emit_store(state, S8, src, dst, inst.offset);
            break;
        case EBPF_OP_STXDW:
            emit_store(state, S64, src, dst, inst.offset);
            break;

        case EBPF_OP_LDDW: {
            struct ebpf_inst inst2 = ubpf_fetch_instruction(vm, ++i);
            uint64_t imm = (uint32_t)inst.imm | ((uint64_t)inst2.imm << 32);
            EMIT_LOAD_IMM(vm, state, dst, imm);
            break;
        }
        case EBPF_OP_ATOMIC_STORE: {
            bool fetch = inst.imm & EBPF_ATOMIC_OP_FETCH;
            switch (inst.imm & EBPF_ALU_OP_MASK) {
            case EBPF_ALU_OP_ADD:
                if (fetch) {
                    emit_atomic_fetch_add64(state, src, dst, inst.offset);
                } else {
                    emit_atomic_add64(state, src, dst, inst.offset);
                }
                break;
            case EBPF_ALU_OP_OR:
                if (fetch) {
                    emit_atomic_fetch_or64(state, src, dst, inst.offset);
                } else {
                    emit_atomic_or64(state, src, dst, inst.offset);
                }
                break;
            case EBPF_ALU_OP_AND:
                if (fetch) {
                    emit_atomic_fetch_and64(state, src, dst, inst.offset);
                } else {
                    emit_atomic_and64(state, src, dst, inst.offset);
                }
                break;
            case EBPF_ALU_OP_XOR:
                if (fetch) {
                    emit_atomic_fetch_xor64(state, src, dst, inst.offset);
                } else {
                    emit_atomic_xor64(state, src, dst, inst.offset);
                }
                break;
            case (EBPF_ATOMIC_OP_XCHG & ~EBPF_ATOMIC_OP_FETCH):
                emit_atomic_exchange64(state, src, dst, inst.offset);
                break;
            case (EBPF_ATOMIC_OP_CMPXCHG & ~EBPF_ATOMIC_OP_FETCH):
                emit_atomic_compare_exchange64(state, src, dst, inst.offset);
                break;
            default:
                *errmsg = ubpf_error("Error: unknown atomic opcode %d at PC %d\n", inst.imm, i);
                return -1;
            }
        } break;

        case EBPF_OP_ATOMIC32_STORE: {
            bool fetch = inst.imm & EBPF_ATOMIC_OP_FETCH;
            switch (inst.imm & EBPF_ALU_OP_MASK) {
            case EBPF_ALU_OP_ADD:
                if (fetch) {
                    emit_atomic_fetch_add32(state, src, dst, inst.offset);
                } else {
                    emit_atomic_add32(state, src, dst, inst.offset);
                }
                break;
            case EBPF_ALU_OP_OR:
                if (fetch) {
                    emit_atomic_fetch_or32(state, src, dst, inst.offset);
                } else {
                    emit_atomic_or32(state, src, dst, inst.offset);
                }
                break;
            case EBPF_ALU_OP_AND:
                if (fetch) {
                    emit_atomic_fetch_and32(state, src, dst, inst.offset);
                } else {
                    emit_atomic_and32(state, src, dst, inst.offset);
                }
                break;
            case EBPF_ALU_OP_XOR:
                if (fetch) {
                    emit_atomic_fetch_xor32(state, src, dst, inst.offset);
                } else {
                    emit_atomic_xor32(state, src, dst, inst.offset);
                }
                break;
            case (EBPF_ATOMIC_OP_XCHG & ~EBPF_ATOMIC_OP_FETCH):
                emit_atomic_exchange32(state, src, dst, inst.offset);
                emit_truncate_u32(state, src);
                break;
            case (EBPF_ATOMIC_OP_CMPXCHG & ~EBPF_ATOMIC_OP_FETCH):
                emit_atomic_compare_exchange32(state, src, dst, inst.offset);
                emit_truncate_u32(state, map_register(0));
                break;
            default:
                *errmsg = ubpf_error("Error: unknown atomic opcode %d at PC %d\n", inst.imm, i);
                return -1;
            }
        } break;

        default:
            state->jit_status = UnknownInstruction;
            *errmsg = ubpf_error("Unknown instruction at PC %d: opcode %02x", i, inst.opcode);
        }

        // If this is a ALU32 instruction, truncate the target register to 32 bits.
        if (((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU) && (inst.opcode & EBPF_ALU_OP_MASK) != 0xd0) {
            emit_truncate_u32(state, dst);
        }
    }

    if (state->jit_status != NoError) {
        switch (state->jit_status) {
        case TooManyJumps: {
            *errmsg = ubpf_error("Too many jump instructions");
            break;
        }
        case TooManyLoads: {
            *errmsg = ubpf_error("Too many load instructions");
            break;
        }
        case TooManyLeas: {
            *errmsg = ubpf_error("Too many LEA calculations");
            break;
        }
        case TooManyLocalCalls: {
            *errmsg = ubpf_error("Too many local calls");
            break;
        }
        case UnexpectedInstruction: {
            // errmsg set at time the error was detected because the message requires
            // information about the unexpected instruction.
            break;
        }
        case UnknownInstruction: {
            // errmsg set at time the error was detected because the message requires
            // information about the unknown instruction.
            break;
        }
        case NotEnoughSpace: {
            *errmsg = ubpf_error("Target buffer too small");
            break;
        }
        case NoError: {
            assert(false);
        }
        }
        return -1;
    }

    /* Epilogue */
    state->exit_loc = state->offset;

    /* Move register 0 into rax */
    if (map_register(BPF_REG_0) != RAX) {
        emit_mov(state, map_register(BPF_REG_0), RAX);
    }

    /* Deallocate stack space by restoring RSP from RBP. */
    emit_mov(state, RBP, RSP);

    if (!(_countof(platform_nonvolatile_registers) % 2)) {
        emit_alu64_imm32(state, 0x81, 0, RSP, 0x8);
    }

    /* Restore platform non-volatile registers */
    for (i = 0; i < _countof(platform_nonvolatile_registers); i++) {
        emit_pop(state, platform_nonvolatile_registers[_countof(platform_nonvolatile_registers) - i - 1]);
    }

    emit1(state, 0xc3); /* ret */

    state->retpoline_loc = emit_retpoline(state);
    state->dispatcher_loc = emit_dispatched_external_helper_address(state, vm);
    state->helper_table_loc = emit_helper_table(state, vm);

    return 0;
}

static bool
resolve_patchable_relatives(struct jit_state* state)
{
    int i;
    for (i = 0; i < state->num_jumps; i++) {
        struct patchable_relative jump = state->jumps[i];

        int target_loc;
        bool is_near = false;

        if (jump.target.is_special) {
            // There are only two special targets for jumps: Exit and Retpoline.
            if (jump.target.target.special == Exit) {
                target_loc = state->exit_loc;
            } else if (jump.target.target.special == Retpoline) {
                target_loc = state->retpoline_loc;
            } else {
                target_loc = -1;
                return false;
            }
        } else {
            // The jit target, if specified, takes precedence.
            if (jump.target.target.regular.jit_target_pc != 0) {
                target_loc = jump.target.target.regular.jit_target_pc;
            } else {
                target_loc = state->pc_locs[jump.target.target.regular.ebpf_target_pc];
            }

            is_near = jump.target.target.regular.near;
        }

        if (is_near) {
            /* When there is a near jump, we need to make sure that the target
             * is within the proper limits. So, we start with a type that can
             * hold values that are bigger than we'll ultimately need. If we
             * went straight to the uint8_t, we couldn't tell if we overflowed.
             */
            int32_t rel = target_loc - (jump.offset_loc + sizeof(uint8_t));
            if (!(-128 <= rel && rel < 128)) {
                return false;
            }
            /* Now that we are sure the target is _near_ enough, we can move
             * to the proper type.
             */
            int8_t rel8 = rel;
            uint8_t* offset_ptr = &state->buf[jump.offset_loc];
            *offset_ptr = rel8;
        } else {
            /* Assumes jump offset is at end of instruction */
            uint32_t rel = target_loc - (jump.offset_loc + sizeof(uint32_t));

            uint8_t* offset_ptr = &state->buf[jump.offset_loc];
            memcpy(offset_ptr, &rel, sizeof(uint32_t));
        }
    }

    for (i = 0; i < state->num_local_calls; i++) {
        struct patchable_relative local_call = state->local_calls[i];

        // There are no special local calls and
        assert(!local_call.target.is_special);
        // the targets must all be eBPF-relative PCs.
        assert(local_call.target.target.regular.jit_target_pc == 0);

        int target_loc = state->pc_locs[local_call.target.target.regular.ebpf_target_pc];

        /* Assumes call offset is at end of instruction */
        uint32_t rel = target_loc - (local_call.offset_loc + sizeof(uint32_t));
        rel -= state->bpf_function_prolog_size; // For the prolog inserted at the start of every local call.

        uint8_t* offset_ptr = &state->buf[local_call.offset_loc];
        memcpy(offset_ptr, &rel, sizeof(uint32_t));
    }

    for (i = 0; i < state->num_loads; i++) {
        struct patchable_relative load = state->loads[i];

        int target_loc = 0;
        // It is only possible to load from the external dispatcher's position.
        if (load.target.is_special && load.target.target.special == ExternalDispatcher) {
            target_loc = state->dispatcher_loc;
        } else {
            target_loc = -1;
            return false;
        }
        /* Assumes load target is calculated relative to the end of instruction */
        uint32_t rel = target_loc - (load.offset_loc + sizeof(uint32_t));

        uint8_t* offset_ptr = &state->buf[load.offset_loc];
        memcpy(offset_ptr, &rel, sizeof(uint32_t));
    }

    for (i = 0; i < state->num_leas; i++) {
        struct patchable_relative lea = state->leas[i];

        int target_loc;
        // It is only possible to LEA from the helper table.
        if (lea.target.is_special && lea.target.target.special == LoadHelperTable) {
            target_loc = state->helper_table_loc;
        } else {
            target_loc = -1;
            return false;
        }
        /* Assumes lea target is calculated relative to the end of instruction */
        uint32_t rel = target_loc - (lea.offset_loc + sizeof(uint32_t));

        uint8_t* offset_ptr = &state->buf[lea.offset_loc];
        memcpy(offset_ptr, &rel, sizeof(uint32_t));
    }
    return true;
}

struct ubpf_jit_result
ubpf_translate_x86_64(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, enum JitMode jit_mode)
{
    struct jit_state state;
    struct ubpf_jit_result compile_result;

    if (initialize_jit_state_result(vm, &state, &compile_result, buffer, *size, jit_mode, &compile_result.errmsg) < 0) {
        goto out;
    }

    if (translate(vm, &state, &compile_result.errmsg) < 0) {
        goto out;
    }

    if (!resolve_patchable_relatives(&state)) {
        compile_result.errmsg = ubpf_error("Could not patch the relative addresses in the JIT'd code");
        goto out;
    }

    compile_result.compile_result = UBPF_JIT_COMPILE_SUCCESS;
    compile_result.external_dispatcher_offset = state.dispatcher_loc;
    compile_result.external_helper_offset = state.helper_table_loc;
    compile_result.jit_mode = jit_mode;
    *size = state.offset;

out:
    release_jit_state_result(&state, &compile_result);
    return compile_result;
}

bool
ubpf_jit_update_dispatcher_x86_64(
    struct ubpf_vm* vm, external_function_dispatcher_t new_dispatcher, uint8_t* buffer, size_t size, uint32_t offset)
{
    UNUSED_PARAMETER(vm);
    uint64_t jit_upper_bound = (uint64_t)buffer + size;
    void* dispatcher_address = (void*)((uint64_t)buffer + offset);
    if ((uint64_t)dispatcher_address + sizeof(void*) < jit_upper_bound) {
        memcpy(dispatcher_address, &new_dispatcher, sizeof(void*));
        return true;
    }

    return false;
}

bool
ubpf_jit_update_helper_x86_64(
    struct ubpf_vm* vm,
    extended_external_helper_t new_helper,
    unsigned int idx,
    uint8_t* buffer,
    size_t size,
    uint32_t offset)
{
    UNUSED_PARAMETER(vm);
    uint64_t jit_upper_bound = (uint64_t)buffer + size;

    void* dispatcher_address = (void*)((uint64_t)buffer + offset + (8 * idx));
    if ((uint64_t)dispatcher_address + sizeof(void*) < jit_upper_bound) {
        memcpy(dispatcher_address, &new_helper, sizeof(void*));
        return true;
    }
    return false;
}
