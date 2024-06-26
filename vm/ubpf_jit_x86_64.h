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
#include "ubpf_jit_support.h"

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
emit_jump_address_reloc(struct jit_state* state, int32_t target_pc)
{
    if (state->num_jumps == UBPF_MAX_INSTS) {
        state->jit_status = TooManyJumps;
        return 0;
    }
    uint32_t target_address_offset = state->offset;
    emit_patchable_relative(state->offset, target_pc, 0, state->jumps, state->num_jumps++);
    emit_4byte_offset_placeholder(state);
    return target_address_offset;
}

static uint32_t
emit_near_jump_address_reloc(struct jit_state* state, int32_t target_pc)
{
    if (state->num_jumps == UBPF_MAX_INSTS) {
        state->jit_status = TooManyJumps;
        return 0;
    }
    uint32_t target_address_offset = state->offset;
    emit_patchable_relative_ex(state->offset, target_pc, 0, state->jumps, state->num_jumps++, true /* near */);
    emit1(state, 0x0);
    return target_address_offset;
}

static uint32_t
emit_local_call_address_reloc(struct jit_state* state, int32_t target_pc)
{
    if (state->num_local_calls == UBPF_MAX_INSTS) {
        state->jit_status = TooManyLocalCalls;
        return 0;
    }
    uint32_t target_address_offset = state->offset;
    emit_patchable_relative(state->offset, target_pc, 0, state->local_calls, state->num_local_calls++);
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
emit_jcc(struct jit_state* state, int code, int32_t target_pc)
{
    emit1(state, 0x0f);
    emit1(state, code);
    return emit_jump_address_reloc(state, target_pc);
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

static uint32_t
emit_rip_relative_load(struct jit_state* state, int dst, int relative_load_tgt)
{
    if (state->num_loads == UBPF_MAX_INSTS) {
        state->jit_status = TooManyLoads;
        return 0;
    }

    emit_rex(state, 1, 0, 0, 0);
    emit1(state, 0x8b);
    emit_modrm(state, 0, dst, 0x05);
    uint32_t load_target_offset = state->offset;
    note_load(state, relative_load_tgt);
    emit_4byte_offset_placeholder(state);
    return load_target_offset;
}

static void
emit_rip_relative_lea(struct jit_state* state, int dst, int lea_tgt)
{
    if (state->num_leas == UBPF_MAX_INSTS) {
        state->jit_status = TooManyLeas;
        return;
    }

    // lea dst, [rip + HELPER TABLE ADDRESS]
    emit_rex(state, 1, 1, 0, 0);
    emit1(state, 0x8d);
    emit_modrm(state, 0, dst, 0x05);
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
emit_jmp(struct jit_state* state, uint32_t target_pc)
{
    emit1(state, 0xe9);
    return emit_jump_address_reloc(state, target_pc);
}

/** @brief Emit a near jump.
 *
 * @param[in] state The JIT state.
 * @param[in] target_pc The PC to which to jump when this near
 *                      jump is executed.
 * @return The offset in the JIT'd code where the jump offset starts.
 */
static inline uint32_t
emit_near_jmp(struct jit_state* state, uint32_t target_pc)
{
    emit1(state, 0xeb);
    return emit_near_jump_address_reloc(state, target_pc);
}

static inline uint32_t
emit_call(struct jit_state* state, uint32_t target_pc)
{
    emit1(state, 0xe8);
    uint32_t call_src = state->offset;
    emit_jump_address_reloc(state, target_pc);
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

    emit_rip_relative_load(state, RAX, TARGET_PC_EXTERNAL_DISPATCHER);
    // cmp rax, 0
    emit_cmp_imm32(state, RAX, 0);
    // jne skip_default_dispatcher_label
    uint32_t skip_default_dispatcher_source = emit_jcc(state, 0x85, 0);

    // Default dispatcher:

    // Load the address of the helper function from the table.
    // mov rax, idx
    emit_alu32(state, 0xc7, 0, RAX);
    emit4(state, idx);
    // shl rax, 3 (i.e., multiply the index by 8 because addresses are that size on x86-64)
    emit_alu64_imm8(state, 0xc1, 4, RAX, 3);

    // lea r10, [rip + HELPER TABLE ADDRESS]
    emit_rip_relative_lea(state, R10, TARGET_LOAD_HELPER_TABLE);

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
    emit1(state, 0xe9);
    uint32_t skip_external_dispatcher_source = emit_jump_address_reloc(state, 0);

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
    emit_call(state, TARGET_PC_RETPOLINE);
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

#endif
