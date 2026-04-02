// Copyright (c) 2015 Big Switch Networks, Inc
// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2015 Big Switch Networks, Inc
 * Copyright 2026 uBPF Contributors
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
 *
 * uBPF JIT backend for MIPS64 Release 6 (mipsel64r6).
 * [JIT-SPEC]: docs/specs/jit-mips.md
 * [MIPS64-ISA]: MIPS64 Architecture for Programmers Vol II, Rev 6.06
 */

#include <stdint.h>
#define _GNU_SOURCE
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include "ubpf_int.h"
#include "ubpf_jit_support.h"

#if !defined(_countof)
#define _countof(array) (sizeof(array) / sizeof(array[0]))
#endif

/* ========================================================================
 * MIPS64r6 GPR definitions (n64 ABI)
 * [JIT-SPEC] §2
 * ======================================================================== */

enum MipsReg {
    ZERO = 0,  AT = 1,   V0 = 2,   V1 = 3,
    A0 = 4,    A1 = 5,   A2 = 6,   A3 = 7,
    A4 = 8,    A5 = 9,   A6 = 10,  A7 = 11,
    T4 = 12,   T5 = 13,  T6 = 14,  T7 = 15,
    S0 = 16,   S1 = 17,  S2 = 18,  S3 = 19,
    S4 = 20,   S5 = 21,  S6 = 22,  S7 = 23,
    T8 = 24,   T9 = 25,  K0 = 26,  K1 = 27,
    GP = 28,   SP = 29,  FP = 30,  RA = 31,
};

#define REGISTER_MAP_SIZE 11

/* BPF → MIPS64 register mapping. [JIT-SPEC] §2.1 */
static enum MipsReg register_map[REGISTER_MAP_SIZE] = {
    V0,  /* BPF R0 — return */
    A0, A1, A2, A3, A4,  /* BPF R1–R5 — params */
    S0, S1, S2, S3,      /* BPF R6–R9 — callee-saved */
    S4,                  /* BPF R10 — frame pointer */
};

/* Scratch registers. [JIT-SPEC] §2.2 */
#define TEMP_REG   T4  /* Large immediates, blinding */
#define TEMP_DIV   T5  /* Division, atomics */
#define TEMP_ADDR  T6  /* Address computation */
#define CTX_REG    S6  /* Context/cookie pointer */
#define HTAB_REG   S5  /* Helper table base */

static enum MipsReg callee_saved_registers[] = {
    S0, S1, S2, S3, S4, S5, S6,
};

static enum MipsReg
map_register(int r)
{
    assert(r < REGISTER_MAP_SIZE);
    return register_map[r % REGISTER_MAP_SIZE];
}

/* ========================================================================
 * MIPS64r6 instruction encoding
 * ======================================================================== */

/* Emit a 32-bit instruction. */
static void
emit(struct jit_state* state, uint32_t instr)
{
    assert(state->offset + 4 <= state->size);
    *(uint32_t*)(state->buf + state->offset) = instr;
    state->offset += 4;
}

/* R-type: opcode(6)|rs(5)|rt(5)|rd(5)|shamt(5)|funct(6) */
static inline uint32_t
r_type(uint8_t op, uint8_t rs, uint8_t rt, uint8_t rd, uint8_t sa, uint8_t fn)
{
    return ((uint32_t)(op & 0x3F) << 26) | ((uint32_t)(rs & 0x1F) << 21) |
           ((uint32_t)(rt & 0x1F) << 16) | ((uint32_t)(rd & 0x1F) << 11) |
           ((uint32_t)(sa & 0x1F) << 6) | (fn & 0x3F);
}

/* I-type: opcode(6)|rs(5)|rt(5)|imm(16) */
static inline uint32_t
i_type(uint8_t op, uint8_t rs, uint8_t rt, uint16_t imm)
{
    return ((uint32_t)(op & 0x3F) << 26) | ((uint32_t)(rs & 0x1F) << 21) |
           ((uint32_t)(rt & 0x1F) << 16) | imm;
}

/* Opcodes */
#define OP_SPECIAL   0x00
#define OP_SPECIAL3  0x1F
#define OP_DADDIU    0x19
#define OP_ORI       0x0D
#define OP_ANDI      0x0C
#define OP_XORI      0x0E
#define OP_LUI       0x0F
#define OP_LD        0x37
#define OP_SD        0x3F
#define OP_LW        0x23
#define OP_LWU       0x27
#define OP_SW        0x2B
#define OP_LH        0x21
#define OP_LHU       0x25
#define OP_SH        0x29
#define OP_LB        0x20
#define OP_LBU       0x24
#define OP_SB        0x28
#define OP_BC        0x32
#define OP_BALC      0x3A
#define OP_BEQC      0x08  /* POP06: rs < rt, rs != 0 */
#define OP_BNEC      0x18  /* POP26: rs < rt, rs != 0 */
#define OP_BEQZC     0x36  /* POP66 */
#define OP_BNEZC     0x3E  /* POP76 */
#define OP_BGEC      0x16  /* POP10: signed, rs >= rt */
#define OP_BLTC      0x17  /* POP11: signed, rs < rt */
#define OP_BGEUC     0x06  /* POP06: unsigned, rs >= rt (rs > rt in encoding) */
#define OP_BLTUC     0x07  /* POP07: unsigned, rs < rt (rs < rt in encoding) */

/* SPECIAL function codes */
#define FN_DADDU    0x2D
#define FN_DSUBU    0x2F
#define FN_OR       0x25
#define FN_AND      0x24
#define FN_XOR      0x26
#define FN_DSLLV    0x14
#define FN_DSRLV    0x16
#define FN_DSRAV    0x17
#define FN_DSLL     0x38
#define FN_DSRL     0x3A
#define FN_DSRA     0x3B
#define FN_DSLL32   0x3C
#define FN_DSRL32   0x3E
#define FN_DSRA32   0x3F
#define FN_SLLV     0x04
#define FN_SRLV     0x06
#define FN_SRAV     0x07
#define FN_SLL      0x00
#define FN_JALR     0x09

/* R6 mul/div: SPECIAL opcode, distinguished by shamt field */
#define FN_SOP30    0x18  /* MUL/MUH */
#define FN_SOP32    0x1A  /* DIV/MOD */
#define FN_SOP33    0x1B  /* DIVU/MODU */
#define FN_SOP34    0x1C  /* DMUL/DMUH */
#define FN_SOP36    0x1E  /* DDIV/DMOD */
#define FN_SOP37    0x1F  /* DDIVU/DMODU */
#define SA_MUL      0x02  /* shamt for MUL/DMUL */
#define SA_MOD      0x03  /* shamt for MOD/DMOD/MUH/DMUH */

/* SPECIAL3 sub-function codes */
#define FN_BSHFL    0x20
#define FN_DBSHFL   0x24
#define SA_SEB      0x10
#define SA_SEH      0x18
#define SA_WSBH     0x02
#define SA_DSBH     0x02
#define SA_DSHD     0x05

/* ========================================================================
 * Instruction emission helpers
 * Each wraps one MIPS64r6 instruction.
 * ======================================================================== */

/* ALU */
static inline void emit_daddu(struct jit_state* s, int rd, int rs, int rt) { emit(s, r_type(OP_SPECIAL, rs, rt, rd, 0, FN_DADDU)); }
static inline void emit_dsubu(struct jit_state* s, int rd, int rs, int rt) { emit(s, r_type(OP_SPECIAL, rs, rt, rd, 0, FN_DSUBU)); }
static inline void emit_or(struct jit_state* s, int rd, int rs, int rt)    { emit(s, r_type(OP_SPECIAL, rs, rt, rd, 0, FN_OR)); }
static inline void emit_and(struct jit_state* s, int rd, int rs, int rt)   { emit(s, r_type(OP_SPECIAL, rs, rt, rd, 0, FN_AND)); }
static inline void emit_xor(struct jit_state* s, int rd, int rs, int rt)   { emit(s, r_type(OP_SPECIAL, rs, rt, rd, 0, FN_XOR)); }
static inline void emit_dsllv(struct jit_state* s, int rd, int rt, int rs) { emit(s, r_type(OP_SPECIAL, rs, rt, rd, 0, FN_DSLLV)); }
static inline void emit_dsrlv(struct jit_state* s, int rd, int rt, int rs) { emit(s, r_type(OP_SPECIAL, rs, rt, rd, 0, FN_DSRLV)); }
static inline void emit_dsrav(struct jit_state* s, int rd, int rt, int rs) { emit(s, r_type(OP_SPECIAL, rs, rt, rd, 0, FN_DSRAV)); }
static inline void emit_sllv(struct jit_state* s, int rd, int rt, int rs)  { emit(s, r_type(OP_SPECIAL, rs, rt, rd, 0, FN_SLLV)); }
static inline void emit_srlv(struct jit_state* s, int rd, int rt, int rs)  { emit(s, r_type(OP_SPECIAL, rs, rt, rd, 0, FN_SRLV)); }
static inline void emit_srav(struct jit_state* s, int rd, int rt, int rs)  { emit(s, r_type(OP_SPECIAL, rs, rt, rd, 0, FN_SRAV)); }
static inline void emit_dsll32(struct jit_state* s, int rd, int rt, int sa){ emit(s, r_type(OP_SPECIAL, 0, rt, rd, sa, FN_DSLL32)); }
static inline void emit_dsrl32(struct jit_state* s, int rd, int rt, int sa){ emit(s, r_type(OP_SPECIAL, 0, rt, rd, sa, FN_DSRL32)); }
static inline void emit_sll(struct jit_state* s, int rd, int rt, int sa)   { emit(s, r_type(OP_SPECIAL, 0, rt, rd, sa, FN_SLL)); }

/* R6 multiply/divide — result in rd directly */
static inline void emit_dmul(struct jit_state* s, int rd, int rs, int rt)  { emit(s, r_type(OP_SPECIAL, rs, rt, rd, SA_MUL, FN_SOP34)); }
static inline void emit_ddiv(struct jit_state* s, int rd, int rs, int rt)  { emit(s, r_type(OP_SPECIAL, rs, rt, rd, SA_MUL, FN_SOP36)); }
static inline void emit_dmod(struct jit_state* s, int rd, int rs, int rt)  { emit(s, r_type(OP_SPECIAL, rs, rt, rd, SA_MOD, FN_SOP36)); }
static inline void emit_ddivu(struct jit_state* s, int rd, int rs, int rt) { emit(s, r_type(OP_SPECIAL, rs, rt, rd, SA_MUL, FN_SOP37)); }
static inline void emit_dmodu(struct jit_state* s, int rd, int rs, int rt) { emit(s, r_type(OP_SPECIAL, rs, rt, rd, SA_MOD, FN_SOP37)); }
static inline void emit_mul(struct jit_state* s, int rd, int rs, int rt)   { emit(s, r_type(OP_SPECIAL, rs, rt, rd, SA_MUL, FN_SOP30)); }
static inline void emit_div(struct jit_state* s, int rd, int rs, int rt)   { emit(s, r_type(OP_SPECIAL, rs, rt, rd, SA_MUL, FN_SOP32)); }
static inline void emit_mod(struct jit_state* s, int rd, int rs, int rt)   { emit(s, r_type(OP_SPECIAL, rs, rt, rd, SA_MOD, FN_SOP32)); }
static inline void emit_divu(struct jit_state* s, int rd, int rs, int rt)  { emit(s, r_type(OP_SPECIAL, rs, rt, rd, SA_MUL, FN_SOP33)); }
static inline void emit_modu(struct jit_state* s, int rd, int rs, int rt)  { emit(s, r_type(OP_SPECIAL, rs, rt, rd, SA_MOD, FN_SOP33)); }

/* Immediates */
static inline void emit_daddiu(struct jit_state* s, int rt, int rs, int16_t imm) { emit(s, i_type(OP_DADDIU, rs, rt, (uint16_t)imm)); }
static inline void emit_ori(struct jit_state* s, int rt, int rs, uint16_t imm)   { emit(s, i_type(OP_ORI, rs, rt, imm)); }
static inline void emit_andi(struct jit_state* s, int rt, int rs, uint16_t imm)  { emit(s, i_type(OP_ANDI, rs, rt, imm)); }
static inline void emit_xori(struct jit_state* s, int rt, int rs, uint16_t imm)  { emit(s, i_type(OP_XORI, rs, rt, imm)); }
static inline void emit_lui(struct jit_state* s, int rt, int16_t imm)            { emit(s, i_type(OP_LUI, 0, rt, (uint16_t)imm)); }

/* Memory */
static inline void emit_ld(struct jit_state* s, int rt, int base, int16_t off)  { emit(s, i_type(OP_LD, base, rt, (uint16_t)off)); }
static inline void emit_sd(struct jit_state* s, int rt, int base, int16_t off)  { emit(s, i_type(OP_SD, base, rt, (uint16_t)off)); }
static inline void emit_lwu(struct jit_state* s, int rt, int base, int16_t off) { emit(s, i_type(OP_LWU, base, rt, (uint16_t)off)); }
static inline void emit_sw(struct jit_state* s, int rt, int base, int16_t off)  { emit(s, i_type(OP_SW, base, rt, (uint16_t)off)); }
static inline void emit_lhu(struct jit_state* s, int rt, int base, int16_t off) { emit(s, i_type(OP_LHU, base, rt, (uint16_t)off)); }
static inline void emit_sh(struct jit_state* s, int rt, int base, int16_t off)  { emit(s, i_type(OP_SH, base, rt, (uint16_t)off)); }
static inline void emit_lbu(struct jit_state* s, int rt, int base, int16_t off) { emit(s, i_type(OP_LBU, base, rt, (uint16_t)off)); }
static inline void emit_sb(struct jit_state* s, int rt, int base, int16_t off)  { emit(s, i_type(OP_SB, base, rt, (uint16_t)off)); }
static inline void emit_lw(struct jit_state* s, int rt, int base, int16_t off)  { emit(s, i_type(OP_LW, base, rt, (uint16_t)off)); }
static inline void emit_lh(struct jit_state* s, int rt, int base, int16_t off)  { emit(s, i_type(OP_LH, base, rt, (uint16_t)off)); }
static inline void emit_lb(struct jit_state* s, int rt, int base, int16_t off)  { emit(s, i_type(OP_LB, base, rt, (uint16_t)off)); }

/* Sign-extension (SPECIAL3/BSHFL) */
static inline void emit_seb(struct jit_state* s, int rd, int rt) { emit(s, r_type(OP_SPECIAL3, 0, rt, rd, SA_SEB, FN_BSHFL)); }
static inline void emit_seh(struct jit_state* s, int rd, int rt) { emit(s, r_type(OP_SPECIAL3, 0, rt, rd, SA_SEH, FN_BSHFL)); }

/* Byte swap (SPECIAL3/BSHFL, DBSHFL) */
static inline void emit_wsbh(struct jit_state* s, int rd, int rt)  { emit(s, r_type(OP_SPECIAL3, 0, rt, rd, SA_WSBH, FN_BSHFL)); }
static inline void emit_dsbh(struct jit_state* s, int rd, int rt)  { emit(s, r_type(OP_SPECIAL3, 0, rt, rd, SA_DSBH, FN_DBSHFL)); }
static inline void emit_dshd(struct jit_state* s, int rd, int rt)  { emit(s, r_type(OP_SPECIAL3, 0, rt, rd, SA_DSHD, FN_DBSHFL)); }

/* Control flow */
static inline void emit_jalr(struct jit_state* s, int rd, int rs) { emit(s, r_type(OP_SPECIAL, rs, 0, rd, 0, FN_JALR)); }
static inline void emit_jr(struct jit_state* s, int rs)           { emit(s, r_type(OP_SPECIAL, rs, 0, 0, 0, FN_JALR)); }

/* R6 compact branches — no delay slot */
static inline void emit_bc(struct jit_state* s, int32_t off26)   { emit(s, ((uint32_t)OP_BC << 26) | ((uint32_t)off26 & 0x03FFFFFF)); }
static inline void emit_balc(struct jit_state* s, int32_t off26) { emit(s, ((uint32_t)OP_BALC << 26) | ((uint32_t)off26 & 0x03FFFFFF)); }

/* R6 compact conditional branches */
static inline void emit_beqc(struct jit_state* s, int rs, int rt, int16_t off) { emit(s, i_type(OP_BEQC, rs, rt, (uint16_t)off)); }
static inline void emit_bnec(struct jit_state* s, int rs, int rt, int16_t off) { emit(s, i_type(OP_BNEC, rs, rt, (uint16_t)off)); }
static inline void emit_beqzc(struct jit_state* s, int rs, int32_t off21) {
    emit(s, ((uint32_t)OP_BEQZC << 26) | ((uint32_t)(rs & 0x1F) << 21) | ((uint32_t)off21 & 0x1FFFFF));
}
static inline void emit_bnezc(struct jit_state* s, int rs, int32_t off21) {
    emit(s, ((uint32_t)OP_BNEZC << 26) | ((uint32_t)(rs & 0x1F) << 21) | ((uint32_t)off21 & 0x1FFFFF));
}
static inline void emit_bgeuc(struct jit_state* s, int rs, int rt, int16_t off) { emit(s, i_type(OP_BGEUC, rs, rt, (uint16_t)off)); }
static inline void emit_bltuc(struct jit_state* s, int rs, int rt, int16_t off) { emit(s, i_type(OP_BLTUC, rs, rt, (uint16_t)off)); }
static inline void emit_bgec(struct jit_state* s, int rs, int rt, int16_t off)  { emit(s, i_type(OP_BGEC, rs, rt, (uint16_t)off)); }
static inline void emit_bltc(struct jit_state* s, int rs, int rt, int16_t off)  { emit(s, i_type(OP_BLTC, rs, rt, (uint16_t)off)); }

/* LL/SC atomics */
/* R6 encodes LL/SC differently: SPECIAL3 opcode, function code in bits 5-0 */
static inline void emit_lld(struct jit_state* s, int rt, int base, int16_t off) {
    emit(s, ((uint32_t)OP_SPECIAL3 << 26) | ((uint32_t)(base & 0x1F) << 21) |
            ((uint32_t)(rt & 0x1F) << 16) | (((uint32_t)(uint16_t)off & 0x1FF) << 7) | 0x37);
}
static inline void emit_scd(struct jit_state* s, int rt, int base, int16_t off) {
    emit(s, ((uint32_t)OP_SPECIAL3 << 26) | ((uint32_t)(base & 0x1F) << 21) |
            ((uint32_t)(rt & 0x1F) << 16) | (((uint32_t)(uint16_t)off & 0x1FF) << 7) | 0x27);
}
static inline void emit_ll(struct jit_state* s, int rt, int base, int16_t off) {
    emit(s, ((uint32_t)OP_SPECIAL3 << 26) | ((uint32_t)(base & 0x1F) << 21) |
            ((uint32_t)(rt & 0x1F) << 16) | (((uint32_t)(uint16_t)off & 0x1FF) << 7) | 0x36);
}
static inline void emit_sc(struct jit_state* s, int rt, int base, int16_t off) {
    emit(s, ((uint32_t)OP_SPECIAL3 << 26) | ((uint32_t)(base & 0x1F) << 21) |
            ((uint32_t)(rt & 0x1F) << 16) | (((uint32_t)(uint16_t)off & 0x1FF) << 7) | 0x26);
}

/* Zero-extend 32-bit to 64-bit. [JIT-SPEC] §3.2 */
static inline void
emit_zext32(struct jit_state* s, int rd)
{
    emit_dsll32(s, rd, rd, 0);
    emit_dsrl32(s, rd, rd, 0);
}

/* Load 64-bit immediate. [JIT-SPEC] §3.9 */
static void
emit_imm64(struct jit_state* s, int rd, uint64_t imm)
{
    if (imm == 0) { emit_or(s, rd, ZERO, ZERO); return; }
    if (imm <= 0xFFFF) { emit_ori(s, rd, ZERO, (uint16_t)imm); return; }
    if ((int64_t)imm >= -32768 && (int64_t)imm <= 32767) { emit_daddiu(s, rd, ZERO, (int16_t)imm); return; }
    if ((imm >> 32) == 0) { emit_lui(s, rd, (int16_t)(imm >> 16)); emit_ori(s, rd, rd, (uint16_t)imm); return; }
    emit_lui(s, rd, (int16_t)(imm >> 48));
    emit_ori(s, rd, rd, (uint16_t)(imm >> 32));
    emit(s, r_type(OP_SPECIAL, 0, rd, rd, 16, FN_DSLL));
    emit_ori(s, rd, rd, (uint16_t)(imm >> 16));
    emit(s, r_type(OP_SPECIAL, 0, rd, rd, 16, FN_DSLL));
    emit_ori(s, rd, rd, (uint16_t)imm);
}

/* ========================================================================
 * Prologue / Epilogue. [JIT-SPEC] §4
 * ======================================================================== */

#define SAVE_SLOTS 10  /* ra, fp, s0-s6, helper_ra */
#define SAVE_SIZE (SAVE_SLOTS * 8)  /* 80 bytes */

static void
emit_prologue(struct jit_state* state, int bpf_stack)
{
    int frame = SAVE_SIZE + ((bpf_stack + 15) & ~15);
    emit_daddiu(state, SP, SP, (int16_t)(-frame));
    int off = frame - 8;
    emit_sd(state, RA, SP, (int16_t)off); off -= 8;
    emit_sd(state, FP, SP, (int16_t)off); off -= 8;
    for (unsigned i = 0; i < _countof(callee_saved_registers); i++) {
        emit_sd(state, callee_saved_registers[i], SP, (int16_t)off);
        off -= 8;
    }
    emit_or(state, FP, SP, ZERO);           /* $fp = $sp */
    emit_or(state, CTX_REG, A0, ZERO);      /* save context */
    emit_daddiu(state, map_register(10), SP, (int16_t)(SAVE_SIZE + bpf_stack)); /* R10 = top of BPF stack */
    state->entry_loc = state->offset;
}

static void
emit_epilogue(struct jit_state* state, int bpf_stack)
{
    state->exit_loc = state->offset;
    int frame = SAVE_SIZE + ((bpf_stack + 15) & ~15);
    int off = frame - 8;
    emit_ld(state, RA, SP, (int16_t)off); off -= 8;
    emit_ld(state, FP, SP, (int16_t)off); off -= 8;
    for (unsigned i = 0; i < _countof(callee_saved_registers); i++) {
        emit_ld(state, callee_saved_registers[i], SP, (int16_t)off);
        off -= 8;
    }
    emit_daddiu(state, SP, SP, (int16_t)frame);
    emit_jr(state, RA);
}

/* Helper: save $ra for helper calls (slot at SP+0) */
#define HELPER_RA_OFF 0

/* ========================================================================
 * Division with zero-check. [JIT-SPEC] §3.3
 * ======================================================================== */

static void
emit_divmod(struct jit_state* state, uint8_t opcode, int dst, int src, int16_t bpf_off, bool w64)
{
    bool is_mod = (opcode & EBPF_ALU_OP_MASK) == (EBPF_OP_MOD_IMM & EBPF_ALU_OP_MASK);
    bool is_signed = (bpf_off == 1);

    /* BNEC src, $zero, +2  (skip zero-result) */
    uint32_t nz_loc = state->offset;
    emit(state, 0); /* placeholder */

    /* Zero-result path */
    if (!is_mod) emit_or(state, dst, ZERO, ZERO);
    else if (!w64) emit_zext32(state, dst);

    uint32_t done_loc = state->offset;
    emit(state, 0); /* placeholder BC .Ldone */

    /* Non-zero path */
    uint32_t nz_target = state->offset;
    if (w64) {
        if (is_signed) { if (is_mod) emit_dmod(state, dst, dst, src); else emit_ddiv(state, dst, dst, src); }
        else           { if (is_mod) emit_dmodu(state, dst, dst, src); else emit_ddivu(state, dst, dst, src); }
    } else {
        if (is_signed) { if (is_mod) emit_mod(state, dst, dst, src); else emit_div(state, dst, dst, src); }
        else           { if (is_mod) emit_modu(state, dst, dst, src); else emit_divu(state, dst, dst, src); }
        emit_zext32(state, dst);
    }

    uint32_t done_target = state->offset;

    /* Patch BNEC */
    int32_t nz_rel = ((int32_t)(nz_target - nz_loc)) >> 2;
    uint32_t bnec = i_type(OP_BNEC, src, ZERO, (uint16_t)nz_rel);
    memcpy(state->buf + nz_loc, &bnec, 4);

    /* Patch BC */
    int32_t done_rel = ((int32_t)(done_target - done_loc)) >> 2;
    uint32_t bc = ((uint32_t)OP_BC << 26) | ((uint32_t)done_rel & 0x03FFFFFF);
    memcpy(state->buf + done_loc, &bc, 4);
}

/* ========================================================================
 * Main translate. [JIT-SPEC] §3
 * ======================================================================== */

static int
translate(struct ubpf_vm* vm, struct jit_state* state, char** errmsg)
{
    emit_prologue(state, UBPF_EBPF_STACK_SIZE);

    for (int i = 0; i < vm->num_insts; i++) {
        if (state->jit_status != NoError) break;

        struct ebpf_inst inst = ubpf_fetch_instruction(vm, i);
        state->pc_locs[i] = state->offset;

        int dst = map_register(inst.dst);
        int src = map_register(inst.src);
        uint8_t opcode = inst.opcode;
        bool w64 = (opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU64;

        /* Jump target */
        uint32_t target_pc;
        if (opcode == EBPF_OP_JA32)
            target_pc = (uint32_t)((int64_t)i + (int64_t)inst.imm + 1);
        else
            target_pc = (uint32_t)((int64_t)i + (int64_t)inst.offset + 1);

        DECLARE_PATCHABLE_REGULAR_EBPF_TARGET(tgt, target_pc);
        DECLARE_PATCHABLE_SPECIAL_TARGET(exit_tgt, Exit);

        /* Pre-materialize immediate operands into TEMP_REG */
        if ((opcode & EBPF_SRC_REG) == 0 &&
            opcode != EBPF_OP_EXIT && opcode != EBPF_OP_JA && opcode != EBPF_OP_JA32 &&
            opcode != EBPF_OP_LDDW && opcode != EBPF_OP_MOV_IMM && opcode != EBPF_OP_MOV64_IMM &&
            opcode != EBPF_OP_STB && opcode != EBPF_OP_STH && opcode != EBPF_OP_STW && opcode != EBPF_OP_STDW) {
            if (vm->constant_blinding_enabled) {
                uint64_t rnd = ubpf_generate_blinding_constant();
                emit_imm64(state, TEMP_REG, (uint64_t)(int64_t)inst.imm ^ rnd);
                emit_imm64(state, TEMP_DIV, rnd);
                emit_xor(state, TEMP_REG, TEMP_REG, TEMP_DIV);
            } else {
                emit_imm64(state, TEMP_REG, (uint64_t)(int64_t)inst.imm);
            }
            src = TEMP_REG;
            opcode |= EBPF_SRC_REG;
        }

        switch (opcode) {

        /* ---- ALU64 ---- */
        case EBPF_OP_ADD64_REG:  emit_daddu(state, dst, dst, src); break;
        case EBPF_OP_SUB64_REG:  emit_dsubu(state, dst, dst, src); break;
        case EBPF_OP_MUL64_REG:  emit_dmul(state, dst, dst, src); break;
        case EBPF_OP_OR64_REG:   emit_or(state, dst, dst, src); break;
        case EBPF_OP_AND64_REG:  emit_and(state, dst, dst, src); break;
        case EBPF_OP_XOR64_REG:  emit_xor(state, dst, dst, src); break;
        case EBPF_OP_LSH64_REG:  emit_dsllv(state, dst, dst, src); break;
        case EBPF_OP_RSH64_REG:  emit_dsrlv(state, dst, dst, src); break;
        case EBPF_OP_ARSH64_REG: emit_dsrav(state, dst, dst, src); break;
        case EBPF_OP_NEG64:      emit_dsubu(state, dst, ZERO, dst); break;
        case EBPF_OP_DIV64_REG: case EBPF_OP_MOD64_REG:
            emit_divmod(state, opcode, dst, src, inst.offset, true); break;

        /* ---- ALU32 — 64-bit ops + zero-ext ---- */
        case EBPF_OP_ADD_REG:  emit_daddu(state, dst, dst, src); emit_zext32(state, dst); break;
        case EBPF_OP_SUB_REG:  emit_dsubu(state, dst, dst, src); emit_zext32(state, dst); break;
        case EBPF_OP_MUL_REG:  emit_dmul(state, dst, dst, src); emit_zext32(state, dst); break;
        case EBPF_OP_OR_REG:   emit_or(state, dst, dst, src); emit_zext32(state, dst); break;
        case EBPF_OP_AND_REG:  emit_and(state, dst, dst, src); emit_zext32(state, dst); break;
        case EBPF_OP_XOR_REG:  emit_xor(state, dst, dst, src); emit_zext32(state, dst); break;
        case EBPF_OP_LSH_REG:  emit_sllv(state, dst, dst, src); emit_zext32(state, dst); break;
        case EBPF_OP_RSH_REG:  emit_srlv(state, dst, dst, src); emit_zext32(state, dst); break;
        case EBPF_OP_ARSH_REG: emit_srav(state, dst, dst, src); emit_zext32(state, dst); break;
        case EBPF_OP_NEG:      emit_dsubu(state, dst, ZERO, dst); emit_zext32(state, dst); break;
        case EBPF_OP_DIV_REG: case EBPF_OP_MOD_REG:
            emit_divmod(state, opcode, dst, src, inst.offset, false); break;

        /* ---- MOV ---- */
        case EBPF_OP_MOV64_IMM:
            if (vm->constant_blinding_enabled) {
                uint64_t rnd = ubpf_generate_blinding_constant();
                emit_imm64(state, dst, (uint64_t)(int64_t)inst.imm ^ rnd);
                emit_imm64(state, TEMP_REG, rnd);
                emit_xor(state, dst, dst, TEMP_REG);
            } else {
                emit_imm64(state, dst, (uint64_t)(int64_t)inst.imm);
            }
            break;
        case EBPF_OP_MOV_IMM:
            if (vm->constant_blinding_enabled) {
                uint64_t rnd = ubpf_generate_blinding_constant();
                emit_imm64(state, dst, (uint64_t)(int64_t)inst.imm ^ rnd);
                emit_imm64(state, TEMP_REG, rnd);
                emit_xor(state, dst, dst, TEMP_REG);
            } else {
                emit_imm64(state, dst, (uint64_t)(int64_t)inst.imm);
            }
            emit_zext32(state, dst);
            break;
        case EBPF_OP_MOV64_REG:
        case EBPF_OP_MOV_REG:
            if (inst.offset == 8)       emit_seb(state, dst, src);
            else if (inst.offset == 16) emit_seh(state, dst, src);
            else if (inst.offset == 32 && w64) emit_sll(state, dst, src, 0);
            else emit_or(state, dst, src, ZERO);
            if (!w64) emit_zext32(state, dst);
            break;

        /* ---- Byte swap ---- */
        case EBPF_OP_LE:
            if (inst.imm == 16) emit_andi(state, dst, dst, 0xFFFF);
            else if (inst.imm == 32) emit_zext32(state, dst);
            break;
        case EBPF_OP_BE:
            if (inst.imm == 16) { emit_wsbh(state, dst, dst); emit_andi(state, dst, dst, 0xFFFF); }
            else if (inst.imm == 32) { emit_wsbh(state, dst, dst); emit(state, r_type(OP_SPECIAL, 1, dst, dst, 16, FN_SRL)); emit_zext32(state, dst); }
            else if (inst.imm == 64) { emit_dsbh(state, dst, dst); emit_dshd(state, dst, dst); }
            break;

        /* ---- Memory loads ---- */
        case EBPF_OP_LDXB:   emit_lbu(state, dst, src, inst.offset); break;
        case EBPF_OP_LDXH:   emit_lhu(state, dst, src, inst.offset); break;
        case EBPF_OP_LDXW:   emit_lwu(state, dst, src, inst.offset); break;
        case EBPF_OP_LDXDW:  emit_ld(state, dst, src, inst.offset); break;
        case EBPF_OP_LDXBSX: emit_lb(state, dst, src, inst.offset); break;
        case EBPF_OP_LDXHSX: emit_lh(state, dst, src, inst.offset); break;
        case EBPF_OP_LDXWSX: emit_lw(state, dst, src, inst.offset); break;

        /* ---- Memory stores ---- */
        case EBPF_OP_STB:  emit_imm64(state, TEMP_REG, (uint64_t)(int64_t)inst.imm); emit_sb(state, TEMP_REG, dst, inst.offset); break;
        case EBPF_OP_STH:  emit_imm64(state, TEMP_REG, (uint64_t)(int64_t)inst.imm); emit_sh(state, TEMP_REG, dst, inst.offset); break;
        case EBPF_OP_STW:  emit_imm64(state, TEMP_REG, (uint64_t)(int64_t)inst.imm); emit_sw(state, TEMP_REG, dst, inst.offset); break;
        case EBPF_OP_STDW: emit_imm64(state, TEMP_REG, (uint64_t)(int64_t)inst.imm); emit_sd(state, TEMP_REG, dst, inst.offset); break;
        case EBPF_OP_STXB:  emit_sb(state, src, dst, inst.offset); break;
        case EBPF_OP_STXH:  emit_sh(state, src, dst, inst.offset); break;
        case EBPF_OP_STXW:  emit_sw(state, src, dst, inst.offset); break;
        case EBPF_OP_STXDW: emit_sd(state, src, dst, inst.offset); break;

        /* ---- LDDW ---- */
        case EBPF_OP_LDDW: {
            struct ebpf_inst next = ubpf_fetch_instruction(vm, ++i);
            uint64_t imm64 = (uint64_t)(uint32_t)inst.imm | ((uint64_t)(uint32_t)next.imm << 32);
            if (vm->constant_blinding_enabled) {
                uint64_t rnd = ubpf_generate_blinding_constant();
                emit_imm64(state, dst, imm64 ^ rnd);
                emit_imm64(state, TEMP_REG, rnd);
                emit_xor(state, dst, dst, TEMP_REG);
            } else {
                emit_imm64(state, dst, imm64);
            }
            break;
        }

        /* ---- Jumps ---- */
        case EBPF_OP_JA:
        case EBPF_OP_JA32:
            emit_patchable_relative(state->jumps, state->offset, tgt, state->num_jumps++);
            emit_bc(state, 0);
            break;

        case EBPF_OP_JEQ_REG:
            emit_patchable_relative(state->jumps, state->offset, tgt, state->num_jumps++);
            emit_beqc(state, dst, src, 0); break;
        case EBPF_OP_JNE_REG:
            emit_patchable_relative(state->jumps, state->offset, tgt, state->num_jumps++);
            emit_bnec(state, dst, src, 0); break;
        case EBPF_OP_JSET_REG:
            emit_and(state, TEMP_REG, dst, src);
            emit_patchable_relative(state->jumps, state->offset, tgt, state->num_jumps++);
            emit_bnezc(state, TEMP_REG, 0); break;
        case EBPF_OP_JGT_REG:
            emit_patchable_relative(state->jumps, state->offset, tgt, state->num_jumps++);
            emit_bltuc(state, src, dst, 0); break;
        case EBPF_OP_JGE_REG:
            emit_patchable_relative(state->jumps, state->offset, tgt, state->num_jumps++);
            emit_bgeuc(state, dst, src, 0); break;
        case EBPF_OP_JLT_REG:
            emit_patchable_relative(state->jumps, state->offset, tgt, state->num_jumps++);
            emit_bltuc(state, dst, src, 0); break;
        case EBPF_OP_JLE_REG:
            emit_patchable_relative(state->jumps, state->offset, tgt, state->num_jumps++);
            emit_bgeuc(state, src, dst, 0); break;
        case EBPF_OP_JSGT_REG:
            emit_patchable_relative(state->jumps, state->offset, tgt, state->num_jumps++);
            emit_bltc(state, src, dst, 0); break;
        case EBPF_OP_JSGE_REG:
            emit_patchable_relative(state->jumps, state->offset, tgt, state->num_jumps++);
            emit_bgec(state, dst, src, 0); break;
        case EBPF_OP_JSLT_REG:
            emit_patchable_relative(state->jumps, state->offset, tgt, state->num_jumps++);
            emit_bltc(state, dst, src, 0); break;
        case EBPF_OP_JSLE_REG:
            emit_patchable_relative(state->jumps, state->offset, tgt, state->num_jumps++);
            emit_bgec(state, src, dst, 0); break;

        /* ---- CALL ---- */
        case EBPF_OP_CALL:
            if (inst.src == 0) {
                /* External helper */
                emit_sd(state, RA, SP, HELPER_RA_OFF);
                emit_or(state, A5, CTX_REG, ZERO);
                emit_imm64(state, TEMP_REG, (uint64_t)(uint32_t)inst.imm * 8);
                emit_daddu(state, TEMP_REG, HTAB_REG, TEMP_REG);
                emit_ld(state, TEMP_REG, TEMP_REG, 0);
                emit_jalr(state, RA, TEMP_REG);
                emit_ld(state, RA, SP, HELPER_RA_OFF);
            } else if (inst.src == 1) {
                /* Local call */
                emit_sd(state, RA, SP, HELPER_RA_OFF);
                int r10 = map_register(10);
                emit_sd(state, map_register(6), r10, -8);
                emit_sd(state, map_register(7), r10, -16);
                emit_sd(state, map_register(8), r10, -24);
                emit_sd(state, map_register(9), r10, -32);
                uint16_t ls = ubpf_stack_usage_for_local_func(vm, (uint16_t)(i + inst.imm + 1));
                emit_imm64(state, TEMP_REG, ls);
                emit_dsubu(state, r10, r10, TEMP_REG);
                DECLARE_PATCHABLE_REGULAR_EBPF_TARGET(call_tgt, (uint32_t)(i + inst.imm + 1));
                emit_patchable_relative(state->local_calls, state->offset, call_tgt, state->num_local_calls++);
                emit_balc(state, 0);
                emit_imm64(state, TEMP_REG, ls);
                emit_daddu(state, r10, r10, TEMP_REG);
                emit_ld(state, map_register(6), r10, -8);
                emit_ld(state, map_register(7), r10, -16);
                emit_ld(state, map_register(8), r10, -24);
                emit_ld(state, map_register(9), r10, -32);
                emit_ld(state, RA, SP, HELPER_RA_OFF);
            }
            break;

        /* ---- EXIT ---- */
        case EBPF_OP_EXIT:
            emit_patchable_relative(state->jumps, state->offset, exit_tgt, state->num_jumps++);
            emit_bc(state, 0);
            break;

        /* TODO: EBPF_OP_ATOMIC_STORE, EBPF_OP_ATOMIC32_STORE */

        default:
            *errmsg = ubpf_error("MIPS64r6 JIT: unsupported opcode 0x%02x at PC %d", inst.opcode, i);
            return -1;
        }
    }

    emit_epilogue(state, UBPF_EBPF_STACK_SIZE);
    return 0;
}

/* ========================================================================
 * Branch fixup. [JIT-SPEC] §9
 * ======================================================================== */

static void
patch_branch(struct jit_state* state, uint32_t loc, int32_t rel)
{
    uint32_t instr;
    memcpy(&instr, state->buf + loc, 4);
    uint8_t op = (instr >> 26) & 0x3F;
    if (op == OP_BC || op == OP_BALC)
        instr |= ((uint32_t)rel & 0x03FFFFFF);
    else if (op == OP_BEQZC || op == OP_BNEZC)
        instr |= ((uint32_t)rel & 0x1FFFFF);
    else
        instr |= ((uint32_t)rel & 0xFFFF);
    memcpy(state->buf + loc, &instr, 4);
}

static bool
resolve_jumps(struct jit_state* state)
{
    for (unsigned i = 0; i < (unsigned)state->num_jumps; i++) {
        struct patchable_relative jmp = state->jumps[i];
        int32_t target;
        if (jmp.target.is_special) {
            if (jmp.target.target.special == Exit) target = state->exit_loc;
            else return false;
        } else {
            target = state->pc_locs[jmp.target.target.regular_ebpf_target];
        }
        patch_branch(state, jmp.offset_loc, ((int32_t)(target - (int32_t)jmp.offset_loc)) >> 2);
    }
    return true;
}

static bool
resolve_local_calls(struct jit_state* state)
{
    for (unsigned i = 0; i < (unsigned)state->num_local_calls; i++) {
        struct patchable_relative call = state->local_calls[i];
        int32_t target = state->pc_locs[call.target.target.regular_ebpf_target];
        patch_branch(state, call.offset_loc, ((int32_t)(target - (int32_t)call.offset_loc)) >> 2);
    }
    return true;
}

/* ========================================================================
 * Public API
 * ======================================================================== */

struct ubpf_jit_result
ubpf_translate_mips64(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, enum JitMode jit_mode)
{
    struct ubpf_jit_result result;
    memset(&result, 0, sizeof(result));
    result.jit_mode = jit_mode;

    struct jit_state state;
    if (!initialize_jit_state_result(&state, &result, buffer, *size, vm->num_insts)) {
        return result;
    }

    char* errmsg = NULL;
    if (translate(vm, &state, &errmsg) < 0) {
        result.compile_result = UBPF_JIT_COMPILE_FAILURE;
        result.errmsg = errmsg;
        release_jit_state_result(&state, &result);
        return result;
    }

    if (!resolve_jumps(&state) || !resolve_local_calls(&state)) {
        result.compile_result = UBPF_JIT_COMPILE_FAILURE;
        result.errmsg = ubpf_error("MIPS64r6 JIT: failed to resolve branches");
        release_jit_state_result(&state, &result);
        return result;
    }

    result.compile_result = UBPF_JIT_COMPILE_SUCCESS;
    result.external_dispatcher_offset = state.dispatcher_loc;
    result.external_helper_offset = state.helper_table_loc;
    *size = state.offset;
    release_jit_state_result(&state, &result);
    return result;
}

bool
ubpf_jit_update_dispatcher_mips64(
    struct ubpf_vm* vm, external_function_dispatcher_t new_dispatcher, uint8_t* buffer, size_t size, uint32_t offset)
{
    (void)vm;
    void* addr = (void*)((uint64_t)buffer + offset);
    if ((uint64_t)addr + sizeof(void*) < (uint64_t)buffer + size) {
        memcpy(addr, &new_dispatcher, sizeof(void*));
        return true;
    }
    return false;
}

bool
ubpf_jit_update_helper_mips64(
    struct ubpf_vm* vm, extended_external_helper_t new_helper, unsigned int idx,
    uint8_t* buffer, size_t size, uint32_t offset)
{
    (void)vm;
    void* addr = (void*)((uint64_t)buffer + offset + (8 * idx));
    if ((uint64_t)addr + sizeof(void*) < (uint64_t)buffer + size) {
        memcpy(addr, &new_helper, sizeof(void*));
        return true;
    }
    return false;
}
