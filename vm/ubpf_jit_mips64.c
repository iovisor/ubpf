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
 *
 * References:
 * [MIPS-ISA]: MIPS64 Architecture for Programmers Volume II:
 *             The MIPS64 Instruction Set, Revision 6.06
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

/* This is guaranteed to be an illegal MIPS instruction (all 1s). */
#define BAD_OPCODE ~UINT32_C(0)

/*
 * MIPS64r6 GPR definitions.
 * [MIPS-ISA]: Table "GPR Encodings"
 */
enum MipsRegister
{
    MIPS_REG_ZERO = 0,  /* $zero — hardwired zero */
    MIPS_REG_AT   = 1,  /* $at   — assembler temporary (reserved) */
    MIPS_REG_V0   = 2,  /* $v0   — function return value 0 */
    MIPS_REG_V1   = 3,  /* $v1   — function return value 1 */
    MIPS_REG_A0   = 4,  /* $a0   — argument 0 */
    MIPS_REG_A1   = 5,  /* $a1   — argument 1 */
    MIPS_REG_A2   = 6,  /* $a2   — argument 2 */
    MIPS_REG_A3   = 7,  /* $a3   — argument 3 */
    MIPS_REG_A4   = 8,  /* $a4   — argument 4 (n64 ABI) */
    MIPS_REG_A5   = 9,  /* $a5   — argument 5 */
    MIPS_REG_A6   = 10, /* $a6   — argument 6 */
    MIPS_REG_A7   = 11, /* $a7   — argument 7 */
    MIPS_REG_T4   = 12, /* $t4   — temporary 4 */
    MIPS_REG_T5   = 13, /* $t5   — temporary 5 */
    MIPS_REG_T6   = 14, /* $t6   — temporary 6 */
    MIPS_REG_T7   = 15, /* $t7   — temporary 7 */
    MIPS_REG_S0   = 16, /* $s0   — callee-saved 0 */
    MIPS_REG_S1   = 17, /* $s1   — callee-saved 1 */
    MIPS_REG_S2   = 18, /* $s2   — callee-saved 2 */
    MIPS_REG_S3   = 19, /* $s3   — callee-saved 3 */
    MIPS_REG_S4   = 20, /* $s4   — callee-saved 4 */
    MIPS_REG_S5   = 21, /* $s5   — callee-saved 5 */
    MIPS_REG_S6   = 22, /* $s6   — callee-saved 6 */
    MIPS_REG_S7   = 23, /* $s7   — callee-saved 7 */
    MIPS_REG_T8   = 24, /* $t8   — temporary 8 */
    MIPS_REG_T9   = 25, /* $t9   — temporary 9 */
    MIPS_REG_K0   = 26, /* $k0   — kernel reserved (do NOT use) */
    MIPS_REG_K1   = 27, /* $k1   — kernel reserved (do NOT use) */
    MIPS_REG_GP   = 28, /* $gp   — global pointer (reserved, ABI) */
    MIPS_REG_SP   = 29, /* $sp   — stack pointer */
    MIPS_REG_FP   = 30, /* $fp   — frame pointer */
    MIPS_REG_RA   = 31, /* $ra   — return address */
};

/*
 * Callee-saved registers that the JIT prologue must preserve.
 * Per n64 ABI: $s0–$s7 ($16–$23), $fp ($30), $ra ($31).
 * Must be a multiple of two for 16-byte stack alignment.
 */
static enum MipsRegister callee_saved_registers[] = {
    MIPS_REG_S0, MIPS_REG_S1, MIPS_REG_S2, MIPS_REG_S3,
    MIPS_REG_S4, MIPS_REG_S5, MIPS_REG_S6, MIPS_REG_FP,
    MIPS_REG_RA,
    MIPS_REG_S7, /* padding to even count */
};

/* Scratch registers used during code generation (jit-mips.md §2.2). */
static enum MipsRegister temp_register      = MIPS_REG_T4; /* Large immediate materialization */
static enum MipsRegister temp_div_register  = MIPS_REG_T5; /* Division / atomic scratch */
static enum MipsRegister offset_register    = MIPS_REG_T6; /* Address computation scratch */
/* MIPS_REG_T7 ($15) is available as additional scratch. */
/* MIPS_REG_S5 ($21) is reserved for helper table base. */
/* MIPS_REG_S6 ($22) is reserved for context/cookie pointer. */
static enum MipsRegister VOLATILE_CTXT      = MIPS_REG_S6;

/* Number of eBPF registers. */
#define REGISTER_MAP_SIZE 11

/*
 * BPF → MIPS64r6 register assignments (jit-mips.md §2.1):
 *
 *   BPF        MIPS64r6       Usage
 *   R0         $v0  ($2)      Return value
 *   R1         $a0  ($4)      Context pointer / param 1
 *   R2         $a1  ($5)      Context length  / param 2
 *   R3         $a2  ($6)      Helper param 3
 *   R4         $a3  ($7)      Helper param 4
 *   R5         $a4  ($8)      Helper param 5
 *   R6         $s0  ($16)     Callee-saved
 *   R7         $s1  ($17)     Callee-saved
 *   R8         $s2  ($18)     Callee-saved
 *   R9         $s3  ($19)     Callee-saved
 *   R10        $s4  ($20)     BPF frame pointer (callee-saved)
 *
 * BPF R1–R5 map to $a0–$a4 so external helper calls need no shuffling.
 * BPF R0 maps to $v0, the natural n64 return register.
 */
static enum MipsRegister register_map[REGISTER_MAP_SIZE] = {
    MIPS_REG_V0, /* BPF R0  — return value */
    MIPS_REG_A0, /* BPF R1  — param 1 */
    MIPS_REG_A1, /* BPF R2  — param 2 */
    MIPS_REG_A2, /* BPF R3  — param 3 */
    MIPS_REG_A3, /* BPF R4  — param 4 */
    MIPS_REG_A4, /* BPF R5  — param 5 */
    MIPS_REG_S0, /* BPF R6  — callee-saved */
    MIPS_REG_S1, /* BPF R7  — callee-saved */
    MIPS_REG_S2, /* BPF R8  — callee-saved */
    MIPS_REG_S3, /* BPF R9  — callee-saved */
    MIPS_REG_S4, /* BPF R10 — frame pointer */
};

/* Return the MIPS64r6 GPR for the given eBPF register number. */
static enum MipsRegister
map_register(int r)
{
    assert(r < REGISTER_MAP_SIZE);
    return register_map[r % REGISTER_MAP_SIZE];
}

/* ================================================================
 * Low-level instruction emission
 * ================================================================ */

static void
emit_bytes(struct jit_state* state, void* data, uint32_t len)
{
    if (!(len <= state->size && state->offset <= state->size - len)) {
        state->jit_status = NotEnoughSpace;
        return;
    }
    if ((state->offset + len) > state->size) {
        state->offset = state->size;
        return;
    }
    memcpy(state->buf + state->offset, data, len);
    state->offset += len;
}

/** @brief Emit a single 32-bit MIPS instruction. */
static inline void
emit_mips64(struct jit_state* state, uint32_t instruction)
{
    assert(instruction != BAD_OPCODE);
    emit_bytes(state, &instruction, 4);
}

/* R-type: opcode(6)|rs(5)|rt(5)|rd(5)|shamt(5)|funct(6)
 * I-type: opcode(6)|rs(5)|rt(5)|imm(16)
 * J-type: opcode(6)|target(26) */

/** @brief Encode and emit an R-type instruction. */
static inline void
emit_r_type(
    struct jit_state* state,
    uint32_t opcode,
    enum MipsRegister rs,
    enum MipsRegister rt,
    enum MipsRegister rd,
    uint32_t shamt,
    uint32_t funct)
{
    uint32_t instr = ((opcode & 0x3F) << 26) |
                     ((rs     & 0x1F) << 21) |
                     ((rt     & 0x1F) << 16) |
                     ((rd     & 0x1F) << 11) |
                     ((shamt  & 0x1F) << 6)  |
                     (funct   & 0x3F);
    emit_mips64(state, instr);
}

/** @brief Encode and emit an I-type instruction. */
static inline void
emit_i_type(
    struct jit_state* state,
    uint32_t opcode,
    enum MipsRegister rs,
    enum MipsRegister rt,
    uint16_t imm16)
{
    uint32_t instr = ((opcode & 0x3F) << 26) |
                     ((rs     & 0x1F) << 21) |
                     ((rt     & 0x1F) << 16) |
                     (imm16   & 0xFFFF);
    emit_mips64(state, instr);
}

/** @brief Encode and emit a J-type instruction (used by BC, BALC). */
static inline void
emit_j_type(struct jit_state* state, uint32_t opcode, uint32_t target26)
{
    uint32_t instr = ((opcode & 0x3F) << 26) |
                     (target26 & 0x03FFFFFF);
    emit_mips64(state, instr);
}

/* MIPS64r6 opcode constants. [MIPS-ISA]: Instruction encodings, Release 6 */

/* Primary opcode fields (bits [31:26]). */
#define MIPS_OP_SPECIAL  0x00
#define MIPS_OP_SPECIAL3 0x1F
#define MIPS_OP_DADDIU   0x19
#define MIPS_OP_ORI      0x0D
#define MIPS_OP_ANDI     0x0C
#define MIPS_OP_XORI     0x0E
#define MIPS_OP_LUI      0x0F

/* Memory access opcodes (I-type). */
#define MIPS_OP_LD       0x37
#define MIPS_OP_SD       0x3F
#define MIPS_OP_LW       0x23
#define MIPS_OP_LWU      0x27
#define MIPS_OP_SW       0x2B
#define MIPS_OP_LH       0x21
#define MIPS_OP_LHU      0x25
#define MIPS_OP_SH       0x29
#define MIPS_OP_LB       0x20
#define MIPS_OP_LBU      0x24
#define MIPS_OP_SB       0x28

/* R6 compact branch opcodes (bits [31:26]). */
#define MIPS_OP_BC       0x32  /* BC  offset26: unconditional */
#define MIPS_OP_BALC     0x3A  /* BALC offset26: branch-and-link */
#define MIPS_OP_POP06    0x08  /* BEQC rs,rt,offset16 (rs < rt, rs != 0) */
#define MIPS_OP_POP26    0x18  /* BNEC rs,rt,offset16 (rs < rt, rs != 0) */
#define MIPS_OP_POP66    0x36  /* BEQZC rs,offset21 (rs != 0) */
#define MIPS_OP_POP76    0x3E  /* BNEZC rs,offset21 (rs != 0) */

/* SPECIAL function codes (bits [5:0] with opcode = 0x00). */
#define MIPS_FUNCT_DADDU  0x2D
#define MIPS_FUNCT_DSUBU  0x2F
#define MIPS_FUNCT_OR     0x25
#define MIPS_FUNCT_AND    0x24
#define MIPS_FUNCT_XOR    0x26
#define MIPS_FUNCT_DSLLV  0x14
#define MIPS_FUNCT_DSRLV  0x16
#define MIPS_FUNCT_DSRAV  0x17
#define MIPS_FUNCT_DSLL   0x38
#define MIPS_FUNCT_DSRL   0x3A
#define MIPS_FUNCT_DSRA   0x3B
#define MIPS_FUNCT_DSLL32 0x3C
#define MIPS_FUNCT_DSRL32 0x3E
#define MIPS_FUNCT_DSRA32 0x3F
#define MIPS_FUNCT_SLL    0x00
#define MIPS_FUNCT_SRL    0x02
#define MIPS_FUNCT_SRA    0x03
#define MIPS_FUNCT_SLLV   0x04
#define MIPS_FUNCT_SRLV   0x06
#define MIPS_FUNCT_SRAV   0x07
#define MIPS_FUNCT_JALR   0x09

/* R6 multiply/divide function codes (SPECIAL, bits [5:0]).
 * shamt field selects the sub-operation (MUL vs MUH, DIV vs MOD). */
#define MIPS_FUNCT_SOP30  0x18  /* MUL/MUH   (word) */
#define MIPS_FUNCT_SOP31  0x19  /* MULU/MUHU (word) */
#define MIPS_FUNCT_SOP32  0x1A  /* DIV/MOD   (word) */
#define MIPS_FUNCT_SOP33  0x1B  /* DIVU/MODU (word) */
#define MIPS_FUNCT_SOP34  0x1C  /* DMUL/DMUH  (doubleword) */
#define MIPS_FUNCT_SOP35  0x1D  /* DMULU/DMUHU */
#define MIPS_FUNCT_SOP36  0x1E  /* DDIV/DMOD  (doubleword) */
#define MIPS_FUNCT_SOP37  0x1F  /* DDIVU/DMODU */
#define MIPS_MUL_SHAMT    0x02  /* shamt for MUL/DIV/DIVU variants */
#define MIPS_MOD_SHAMT    0x03  /* shamt for MUH/MOD/MODU variants */

/* SPECIAL3 function codes for byte/halfword manipulation. */
#define MIPS_FUNCT_BSHFL  0x20  /* Byte-swap halfword field (SEB, SEH, WSBH) */
#define MIPS_FUNCT_DBSHFL 0x24  /* Doubleword byte-swap (DSBH, DSHD) */
/* BSHFL shamt sub-opcodes: */
#define MIPS_BSHFL_SEB    0x10  /* Sign-extend byte */
#define MIPS_BSHFL_SEH    0x18  /* Sign-extend halfword */
#define MIPS_BSHFL_WSBH   0x02  /* Word swap bytes within halfwords */
/* DBSHFL shamt sub-opcodes: */
#define MIPS_DBSHFL_DSBH  0x02  /* Doubleword swap bytes within halfwords */
#define MIPS_DBSHFL_DSHD  0x05  /* Doubleword swap halfwords within doublewords */

/* R6 LL/SC function codes (SPECIAL3, bits [5:0]).
 * Format: SPECIAL3 | base(5) | rt(5) | offset(9) | 0 | funct(6) */
#define MIPS_FUNCT_LL6    0x36
#define MIPS_FUNCT_SC6    0x26
#define MIPS_FUNCT_LLD6   0x37
#define MIPS_FUNCT_SCD6   0x27

/* ALU instruction emission helpers */

/** @brief DADDU rd, rs, rt — 64-bit unsigned add. [MIPS-ISA]: "DADDU" */
static inline void
emit_daddu(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rs, enum MipsRegister rt)
{
    emit_r_type(state, MIPS_OP_SPECIAL, rs, rt, rd, 0, MIPS_FUNCT_DADDU);
}

/** @brief DADDIU rt, rs, imm — 64-bit add immediate. [MIPS-ISA]: "DADDIU" */
static inline void
emit_daddiu(struct jit_state* state, enum MipsRegister rt, enum MipsRegister rs, int16_t imm)
{
    emit_i_type(state, MIPS_OP_DADDIU, rs, rt, (uint16_t)imm);
}

/** @brief DSUBU rd, rs, rt — 64-bit unsigned subtract. [MIPS-ISA]: "DSUBU" */
static inline void
emit_dsubu(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rs, enum MipsRegister rt)
{
    emit_r_type(state, MIPS_OP_SPECIAL, rs, rt, rd, 0, MIPS_FUNCT_DSUBU);
}

/** @brief OR rd, rs, rt — bitwise OR. [MIPS-ISA]: "OR" */
static inline void
emit_or(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rs, enum MipsRegister rt)
{
    emit_r_type(state, MIPS_OP_SPECIAL, rs, rt, rd, 0, MIPS_FUNCT_OR);
}

/** @brief AND rd, rs, rt — bitwise AND. [MIPS-ISA]: "AND" */
static inline void
emit_and(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rs, enum MipsRegister rt)
{
    emit_r_type(state, MIPS_OP_SPECIAL, rs, rt, rd, 0, MIPS_FUNCT_AND);
}

/** @brief XOR rd, rs, rt — bitwise XOR. [MIPS-ISA]: "XOR" */
static inline void
emit_xor(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rs, enum MipsRegister rt)
{
    emit_r_type(state, MIPS_OP_SPECIAL, rs, rt, rd, 0, MIPS_FUNCT_XOR);
}

/* Shift instruction emission helpers */

/** @brief DSLLV rd, rt, rs — 64-bit shift left logical variable. [MIPS-ISA]: "DSLLV" */
static inline void
emit_dsllv(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rt, enum MipsRegister rs)
{
    emit_r_type(state, MIPS_OP_SPECIAL, rs, rt, rd, 0, MIPS_FUNCT_DSLLV);
}

/** @brief DSRLV rd, rt, rs — 64-bit shift right logical variable. [MIPS-ISA]: "DSRLV" */
static inline void
emit_dsrlv(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rt, enum MipsRegister rs)
{
    emit_r_type(state, MIPS_OP_SPECIAL, rs, rt, rd, 0, MIPS_FUNCT_DSRLV);
}

/** @brief DSRAV rd, rt, rs — 64-bit shift right arithmetic variable. [MIPS-ISA]: "DSRAV" */
static inline void
emit_dsrav(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rt, enum MipsRegister rs)
{
    emit_r_type(state, MIPS_OP_SPECIAL, rs, rt, rd, 0, MIPS_FUNCT_DSRAV);
}

/** @brief DSLL rd, rt, sa — 64-bit shift left logical (sa 0–31). [MIPS-ISA]: "DSLL" */
static inline void
emit_dsll(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rt, uint32_t sa)
{
    assert(sa < 32);
    emit_r_type(state, MIPS_OP_SPECIAL, MIPS_REG_ZERO, rt, rd, sa, MIPS_FUNCT_DSLL);
}

/** @brief DSRL rd, rt, sa — 64-bit shift right logical (sa 0–31). [MIPS-ISA]: "DSRL" */
static inline void
emit_dsrl(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rt, uint32_t sa)
{
    assert(sa < 32);
    emit_r_type(state, MIPS_OP_SPECIAL, MIPS_REG_ZERO, rt, rd, sa, MIPS_FUNCT_DSRL);
}

/** @brief DSRA rd, rt, sa — 64-bit shift right arithmetic (sa 0–31). [MIPS-ISA]: "DSRA" */
static inline void
emit_dsra(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rt, uint32_t sa)
{
    assert(sa < 32);
    emit_r_type(state, MIPS_OP_SPECIAL, MIPS_REG_ZERO, rt, rd, sa, MIPS_FUNCT_DSRA);
}

/** @brief DSLL32 rd, rt, sa — 64-bit shift left logical +32 (sa 0–31). [MIPS-ISA]: "DSLL32" */
static inline void
emit_dsll32(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rt, uint32_t sa)
{
    assert(sa < 32);
    emit_r_type(state, MIPS_OP_SPECIAL, MIPS_REG_ZERO, rt, rd, sa, MIPS_FUNCT_DSLL32);
}

/** @brief DSRL32 rd, rt, sa — 64-bit shift right logical +32 (sa 0–31). [MIPS-ISA]: "DSRL32" */
static inline void
emit_dsrl32(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rt, uint32_t sa)
{
    assert(sa < 32);
    emit_r_type(state, MIPS_OP_SPECIAL, MIPS_REG_ZERO, rt, rd, sa, MIPS_FUNCT_DSRL32);
}

/** @brief SLL rd, rt, sa — 32-bit shift left logical. Also used for sign-extension. [MIPS-ISA]: "SLL" */
static inline void
emit_sll(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rt, uint32_t sa)
{
    assert(sa < 32);
    emit_r_type(state, MIPS_OP_SPECIAL, MIPS_REG_ZERO, rt, rd, sa, MIPS_FUNCT_SLL);
}

/* Immediate materialization helpers */

/** @brief LUI rt, imm — Load upper immediate. [MIPS-ISA]: "LUI"
 *
 * Sets the upper 16 bits of a 32-bit value, sign-extended to 64 bits.
 */
static inline void
emit_lui(struct jit_state* state, enum MipsRegister rt, uint16_t imm)
{
    emit_i_type(state, MIPS_OP_LUI, MIPS_REG_ZERO, rt, imm);
}

/** @brief ORI rt, rs, imm — OR immediate (zero-extended). [MIPS-ISA]: "ORI" */
static inline void
emit_ori(struct jit_state* state, enum MipsRegister rt, enum MipsRegister rs, uint16_t imm)
{
    emit_i_type(state, MIPS_OP_ORI, rs, rt, imm);
}

/**
 * @brief Materialize a full 64-bit immediate into a register.
 *
 * Uses the LUI+ORI+DSLL sequence from jit-mips.md §3.9.
 * Optimized shorter sequences are used when possible:
 *   - Zero:          OR rd, $zero, $zero                  (1 insn)
 *   - 16-bit unsigned: ORI rd, $zero, imm                (1 insn)
 *   - 16-bit signed:   DADDIU rd, $zero, imm             (1 insn)
 *   - 32-bit:         LUI + ORI                           (2 insns)
 *   - Full 64-bit:    LUI+ORI+DSLL+ORI+DSLL+ORI          (6 insns)
 */
static void
emit_load_imm64(struct jit_state* state, enum MipsRegister rd, uint64_t imm)
{
    if (imm == 0) {
        emit_or(state, rd, MIPS_REG_ZERO, MIPS_REG_ZERO);
        return;
    }

    if (imm <= 0xFFFF) {
        emit_ori(state, rd, MIPS_REG_ZERO, (uint16_t)imm);
        return;
    }

    if ((int64_t)imm >= -32768 && (int64_t)imm <= 32767) {
        emit_daddiu(state, rd, MIPS_REG_ZERO, (int16_t)imm);
        return;
    }

    /* Check if value fits in 32 bits (sign-extended from LUI). */
    int64_t simm = (int64_t)imm;
    if (simm >= -2147483648LL && simm <= 2147483647LL) {
        uint16_t upper = (uint16_t)(imm >> 16);
        uint16_t lower = (uint16_t)(imm & 0xFFFF);
        emit_lui(state, rd, upper);
        if (lower != 0) {
            emit_ori(state, rd, rd, lower);
        }
        return;
    }

    /* Full 64-bit: LUI bits[63:48], ORI bits[47:32], DSLL 16, ORI bits[31:16], DSLL 16, ORI bits[15:0]. */
    uint16_t bits_63_48 = (uint16_t)((imm >> 48) & 0xFFFF);
    uint16_t bits_47_32 = (uint16_t)((imm >> 32) & 0xFFFF);
    uint16_t bits_31_16 = (uint16_t)((imm >> 16) & 0xFFFF);
    uint16_t bits_15_0  = (uint16_t)(imm & 0xFFFF);

    emit_lui(state, rd, bits_63_48);
    if (bits_47_32 != 0) {
        emit_ori(state, rd, rd, bits_47_32);
    }
    emit_dsll(state, rd, rd, 16);
    if (bits_31_16 != 0) {
        emit_ori(state, rd, rd, bits_31_16);
    }
    emit_dsll(state, rd, rd, 16);
    if (bits_15_0 != 0) {
        emit_ori(state, rd, rd, bits_15_0);
    }
}

/**
 * @brief Zero-extend a 32-bit value in a register to 64 bits.
 *
 * Implements the DSLL32+DSRL32 idiom from jit-mips.md §3.2.
 */
static inline void
emit_zero_ext32(struct jit_state* state, enum MipsRegister rd)
{
    emit_dsll32(state, rd, rd, 0);
    emit_dsrl32(state, rd, rd, 0);
}

/* Memory access emission helpers.
 * BPF offsets are signed 16-bit, matching MIPS I-type immediate range. */

/** @brief LD rt, offset(base) — load doubleword. [MIPS-ISA]: "LD" */
static inline void
emit_ld(struct jit_state* state, enum MipsRegister rt, enum MipsRegister base, int16_t offset)
{
    emit_i_type(state, MIPS_OP_LD, base, rt, (uint16_t)offset);
}

/** @brief SD rt, offset(base) — store doubleword. [MIPS-ISA]: "SD" */
static inline void
emit_sd(struct jit_state* state, enum MipsRegister rt, enum MipsRegister base, int16_t offset)
{
    emit_i_type(state, MIPS_OP_SD, base, rt, (uint16_t)offset);
}

/** @brief LW rt, offset(base) — load word (sign-extending). [MIPS-ISA]: "LW" */
static inline void
emit_lw(struct jit_state* state, enum MipsRegister rt, enum MipsRegister base, int16_t offset)
{
    emit_i_type(state, MIPS_OP_LW, base, rt, (uint16_t)offset);
}

/** @brief LWU rt, offset(base) — load word unsigned (zero-extending). [MIPS-ISA]: "LWU" */
static inline void
emit_lwu(struct jit_state* state, enum MipsRegister rt, enum MipsRegister base, int16_t offset)
{
    emit_i_type(state, MIPS_OP_LWU, base, rt, (uint16_t)offset);
}

/** @brief SW rt, offset(base) — store word. [MIPS-ISA]: "SW" */
static inline void
emit_sw(struct jit_state* state, enum MipsRegister rt, enum MipsRegister base, int16_t offset)
{
    emit_i_type(state, MIPS_OP_SW, base, rt, (uint16_t)offset);
}

/** @brief LH rt, offset(base) — load halfword (sign-extending). [MIPS-ISA]: "LH" */
static inline void
emit_lh(struct jit_state* state, enum MipsRegister rt, enum MipsRegister base, int16_t offset)
{
    emit_i_type(state, MIPS_OP_LH, base, rt, (uint16_t)offset);
}

/** @brief LHU rt, offset(base) — load halfword unsigned (zero-extending). [MIPS-ISA]: "LHU" */
static inline void
emit_lhu(struct jit_state* state, enum MipsRegister rt, enum MipsRegister base, int16_t offset)
{
    emit_i_type(state, MIPS_OP_LHU, base, rt, (uint16_t)offset);
}

/** @brief SH rt, offset(base) — store halfword. [MIPS-ISA]: "SH" */
static inline void
emit_sh(struct jit_state* state, enum MipsRegister rt, enum MipsRegister base, int16_t offset)
{
    emit_i_type(state, MIPS_OP_SH, base, rt, (uint16_t)offset);
}

/** @brief LB rt, offset(base) — load byte (sign-extending). [MIPS-ISA]: "LB" */
static inline void
emit_lb(struct jit_state* state, enum MipsRegister rt, enum MipsRegister base, int16_t offset)
{
    emit_i_type(state, MIPS_OP_LB, base, rt, (uint16_t)offset);
}

/** @brief LBU rt, offset(base) — load byte unsigned (zero-extending). [MIPS-ISA]: "LBU" */
static inline void
emit_lbu(struct jit_state* state, enum MipsRegister rt, enum MipsRegister base, int16_t offset)
{
    emit_i_type(state, MIPS_OP_LBU, base, rt, (uint16_t)offset);
}

/** @brief SB rt, offset(base) — store byte. [MIPS-ISA]: "SB" */
static inline void
emit_sb(struct jit_state* state, enum MipsRegister rt, enum MipsRegister base, int16_t offset)
{
    emit_i_type(state, MIPS_OP_SB, base, rt, (uint16_t)offset);
}

/* Branch emission helpers (R6 compact branches — no delay slots) */

/** @brief BC offset26 — unconditional compact branch. [MIPS-ISA]: "BC" */
static inline void
emit_bc(struct jit_state* state, uint32_t offset26)
{
    emit_j_type(state, MIPS_OP_BC, offset26);
}

/** @brief BALC offset26 — branch-and-link compact. [MIPS-ISA]: "BALC" */
static inline void
emit_balc(struct jit_state* state, uint32_t offset26)
{
    emit_j_type(state, MIPS_OP_BALC, offset26);
}

/**
 * @brief BEQC rs, rt, offset16 — branch if rs == rt (compact). [MIPS-ISA]: "BEQC"
 *
 * Encoding requires rs < rt and rs != 0 (POP06).
 * The caller must ensure the register ordering constraint.
 */
static inline void
emit_beqc(struct jit_state* state, enum MipsRegister rs, enum MipsRegister rt, int16_t offset)
{
    /* Swap rs/rt if needed to satisfy rs < rt encoding constraint. */
    if (rs > rt) {
        enum MipsRegister tmp = rs;
        rs = rt;
        rt = tmp;
    }
    emit_i_type(state, MIPS_OP_POP06, rs, rt, (uint16_t)offset);
}

/**
 * @brief BNEC rs, rt, offset16 — branch if rs != rt (compact). [MIPS-ISA]: "BNEC"
 *
 * Encoding requires rs < rt and rs != 0 (POP26).
 */
static inline void
emit_bnec(struct jit_state* state, enum MipsRegister rs, enum MipsRegister rt, int16_t offset)
{
    if (rs > rt) {
        enum MipsRegister tmp = rs;
        rs = rt;
        rt = tmp;
    }
    emit_i_type(state, MIPS_OP_POP26, rs, rt, (uint16_t)offset);
}

/**
 * @brief BEQZC rs, offset21 — branch if rs == 0 (compact). [MIPS-ISA]: "BEQZC"
 *
 * Uses POP66 encoding with 21-bit offset. rs must not be $zero.
 */
static inline void
emit_beqzc(struct jit_state* state, enum MipsRegister rs, uint32_t offset21)
{
    assert(rs != MIPS_REG_ZERO);
    uint32_t instr = ((uint32_t)MIPS_OP_POP66 << 26) |
                     ((rs & 0x1F) << 21) |
                     (offset21 & 0x1FFFFF);
    emit_mips64(state, instr);
}

/**
 * @brief BNEZC rs, offset21 — branch if rs != 0 (compact). [MIPS-ISA]: "BNEZC"
 *
 * Uses POP76 encoding with 21-bit offset. rs must not be $zero.
 */
static inline void
emit_bnezc(struct jit_state* state, enum MipsRegister rs, uint32_t offset21)
{
    assert(rs != MIPS_REG_ZERO);
    uint32_t instr = ((uint32_t)MIPS_OP_POP76 << 26) |
                     ((rs & 0x1F) << 21) |
                     (offset21 & 0x1FFFFF);
    emit_mips64(state, instr);
}

/* Call emission helpers */

/** @brief JALR rd, rs — jump-and-link register. [MIPS-ISA]: "JALR"
 *
 * In R6, JALR has no delay slot when used in compact form (JR is aliased to JALR $zero, rs).
 * rd defaults to $ra ($31) for standard calls.
 */
static inline void
emit_jalr(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rs)
{
    emit_r_type(state, MIPS_OP_SPECIAL, rs, MIPS_REG_ZERO, rd, 0, MIPS_FUNCT_JALR);
}

/* Atomic operation emission helpers (LL/SC, R6 encodings).
 * R6 LL/SC format: SPECIAL3(6)|base(5)|rt(5)|offset(9)|0(1)|funct(6)
 * The offset is a 9-bit signed value (byte-addressed, NOT scaled). */

/** @brief Emit an R6 LL/SC-class instruction. */
static inline void
emit_llsc_r6(
    struct jit_state* state,
    uint32_t funct,
    enum MipsRegister rt,
    enum MipsRegister base,
    int16_t offset9)
{
    assert(offset9 >= -256 && offset9 <= 255);
    uint32_t instr = ((uint32_t)MIPS_OP_SPECIAL3 << 26) |
                     ((base & 0x1F) << 21) |
                     ((rt   & 0x1F) << 16) |
                     (((uint32_t)offset9 & 0x1FF) << 7) |
                     (funct & 0x3F);
    emit_mips64(state, instr);
}

/** @brief LLD rt, offset(base) — load linked doubleword (R6). [MIPS-ISA]: "LLD" */
static inline void
emit_lld(struct jit_state* state, enum MipsRegister rt, enum MipsRegister base, int16_t offset9)
{
    emit_llsc_r6(state, MIPS_FUNCT_LLD6, rt, base, offset9);
}

/** @brief SCD rt, offset(base) — store conditional doubleword (R6). [MIPS-ISA]: "SCD" */
static inline void
emit_scd(struct jit_state* state, enum MipsRegister rt, enum MipsRegister base, int16_t offset9)
{
    emit_llsc_r6(state, MIPS_FUNCT_SCD6, rt, base, offset9);
}

/** @brief LL rt, offset(base) — load linked word (R6). [MIPS-ISA]: "LL" */
static inline void
emit_ll(struct jit_state* state, enum MipsRegister rt, enum MipsRegister base, int16_t offset9)
{
    emit_llsc_r6(state, MIPS_FUNCT_LL6, rt, base, offset9);
}

/** @brief SC rt, offset(base) — store conditional word (R6). [MIPS-ISA]: "SC" */
static inline void
emit_sc(struct jit_state* state, enum MipsRegister rt, enum MipsRegister base, int16_t offset9)
{
    emit_llsc_r6(state, MIPS_FUNCT_SC6, rt, base, offset9);
}

/* Sign-extension and byte-manipulation helpers (SPECIAL3) */

/** @brief SEB rd, rt — sign-extend byte. [MIPS-ISA]: "SEB" */
static inline void
emit_seb(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rt)
{
    emit_r_type(state, MIPS_OP_SPECIAL3, MIPS_REG_ZERO, rt, rd, MIPS_BSHFL_SEB, MIPS_FUNCT_BSHFL);
}

/** @brief SEH rd, rt — sign-extend halfword. [MIPS-ISA]: "SEH" */
static inline void
emit_seh(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rt)
{
    emit_r_type(state, MIPS_OP_SPECIAL3, MIPS_REG_ZERO, rt, rd, MIPS_BSHFL_SEH, MIPS_FUNCT_BSHFL);
}

/** @brief WSBH rd, rt — swap bytes within halfwords (32-bit). [MIPS-ISA]: "WSBH" */
static inline void
emit_wsbh(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rt)
{
    emit_r_type(state, MIPS_OP_SPECIAL3, MIPS_REG_ZERO, rt, rd, MIPS_BSHFL_WSBH, MIPS_FUNCT_BSHFL);
}

/** @brief DSBH rd, rt — swap bytes within halfwords (64-bit). [MIPS-ISA]: "DSBH" */
static inline void
emit_dsbh(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rt)
{
    emit_r_type(state, MIPS_OP_SPECIAL3, MIPS_REG_ZERO, rt, rd, MIPS_DBSHFL_DSBH, MIPS_FUNCT_DBSHFL);
}

/** @brief DSHD rd, rt — swap halfwords within doublewords. [MIPS-ISA]: "DSHD" */
static inline void
emit_dshd(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rt)
{
    emit_r_type(state, MIPS_OP_SPECIAL3, MIPS_REG_ZERO, rt, rd, MIPS_DBSHFL_DSHD, MIPS_FUNCT_DBSHFL);
}

/* R6 multiply/divide helpers (results go directly to GPR, no HI/LO) */

/** @brief DMUL rd, rs, rt — signed 64-bit multiply (low result). [MIPS-ISA]: "DMUL" */
static inline void
emit_dmul(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rs, enum MipsRegister rt)
{
    emit_r_type(state, MIPS_OP_SPECIAL, rs, rt, rd, MIPS_MUL_SHAMT, MIPS_FUNCT_SOP34);
}

/** @brief DDIV rd, rs, rt — signed 64-bit divide. [MIPS-ISA]: "DDIV" */
static inline void
emit_ddiv(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rs, enum MipsRegister rt)
{
    emit_r_type(state, MIPS_OP_SPECIAL, rs, rt, rd, MIPS_MUL_SHAMT, MIPS_FUNCT_SOP36);
}

/** @brief DMOD rd, rs, rt — signed 64-bit modulo. [MIPS-ISA]: "DMOD" */
static inline void
emit_dmod(struct jit_state* state, enum MipsRegister rd, enum MipsRegister rs, enum MipsRegister rt)
{
    emit_r_type(state, MIPS_OP_SPECIAL, rs, rt, rd, MIPS_MOD_SHAMT, MIPS_FUNCT_SOP36);
}

/* Public API stubs */

/**
 * @brief Update the external dispatcher address in JIT'd MIPS64 code.
 *
 * @param[in] vm The VM instance.
 * @param[in] new_dispatcher The new dispatcher function pointer.
 * @param[in] buffer The JIT'd code buffer.
 * @param[in] size Size of the buffer.
 * @param[in] offset Offset within the buffer to the dispatcher slot.
 * @return true on success, false if offset is out of bounds.
 */
bool
ubpf_jit_update_dispatcher_mips64(
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

/**
 * @brief Update a specific external helper address in JIT'd MIPS64 code.
 *
 * @param[in] vm The VM instance.
 * @param[in] new_helper The new helper function pointer.
 * @param[in] idx Index of the helper to update.
 * @param[in] buffer The JIT'd code buffer.
 * @param[in] size Size of the buffer.
 * @param[in] offset Offset within the buffer to the helper table.
 * @return true on success, false if offset is out of bounds.
 */
bool
ubpf_jit_update_helper_mips64(
    struct ubpf_vm* vm,
    extended_external_helper_t new_helper,
    unsigned int idx,
    uint8_t* buffer,
    size_t size,
    uint32_t offset)
{
    UNUSED_PARAMETER(vm);
    uint64_t jit_upper_bound = (uint64_t)buffer + size;
    void* helper_address = (void*)((uint64_t)buffer + offset + (8 * idx));
    if ((uint64_t)helper_address + sizeof(void*) < jit_upper_bound) {
        memcpy(helper_address, &new_helper, sizeof(void*));
        return true;
    }
    return false;
}

/**
 * @brief Translate eBPF instructions to MIPS64r6 native code.
 * Stub — full implementation pending.
 */
struct ubpf_jit_result
ubpf_translate_mips64(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, enum JitMode jit_mode)
{
    (void)vm;
    (void)buffer;
    (void)size;
    (void)jit_mode;

    struct ubpf_jit_result compile_result;
    memset(&compile_result, 0, sizeof(compile_result));
    compile_result.compile_result = UBPF_JIT_COMPILE_FAILURE;
    compile_result.errmsg = ubpf_error("MIPS64r6 JIT backend not yet implemented");
    return compile_result;
}
