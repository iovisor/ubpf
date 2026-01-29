// Copyright (c) 2015 Big Switch Networks, Inc
// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2015 Big Switch Networks, Inc
 * Copyright 2017 Google Inc.
 * Copyright 2022 Linaro Limited
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
 * [ArmARM-A H.a]: https://developer.arm.com/documentation/ddi0487/ha
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

// This is guaranteed to be an illegal A64 instruction.
#define BAD_OPCODE ~UINT32_C(0)
// All A64 registers (note SP & RZ get encoded the same way).
enum Registers
{
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    R16,
    R17,
    R18,
    R19,
    R20,
    R21,
    R22,
    R23,
    R24,
    R25,
    R26,
    R27,
    R28,
    R29,
    R30,
    SP,
    RZ = 31
};

// Callee saved registers - this must be a multiple of two because of how we save the stack later on.
static enum Registers callee_saved_registers[] = {R19, R20, R21, R22, R23, R24, R25, R26};
// Caller saved registers (and parameter registers)
// static enum Registers caller_saved_registers[] = {R0, R1, R2, R3, R4};
// Temp register for immediate generation
static enum Registers temp_register = R24;
// Temp register for division results
static enum Registers temp_div_register = R25;
// Temp register for load/store offsets
static enum Registers offset_register = R26;
// Special register for external dispatcher context.
static enum Registers VOLATILE_CTXT = R26;

// Number of eBPF registers
#define REGISTER_MAP_SIZE 11

// Register assignments:
//   BPF        Arm64       Usage
//   r0         r5          Return value from calls (see note)
//   r1 - r5    r0 - r4     Function parameters, caller-saved
//   r6 - r10   r19 - r23   Callee-saved registers
//              r24         Temp - used for generating 32-bit immediates
//              r25         Temp - used for modulous calculations
//              r26         Temp - used for large load/store offsets
//
// Note that the AArch64 ABI uses r0 both for function parameters and result.  We use r5 to hold
// the result during the function and do an extra final move at the end of the function to copy the
// result to the correct place.
static enum Registers register_map[REGISTER_MAP_SIZE] = {
    R5, // result
    R0,
    R1,
    R2,
    R3,
    R4, // parameters
    R19,
    R20,
    R21,
    R22,
    R23, // callee-saved
};

/* Return the Arm64 register for the given eBPF register */
static enum Registers
map_register(int r)
{
    assert(r < REGISTER_MAP_SIZE);
    return register_map[r % REGISTER_MAP_SIZE];
}

/* Some forward declarations.  */
static void
emit_movewide_immediate(struct jit_state* state, bool sixty_four, enum Registers rd, uint64_t imm);
static void
divmod(struct jit_state* state, uint8_t opcode, int rd, int rn, int rm, int16_t offset);

static uint32_t inline align_to(uint32_t amount, uint64_t boundary)
{
    return (amount + (boundary - 1)) & ~(boundary - 1);
}

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

static void
emit_instruction(struct jit_state* state, uint32_t instr)
{
    assert(instr != BAD_OPCODE);
    emit_bytes(state, &instr, 4);
}

enum AddSubOpcode
{
    AS_ADD = 0,
    AS_ADDS = 1,
    AS_SUB = 2,
    AS_SUBS = 3
};

/* Get the value of the size bit in most instruction encodings (bit 31). */
static uint32_t
sz(bool sixty_four)
{
    return (sixty_four ? UINT32_C(1) : UINT32_C(0)) << 31;
}

/* [ArmARM-A H.a]: C4.1.64: Add/subtract (immediate).  */
static void
emit_addsub_immediate(
    struct jit_state* state,
    bool sixty_four,
    enum AddSubOpcode op,
    enum Registers rd,
    enum Registers rn,
    uint32_t imm12)
{
    const uint32_t imm_op_base = 0x11000000;
    const uint32_t imm_unshifted_max = 0x1000;
    const uint32_t imm_shifted_destroyed = 0xfff;
    const uint32_t imm_shift_on = 1 << 22;

    // When the value of the immediate needs more than 12 bits,
    // the instruction can be encoded using a shift. However, that
    // means that the lower 12 bits will have no bearing on the
    // value added to the source register and stored in the destination.
    // Make sure that matches what the user gave us.
    uint32_t sh = 0x0;
    if (imm12 >= imm_unshifted_max) {
        // If we are going to use the sh field,
        // make sure that the user does not accidentally
        // lose any information.
        UNUSED_LOCAL(imm_shifted_destroyed);
        assert(!(imm12 & imm_shifted_destroyed));
        imm12 >>= 12;
        sh = imm_shift_on;
    }
    assert(imm12 < imm_unshifted_max);
    emit_instruction(
        state, sz(sixty_four) | sh | (op << 29) | imm_op_base | (0 << 22) | (imm12 << 10) | (rn << 5) | rd);
}

/* [ArmARM-A H.a]: C4.1.67: Add/subtract (shifted register).  */
static void
emit_addsub_register(
    struct jit_state* state,
    bool sixty_four,
    enum AddSubOpcode op,
    enum Registers rd,
    enum Registers rn,
    enum Registers rm)
{
    const uint32_t reg_op_base = 0x0b000000;
    emit_instruction(state, sz(sixty_four) | (op << 29) | reg_op_base | (rm << 16) | (rn << 5) | rd);
}

enum LoadStoreOpcode
{
    // sz    V   op
    LS_STRB = 0x00000000U,   // 0000_0000_0000_0000_0000_0000_0000_0000
    LS_LDRB = 0x00400000U,   // 0000_0000_0100_0000_0000_0000_0000_0000
    LS_LDRL = 0x50000000U,   // 0000_0000_0100_0000_0000_0000_0000_0000
    LS_LDRSBX = 0x00800000U, // 0000_0000_1000_0000_0000_0000_0000_0000
    LS_LDRSBW = 0x00c00000U, // 0000_0000_1100_0000_0000_0000_0000_0000
    LS_STRH = 0x40000000U,   // 0100_0000_0000_0000_0000_0000_0000_0000
    LS_LDRH = 0x40400000U,   // 0100_0000_0100_0000_0000_0000_0000_0000
    LS_LDRSHX = 0x40800000U, // 0100_0000_1000_0000_0000_0000_0000_0000
    LS_LDRSHW = 0x40c00000U, // 0100_0000_1100_0000_0000_0000_0000_0000
    LS_STRW = 0x80000000U,   // 1000_0000_0000_0000_0000_0000_0000_0000
    LS_LDRW = 0x80400000U,   // 1000_0000_0100_0000_0000_0000_0000_0000
    LS_LDRSW = 0x80800000U,  // 1000_0000_1000_0000_0000_0000_0000_0000
    LS_STRX = 0xc0000000U,   // 1100_0000_0000_0000_0000_0000_0000_0000
    LS_LDRX = 0xc0400000U,   // 1100_0000_0100_0000_0000_0000_0000_0000
};

enum LoadStoreExclusiveOpcode
{
    // sz    o2 L  o1 Rs o0
    LSE_STXRW = 0x88007c00U,  // 1000_1000_0000_0000_0111_1100_0000_0000
    LSE_LDXRW = 0x885f7c00U,  // 1000_1000_0101_1111_0111_1100_0000_0000
    LSE_STXRX = 0xc8007c00U,  // 1100_1000_0000_0000_0111_1100_0000_0000
    LSE_LDXRX = 0xc85f7c00U,  // 1100_1000_0101_1111_0111_1100_0000_0000
};

/* [ArmARM-A H.a]: C4.1.66: Load/store register (unscaled immediate).  */
static void
emit_loadstore_immediate(
    struct jit_state* state, enum LoadStoreOpcode op, enum Registers rt, enum Registers rn, int16_t imm9)
{
    const uint32_t imm_op_base = 0x38000000U;
    assert(imm9 >= -256 && imm9 < 256);
    imm9 &= 0x1ff;
    emit_instruction(state, imm_op_base | op | (imm9 << 12) | (rn << 5) | rt);
}

/* Load-Exclusive/Store-Exclusive for atomics */
static void
emit_loadstore_exclusive(
    struct jit_state* state, enum LoadStoreExclusiveOpcode op, enum Registers rt, enum Registers rn, enum Registers rs)
{
    // For LDXR, Rs is ignored (set to 31/RZ), for STXR it's the status register
    emit_instruction(state, op | (rs << 16) | (rn << 5) | rt);
}

static void
emit_loadstore_literal(
    struct jit_state* state, enum LoadStoreOpcode op, enum Registers rt, struct PatchableTarget target)
{
    note_load(state, target);
    const uint32_t reg_op_base = 0x08000000U;
    emit_instruction(state, op | reg_op_base | rt);
}

static void
emit_adr(struct jit_state* state, struct PatchableTarget target, enum Registers rd)
{
    note_lea(state, target);
    uint32_t instr = 0x10000000 | rd;
    emit_instruction(state, instr);
}

enum LoadStorePairOpcode
{
    // op    V    L
    LSP_STPW = 0x29000000U,  // 0010_1001_0000_0000_0000_0000_0000_0000
    LSP_LDPW = 0x29400000U,  // 0010_1001_0100_0000_0000_0000_0000_0000
    LSP_LDPSW = 0x69400000U, // 0110_1001_0100_0000_0000_0000_0000_0000
    LSP_STPX = 0xa9000000U,  // 1010_1001_0000_0000_0000_0000_0000_0000
    LSP_LDPX = 0xa9400000U,  // 1010_1001_0100_0000_0000_0000_0000_0000
};

/* [ArmARM-A H.a]: C4.1.66: Load/store register pair (offset).  */
static void
emit_loadstorepair_immediate(
    struct jit_state* state,
    enum LoadStorePairOpcode op,
    enum Registers rt,
    enum Registers rt2,
    enum Registers rn,
    int32_t imm7)
{
    int32_t imm_div = ((op == LSP_STPX) || (op == LSP_LDPX)) ? 8 : 4;
    assert(imm7 % imm_div == 0);
    imm7 /= imm_div;
    emit_instruction(state, op | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt);
}

enum LogicalOpcode
{
    //  op         N
    LOG_AND = 0x00000000U,  // 0000_0000_0000_0000_0000_0000_0000_0000
    LOG_BIC = 0x00200000U,  // 0000_0000_0010_0000_0000_0000_0000_0000
    LOG_ORR = 0x20000000U,  // 0010_0000_0000_0000_0000_0000_0000_0000
    LOG_ORN = 0x20200000U,  // 0010_0000_0010_0000_0000_0000_0000_0000
    LOG_EOR = 0x40000000U,  // 0100_0000_0000_0000_0000_0000_0000_0000
    LOG_EON = 0x40200000U,  // 0100_0000_0010_0000_0000_0000_0000_0000
    LOG_ANDS = 0x60000000U, // 0110_0000_0000_0000_0000_0000_0000_0000
    LOG_BICS = 0x60200000U, // 0110_0000_0010_0000_0000_0000_0000_0000
};

/* [ArmARM-A H.a]: C4.1.67: Logical (shifted register).  */
static void
emit_logical_register(
    struct jit_state* state,
    bool sixty_four,
    enum LogicalOpcode op,
    enum Registers rd,
    enum Registers rn,
    enum Registers rm)
{
    emit_instruction(state, sz(sixty_four) | op | (1 << 27) | (1 << 25) | (rm << 16) | (rn << 5) | rd);
}

enum UnconditionalBranchOpcode
{
    //         opc-|op2--|op3----|        op4|
    BR_BR = 0xd61f0000U,  // 1101_0110_0001_1111_0000_0000_0000_0000
    BR_BLR = 0xd63f0000U, // 1101_0110_0011_1111_0000_0000_0000_0000
    BR_RET = 0xd65f0000U, // 1101_0110_0101_1111_0000_0000_0000_0000
};

/* [ArmARM-A H.a]: C4.1.65: Unconditional branch (register).  */
static void
emit_unconditionalbranch_register(struct jit_state* state, enum UnconditionalBranchOpcode op, enum Registers rn)
{
    emit_instruction(state, op | (rn << 5));
}

enum UnconditionalBranchImmediateOpcode
{
    // O
    UBR_B = 0x14000000U,  // 0001_0100_0000_0000_0000_0000_0000_0000
    UBR_BL = 0x94000000U, // 1001_0100_0000_0000_0000_0000_0000_0000
};

/* [ArmARM-A H.a]: C4.1.65: Unconditional branch (immediate).  */
static uint32_t
emit_unconditionalbranch_immediate(
    struct jit_state* state, enum UnconditionalBranchImmediateOpcode op, struct PatchableTarget target)
{
    uint32_t source_offset = state->offset;
    struct patchable_relative* table = state->jumps;
    int* num_jumps = &state->num_jumps;
    if (op == UBR_BL && !target.is_special) {
        table = state->local_calls;
        num_jumps = &state->num_local_calls;
    }

    emit_patchable_relative(table, state->offset, target, (*num_jumps)++);
    emit_instruction(state, op);

    return source_offset;
}

enum Condition
{
    COND_EQ,
    COND_NE,
    COND_CS,
    COND_CC,
    COND_MI,
    COND_PL,
    COND_VS,
    COND_VC,
    COND_HI,
    COND_LS,
    COND_GE,
    COND_LT,
    COND_GT,
    COND_LE,
    COND_AL,
    COND_NV,
    COND_HS = COND_CS,
    COND_LO = COND_CC
};

enum ConditionalBranchImmediateOpcode
{
    BR_Bcond = 0x54000000U
};

/* [ArmARM-A H.a]: C4.1.65: Conditional branch (immediate).  */
static uint32_t
emit_conditionalbranch_immediate(struct jit_state* state, enum Condition cond, struct PatchableTarget target)
{
    uint32_t source_offset = state->offset;
    emit_patchable_relative(state->jumps, state->offset, target, state->num_jumps++);
    emit_instruction(state, BR_Bcond | (0 << 5) | cond);
    return source_offset;
}

enum CompareBranchOpcode
{
    //          o
    CBR_CBZ = 0x34000000U,  // 0011_0100_0000_0000_0000_0000_0000_0000
    CBR_CBNZ = 0x35000000U, // 0011_0101_0000_0000_0000_0000_0000_0000
};

enum DP1Opcode
{
    //   S          op2--|op-----|
    DP1_REV16 = 0x5ac00400U, // 0101_1010_1100_0000_0000_0100_0000_0000
    DP1_REV32 = 0x5ac00800U, // 0101_1010_1100_0000_0000_1000_0000_0000
    DP1_REV64 = 0xdac00c00U, // 0101_1010_1100_0000_0000_1100_0000_0000
};

/* [ArmARM-A H.a]: C4.1.67: Data-processing (1 source).  */
static void
emit_dataprocessing_onesource(
    struct jit_state* state, bool sixty_four, enum DP1Opcode op, enum Registers rd, enum Registers rn)
{
    emit_instruction(state, sz(sixty_four) | op | (rn << 5) | rd);
}

enum DP2Opcode
{
    //   S                 opcode|
    DP2_UDIV = 0x1ac00800U, // 0001_1010_1100_0000_0000_1000_0000_0000
    DP2_SDIV = 0x1ac00c00U, // 0001_1010_1100_0000_0000_1100_0000_0000
    DP2_LSLV = 0x1ac02000U, // 0001_1010_1100_0000_0010_0000_0000_0000
    DP2_LSRV = 0x1ac02400U, // 0001_1010_1100_0000_0010_0100_0000_0000
    DP2_ASRV = 0x1ac02800U, // 0001_1010_1100_0000_0010_1000_0000_0000
    DP2_RORV = 0x1ac02800U, // 0001_1010_1100_0000_0010_1100_0000_0000
};

/* [ArmARM-A H.a]: C4.1.67: Data-processing (2 source).  */
static void
emit_dataprocessing_twosource(
    struct jit_state* state,
    bool sixty_four,
    enum DP2Opcode op,
    enum Registers rd,
    enum Registers rn,
    enum Registers rm)
{
    emit_instruction(state, sz(sixty_four) | op | (rm << 16) | (rn << 5) | rd);
}

enum DP3Opcode
{
    //  54       31|       0
    DP3_MADD = 0x1b000000U, // 0001_1011_0000_0000_0000_0000_0000_0000
    DP3_MSUB = 0x1b008000U, // 0001_1011_0000_0000_1000_0000_0000_0000
};

/* [ArmARM-A H.a]: C4.1.67: Data-processing (3 source).  */
static void
emit_dataprocessing_threesource(
    struct jit_state* state,
    bool sixty_four,
    enum DP3Opcode op,
    enum Registers rd,
    enum Registers rn,
    enum Registers rm,
    enum Registers ra)
{
    emit_instruction(state, sz(sixty_four) | op | (rm << 16) | (ra << 10) | (rn << 5) | rd);
}

enum MoveWideOpcode
{
    //  op
    MW_MOVN = 0x12800000U, // 0001_0010_1000_0000_0000_0000_0000_0000
    MW_MOVZ = 0x52800000U, // 0101_0010_1000_0000_0000_0000_0000_0000
    MW_MOVK = 0x72800000U, // 0111_0010_1000_0000_0000_0000_0000_0000
};

/* [ArmARM-A H.a]: C4.1.64: Move wide (Immediate).  */
static void
emit_movewide_immediate(struct jit_state* state, bool sixty_four, enum Registers rd, uint64_t imm)
{
    /* Emit a MOVZ or MOVN followed by a sequence of MOVKs to generate the 64-bit constant in imm.
     * See whether the 0x0000 or 0xffff pattern is more common in the immediate.  This ensures we
     * produce the fewest number of immediates.
     */
    unsigned count0000 = sixty_four ? 0 : 2;
    unsigned countffff = 0;
    for (unsigned i = 0; i < (sixty_four ? 64 : 32); i += 16) {
        uint64_t block = (imm >> i) & 0xffff;
        if (block == 0xffff) {
            ++countffff;
        } else if (block == 0) {
            ++count0000;
        }
    }

    /* Iterate over 16-bit elements of imm, outputting an appropriate move instruction.  */
    bool invert = (count0000 < countffff);
    enum MoveWideOpcode op = invert ? MW_MOVN : MW_MOVZ;
    uint64_t skip_pattern = invert ? 0xffff : 0;
    for (unsigned i = 0; i < (sixty_four ? 4 : 2); ++i) {
        uint64_t imm16 = (imm >> (i * 16)) & 0xffff;
        if (imm16 != skip_pattern) {
            if (invert) {
                imm16 = ~imm16;
                imm16 &= 0xffff;
            }
            emit_instruction(state, sz(sixty_four) | op | (i << 21) | (imm16 << 5) | rd);
            op = MW_MOVK;
            invert = false;
        }
    }

    /* Tidy up for the case imm = 0 or imm == -1.  */
    if (op != MW_MOVK) {
        emit_instruction(state, sz(sixty_four) | op | (0 << 21) | (0 << 5) | rd);
    }
}

/* [ArmARM-A H.a]: C4.1.64: Move wide (Immediate) with constant blinding.
 * This variant loads a blinded immediate value and XORs it with a random value
 * to recover the original constant, preventing JIT spray attacks.
 */
static void
emit_movewide_immediate_blinded(struct jit_state* state, bool sixty_four, enum Registers rd, uint64_t imm)
{
    /* Generate random blinding constant */
    uint64_t random = ubpf_generate_blinding_constant();
    uint64_t blinded = imm ^ random;

    /* Use a single scratch register to avoid clobbering live values (notably temp_register in
     * load/store large-offset sequences).
     */
    enum Registers scratch = (rd == temp_div_register) ? temp_register : temp_div_register;

    /* Load blinded constant into rd */
    emit_movewide_immediate(state, sixty_four, rd, blinded);

    /* Load random into scratch */
    emit_movewide_immediate(state, sixty_four, scratch, random);

    /* XOR to recover original: EOR rd, rd, scratch */
    emit_logical_register(state, sixty_four, LOG_EOR, rd, rd, scratch);
}

/* Macro to conditionally emit movewide immediate with or without blinding */
#define EMIT_MOVEWIDE_IMMEDIATE(vm, state, sixty_four, rd, imm) \
    do { \
        if ((vm)->constant_blinding_enabled) { \
            emit_movewide_immediate_blinded(state, sixty_four, rd, imm); \
        } else { \
            emit_movewide_immediate(state, sixty_four, rd, imm); \
        } \
    } while (0)

/* Generate the function prologue.
 *
 * We set the stack to look like:
 *   ubpf_stack_size bytes of UBPF stack
 *   SP on entry
 *   SP on entry
 *   Callee saved registers
 *   Frame <- SP.
 * Precondition: The runtime stack pointer is 16-byte aligned.
 * Postcondition:  The runtime stack pointer is 16-byte aligned.
 */
static void
emit_jit_prologue(struct jit_state* state, size_t ubpf_stack_size)
{
    emit_addsub_immediate(state, true, AS_SUB, SP, SP, 16);
    emit_loadstorepair_immediate(state, LSP_STPX, R29, R30, SP, 0);

    state->stack_size = _countof(callee_saved_registers) * 8;
    emit_addsub_immediate(state, true, AS_SUB, SP, SP, state->stack_size);
    /* Save callee saved registers */
    unsigned i;
    for (i = 0; i < _countof(callee_saved_registers); i += 2) {
        emit_loadstorepair_immediate(
            state, LSP_STPX, callee_saved_registers[i], callee_saved_registers[i + 1], SP, (i) * 8);
    }
    emit_addsub_immediate(state, true, AS_ADD, R29, SP, 0);

    if (state->jit_mode == BasicJitMode) {
        /* Setup UBPF frame pointer. */
        emit_addsub_immediate(state, true, AS_ADD, map_register(10), SP, 0);
        emit_addsub_immediate(state, true, AS_SUB, SP, SP, ubpf_stack_size);
    } else {
        emit_addsub_immediate(state, true, AS_ADD, map_register(10), R2, 0);
        emit_addsub_register(state, true, AS_ADD, map_register(10), map_register(10), R3);
    }

    /* Copy R0 to the volatile context for safe keeping. */
    emit_logical_register(state, true, LOG_ORR, VOLATILE_CTXT, RZ, R0);

    DECLARE_PATCHABLE_SPECIAL_TARGET(exit_tgt, Exit);
    DECLARE_PATCHABLE_SPECIAL_TARGET(enter_tgt, Enter);
    emit_unconditionalbranch_immediate(state, UBR_BL, enter_tgt);
    emit_unconditionalbranch_immediate(state, UBR_B, exit_tgt);
    state->entry_loc = state->offset;
}

static void
emit_jit_epilogue(struct jit_state* state)
{
    state->exit_loc = state->offset;

    /* Move register 0 into R0 */
    if (map_register(0) != R0) {
        emit_logical_register(state, true, LOG_ORR, R0, RZ, map_register(0));
    }

    /* We could be anywhere in the stack if we excepted. Get our head right. */
    emit_addsub_immediate(state, true, AS_ADD, SP, R29, 0);

    /* Restore callee-saved registers).  */
    size_t i;
    for (i = 0; i < _countof(callee_saved_registers); i += 2) {
        emit_loadstorepair_immediate(
            state, LSP_LDPX, callee_saved_registers[i], callee_saved_registers[i + 1], SP, (i) * 8);
    }
    emit_addsub_immediate(state, true, AS_ADD, SP, SP, state->stack_size);

    emit_loadstorepair_immediate(state, LSP_LDPX, R29, R30, SP, 0);
    emit_addsub_immediate(state, true, AS_ADD, SP, SP, 16);

    emit_unconditionalbranch_register(state, BR_RET, R30);
}

static void
emit_dispatched_external_helper_call(struct jit_state* state, struct ubpf_vm* vm, unsigned int idx)
{
    /*
     * There are two paths through the function:
     * 1. There is an external dispatcher registered. If so, we prioritize that.
     * 2. We fall back to the regular registered helper.
     * See translate and emit_dispatched_external_helper_call in ubpf_jit_x86_64.c for additional
     * details.
     */

    uint32_t stack_movement = align_to(8, 16);
    emit_addsub_immediate(state, true, AS_SUB, SP, SP, stack_movement);
    emit_loadstore_immediate(state, LS_STRX, R30, SP, 0);

    // Determine whether to call it through a dispatcher or by index and then load up the address
    // of that function.
    DECLARE_PATCHABLE_SPECIAL_TARGET(external_dispatcher_pt, ExternalDispatcher);
    emit_loadstore_literal(state, LS_LDRL, temp_register, external_dispatcher_pt);

    // Check whether temp_register is empty.
    emit_addsub_immediate(state, true, AS_SUBS, temp_register, temp_register, 0);

    // Jump to the call if we are ready to roll (because we are using an external dispatcher).
    DECLARE_PATCHABLE_REGULAR_EBPF_TARGET(default_tgt, 0);
    uint32_t external_dispatcher_jump_source = emit_conditionalbranch_immediate(state, COND_NE, default_tgt);

    // We are not ready to roll. In other words, we are going to load the helper function address by index.
    EMIT_MOVEWIDE_IMMEDIATE(vm, state, true, R5, idx);
    emit_movewide_immediate(state, true, R6, 3);
    emit_dataprocessing_twosource(state, true, DP2_LSLV, R5, R5, R6);

    emit_movewide_immediate(state, true, temp_register, 0);
    DECLARE_PATCHABLE_SPECIAL_TARGET(load_helper_tgt, LoadHelperTable);
    emit_adr(state, load_helper_tgt, temp_register);
    emit_addsub_register(state, true, AS_ADD, temp_register, temp_register, R5);
    emit_loadstore_immediate(state, LS_LDRX, temp_register, temp_register, 0);

    // Add the implicit 6th parameter (the context)
    emit_logical_register(state, true, LOG_ORR, R5, RZ, VOLATILE_CTXT);

    // And now we, too, are ready to roll. So, let's jump around the code that sets up the additional
    // parameters for the external dispatcher. We will end up at the call site where both paths
    // will rendezvous.
    uint32_t no_dispatcher_jump_source = emit_unconditionalbranch_immediate(state, UBR_B, default_tgt);

    // Mark the landing spot for the jump around the code that sets up a call to a helper function
    // when no external dispatcher is present.
    emit_jump_target(state, external_dispatcher_jump_source);

    // ... set up the final two arguments for the external dispatcher.

    // The index of the helper to be invoked.
    EMIT_MOVEWIDE_IMMEDIATE(vm, state, true, R5, idx);

    // The context.
    // Use a sneaky way to copy the context register into the R6 register (as the final parameter).
    emit_logical_register(state, true, LOG_ORR, R6, RZ, VOLATILE_CTXT);

    // Mark the landing spot for the jump around the external-dispatcher-argument-setup code.
    emit_jump_target(state, no_dispatcher_jump_source);

    // Both paths meet here -- all that's left is to call!
    emit_unconditionalbranch_register(state, BR_BLR, temp_register);

    /* On exit need to move result from r0 to whichever register we've mapped EBPF r0 to.  */
    enum Registers dest = map_register(0);
    if (dest != R0) {
        emit_logical_register(state, true, LOG_ORR, dest, RZ, R0);
    }

    emit_loadstore_immediate(state, LS_LDRX, R30, SP, 0);
    emit_addsub_immediate(state, true, AS_ADD, SP, SP, stack_movement);
}

static void
emit_local_call(struct jit_state* state, uint32_t target_pc)
{
    emit_loadstore_immediate(state, LS_LDRX, temp_register, SP, 0);
    emit_addsub_register(state, true, AS_SUB, map_register(10), map_register(10), temp_register);

    uint32_t stack_movement = align_to(48, 16);
    emit_addsub_immediate(state, true, AS_SUB, SP, SP, stack_movement);

    emit_loadstore_immediate(state, LS_STRX, R30, SP, 0);
    emit_loadstore_immediate(state, LS_STRX, temp_register, SP, 8);
    emit_loadstorepair_immediate(state, LSP_STPX, map_register(6), map_register(7), SP, 16);
    emit_loadstorepair_immediate(state, LSP_STPX, map_register(8), map_register(9), SP, 32);

    DECLARE_PATCHABLE_REGULAR_EBPF_TARGET(tgt, target_pc);
    emit_unconditionalbranch_immediate(state, UBR_BL, tgt);

    emit_loadstore_immediate(state, LS_LDRX, R30, SP, 0);
    emit_loadstore_immediate(state, LS_LDRX, temp_register, SP, 8);
    emit_loadstorepair_immediate(state, LSP_LDPX, map_register(6), map_register(7), SP, 16);
    emit_loadstorepair_immediate(state, LSP_LDPX, map_register(8), map_register(9), SP, 32);

    emit_addsub_immediate(state, true, AS_ADD, SP, SP, stack_movement);

    emit_addsub_register(state, true, AS_ADD, map_register(10), map_register(10), temp_register);
}

/* Helper for emitting atomic operations using LDXR/STXR loop */
static void
emit_atomic_operation(
    struct jit_state* state,
    struct ubpf_vm* vm,
    bool is_64bit,
    enum Registers value_reg,
    enum Registers addr_reg,
    enum Registers result_reg,
    enum Registers temp_reg,
    enum Registers status_reg,
    int16_t offset,
    uint8_t alu_op,
    bool is_cmpxchg,
    bool is_xchg,
    bool fetch)
{
    // Save the target address (addr_reg + offset) into a temporary register.
    // Ensure that the base address register used for LDXR/STXR never aliases
    // the status register used by STXR.
    enum Registers addr_temp =
        (status_reg == temp_div_register) ? offset_register : temp_div_register;
    
    if (offset != 0) {
        // Use int32_t to avoid undefined behavior when negating INT16_MIN
        int32_t abs_offset = offset;
        enum AddSubOpcode op = AS_ADD;

        if (offset < 0) {
            op = AS_SUB;
            abs_offset = -(int32_t)offset;
        }

        if (abs_offset < 256) {
            emit_addsub_immediate(state, true, op, addr_temp, addr_reg, (int16_t)abs_offset);
        } else {
            // Choose a scratch register for the offset that is distinct from addr_temp.
            enum Registers offset_temp =
                (addr_temp == offset_register) ? temp_div_register : offset_register;
            EMIT_MOVEWIDE_IMMEDIATE(vm, state, true, offset_temp, offset);
            emit_addsub_register(state, true, AS_ADD, addr_temp, addr_reg, offset_temp);
        }
    } else {
        // Copy addr_reg into addr_temp so that the base register used by LDXR/STXR
        // is guaranteed not to alias status_reg.
        emit_logical_register(state, true, LOG_ORR, addr_temp, RZ, addr_reg);
    }

    // Mark retry label location
    uint32_t retry_loc = state->offset;
    
    // Load exclusive - use temp_reg to avoid clobbering value_reg or result_reg
    enum Registers load_reg = temp_reg;
    if (is_64bit) {
        emit_loadstore_exclusive(state, LSE_LDXRX, load_reg, addr_temp, RZ);
    } else {
        emit_loadstore_exclusive(state, LSE_LDXRW, load_reg, addr_temp, RZ);
    }
    
    // Perform the operation
    if (is_cmpxchg) {
        // Compare and exchange: compare loaded value with expected value (in value_reg for BPF semantics)
        // For CMPXCHG, BPF expects r0 to contain the expected value
        // value_reg points to the "new" value register, and we compare loaded value with map_register(0)
        enum Registers expected_reg = map_register(0);
        emit_addsub_register(state, is_64bit, AS_SUBS, RZ, load_reg, expected_reg);
        
        // If not equal, skip the store and return the loaded value
        DECLARE_PATCHABLE_REGULAR_EBPF_TARGET(skip_store_tgt, 0);
        uint32_t skip_store_src = emit_conditionalbranch_immediate(state, COND_NE, skip_store_tgt);
        
        // Store exclusive with value_reg (the "new" value)
        if (is_64bit) {
            emit_loadstore_exclusive(state, LSE_STXRX, value_reg, addr_temp, status_reg);
        } else {
            emit_loadstore_exclusive(state, LSE_STXRW, value_reg, addr_temp, status_reg);
        }
        
        // Check if store succeeded (status_reg == 0)
        emit_addsub_immediate(state, false, AS_SUBS, RZ, status_reg, 0);
        
        // Retry if failed (status != 0)
        DECLARE_PATCHABLE_REGULAR_JIT_TARGET(retry_tgt, retry_loc);
        emit_conditionalbranch_immediate(state, COND_NE, retry_tgt);
        
        // Mark skip store target
        emit_jump_target(state, skip_store_src);
        
        // CMPXCHG always returns the loaded value in result_reg (which is r0)
        if (result_reg != load_reg) {
            emit_logical_register(state, is_64bit, LOG_ORR, result_reg, RZ, load_reg);
        }
        
    } else if (is_xchg) {
        // Exchange: store value_reg, return old value in result_reg if fetch
        if (is_64bit) {
            emit_loadstore_exclusive(state, LSE_STXRX, value_reg, addr_temp, status_reg);
        } else {
            emit_loadstore_exclusive(state, LSE_STXRW, value_reg, addr_temp, status_reg);
        }
        
        // Check if store succeeded
        emit_addsub_immediate(state, false, AS_SUBS, RZ, status_reg, 0);
        
        // Retry if failed
        DECLARE_PATCHABLE_REGULAR_JIT_TARGET(retry_tgt, retry_loc);
        emit_conditionalbranch_immediate(state, COND_NE, retry_tgt);
        
        // XCHG always has implicit fetch semantics
        if (result_reg != load_reg) {
            emit_logical_register(state, is_64bit, LOG_ORR, result_reg, RZ, load_reg);
        }
        
    } else {
        // Arithmetic/logical operation based on alu_op
        // Use R8 for the operation result. R8 is caller-saved and not used elsewhere.
        // We cannot use status_reg (R25) because STXR writes status there.
        // We cannot use addr_temp (R26) because it holds the address.
        // We cannot use load_reg (R24/temp_reg) because we need the loaded value.
        enum Registers op_result_reg = R8;
        
        switch (alu_op) {
        case EBPF_ALU_OP_ADD:
            emit_addsub_register(state, is_64bit, AS_ADD, op_result_reg, load_reg, value_reg);
            break;
        case EBPF_ALU_OP_OR:
            emit_logical_register(state, is_64bit, LOG_ORR, op_result_reg, load_reg, value_reg);
            break;
        case EBPF_ALU_OP_AND:
            emit_logical_register(state, is_64bit, LOG_AND, op_result_reg, load_reg, value_reg);
            break;
        case EBPF_ALU_OP_XOR:
            emit_logical_register(state, is_64bit, LOG_EOR, op_result_reg, load_reg, value_reg);
            break;
        default:
            // Should not happen
            break;
        }
        
        // Store exclusive
        if (is_64bit) {
            emit_loadstore_exclusive(state, LSE_STXRX, op_result_reg, addr_temp, status_reg);
        } else {
            emit_loadstore_exclusive(state, LSE_STXRW, op_result_reg, addr_temp, status_reg);
        }
        
        // Check if store succeeded
        emit_addsub_immediate(state, false, AS_SUBS, RZ, status_reg, 0);
        
        // Retry if failed
        DECLARE_PATCHABLE_REGULAR_JIT_TARGET(retry_tgt, retry_loc);
        emit_conditionalbranch_immediate(state, COND_NE, retry_tgt);
        
        // If fetch is requested, copy the old value (in load_reg) to result_reg
        if (fetch && result_reg != load_reg) {
            emit_logical_register(state, is_64bit, LOG_ORR, result_reg, RZ, load_reg);
        }
    }
}

static uint32_t
emit_dispatched_external_helper_address(struct jit_state* state, uint64_t dispatcher_addr)
{
    // We will assume that the buffer of memory holding the JIT'd code is 4-byte aligned.
    // And, because ARM is 32-bit instructions, we know that each instruction is 4-byte aligned.
    // And, finally, we need to make sure that the place we are putting the dispatch address
    // is also 4-byte aligned. As a result, we can be sure that the delta between whoever
    // is doing the PC-relative load and this address is a multiple of 4 bytes (which is how
    // the PC-relative load instruction encodes its offset).
    uint8_t byte = 0;
    int adjustment = (4 - (state->offset % 4)) % 4;
    for (int i = 0; i < adjustment; i++) {
        emit_bytes(state, &byte, 1);
    }
    uint32_t helper_address = state->offset;
    emit_bytes(state, &dispatcher_addr, sizeof(uint64_t));
    return helper_address;
}

static uint32_t
emit_helper_table(struct jit_state* state, struct ubpf_vm* vm)
{

    uint32_t helper_table_address_target = state->offset;
    for (int i = 0; i < MAX_EXT_FUNCS; i++) {
        emit_bytes(state, &vm->ext_funcs[i], sizeof(uint64_t));
    }
    return helper_table_address_target;
}

static bool
is_imm_op(struct ebpf_inst const* inst)
{
    int class = inst->opcode & EBPF_CLS_MASK;
    bool is_imm = (inst->opcode & EBPF_SRC_REG) == EBPF_SRC_IMM;
    bool is_endian = (inst->opcode & EBPF_ALU_OP_MASK) == 0xd0;
    bool is_neg = (inst->opcode & EBPF_ALU_OP_MASK) == 0x80;
    bool is_call = inst->opcode == EBPF_OP_CALL;
    bool is_exit = inst->opcode == EBPF_OP_EXIT;
    bool is_ja = inst->opcode == EBPF_OP_JA || inst->opcode == EBPF_OP_JA32;
    bool is_alu = (class == EBPF_CLS_ALU || class == EBPF_CLS_ALU64) && !is_endian && !is_neg;
    bool is_jmp = (class == EBPF_CLS_JMP && !is_ja && !is_call && !is_exit);
    bool is_jmp32 = (class == EBPF_CLS_JMP32 && inst->opcode != EBPF_OP_JA32);
    bool is_store = class == EBPF_CLS_ST;
    return (is_imm && (is_alu || is_jmp || is_jmp32)) || is_store;
}

static bool
is_alu64_op(struct ebpf_inst const* inst)
{
    int class = inst->opcode & EBPF_CLS_MASK;
    return class == EBPF_CLS_ALU64 || class == EBPF_CLS_JMP;
}

static bool
is_simple_imm(struct ebpf_inst const* inst)
{
    switch (inst->opcode) {
    case EBPF_OP_ADD_IMM:
    case EBPF_OP_ADD64_IMM:
    case EBPF_OP_SUB_IMM:
    case EBPF_OP_SUB64_IMM:
    case EBPF_OP_JEQ_IMM:
    case EBPF_OP_JGT_IMM:
    case EBPF_OP_JGE_IMM:
    case EBPF_OP_JNE_IMM:
    case EBPF_OP_JSGT_IMM:
    case EBPF_OP_JSGE_IMM:
    case EBPF_OP_JLT_IMM:
    case EBPF_OP_JLE_IMM:
    case EBPF_OP_JSLT_IMM:
    case EBPF_OP_JSLE_IMM:
    case EBPF_OP_JEQ32_IMM:
    case EBPF_OP_JGT32_IMM:
    case EBPF_OP_JGE32_IMM:
    case EBPF_OP_JNE32_IMM:
    case EBPF_OP_JSGT32_IMM:
    case EBPF_OP_JSGE32_IMM:
    case EBPF_OP_JLT32_IMM:
    case EBPF_OP_JLE32_IMM:
    case EBPF_OP_JSLT32_IMM:
    case EBPF_OP_JSLE32_IMM:
        return inst->imm >= 0 && inst->imm < 0x1000;
    case EBPF_OP_MOV_IMM:
    case EBPF_OP_MOV64_IMM:
        return true;
    case EBPF_OP_AND_IMM:
    case EBPF_OP_AND64_IMM:
    case EBPF_OP_OR_IMM:
    case EBPF_OP_OR64_IMM:
    case EBPF_OP_XOR_IMM:
    case EBPF_OP_XOR64_IMM:
        return false;
    case EBPF_OP_ARSH_IMM:
    case EBPF_OP_ARSH64_IMM:
    case EBPF_OP_LSH_IMM:
    case EBPF_OP_LSH64_IMM:
    case EBPF_OP_RSH_IMM:
    case EBPF_OP_RSH64_IMM:
        return false;
    case EBPF_OP_JSET_IMM:
    case EBPF_OP_JSET32_IMM:
        return false;
    case EBPF_OP_DIV_IMM:
    case EBPF_OP_DIV64_IMM:
    case EBPF_OP_MOD_IMM:
    case EBPF_OP_MOD64_IMM:
    case EBPF_OP_MUL_IMM:
    case EBPF_OP_MUL64_IMM:
        return false;
    case EBPF_OP_STB:
    case EBPF_OP_STH:
    case EBPF_OP_STW:
    case EBPF_OP_STDW:
        return false;
    default:
        assert(false);
        return false;
    }
}

static uint8_t
to_reg_op(uint8_t opcode)
{
    int class = opcode & EBPF_CLS_MASK;
    if (class == EBPF_CLS_ALU64 || class == EBPF_CLS_ALU || class == EBPF_CLS_JMP || class == EBPF_CLS_JMP32) {
        return opcode | EBPF_SRC_REG;
    } else if (class == EBPF_CLS_ST) {
        return (opcode & ~EBPF_CLS_MASK) | EBPF_CLS_STX;
    }
    assert(false);
    return 0;
}

static enum AddSubOpcode
to_addsub_opcode(int opcode)
{
    switch (opcode) {
    case EBPF_OP_ADD_IMM:
    case EBPF_OP_ADD_REG:
    case EBPF_OP_ADD64_IMM:
    case EBPF_OP_ADD64_REG:
        return AS_ADD;
    case EBPF_OP_SUB_IMM:
    case EBPF_OP_SUB_REG:
    case EBPF_OP_SUB64_IMM:
    case EBPF_OP_SUB64_REG:
        return AS_SUB;
    default:
        assert(false);
        return (enum AddSubOpcode)BAD_OPCODE;
    }
}

static enum LogicalOpcode
to_logical_opcode(int opcode)
{
    switch (opcode) {
    case EBPF_OP_OR_IMM:
    case EBPF_OP_OR_REG:
    case EBPF_OP_OR64_IMM:
    case EBPF_OP_OR64_REG:
        return LOG_ORR;
    case EBPF_OP_AND_IMM:
    case EBPF_OP_AND_REG:
    case EBPF_OP_AND64_IMM:
    case EBPF_OP_AND64_REG:
        return LOG_AND;
    case EBPF_OP_XOR_IMM:
    case EBPF_OP_XOR_REG:
    case EBPF_OP_XOR64_IMM:
    case EBPF_OP_XOR64_REG:
        return LOG_EOR;
    default:
        assert(false);
        return (enum LogicalOpcode)BAD_OPCODE;
    }
}

static enum DP1Opcode
to_dp1_opcode(int opcode, uint32_t imm)
{
    switch (opcode) {
    case EBPF_OP_BE:
    case EBPF_OP_LE:
    case EBPF_OP_BSWAP:
        switch (imm) {
        case 16:
            return DP1_REV16;
        case 32:
            return DP1_REV32;
        case 64:
            return DP1_REV64;
        default:
            assert(false);
            return 0;
        }
        break;
    default:
        assert(false);
        return (enum DP1Opcode)BAD_OPCODE;
    }
}

static enum DP2Opcode
to_dp2_opcode(int opcode)
{
    switch (opcode) {
    case EBPF_OP_LSH_IMM:
    case EBPF_OP_LSH_REG:
    case EBPF_OP_LSH64_IMM:
    case EBPF_OP_LSH64_REG:
        return DP2_LSLV;
    case EBPF_OP_RSH_IMM:
    case EBPF_OP_RSH_REG:
    case EBPF_OP_RSH64_IMM:
    case EBPF_OP_RSH64_REG:
        return DP2_LSRV;
    case EBPF_OP_ARSH_IMM:
    case EBPF_OP_ARSH_REG:
    case EBPF_OP_ARSH64_IMM:
    case EBPF_OP_ARSH64_REG:
        return DP2_ASRV;
    case EBPF_OP_DIV_IMM:
    case EBPF_OP_DIV_REG:
    case EBPF_OP_DIV64_IMM:
    case EBPF_OP_DIV64_REG:
        return DP2_UDIV;
    default:
        assert(false);
        return (enum DP2Opcode)BAD_OPCODE;
    }
}

static enum LoadStoreOpcode
to_loadstore_opcode(int opcode)
{
    switch (opcode) {
    case EBPF_OP_LDXW:
        return LS_LDRW;
    case EBPF_OP_LDXH:
        return LS_LDRH;
    case EBPF_OP_LDXB:
        return LS_LDRB;
    case EBPF_OP_LDXDW:
        return LS_LDRX;
    case EBPF_OP_LDXWSX:
        return LS_LDRSW;
    case EBPF_OP_LDXHSX:
        return LS_LDRSHX;
    case EBPF_OP_LDXBSX:
        return LS_LDRSBX;
    case EBPF_OP_STW:
    case EBPF_OP_STXW:
        return LS_STRW;
    case EBPF_OP_STH:
    case EBPF_OP_STXH:
        return LS_STRH;
    case EBPF_OP_STB:
    case EBPF_OP_STXB:
        return LS_STRB;
    case EBPF_OP_STDW:
    case EBPF_OP_STXDW:
        return LS_STRX;
    default:
        assert(false);
        return (enum LoadStoreOpcode)BAD_OPCODE;
    }
}

static enum Condition
to_condition(int opcode)
{
    uint8_t jmp_type = opcode & EBPF_JMP_OP_MASK;
    switch (jmp_type) {
    case EBPF_MODE_JEQ:
        return COND_EQ;
    case EBPF_MODE_JGT:
        return COND_HI;
    case EBPF_MODE_JGE:
        return COND_HS;
    case EBPF_MODE_JLT:
        return COND_LO;
    case EBPF_MODE_JLE:
        return COND_LS;
    case EBPF_MODE_JSET:
        return COND_NE;
    case EBPF_MODE_JNE:
        return COND_NE;
    case EBPF_MODE_JSGT:
        return COND_GT;
    case EBPF_MODE_JSGE:
        return COND_GE;
    case EBPF_MODE_JSLT:
        return COND_LT;
    case EBPF_MODE_JSLE:
        return COND_LE;
    default:
        assert(false);
        return COND_NV;
    }
}

/*
 * The layout of the JIT'd code follows a certain pattern. There are
 * several invariants in the JIT'd code as well. Those are documented
 * in the translate function of the x86_64 JIT.
 * Note: The amount of space used to store the eBPF program's stack
 * usage in a location function is 8 bytes for both x86 and Arm. However,
 * in the Arm case, the value is pushed to the stack twice to maintain
 * 16-byte stack alignment.
 */
static int
translate(struct ubpf_vm* vm, struct jit_state* state, char** errmsg)
{
    int i;

    emit_jit_prologue(state, UBPF_EBPF_STACK_SIZE);

    for (i = 0; i < vm->num_insts; i++) {

        if (state->jit_status != NoError) {
            break;
        }

        // All checks for errors during the encoding of _this_ instruction
        // occur at the end of the loop.
        struct ebpf_inst inst = ubpf_fetch_instruction(vm, i);

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
                DECLARE_PATCHABLE_REGULAR_EBPF_TARGET(default_tgt, 0)
                fallthrough_jump_source = emit_unconditionalbranch_immediate(state, UBR_B, default_tgt);
                fallthrough_jump_present = true;
            }
        }

        if (i == 0 || vm->int_funcs[i]) {
            size_t prolog_start = state->offset;
            emit_movewide_immediate(state, true, temp_register, ubpf_stack_usage_for_local_func(vm, i));
            emit_addsub_immediate(state, true, AS_SUB, SP, SP, 16);
            emit_loadstorepair_immediate(state, LSP_STPX, temp_register, temp_register, SP, 0);
            // Record the size of the prolog so that we can calculate offset when doing a local call.
            if (state->bpf_function_prolog_size == 0) {
                state->bpf_function_prolog_size = state->offset - prolog_start;
            } else {
                assert(state->bpf_function_prolog_size == state->offset - prolog_start);
            }
        }

        if (fallthrough_jump_present) {
            DECLARE_PATCHABLE_REGULAR_JIT_TARGET(fallthrough_tgt, state->offset)
            modify_patchable_relatives_target(state->jumps, state->num_jumps, fallthrough_jump_source, fallthrough_tgt);
        }

        state->pc_locs[i] = state->offset;

        enum Registers dst = map_register(inst.dst);
        enum Registers src = map_register(inst.src);
        uint8_t opcode = inst.opcode;

        // Use int64_t to avoid signed overflow with large immediates
        int64_t target_pc_64;
        if (inst.opcode == EBPF_OP_JA32) {
            target_pc_64 = (int64_t)i + (int64_t)inst.imm + 1;
        } else {
            target_pc_64 = (int64_t)i + (int64_t)inst.offset + 1;
        }
        uint32_t target_pc = (uint32_t)target_pc_64;

        DECLARE_PATCHABLE_REGULAR_EBPF_TARGET(tgt, target_pc);

        int sixty_four = is_alu64_op(&inst);

        // If this is an operation with an immediate operand (and that immediate
        // operand is _not_ simple), then we convert the operation to the equivalent
        // register version after moving the immediate into a temporary register.
        // When constant blinding is enabled, we also convert simple immediates to ensure
        // all attacker-controlled immediates are blinded.
        // Exception: MOV_IMM/MOV64_IMM are handled directly in their switch case to avoid
        // an extra ORR instruction when blinding is enabled.
        if (is_imm_op(&inst) &&
            opcode != EBPF_OP_MOV_IMM &&
            opcode != EBPF_OP_MOV64_IMM &&
            (!is_simple_imm(&inst) || vm->constant_blinding_enabled)) {
            EMIT_MOVEWIDE_IMMEDIATE(vm, state, sixty_four, temp_register, (int64_t)inst.imm);
            src = temp_register;
            opcode = to_reg_op(opcode);
        }

        switch (opcode) {
        case EBPF_OP_ADD_IMM:
        case EBPF_OP_ADD64_IMM:
        case EBPF_OP_SUB_IMM:
        case EBPF_OP_SUB64_IMM:
            emit_addsub_immediate(state, sixty_four, to_addsub_opcode(opcode), dst, dst, inst.imm);
            break;
        case EBPF_OP_ADD_REG:
        case EBPF_OP_ADD64_REG:
        case EBPF_OP_SUB_REG:
        case EBPF_OP_SUB64_REG:
            emit_addsub_register(state, sixty_four, to_addsub_opcode(opcode), dst, dst, src);
            break;
        case EBPF_OP_LSH_REG:
        case EBPF_OP_RSH_REG:
        case EBPF_OP_ARSH_REG:
        case EBPF_OP_LSH64_REG:
        case EBPF_OP_RSH64_REG:
        case EBPF_OP_ARSH64_REG:
            /* TODO: CHECK imm is small enough.  */
            emit_dataprocessing_twosource(state, sixty_four, to_dp2_opcode(opcode), dst, dst, src);
            break;
        case EBPF_OP_MUL_REG:
        case EBPF_OP_MUL64_REG:
            emit_dataprocessing_threesource(state, sixty_four, DP3_MADD, dst, dst, src, RZ);
            break;
        case EBPF_OP_DIV_REG:
        case EBPF_OP_MOD_REG:
        case EBPF_OP_DIV64_REG:
        case EBPF_OP_MOD64_REG:
            divmod(state, opcode, dst, dst, src, inst.offset);
            break;
        case EBPF_OP_OR_REG:
        case EBPF_OP_AND_REG:
        case EBPF_OP_XOR_REG:
        case EBPF_OP_OR64_REG:
        case EBPF_OP_AND64_REG:
        case EBPF_OP_XOR64_REG:
            emit_logical_register(state, sixty_four, to_logical_opcode(opcode), dst, dst, src);
            break;
        case EBPF_OP_NEG:
        case EBPF_OP_NEG64:
            emit_addsub_register(state, sixty_four, AS_SUB, dst, RZ, dst);
            break;
        case EBPF_OP_MOV_IMM:
        case EBPF_OP_MOV64_IMM:
            EMIT_MOVEWIDE_IMMEDIATE(vm, state, sixty_four, dst, (int64_t)inst.imm);
            break;
        case EBPF_OP_MOV_REG:
        case EBPF_OP_MOV64_REG:
            emit_logical_register(state, sixty_four, LOG_ORR, dst, RZ, src);
            break;
        case EBPF_OP_LE:
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            /* No-op */
#else
            emit_dataprocessing_onesource(state, sixty_four, to_dp1_opcode(opcode, inst.imm), dst, dst);
#endif
            if (inst.imm == 16) {
                /* UXTH dst, dst. */
                emit_instruction(state, 0x53003c00 | (dst << 5) | dst);
            } else if (inst.imm == 32) {
                /* UXTW dst, dst. */
                emit_instruction(state, 0x53007c00 | (dst << 5) | dst);
            }
            break;
        case EBPF_OP_BE:
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            emit_dataprocessing_onesource(state, sixty_four, to_dp1_opcode(opcode, inst.imm), dst, dst);
#else
            /* No-op. */
#endif
            if (inst.imm == 16) {
                /* UXTH dst, dst. */
                emit_instruction(state, 0x53003c00 | (dst << 5) | dst);
            }
            break;

        case EBPF_OP_BSWAP:
            /* Always swap bytes for bswap (unconditional) */
            emit_dataprocessing_onesource(state, sixty_four, to_dp1_opcode(opcode, inst.imm), dst, dst);
            if (inst.imm == 16) {
                /* UXTH dst, dst - zero extend to 64 bits */
                emit_instruction(state, 0x53003c00 | (dst << 5) | dst);
            } else if (inst.imm == 32) {
                /* UXTW dst, dst - zero extend to 64 bits */
                emit_instruction(state, 0x53007c00 | (dst << 5) | dst);
            }
            break;

        /* TODO use 8 bit immediate when possible */
        case EBPF_OP_JA:
        case EBPF_OP_JA32:
            emit_unconditionalbranch_immediate(state, UBR_B, tgt);
            break;
        case EBPF_OP_JEQ_IMM:
        case EBPF_OP_JGT_IMM:
        case EBPF_OP_JGE_IMM:
        case EBPF_OP_JLT_IMM:
        case EBPF_OP_JLE_IMM:
        case EBPF_OP_JNE_IMM:
        case EBPF_OP_JSGT_IMM:
        case EBPF_OP_JSGE_IMM:
        case EBPF_OP_JSLT_IMM:
        case EBPF_OP_JSLE_IMM:
        case EBPF_OP_JEQ32_IMM:
        case EBPF_OP_JGT32_IMM:
        case EBPF_OP_JGE32_IMM:
        case EBPF_OP_JLT32_IMM:
        case EBPF_OP_JLE32_IMM:
        case EBPF_OP_JNE32_IMM:
        case EBPF_OP_JSGT32_IMM:
        case EBPF_OP_JSGE32_IMM:
        case EBPF_OP_JSLT32_IMM:
        case EBPF_OP_JSLE32_IMM:
            emit_addsub_immediate(state, sixty_four, AS_SUBS, RZ, dst, inst.imm);
            emit_conditionalbranch_immediate(state, to_condition(opcode), tgt);
            break;
        case EBPF_OP_JEQ_REG:
        case EBPF_OP_JGT_REG:
        case EBPF_OP_JGE_REG:
        case EBPF_OP_JLT_REG:
        case EBPF_OP_JLE_REG:
        case EBPF_OP_JNE_REG:
        case EBPF_OP_JSGT_REG:
        case EBPF_OP_JSGE_REG:
        case EBPF_OP_JSLT_REG:
        case EBPF_OP_JSLE_REG:
        case EBPF_OP_JEQ32_REG:
        case EBPF_OP_JGT32_REG:
        case EBPF_OP_JGE32_REG:
        case EBPF_OP_JLT32_REG:
        case EBPF_OP_JLE32_REG:
        case EBPF_OP_JNE32_REG:
        case EBPF_OP_JSGT32_REG:
        case EBPF_OP_JSGE32_REG:
        case EBPF_OP_JSLT32_REG:
        case EBPF_OP_JSLE32_REG:
            emit_addsub_register(state, sixty_four, AS_SUBS, RZ, dst, src);
            emit_conditionalbranch_immediate(state, to_condition(opcode), tgt);
            break;
        case EBPF_OP_JSET_REG:
        case EBPF_OP_JSET32_REG:
            emit_logical_register(state, sixty_four, LOG_ANDS, RZ, dst, src);
            emit_conditionalbranch_immediate(state, to_condition(opcode), tgt);
            break;
        case EBPF_OP_CALL: {
            DECLARE_PATCHABLE_SPECIAL_TARGET(exit_tgt, Exit);
            if (inst.src == 0) {
                emit_dispatched_external_helper_call(state, vm, inst.imm);
                if (inst.imm == vm->unwind_stack_extension_index) {
                    emit_addsub_immediate(state, true, AS_SUBS, RZ, map_register(0), 0);
                    emit_conditionalbranch_immediate(state, COND_EQ, exit_tgt);
                }
            } else if (inst.src == 1) {
                uint32_t call_target = i + inst.imm + 1;
                emit_local_call(state, call_target);
            } else {
                emit_unconditionalbranch_immediate(state, UBR_B, exit_tgt);
            }
            break;
        }
        case EBPF_OP_EXIT:
            emit_addsub_immediate(state, true, AS_ADD, SP, SP, 16);
            emit_unconditionalbranch_register(state, BR_RET, R30);
            break;

        case EBPF_OP_STXW:
        case EBPF_OP_STXH:
        case EBPF_OP_STXB:
        case EBPF_OP_STXDW: {
            enum Registers tmp = dst;
            dst = src;
            src = tmp;
        }
            /* fallthrough: */
        case EBPF_OP_LDXW:
        case EBPF_OP_LDXH:
        case EBPF_OP_LDXB:
        case EBPF_OP_LDXDW:
        case EBPF_OP_LDXWSX:
        case EBPF_OP_LDXHSX:
        case EBPF_OP_LDXBSX:
            if (inst.offset >= -256 && inst.offset < 256) {
                emit_loadstore_immediate(state, to_loadstore_opcode(opcode), dst, src, inst.offset);
            } else {
                // Compute address into a temporary register so negative large offsets work correctly.
                // (A64 load/store register-offset form is unsuitable for negative offsets.)
                enum Registers addr_temp = temp_div_register;
                int32_t abs_offset = inst.offset;
                enum AddSubOpcode op = AS_ADD;

                if (inst.offset < 0) {
                    op = AS_SUB;
                    abs_offset = -(int32_t)inst.offset;
                }

                if (abs_offset < 0x1000) {
                    emit_addsub_immediate(state, true, op, addr_temp, src, (uint32_t)abs_offset);
                } else {
                    EMIT_MOVEWIDE_IMMEDIATE(vm, state, true, offset_register, (uint32_t)abs_offset);
                    emit_addsub_register(state, true, op, addr_temp, src, offset_register);
                }

                emit_loadstore_immediate(state, to_loadstore_opcode(opcode), dst, addr_temp, 0);
            }
            break;

        case EBPF_OP_ATOMIC_STORE: {
            bool fetch = inst.imm & EBPF_ATOMIC_OP_FETCH;
            // Use R24 as temp for loaded value, offset_register (R26) for address calc
            // Use temp_div_register (R25) as status register for STXR (not mapped to any BPF register)
            enum Registers result_reg = src; // Where to store the fetched value
            enum Registers temp_reg = temp_register; // Temp for operation result
            enum Registers status_reg = temp_div_register; // Status register for STXR (R25)
            
            switch (inst.imm & EBPF_ALU_OP_MASK) {
            case EBPF_ALU_OP_ADD:
                emit_atomic_operation(state, vm, true, src, dst, result_reg, temp_reg, status_reg, inst.offset, EBPF_ALU_OP_ADD, false, false, fetch);
                break;
            case EBPF_ALU_OP_OR:
                emit_atomic_operation(state, vm, true, src, dst, result_reg, temp_reg, status_reg, inst.offset, EBPF_ALU_OP_OR, false, false, fetch);
                break;
            case EBPF_ALU_OP_AND:
                emit_atomic_operation(state, vm, true, src, dst, result_reg, temp_reg, status_reg, inst.offset, EBPF_ALU_OP_AND, false, false, fetch);
                break;
            case EBPF_ALU_OP_XOR:
                emit_atomic_operation(state, vm, true, src, dst, result_reg, temp_reg, status_reg, inst.offset, EBPF_ALU_OP_XOR, false, false, fetch);
                break;
            case (EBPF_ATOMIC_OP_XCHG & ~EBPF_ATOMIC_OP_FETCH):
                emit_atomic_operation(state, vm, true, src, dst, result_reg, temp_reg, status_reg, inst.offset, 0, false, true, true);
                break;
            case (EBPF_ATOMIC_OP_CMPXCHG & ~EBPF_ATOMIC_OP_FETCH):
                // For CMPXCHG, result goes to R0 (BPF register 0)
                result_reg = map_register(0);
                emit_atomic_operation(state, vm, true, src, dst, result_reg, temp_reg, status_reg, inst.offset, 0, true, false, true);
                break;
            default:
                *errmsg = ubpf_error("Unknown atomic operation at PC %d: imm %02x", i, inst.imm);
                state->jit_status = UnknownInstruction;
                break;
            }
        } break;

        case EBPF_OP_ATOMIC32_STORE: {
            bool fetch = inst.imm & EBPF_ATOMIC_OP_FETCH;
            // Use R24 as temp for loaded value, offset_register (R26) for address calc
            // Use temp_div_register (R25) as status register for STXR (not mapped to any BPF register)
            enum Registers result_reg = src; // Where to store the fetched value
            enum Registers temp_reg = temp_register; // Temp for operation result
            enum Registers status_reg = temp_div_register; // Status register for STXR (R25)
            
            switch (inst.imm & EBPF_ALU_OP_MASK) {
            case EBPF_ALU_OP_ADD:
                emit_atomic_operation(state, vm, false, src, dst, result_reg, temp_reg, status_reg, inst.offset, EBPF_ALU_OP_ADD, false, false, fetch);
                break;
            case EBPF_ALU_OP_OR:
                emit_atomic_operation(state, vm, false, src, dst, result_reg, temp_reg, status_reg, inst.offset, EBPF_ALU_OP_OR, false, false, fetch);
                break;
            case EBPF_ALU_OP_AND:
                emit_atomic_operation(state, vm, false, src, dst, result_reg, temp_reg, status_reg, inst.offset, EBPF_ALU_OP_AND, false, false, fetch);
                break;
            case EBPF_ALU_OP_XOR:
                emit_atomic_operation(state, vm, false, src, dst, result_reg, temp_reg, status_reg, inst.offset, EBPF_ALU_OP_XOR, false, false, fetch);
                break;
            case (EBPF_ATOMIC_OP_XCHG & ~EBPF_ATOMIC_OP_FETCH):
                emit_atomic_operation(state, vm, false, src, dst, result_reg, temp_reg, status_reg, inst.offset, 0, false, true, true);
                break;
            case (EBPF_ATOMIC_OP_CMPXCHG & ~EBPF_ATOMIC_OP_FETCH):
                // For CMPXCHG, result goes to R0 (BPF register 0)
                result_reg = map_register(0);
                emit_atomic_operation(state, vm, false, src, dst, result_reg, temp_reg, status_reg, inst.offset, 0, true, false, true);
                break;
            default:
                *errmsg = ubpf_error("Unknown atomic operation at PC %d: imm %02x", i, inst.imm);
                state->jit_status = UnknownInstruction;
                break;
            }
        } break;

        case EBPF_OP_LDDW: {
            struct ebpf_inst inst2 = ubpf_fetch_instruction(vm, ++i);
            uint64_t imm = (uint32_t)inst.imm | ((uint64_t)inst2.imm << 32);
            EMIT_MOVEWIDE_IMMEDIATE(vm, state, true, dst, imm);
            break;
        }

        case EBPF_OP_MUL_IMM:
        case EBPF_OP_MUL64_IMM:
        case EBPF_OP_DIV_IMM:
        case EBPF_OP_MOD_IMM:
        case EBPF_OP_DIV64_IMM:
        case EBPF_OP_MOD64_IMM:
        case EBPF_OP_STW:
        case EBPF_OP_STH:
        case EBPF_OP_STB:
        case EBPF_OP_STDW:
        case EBPF_OP_JSET_IMM:
        case EBPF_OP_JSET32_IMM:
        case EBPF_OP_OR_IMM:
        case EBPF_OP_AND_IMM:
        case EBPF_OP_XOR_IMM:
        case EBPF_OP_OR64_IMM:
        case EBPF_OP_AND64_IMM:
        case EBPF_OP_XOR64_IMM:
        case EBPF_OP_LSH_IMM:
        case EBPF_OP_RSH_IMM:
        case EBPF_OP_ARSH_IMM:
        case EBPF_OP_LSH64_IMM:
        case EBPF_OP_RSH64_IMM:
        case EBPF_OP_ARSH64_IMM:
            *errmsg = ubpf_error("Unexpected instruction at PC %d: opcode %02x, immediate %08x", i, opcode, inst.imm);
            state->jit_status = UnexpectedInstruction;
        default:
            *errmsg = ubpf_error("Unknown instruction at PC %d: opcode %02x", i, opcode);
            state->jit_status = UnknownInstruction;
        }
    }

    if (state->jit_status != NoError) {
        switch (state->jit_status) {
        case TooManyJumps: {
            *errmsg = ubpf_error("Too many jump instructions.");
            break;
        }
        case TooManyLoads: {
            *errmsg = ubpf_error("Too many load instructions.");
            break;
        }
        case TooManyLeas: {
            *errmsg = ubpf_error("Too many LEA calculations.");
            break;
        }
        case TooManyLocalCalls: {
            *errmsg = ubpf_error("Too many local calls.");
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

    emit_jit_epilogue(state);

    state->dispatcher_loc = emit_dispatched_external_helper_address(state, (uint64_t)vm->dispatcher);
    state->helper_table_loc = emit_helper_table(state, vm);

    return 0;
}

static void
divmod(struct jit_state* state, uint8_t opcode, int rd, int rn, int rm, int16_t offset)
{
    bool mod = (opcode & EBPF_ALU_OP_MASK) == (EBPF_OP_MOD_IMM & EBPF_ALU_OP_MASK);
    bool sixty_four = (opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU64;
    bool is_signed = (offset == 1);
    enum Registers div_dest = mod ? temp_div_register : rd;

    /* Do not need to treat divide by zero as special because the UDIV/SDIV instructions
     * already return 0 when dividing by zero.
     */
    enum DP2Opcode div_op = is_signed ? DP2_SDIV : DP2_UDIV;
    emit_dataprocessing_twosource(state, sixty_four, div_op, div_dest, rn, rm);
    if (mod) {
        emit_dataprocessing_threesource(state, sixty_four, DP3_MSUB, rd, rm, div_dest, rn);
    }
}

static void
resolve_branch_immediate(struct jit_state* state, uint32_t offset, int32_t imm)
{
    assert((imm & 3) == 0);
    uint32_t instr;
    imm >>= 2;
    memcpy(&instr, state->buf + offset, sizeof(uint32_t));
    if ((instr & 0xfe000000U) == 0x54000000U       /* Conditional branch immediate.  */
        || (instr & 0x7e000000U) == 0x34000000U) { /* Compare and branch immediate.  */
        assert((imm >> 19) == INT64_C(-1) || (imm >> 19) == 0);
        instr |= (imm & 0x7ffff) << 5;
    } else if ((instr & 0x7c000000U) == 0x14000000U) {
        /* Unconditional branch immediate.  */
        assert((imm >> 26) == INT64_C(-1) || (imm >> 26) == 0);
        instr |= (imm & 0x03ffffffU) << 0;
    } else {
        assert(false);
        instr = BAD_OPCODE;
    }
    memcpy(state->buf + offset, &instr, sizeof(uint32_t));
}

static void
resolve_load_literal(struct jit_state* state, uint32_t instr_offset, int32_t target_offset)
{
    uint32_t instr;
    target_offset = (0x7FFFF & target_offset) << 5;
    memcpy(&instr, state->buf + instr_offset, sizeof(uint32_t));
    instr |= target_offset;
    memcpy(state->buf + instr_offset, &instr, sizeof(uint32_t));
}

static void
resolve_adr(struct jit_state* state, uint32_t instr_offset, int32_t immediate)
{
    uint32_t instr;
    uint32_t immhi = (immediate & 0x00ffffff) << 5;
    memcpy(&instr, state->buf + instr_offset, sizeof(uint32_t));
    instr |= immhi;
    memcpy(state->buf + instr_offset, &instr, sizeof(uint32_t));
}

static bool
resolve_jumps(struct jit_state* state)
{
    for (unsigned i = 0; i < state->num_jumps; ++i) {
        struct patchable_relative jump = state->jumps[i];

        int32_t target_loc;

        if (jump.target.is_special) {
            // Jumps to special targets Exit and Enter are the only
            // valid options.
            if (jump.target.target.special == Exit) {
                target_loc = state->exit_loc;
            } else if (jump.target.target.special == Enter) {
                target_loc = state->entry_loc;
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
        }

        int32_t rel = target_loc - jump.offset_loc;
        resolve_branch_immediate(state, jump.offset_loc, rel);
    }
    return true;
}

static bool
resolve_loads(struct jit_state* state)
{
    for (unsigned i = 0; i < state->num_loads; ++i) {
        struct patchable_relative jump = state->loads[i];

        int32_t target_loc = 0;
        // Right now it is only possible to load from the external dispatcher.
        if (jump.target.is_special && jump.target.target.special == ExternalDispatcher) {
            target_loc = state->dispatcher_loc;
        } else {
            return false;
        }

        int32_t rel = target_loc - jump.offset_loc;
        assert(rel % 4 == 0);
        rel >>= 2;
        resolve_load_literal(state, jump.offset_loc, rel);
    }
    return true;
}

static bool
resolve_leas(struct jit_state* state)
{
    for (unsigned i = 0; i < state->num_leas; ++i) {
        struct patchable_relative jump = state->leas[i];

        int32_t target_loc = 0;
        // Right now it is only possible to have leas to the helper table.
        if (jump.target.is_special && jump.target.target.special == LoadHelperTable) {
            target_loc = state->helper_table_loc;
        } else {
            return false;
        }

        int32_t rel = target_loc - jump.offset_loc;
        assert(rel % 4 == 0);
        rel >>= 2;
        resolve_adr(state, jump.offset_loc, rel);
    }
    return true;
}

static bool
resolve_local_calls(struct jit_state* state)
{
    for (unsigned i = 0; i < state->num_local_calls; ++i) {
        struct patchable_relative local_call = state->local_calls[i];

        int32_t target_loc = 0;
        // A local call must be eBPF PC-relative and it cannot be special.
        assert(!local_call.target.is_special);
        target_loc = state->pc_locs[local_call.target.target.regular.ebpf_target_pc];

        int32_t rel = target_loc - local_call.offset_loc;
        rel -= state->bpf_function_prolog_size;
        resolve_branch_immediate(state, local_call.offset_loc, rel);
    }
    return true;
}

bool
ubpf_jit_update_dispatcher_arm64(
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
ubpf_jit_update_helper_arm64(
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

struct ubpf_jit_result
ubpf_translate_arm64(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, enum JitMode jit_mode)
{
    struct jit_state state;
    struct ubpf_jit_result compile_result;

    if (initialize_jit_state_result(vm, &state, &compile_result, buffer, *size, jit_mode, &compile_result.errmsg) < 0) {
        goto out;
    }

    if (translate(vm, &state, &compile_result.errmsg) < 0) {
        goto out;
    }

    if (!resolve_jumps(&state) || !resolve_loads(&state) || !resolve_leas(&state) || !resolve_local_calls(&state)) {
        compile_result.errmsg = ubpf_error("Could not patch the relative addresses in the JIT'd code.");
        goto out;
    }

    compile_result.compile_result = UBPF_JIT_COMPILE_SUCCESS;
    *size = state.offset;
    compile_result.external_dispatcher_offset = state.dispatcher_loc;
    compile_result.external_helper_offset = state.helper_table_loc;

out:
    release_jit_state_result(&state, &compile_result);
    return compile_result;
}
