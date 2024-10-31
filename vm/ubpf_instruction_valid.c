// Copyright (c) 2015 Big Switch Networks, Inc
// SPDX-License-Identifier: Apache-2.0

#include "ubpf_int.h"

// This file contains the list of all valid eBPF instructions and the fields that are valid for each instruction.

/**
 * @brief Structure to filter valid fields for each eBPF instruction.
 * Each field has an optional validation function that is called to validate the field.
 * If the validation function is NULL, the field is reserved and must be zero.
 */
typedef struct _ubpf_inst_filter
{
    uint8_t opcode;                       ///< The opcode of the instruction.
    bool (*source)(int64_t source);       ///< Function to validate the source register.
    bool (*destination)(int64_t dest);    ///< Function to validate the source register.
    bool (*offset)(int64_t offset);       ///< Function to validate the offset.
    bool (*immediate)(int64_t immediate); ///< Function to validate the immediate value.
} ubpf_inst_filter_t;

bool
_is_r0_through_r9(int64_t src)
{
    return src >= BPF_REG_0 && src <= BPF_REG_9;
}

bool
_is_r0_through_r10(int64_t dst)
{
    return dst >= BPF_REG_0 && dst <= BPF_REG_10;
}

bool
_is_integer_width(int64_t imm)
{
    switch (imm) {
    case 8:
    case 16:
    case 32:
    case 64:
        return true;
    default:
        return false;
    }
}

bool
_is_16bit(int64_t imm)
{
    return imm >= INT16_MIN && imm <= INT16_MAX;
}

bool
_is_32bit(int64_t imm)
{
    return imm >= INT32_MIN && imm <= INT32_MAX;
}

bool
_is_valid_call_type(int64_t imm)
{
    return imm == 0 || imm == 1;
}

bool
_is_valid_atomic_alu_op(int64_t imm)
{
    switch (imm) {
    case EBPF_ALU_OP_ADD:
    case EBPF_ALU_OP_OR:
    case EBPF_ALU_OP_AND:
    case EBPF_ALU_OP_XOR:
    case EBPF_ALU_OP_ADD | EBPF_ATOMIC_OP_FETCH:
    case EBPF_ALU_OP_OR | EBPF_ATOMIC_OP_FETCH:
    case EBPF_ALU_OP_AND | EBPF_ATOMIC_OP_FETCH:
    case EBPF_ALU_OP_XOR | EBPF_ATOMIC_OP_FETCH:
        return true;
    case EBPF_ATOMIC_OP_XCHG:
    case EBPF_ATOMIC_OP_CMPXCHG:
        return true;
    default:
        return false;
    }
}

/**
 * @brief Array of valid eBPF instructions and their fields.
 */
static ubpf_inst_filter_t _ubpf_instruction_filter[] = {
    {
        .opcode = 0, // Second half of a LDDW instruction.
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_ADD_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_ADD_REG,
        .destination = _is_r0_through_r9,
        .source = _is_r0_through_r9,
    },
    {
        .opcode = EBPF_OP_SUB_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_SUB_REG,
        .destination = _is_r0_through_r9,
        .source = _is_r0_through_r9,
    },
    {
        .opcode = EBPF_OP_MUL_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_MUL_REG,
        .destination = _is_r0_through_r9,
        .source = _is_r0_through_r9,
    },
    {
        .opcode = EBPF_OP_DIV_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_DIV_REG,
        .destination = _is_r0_through_r9,
        .source = _is_r0_through_r9,
    },
    {
        .opcode = EBPF_OP_OR_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_OR_REG,
        .destination = _is_r0_through_r9,
        .source = _is_r0_through_r9,
    },
    {
        .opcode = EBPF_OP_AND_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_AND_REG,
        .destination = _is_r0_through_r9,
        .source = _is_r0_through_r9,
    },
    {
        .opcode = EBPF_OP_LSH_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_LSH_REG,
        .destination = _is_r0_through_r9,
        .source = _is_r0_through_r9,
    },
    {
        .opcode = EBPF_OP_RSH_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_RSH_REG,
        .destination = _is_r0_through_r9,
        .source = _is_r0_through_r9,
    },
    {
        .opcode = EBPF_OP_NEG,
        .destination = _is_r0_through_r9,
    },
    {
        .opcode = EBPF_OP_MOD_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_MOD_REG,
        .destination = _is_r0_through_r9,
        .source = _is_r0_through_r9,
    },
    {
        .opcode = EBPF_OP_XOR_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_XOR_REG,
        .destination = _is_r0_through_r9,
        .source = _is_r0_through_r9,
    },
    {
        .opcode = EBPF_OP_MOV_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_MOV_REG,
        .destination = _is_r0_through_r9,
        .source = _is_r0_through_r9,
    },
    {
        .opcode = EBPF_OP_ARSH_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_ARSH_REG,
        .destination = _is_r0_through_r9,
        .source = _is_r0_through_r9,
    },
    {
        .opcode = EBPF_OP_LE,
        .destination = _is_r0_through_r9,
        .immediate = _is_integer_width,
    },
    {
        .opcode = EBPF_OP_BE,
        .destination = _is_r0_through_r9,
        .immediate = _is_integer_width,
    },
    {
        .opcode = EBPF_OP_ADD64_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_ADD64_REG,
        .destination = _is_r0_through_r9,
        .source = _is_r0_through_r9,
    },
    {
        .opcode = EBPF_OP_SUB64_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_SUB64_REG,
        .destination = _is_r0_through_r9,
        .source = _is_r0_through_r9,
    },
    {
        .opcode = EBPF_OP_MUL64_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_MUL64_REG,
        .destination = _is_r0_through_r9,
        .source = _is_r0_through_r9,
    },
    {
        .opcode = EBPF_OP_DIV64_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_DIV64_REG,
        .destination = _is_r0_through_r9,
        .source = _is_r0_through_r9,
    },
    {
        .opcode = EBPF_OP_OR64_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_OR64_REG,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_AND64_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_AND64_REG,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_LSH64_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_LSH64_REG,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_RSH64_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_RSH64_REG,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_NEG64,
        .destination = _is_r0_through_r9,
    },
    {
        .opcode = EBPF_OP_MOD64_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_MOD64_REG,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_XOR64_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_XOR64_REG,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_MOV64_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_MOV64_REG,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_ARSH64_IMM,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_ARSH64_REG,
        .destination = _is_r0_through_r9,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_LDXW,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_LDXH,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_LDXB,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_LDXDW,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_STW,
        .destination = _is_r0_through_r10,
        .offset = _is_16bit,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_STH,
        .destination = _is_r0_through_r10,
        .offset = _is_16bit,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_STB,
        .destination = _is_r0_through_r10,
        .offset = _is_16bit,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_STDW,
        .destination = _is_r0_through_r10,
        .offset = _is_16bit,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_STXW,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_STXH,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_STXB,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_STXDW,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_LDDW,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_JA,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JEQ_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JEQ_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JGT_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JGT_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JGE_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JGE_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JSET_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JSET_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JNE_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JNE_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JSGT_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JSGT_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JSGE_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JSGE_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_CALL,
        .source = _is_valid_call_type,
        .immediate = _is_32bit,
    },
    {
        .opcode = EBPF_OP_EXIT,
    },
    {
        .opcode = EBPF_OP_JLT_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JLT_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JLE_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JLE_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JSLT_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JSLT_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JSLE_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JSLE_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JEQ32_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JEQ32_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JGT32_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JGT32_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JGE32_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JGE32_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JSET32_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JSET32_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JNE32_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JNE32_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JSGT32_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JSGT32_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JSGE32_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JSGE32_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JLT32_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JLT32_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JLE32_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JLE32_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JSLT32_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JSLT32_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JSLE32_IMM,
        .destination = _is_r0_through_r10,
        .immediate = _is_32bit,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_JSLE32_REG,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_ATOMIC32_STORE,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .immediate = _is_valid_atomic_alu_op,
        .offset = _is_16bit,
    },
    {
        .opcode = EBPF_OP_ATOMIC_STORE,
        .destination = _is_r0_through_r10,
        .source = _is_r0_through_r10,
        .offset = _is_16bit,
    },
};

static ubpf_inst_filter_t* _ubpf_filter_instruction_lookup_table[256];

/**
 * @brief Initialize the lookup table for the instruction filter.
 */
static void
_initialize_lookup_table()
{
    static bool _initialized = false;

    if (_initialized) {
        return;
    }

    for (size_t i = 0; i < sizeof(_ubpf_instruction_filter) / sizeof(_ubpf_instruction_filter[0]); i++) {
        _ubpf_filter_instruction_lookup_table[_ubpf_instruction_filter[i].opcode] = &_ubpf_instruction_filter[i];
    }

    _initialized = true;
}

bool
ubpf_is_valid_instruction(const struct ebpf_inst inst, char** errmsg)
{
    _initialize_lookup_table();

    // Lookup the instruction.
    ubpf_inst_filter_t* filter = _ubpf_filter_instruction_lookup_table[inst.opcode];

    if (filter == NULL) {
        *errmsg = ubpf_error("Invalid instruction opcode %2X.", inst.opcode);
        return false;
    }

    // Validate the source register.
    if (inst.src != 0 && filter->source != NULL && !filter->source(inst.src)) {
        *errmsg = ubpf_error("Invalid source register %d for instruction %2X.", inst.src, inst.opcode);
        return false;
    }

    // Validate the destination register.
    if (inst.dst != 0 && filter->destination != NULL && !filter->destination(inst.dst)) {
        *errmsg = ubpf_error("Invalid destination register %d for instruction %2X.", inst.dst, inst.opcode);
        return false;
    }

    // Validate the offset.
    if (inst.offset != 0 && filter->offset != NULL && !filter->offset(inst.offset)) {
        *errmsg = ubpf_error("Invalid offset %d for instruction %2X.", inst.offset, inst.opcode);
        return false;
    }

    // Validate the immediate value.
    if (inst.imm != 0 && filter->immediate != NULL && !filter->immediate(inst.imm)) {
        *errmsg = ubpf_error("Invalid immediate value %d for instruction %2X.", inst.imm, inst.opcode);
        return false;
    }

    return true;
}
