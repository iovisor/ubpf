// Copyright (c) 2015 Big Switch Networks, Inc
// SPDX-License-Identifier: Apache-2.0

#include "ubpf_int.h"

// This file contains the list of all valid eBPF instructions and the fields that are valid for each instruction.

/**
 * @brief Structure to filter valid fields for each eBPF instruction.
 * Default values are all zeros, which means the field is reserved and must be zero.
 */
typedef struct _ubpf_inst_filter
{
    uint8_t opcode;                       ///< The opcode of the instruction.
    uint8_t source_lower_bound;           ///< The lower bound of the source register.
    uint8_t source_upper_bound;           ///< The upper bound of the source register.
    uint8_t destination_lower_bound;      ///< The lower bound of the destination register.
    uint8_t destination_upper_bound;      ///< The upper bound of the destination register.
    int16_t offset_lower_bound;           ///< The lower bound of the offset.
    int16_t offset_upper_bound;           ///< The upper bound of the offset.
    int32_t immediate_lower_bound;        ///< The lower bound of the immediate value.
    int32_t immediate_upper_bound;        ///< The upper bound of the immediate value.
    int32_t* immediate_enumerated;        ///< A specific enumeration of the valid immediate values.
    uint32_t immediate_enumerated_length; ///< The number of valid enumerated immediate values.
} ubpf_inst_filter_t;

static int32_t ebpf_atomic_store_immediate_enumerated[] = {
    EBPF_ALU_OP_ADD,
    EBPF_ALU_OP_ADD | EBPF_ATOMIC_OP_FETCH,
    EBPF_ALU_OP_OR,
    EBPF_ALU_OP_OR | EBPF_ATOMIC_OP_FETCH,
    EBPF_ALU_OP_AND,
    EBPF_ALU_OP_AND | EBPF_ATOMIC_OP_FETCH,
    EBPF_ALU_OP_XOR,
    EBPF_ALU_OP_XOR | EBPF_ATOMIC_OP_FETCH,
    EBPF_ATOMIC_OP_XCHG | EBPF_ATOMIC_OP_FETCH,
    EBPF_ATOMIC_OP_CMPXCHG | EBPF_ATOMIC_OP_FETCH};

/**
 * @brief Array of valid eBPF instructions and their fields.
 */
static ubpf_inst_filter_t _ubpf_instruction_filter[] = {
    {
        .opcode = 0, // Second half of a LDDW instruction.
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_ADD_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_ADD_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_SUB_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_SUB_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_MUL_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_MUL_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_DIV_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_DIV_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_OR_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_OR_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_AND_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_AND_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_LSH_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_LSH_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_RSH_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_RSH_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_NEG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
    },
    {
        .opcode = EBPF_OP_MOD_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_MOD_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_XOR_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_XOR_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_MOV_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_MOV_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_ARSH_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_ARSH_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_LE,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        // specific valid values for the immediate field are checked in validate.
        .immediate_lower_bound = 0,
        .immediate_upper_bound = 64,
    },
    {
        .opcode = EBPF_OP_BE,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        // specific valid values for the immediate field are checked in validate.
        .immediate_lower_bound = 0,
        .immediate_upper_bound = 64,
    },
    {
        .opcode = EBPF_OP_ADD64_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_ADD64_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_SUB64_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_SUB64_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_MUL64_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_MUL64_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_DIV64_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_DIV64_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_OR64_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_OR64_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_AND64_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_AND64_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_LSH64_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_LSH64_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_RSH64_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_RSH64_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_NEG64,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
    },
    {
        .opcode = EBPF_OP_MOD64_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_MOD64_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_XOR64_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_XOR64_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_MOV64_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_MOV64_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_ARSH64_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_ARSH64_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_9,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
    },
    {
        .opcode = EBPF_OP_LDXW,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_LDXH,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_LDXB,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_LDXDW,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_LDXWSX,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_LDXHSX,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_LDXBSX,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_STW,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_STH,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_STB,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_STDW,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_STXW,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_STXH,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_STXB,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_STXDW,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_LDDW,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        // specific valid source values are checked in validate.
        .source_lower_bound = 0,
        .source_upper_bound = 6,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_JA,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JEQ_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JEQ_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JGT_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JGT_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JGE_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JGE_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JSET_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JSET_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JNE_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JNE_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JSGT_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JSGT_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JSGE_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JSGE_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_CALL,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_1, // Only supports up to local calls aka 1.
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
    },
    {
        .opcode = EBPF_OP_EXIT,
    },
    {
        .opcode = EBPF_OP_JLT_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JLT_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JLE_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JLE_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JSLT_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JSLT_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JSLE_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JSLE_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JEQ32_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JEQ32_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JGT32_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JGT32_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JGE32_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JGE32_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JSET32_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JSET32_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JNE32_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JNE32_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JSGT32_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JSGT32_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JSGE32_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JSGE32_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JLT32_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JLT32_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JLE32_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JLE32_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JSLT32_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JSLT32_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JSLE32_IMM,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .immediate_lower_bound = INT32_MIN,
        .immediate_upper_bound = INT32_MAX,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_JSLE32_REG,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_ATOMIC32_STORE,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .immediate_lower_bound = 0x0,
        .immediate_upper_bound = 0xff,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
    {
        .opcode = EBPF_OP_ATOMIC_STORE,
        .destination_lower_bound = BPF_REG_0,
        .destination_upper_bound = BPF_REG_10,
        .source_lower_bound = BPF_REG_0,
        .source_upper_bound = BPF_REG_10,
        .immediate_enumerated = ebpf_atomic_store_immediate_enumerated,
        .immediate_enumerated_length = 10,
        .offset_lower_bound = INT16_MIN,
        .offset_upper_bound = INT16_MAX,
    },
};

static ubpf_inst_filter_t* _ubpf_filter_instruction_lookup_table[256];

/**
 * @brief Initialize the lookup table for the instruction filter.
 */
static void _initialize_lookup_table()
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


static bool _in_range(int32_t value, int32_t lower_bound, int32_t upper_bound)
{
    return value >= lower_bound && value <= upper_bound;
}

bool
ubpf_is_valid_instruction(const struct ebpf_inst insts, char ** errmsg)
{
    _initialize_lookup_table();

    // Lookup the instruction.
    ubpf_inst_filter_t* filter = _ubpf_filter_instruction_lookup_table[insts.opcode];

    if (filter == NULL) {
        *errmsg = ubpf_error("Invalid instruction opcode %2X.", insts.opcode);
        return false;
    }

    // Validate the instruction.

    // Validate destination register.
    if (!_in_range(insts.dst, filter->destination_lower_bound, filter->destination_upper_bound)) {
        *errmsg = ubpf_error("Invalid destination register %d for opcode %2X.", insts.dst, insts.opcode);
        return false;
    }

    // Validate source register.
    if (!_in_range(insts.src, filter->source_lower_bound, filter->source_upper_bound)) {
        *errmsg = ubpf_error("Invalid source register %d for opcode %2X.", insts.src, insts.opcode);
        return false;
    }

    // Validate immediate values in the presence of enumerated values.
    if (filter->immediate_enumerated != NULL) {
        bool valid = false;
        for (int i = 0; i < filter->immediate_enumerated_length; i++) {
            if (filter->immediate_enumerated[i] == insts.imm) {
                valid = true;
                break;
            }
        }
        if (!valid) {
            *errmsg = ubpf_error("Invalid immediate value %d for opcode %2X.", insts.imm, insts.opcode);
            return false;
        }
    } else {
        // Validate immediate value.
        if (!_in_range(insts.imm, filter->immediate_lower_bound, filter->immediate_upper_bound)) {
            *errmsg = ubpf_error("Invalid immediate value %d for opcode %2X.", insts.imm, insts.opcode);
            return false;
        }
    }

    // Validate offset value.
    if (!_in_range(insts.offset, filter->offset_lower_bound, filter->offset_upper_bound)) {
        *errmsg = ubpf_error("Invalid offset value %d for opcode %2X.", insts.offset, insts.opcode);
        return false;
    }

    return true;
}
