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
#include <assert.h>
#include "ubpf_int.h"
#include "ubpf_jit_x86_64.h"

#if !defined(_countof)
#define _countof(array) (sizeof(array) / sizeof(array[0]))
#endif

static void
muldivmod(struct jit_state* state, uint8_t opcode, int src, int dst, int32_t imm);

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
emit_local_call(struct ubpf_vm* vm, struct jit_state* state, uint32_t target_pc)
{
    UNUSED_PARAMETER(vm);
    // Because the top of the stack holds the stack usage of the calling function,
    // we adjust the base pointer down by that value!
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
    emit_local_call_address_reloc(state, target_pc);

#if defined(_WIN32)
    /* Deallocate home register space - 4 registers */
    emit_alu64_imm32(state, 0x81, 0, RSP, 4 * sizeof(uint64_t));
#endif
    emit_pop(state, map_register(BPF_REG_9));
    emit_pop(state, map_register(BPF_REG_8));
    emit_pop(state, map_register(BPF_REG_7));
    emit_pop(state, map_register(BPF_REG_6));

    // Because the top of the stack holds the stack usage of the calling function,
    // we adjust the base pointer back up by that value!
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
    uint32_t label1_call_offset = emit_call(state, 0);

    /* capture_ret_spec: */
    /* pause */
    uint32_t capture_ret_spec = state->offset;
    emit_pause(state);
    /* jmp  capture_ret_spec */
    emit_jmp(state, capture_ret_spec);

    /* label1: */
    /* mov rax, (rsp) */
    uint32_t label1 = state->offset;
    emit1(state, 0x48);
    emit1(state, 0x89);
    emit1(state, 0x04); // Mod: 00b Reg: 000b RM: 100b
    emit1(state, 0x24); // Scale: 00b Index: 100b Base: 100b

    /* ret */
    emit_ret(state);

    fixup_jump_target(state->jumps, state->num_jumps, label1_call_offset, label1);

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
 * The layout and operation of this mechanism is identical for code JIT compiled for Arm.
 */

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
    emit_jmp(state, TARGET_PC_EXIT);

    for (i = 0; i < vm->num_insts; i++) {
        if (state->jit_status != NoError) {
            break;
        }

        struct ebpf_inst inst = ubpf_fetch_instruction(vm, i);

        int dst = map_register(inst.dst);
        int src = map_register(inst.src);
        uint32_t target_pc = i + inst.offset + 1;

        if (i == 0 || vm->int_funcs[i]) {
            size_t prolog_start = state->offset;
            uint16_t stack_usage = ubpf_stack_usage_for_local_func(vm, i);
            emit_alu64_imm32(state, 0x81, 5, RSP, 8);
            emit1(state, 0x48);
            emit1(state, 0xC7);
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

        state->pc_locs[i] = state->offset;

        switch (inst.opcode) {
        case EBPF_OP_ADD_IMM:
            emit_alu32_imm32(state, 0x81, 0, dst, inst.imm);
            break;
        case EBPF_OP_ADD_REG:
            emit_alu32(state, 0x01, src, dst);
            break;
        case EBPF_OP_SUB_IMM:
            emit_alu32_imm32(state, 0x81, 5, dst, inst.imm);
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
            muldivmod(state, inst.opcode, src, dst, inst.imm);
            break;
        case EBPF_OP_OR_IMM:
            emit_alu32_imm32(state, 0x81, 1, dst, inst.imm);
            break;
        case EBPF_OP_OR_REG:
            emit_alu32(state, 0x09, src, dst);
            break;
        case EBPF_OP_AND_IMM:
            emit_alu32_imm32(state, 0x81, 4, dst, inst.imm);
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
            emit_alu32_imm32(state, 0x81, 6, dst, inst.imm);
            break;
        case EBPF_OP_XOR_REG:
            emit_alu32(state, 0x31, src, dst);
            break;
        case EBPF_OP_MOV_IMM:
            emit_alu32_imm32(state, 0xc7, 0, dst, inst.imm);
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
            /* No-op */
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

        case EBPF_OP_ADD64_IMM:
            emit_alu64_imm32(state, 0x81, 0, dst, inst.imm);
            break;
        case EBPF_OP_ADD64_REG:
            emit_alu64(state, 0x01, src, dst);
            break;
        case EBPF_OP_SUB64_IMM:
            emit_alu64_imm32(state, 0x81, 5, dst, inst.imm);
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
            muldivmod(state, inst.opcode, src, dst, inst.imm);
            break;
        case EBPF_OP_OR64_IMM:
            emit_alu64_imm32(state, 0x81, 1, dst, inst.imm);
            break;
        case EBPF_OP_OR64_REG:
            emit_alu64(state, 0x09, src, dst);
            break;
        case EBPF_OP_AND64_IMM:
            emit_alu64_imm32(state, 0x81, 4, dst, inst.imm);
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
            emit_alu64_imm32(state, 0x81, 6, dst, inst.imm);
            break;
        case EBPF_OP_XOR64_REG:
            emit_alu64(state, 0x31, src, dst);
            break;
        case EBPF_OP_MOV64_IMM:
            emit_load_imm(state, dst, inst.imm);
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
            emit_jmp(state, target_pc);
            break;
        case EBPF_OP_JEQ_IMM:
            emit_cmp_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x84, target_pc);
            break;
        case EBPF_OP_JEQ_REG:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x84, target_pc);
            break;
        case EBPF_OP_JGT_IMM:
            emit_cmp_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x87, target_pc);
            break;
        case EBPF_OP_JGT_REG:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x87, target_pc);
            break;
        case EBPF_OP_JGE_IMM:
            emit_cmp_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x83, target_pc);
            break;
        case EBPF_OP_JGE_REG:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x83, target_pc);
            break;
        case EBPF_OP_JLT_IMM:
            emit_cmp_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x82, target_pc);
            break;
        case EBPF_OP_JLT_REG:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x82, target_pc);
            break;
        case EBPF_OP_JLE_IMM:
            emit_cmp_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x86, target_pc);
            break;
        case EBPF_OP_JLE_REG:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x86, target_pc);
            break;
        case EBPF_OP_JSET_IMM:
            emit_alu64_imm32(state, 0xf7, 0, dst, inst.imm);
            emit_jcc(state, 0x85, target_pc);
            break;
        case EBPF_OP_JSET_REG:
            emit_alu64(state, 0x85, src, dst);
            emit_jcc(state, 0x85, target_pc);
            break;
        case EBPF_OP_JNE_IMM:
            emit_cmp_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x85, target_pc);
            break;
        case EBPF_OP_JNE_REG:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x85, target_pc);
            break;
        case EBPF_OP_JSGT_IMM:
            emit_cmp_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x8f, target_pc);
            break;
        case EBPF_OP_JSGT_REG:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x8f, target_pc);
            break;
        case EBPF_OP_JSGE_IMM:
            emit_cmp_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x8d, target_pc);
            break;
        case EBPF_OP_JSGE_REG:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x8d, target_pc);
            break;
        case EBPF_OP_JSLT_IMM:
            emit_cmp_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x8c, target_pc);
            break;
        case EBPF_OP_JSLT_REG:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x8c, target_pc);
            break;
        case EBPF_OP_JSLE_IMM:
            emit_cmp_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x8e, target_pc);
            break;
        case EBPF_OP_JSLE_REG:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x8e, target_pc);
            break;
        case EBPF_OP_JEQ32_IMM:
            emit_cmp32_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x84, target_pc);
            break;
        case EBPF_OP_JEQ32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x84, target_pc);
            break;
        case EBPF_OP_JGT32_IMM:
            emit_cmp32_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x87, target_pc);
            break;
        case EBPF_OP_JGT32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x87, target_pc);
            break;
        case EBPF_OP_JGE32_IMM:
            emit_cmp32_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x83, target_pc);
            break;
        case EBPF_OP_JGE32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x83, target_pc);
            break;
        case EBPF_OP_JLT32_IMM:
            emit_cmp32_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x82, target_pc);
            break;
        case EBPF_OP_JLT32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x82, target_pc);
            break;
        case EBPF_OP_JLE32_IMM:
            emit_cmp32_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x86, target_pc);
            break;
        case EBPF_OP_JLE32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x86, target_pc);
            break;
        case EBPF_OP_JSET32_IMM:
            emit_alu32_imm32(state, 0xf7, 0, dst, inst.imm);
            emit_jcc(state, 0x85, target_pc);
            break;
        case EBPF_OP_JSET32_REG:
            emit_alu32(state, 0x85, src, dst);
            emit_jcc(state, 0x85, target_pc);
            break;
        case EBPF_OP_JNE32_IMM:
            emit_cmp32_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x85, target_pc);
            break;
        case EBPF_OP_JNE32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x85, target_pc);
            break;
        case EBPF_OP_JSGT32_IMM:
            emit_cmp32_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x8f, target_pc);
            break;
        case EBPF_OP_JSGT32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x8f, target_pc);
            break;
        case EBPF_OP_JSGE32_IMM:
            emit_cmp32_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x8d, target_pc);
            break;
        case EBPF_OP_JSGE32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x8d, target_pc);
            break;
        case EBPF_OP_JSLT32_IMM:
            emit_cmp32_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x8c, target_pc);
            break;
        case EBPF_OP_JSLT32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x8c, target_pc);
            break;
        case EBPF_OP_JSLE32_IMM:
            emit_cmp32_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x8e, target_pc);
            break;
        case EBPF_OP_JSLE32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x8e, target_pc);
            break;
        case EBPF_OP_CALL:
            /* We reserve RCX for shifts */
            if (inst.src == 0) {
                emit_mov(state, RCX_ALT, RCX);
                emit_dispatched_external_helper_call(state, inst.imm);
                if (inst.imm == vm->unwind_stack_extension_index) {
                    emit_cmp_imm32(state, map_register(BPF_REG_0), 0);
                    emit_jcc(state, 0x84, TARGET_PC_EXIT);
                }
            } else if (inst.src == 1) {
                target_pc = i + inst.imm + 1;
                emit_local_call(vm, state, target_pc);
            }
            break;
        case EBPF_OP_EXIT:
            /* On entry to every local function we add an additional 8 bytes.
             * Undo that here!
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

        case EBPF_OP_STW:
            emit_store_imm32(state, S32, dst, inst.offset, inst.imm);
            break;
        case EBPF_OP_STH:
            emit_store_imm32(state, S16, dst, inst.offset, inst.imm);
            break;
        case EBPF_OP_STB:
            emit_store_imm32(state, S8, dst, inst.offset, inst.imm);
            break;
        case EBPF_OP_STDW:
            emit_store_imm32(state, S64, dst, inst.offset, inst.imm);
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
            emit_load_imm(state, dst, imm);
            break;
        }

        default:
            state->jit_status = UnknownInstruction;
            *errmsg = ubpf_error("Unknown instruction at PC %d: opcode %02x", i, inst.opcode);
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

static void
muldivmod(struct jit_state* state, uint8_t opcode, int src, int dst, int32_t imm)
{
    bool mul = (opcode & EBPF_ALU_OP_MASK) == (EBPF_OP_MUL_IMM & EBPF_ALU_OP_MASK);
    bool div = (opcode & EBPF_ALU_OP_MASK) == (EBPF_OP_DIV_IMM & EBPF_ALU_OP_MASK);
    bool mod = (opcode & EBPF_ALU_OP_MASK) == (EBPF_OP_MOD_IMM & EBPF_ALU_OP_MASK);
    bool is64 = (opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU64;
    bool reg = (opcode & EBPF_SRC_REG) == EBPF_SRC_REG;

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
        emit_load_imm(state, RCX, imm);
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

        /* xor %edx,%edx */
        emit_alu32(state, 0x31, RDX, RDX);
    }

    if (is64) {
        emit_rex(state, 1, 0, 0, 0);
    }

    // Multiply or divide.
    emit_alu32(state, 0xf7, mul ? 4 : 6, RCX);

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

static bool
resolve_patchable_relatives(struct jit_state* state)
{
    int i;
    for (i = 0; i < state->num_jumps; i++) {
        struct patchable_relative jump = state->jumps[i];

        int target_loc;
        if (jump.target_offset != 0) {
            target_loc = jump.target_offset;
        } else if (jump.target_pc == TARGET_PC_EXIT) {
            target_loc = state->exit_loc;
        } else if (jump.target_pc == TARGET_PC_RETPOLINE) {
            target_loc = state->retpoline_loc;
        } else {
            target_loc = state->pc_locs[jump.target_pc];
        }

        /* Assumes jump offset is at end of instruction */
        uint32_t rel = target_loc - (jump.offset_loc + sizeof(uint32_t));

        uint8_t* offset_ptr = &state->buf[jump.offset_loc];
        memcpy(offset_ptr, &rel, sizeof(uint32_t));
    }

    for (i = 0; i < state->num_local_calls; i++) {
        struct patchable_relative local_call = state->local_calls[i];

        int target_loc;
        assert(local_call.target_offset == 0);
        assert(local_call.target_pc != TARGET_PC_EXIT);
        assert(local_call.target_pc != TARGET_PC_RETPOLINE);

        target_loc = state->pc_locs[local_call.target_pc];

        /* Assumes call offset is at end of instruction */
        uint32_t rel = target_loc - (local_call.offset_loc + sizeof(uint32_t));
        rel -= state->bpf_function_prolog_size; // For the prolog inserted at the start of every local call.

        uint8_t* offset_ptr = &state->buf[local_call.offset_loc];
        memcpy(offset_ptr, &rel, sizeof(uint32_t));
    }

    for (i = 0; i < state->num_loads; i++) {
        struct patchable_relative load = state->loads[i];

        int target_loc;
        // It is only possible to load from the external dispatcher's position.
        if (load.target_pc == TARGET_PC_EXTERNAL_DISPATCHER) {
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
        if (lea.target_pc == TARGET_LOAD_HELPER_TABLE) {
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

    if (initialize_jit_state_result(&state, &compile_result, buffer, *size, jit_mode, &compile_result.errmsg) < 0) {
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
    struct ubpf_vm* vm, ext_func new_helper, unsigned int idx, uint8_t* buffer, size_t size, uint32_t offset)
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
