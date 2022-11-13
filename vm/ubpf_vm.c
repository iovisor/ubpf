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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <endian.h>
#include "ubpf_int.h"
#include <unistd.h>

#define MAX_EXT_FUNCS 64

static bool
validate(const struct ubpf_vm* vm, const struct ebpf_inst* insts, uint32_t num_insts, char** errmsg);
static bool
bounds_check(
    const struct ubpf_vm* vm,
    void* addr,
    int size,
    const char* type,
    uint16_t cur_pc,
    void* mem,
    size_t mem_len,
    void* stack);

bool
ubpf_toggle_bounds_check(struct ubpf_vm* vm, bool enable)
{
    bool old = vm->bounds_check_enabled;
    vm->bounds_check_enabled = enable;
    return old;
}

void
ubpf_set_error_print(struct ubpf_vm* vm, int (*error_printf)(FILE* stream, const char* format, ...))
{
    if (error_printf)
        vm->error_printf = error_printf;
    else
        vm->error_printf = fprintf;
}

struct ubpf_vm*
ubpf_create(void)
{
    struct ubpf_vm* vm = calloc(1, sizeof(*vm));
    if (vm == NULL) {
        return NULL;
    }

    vm->ext_funcs = calloc(MAX_EXT_FUNCS, sizeof(*vm->ext_funcs));
    if (vm->ext_funcs == NULL) {
        ubpf_destroy(vm);
        return NULL;
    }

    vm->ext_func_names = calloc(MAX_EXT_FUNCS, sizeof(*vm->ext_func_names));
    if (vm->ext_func_names == NULL) {
        ubpf_destroy(vm);
        return NULL;
    }

    vm->bounds_check_enabled = true;
    vm->error_printf = fprintf;

#if defined(__x86_64__) || defined(_M_X64)
    vm->translate = ubpf_translate_x86_64;
#elif defined(__aarch64__) || defined(_M_ARM64)
    vm->translate = ubpf_translate_arm64;
#else
    vm->translate = ubpf_translate_null;
#endif
    vm->unwind_stack_extension_index = -1;
    return vm;
}

void
ubpf_destroy(struct ubpf_vm* vm)
{
    ubpf_unload_code(vm);
    free(vm->ext_funcs);
    free(vm->ext_func_names);
    free(vm);
}

int
ubpf_register(struct ubpf_vm* vm, unsigned int idx, const char* name, void* fn)
{
    if (idx >= MAX_EXT_FUNCS) {
        return -1;
    }

    vm->ext_funcs[idx] = (ext_func)fn;
    vm->ext_func_names[idx] = name;

    return 0;
}

int
ubpf_set_unwind_function_index(struct ubpf_vm* vm, unsigned int idx)
{
    if (vm->unwind_stack_extension_index != -1) {
        return -1;
    }

    vm->unwind_stack_extension_index = idx;
    return 0;
}

unsigned int
ubpf_lookup_registered_function(struct ubpf_vm* vm, const char* name)
{
    int i;
    for (i = 0; i < MAX_EXT_FUNCS; i++) {
        const char* other = vm->ext_func_names[i];
        if (other && !strcmp(other, name)) {
            return i;
        }
    }
    return -1;
}

int
ubpf_load(struct ubpf_vm* vm, const void* code, uint32_t code_len, char** errmsg)
{
    const struct ebpf_inst* source_inst = code;
    *errmsg = NULL;

    if (vm->insts) {
        *errmsg = ubpf_error(
            "code has already been loaded into this VM. Use ubpf_unload_code() if you need to reuse this VM");
        return -1;
    }

    if (code_len % 8 != 0) {
        *errmsg = ubpf_error("code_len must be a multiple of 8");
        return -1;
    }

    if (!validate(vm, code, code_len / 8, errmsg)) {
        return -1;
    }

    vm->insts = malloc(code_len);
    if (vm->insts == NULL) {
        *errmsg = ubpf_error("out of memory");
        return -1;
    }

    vm->num_insts = code_len / sizeof(vm->insts[0]);

    // Store instructions in the vm.
    for (uint32_t i = 0; i < vm->num_insts; i++) {
        ubpf_store_instruction(vm, i, source_inst[i]);
    }

    return 0;
}

void
ubpf_unload_code(struct ubpf_vm* vm)
{
    if (vm->jitted) {
        munmap(vm->jitted, vm->jitted_size);
        vm->jitted = NULL;
        vm->jitted_size = 0;
    }
    if (vm->insts) {
        free(vm->insts);
        vm->insts = NULL;
        vm->num_insts = 0;
    }
}

static uint32_t
u32(uint64_t x)
{
    return x;
}

static int32_t
i32(uint64_t x)
{
    return x;
}

#define IS_ALIGNED(x, a) (((uintptr_t)(x) & ((a)-1)) == 0)

inline static uint64_t
ubpf_mem_load(uint64_t address, size_t size)
{
    if (!IS_ALIGNED(address, size)) {
        // Fill the result with 0 to avoid leaking uninitialized memory.
        uint64_t value = 0;
        memcpy(&value, (void*)address, size);
        return value;
    }

    switch (size) {
    case 1:
        return *(uint8_t*)address;
    case 2:
        return *(uint16_t*)address;
    case 4:
        return *(uint32_t*)address;
    case 8:
        return *(uint64_t*)address;
    default:
        abort();
    }
}

inline static void
ubpf_mem_store(uint64_t address, uint64_t value, size_t size)
{
    if (!IS_ALIGNED(address, size)) {
        memcpy((void*)address, &value, size);
        return;
    }

    switch (size) {
    case 1:
        *(uint8_t*)address = value;
        break;
    case 2:
        *(uint16_t*)address = value;
        break;
    case 4:
        *(uint32_t*)address = value;
        break;
    case 8:
        *(uint64_t*)address = value;
        break;
    default:
        abort();
    }
}

int
ubpf_exec(const struct ubpf_vm* vm, void* mem, size_t mem_len, uint64_t* bpf_return_value)
{
    uint16_t pc = 0;
    const struct ebpf_inst* insts = vm->insts;
    uint64_t* reg;
    uint64_t _reg[16];
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];

    if (!insts) {
        /* Code must be loaded before we can execute */
        return -1;
    }

#ifdef DEBUG
    if (vm->regs)
        reg = vm->regs;
    else
        reg = _reg;
#else
    reg = _reg;
#endif

    reg[1] = (uintptr_t)mem;
    reg[2] = (uint64_t)mem_len;
    reg[10] = (uintptr_t)stack + sizeof(stack);

    while (1) {
        const uint16_t cur_pc = pc;
        struct ebpf_inst inst = ubpf_fetch_instruction(vm, pc++);

        switch (inst.opcode) {
        case EBPF_OP_ADD_IMM:
            reg[inst.dst] += inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_ADD_REG:
            reg[inst.dst] += reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_SUB_IMM:
            reg[inst.dst] -= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_SUB_REG:
            reg[inst.dst] -= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MUL_IMM:
            reg[inst.dst] *= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MUL_REG:
            reg[inst.dst] *= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_DIV_IMM:
            reg[inst.dst] = u32(inst.imm) ? u32(reg[inst.dst]) / u32(inst.imm) : 0;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_DIV_REG:
            reg[inst.dst] = reg[inst.src] ? u32(reg[inst.dst]) / u32(reg[inst.src]) : 0;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_OR_IMM:
            reg[inst.dst] |= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_OR_REG:
            reg[inst.dst] |= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_AND_IMM:
            reg[inst.dst] &= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_AND_REG:
            reg[inst.dst] &= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_LSH_IMM:
            reg[inst.dst] <<= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_LSH_REG:
            reg[inst.dst] <<= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_RSH_IMM:
            reg[inst.dst] = u32(reg[inst.dst]) >> inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_RSH_REG:
            reg[inst.dst] = u32(reg[inst.dst]) >> reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_NEG:
            reg[inst.dst] = -(int64_t)reg[inst.dst];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOD_IMM:
            reg[inst.dst] = u32(inst.imm) ? u32(reg[inst.dst]) % u32(inst.imm) : u32(reg[inst.dst]);
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOD_REG:
            reg[inst.dst] = u32(reg[inst.src]) ? u32(reg[inst.dst]) % u32(reg[inst.src]) : u32(reg[inst.dst]);
            break;
        case EBPF_OP_XOR_IMM:
            reg[inst.dst] ^= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_XOR_REG:
            reg[inst.dst] ^= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOV_IMM:
            reg[inst.dst] = inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOV_REG:
            reg[inst.dst] = reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_ARSH_IMM:
            reg[inst.dst] = (int32_t)reg[inst.dst] >> inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_ARSH_REG:
            reg[inst.dst] = (int32_t)reg[inst.dst] >> u32(reg[inst.src]);
            reg[inst.dst] &= UINT32_MAX;
            break;

        case EBPF_OP_LE:
            if (inst.imm == 16) {
                reg[inst.dst] = htole16(reg[inst.dst]);
            } else if (inst.imm == 32) {
                reg[inst.dst] = htole32(reg[inst.dst]);
            } else if (inst.imm == 64) {
                reg[inst.dst] = htole64(reg[inst.dst]);
            }
            break;
        case EBPF_OP_BE:
            if (inst.imm == 16) {
                reg[inst.dst] = htobe16(reg[inst.dst]);
            } else if (inst.imm == 32) {
                reg[inst.dst] = htobe32(reg[inst.dst]);
            } else if (inst.imm == 64) {
                reg[inst.dst] = htobe64(reg[inst.dst]);
            }
            break;

        case EBPF_OP_ADD64_IMM:
            reg[inst.dst] += inst.imm;
            break;
        case EBPF_OP_ADD64_REG:
            reg[inst.dst] += reg[inst.src];
            break;
        case EBPF_OP_SUB64_IMM:
            reg[inst.dst] -= inst.imm;
            break;
        case EBPF_OP_SUB64_REG:
            reg[inst.dst] -= reg[inst.src];
            break;
        case EBPF_OP_MUL64_IMM:
            reg[inst.dst] *= inst.imm;
            break;
        case EBPF_OP_MUL64_REG:
            reg[inst.dst] *= reg[inst.src];
            break;
        case EBPF_OP_DIV64_IMM:
            reg[inst.dst] = inst.imm ? reg[inst.dst] / inst.imm : 0;
            break;
        case EBPF_OP_DIV64_REG:
            reg[inst.dst] = reg[inst.src] ? reg[inst.dst] / reg[inst.src] : 0;
            break;
        case EBPF_OP_OR64_IMM:
            reg[inst.dst] |= inst.imm;
            break;
        case EBPF_OP_OR64_REG:
            reg[inst.dst] |= reg[inst.src];
            break;
        case EBPF_OP_AND64_IMM:
            reg[inst.dst] &= inst.imm;
            break;
        case EBPF_OP_AND64_REG:
            reg[inst.dst] &= reg[inst.src];
            break;
        case EBPF_OP_LSH64_IMM:
            reg[inst.dst] <<= inst.imm;
            break;
        case EBPF_OP_LSH64_REG:
            reg[inst.dst] <<= reg[inst.src];
            break;
        case EBPF_OP_RSH64_IMM:
            reg[inst.dst] >>= inst.imm;
            break;
        case EBPF_OP_RSH64_REG:
            reg[inst.dst] >>= reg[inst.src];
            break;
        case EBPF_OP_NEG64:
            reg[inst.dst] = -reg[inst.dst];
            break;
        case EBPF_OP_MOD64_IMM:
            reg[inst.dst] = inst.imm ? reg[inst.dst] % inst.imm : reg[inst.dst];
            break;
        case EBPF_OP_MOD64_REG:
            reg[inst.dst] = reg[inst.src] ? reg[inst.dst] % reg[inst.src] : reg[inst.dst];
            break;
        case EBPF_OP_XOR64_IMM:
            reg[inst.dst] ^= inst.imm;
            break;
        case EBPF_OP_XOR64_REG:
            reg[inst.dst] ^= reg[inst.src];
            break;
        case EBPF_OP_MOV64_IMM:
            reg[inst.dst] = inst.imm;
            break;
        case EBPF_OP_MOV64_REG:
            reg[inst.dst] = reg[inst.src];
            break;
        case EBPF_OP_ARSH64_IMM:
            reg[inst.dst] = (int64_t)reg[inst.dst] >> inst.imm;
            break;
        case EBPF_OP_ARSH64_REG:
            reg[inst.dst] = (int64_t)reg[inst.dst] >> reg[inst.src];
            break;

            /*
             * HACK runtime bounds check
             *
             * Needed since we don't have a verifier yet.
             */
#define BOUNDS_CHECK_LOAD(size)                                                                                 \
    do {                                                                                                        \
        if (!bounds_check(vm, (char*)reg[inst.src] + inst.offset, size, "load", cur_pc, mem, mem_len, stack)) { \
            return -1;                                                                                          \
        }                                                                                                       \
    } while (0)
#define BOUNDS_CHECK_STORE(size)                                                                                 \
    do {                                                                                                         \
        if (!bounds_check(vm, (char*)reg[inst.dst] + inst.offset, size, "store", cur_pc, mem, mem_len, stack)) { \
            return -1;                                                                                           \
        }                                                                                                        \
    } while (0)

        case EBPF_OP_LDXW:
            BOUNDS_CHECK_LOAD(4);
            reg[inst.dst] = ubpf_mem_load(reg[inst.src] + inst.offset, 4);
            break;
        case EBPF_OP_LDXH:
            BOUNDS_CHECK_LOAD(2);
            reg[inst.dst] = ubpf_mem_load(reg[inst.src] + inst.offset, 2);
            break;
        case EBPF_OP_LDXB:
            BOUNDS_CHECK_LOAD(1);
            reg[inst.dst] = ubpf_mem_load(reg[inst.src] + inst.offset, 1);
            break;
        case EBPF_OP_LDXDW:
            BOUNDS_CHECK_LOAD(8);
            reg[inst.dst] = ubpf_mem_load(reg[inst.src] + inst.offset, 8);
            break;

        case EBPF_OP_STW:
            BOUNDS_CHECK_STORE(4);
            ubpf_mem_store(reg[inst.dst] + inst.offset, inst.imm, 4);
            break;
        case EBPF_OP_STH:
            BOUNDS_CHECK_STORE(2);
            ubpf_mem_store(reg[inst.dst] + inst.offset, inst.imm, 2);
            break;
        case EBPF_OP_STB:
            BOUNDS_CHECK_STORE(1);
            ubpf_mem_store(reg[inst.dst] + inst.offset, inst.imm, 1);
            break;
        case EBPF_OP_STDW:
            BOUNDS_CHECK_STORE(8);
            ubpf_mem_store(reg[inst.dst] + inst.offset, inst.imm, 8);
            break;

        case EBPF_OP_STXW:
            BOUNDS_CHECK_STORE(4);
            ubpf_mem_store(reg[inst.dst] + inst.offset, reg[inst.src], 4);
            break;
        case EBPF_OP_STXH:
            BOUNDS_CHECK_STORE(2);
            ubpf_mem_store(reg[inst.dst] + inst.offset, reg[inst.src], 2);
            break;
        case EBPF_OP_STXB:
            BOUNDS_CHECK_STORE(1);
            ubpf_mem_store(reg[inst.dst] + inst.offset, reg[inst.src], 1);
            break;
        case EBPF_OP_STXDW:
            BOUNDS_CHECK_STORE(8);
            ubpf_mem_store(reg[inst.dst] + inst.offset, reg[inst.src], 8);
            break;

        case EBPF_OP_LDDW:
            reg[inst.dst] = u32(inst.imm) | ((uint64_t)ubpf_fetch_instruction(vm, pc++).imm << 32);
            break;

        case EBPF_OP_JA:
            pc += inst.offset;
            break;
        case EBPF_OP_JEQ_IMM:
            if (reg[inst.dst] == inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JEQ_REG:
            if (reg[inst.dst] == reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JEQ32_IMM:
            if (u32(reg[inst.dst]) == u32(inst.imm)) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JEQ32_REG:
            if (u32(reg[inst.dst]) == reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGT_IMM:
            if (reg[inst.dst] > u32(inst.imm)) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGT_REG:
            if (reg[inst.dst] > reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGT32_IMM:
            if (u32(reg[inst.dst]) > u32(inst.imm)) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGT32_REG:
            if (u32(reg[inst.dst]) > u32(reg[inst.src])) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGE_IMM:
            if (reg[inst.dst] >= u32(inst.imm)) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGE_REG:
            if (reg[inst.dst] >= reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGE32_IMM:
            if (u32(reg[inst.dst]) >= u32(inst.imm)) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGE32_REG:
            if (u32(reg[inst.dst]) >= u32(reg[inst.src])) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLT_IMM:
            if (reg[inst.dst] < u32(inst.imm)) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLT_REG:
            if (reg[inst.dst] < reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLT32_IMM:
            if (u32(reg[inst.dst]) < u32(inst.imm)) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLT32_REG:
            if (u32(reg[inst.dst]) < u32(reg[inst.src])) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLE_IMM:
            if (reg[inst.dst] <= u32(inst.imm)) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLE_REG:
            if (reg[inst.dst] <= reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLE32_IMM:
            if (u32(reg[inst.dst]) <= u32(inst.imm)) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLE32_REG:
            if (u32(reg[inst.dst]) <= u32(reg[inst.src])) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSET_IMM:
            if (reg[inst.dst] & inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSET_REG:
            if (reg[inst.dst] & reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSET32_IMM:
            if (u32(reg[inst.dst]) & u32(inst.imm)) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSET32_REG:
            if (u32(reg[inst.dst]) & u32(reg[inst.src])) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JNE_IMM:
            if (reg[inst.dst] != inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JNE_REG:
            if (reg[inst.dst] != reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JNE32_IMM:
            if (u32(reg[inst.dst]) != u32(inst.imm)) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JNE32_REG:
            if (u32(reg[inst.dst]) != u32(reg[inst.src])) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGT_IMM:
            if ((int64_t)reg[inst.dst] > inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGT_REG:
            if ((int64_t)reg[inst.dst] > (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGT32_IMM:
            if (i32(reg[inst.dst]) > i32(inst.imm)) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGT32_REG:
            if (i32(reg[inst.dst]) > i32(reg[inst.src])) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGE_IMM:
            if ((int64_t)reg[inst.dst] >= inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGE_REG:
            if ((int64_t)reg[inst.dst] >= (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGE32_IMM:
            if (i32(reg[inst.dst]) >= i32(inst.imm)) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGE32_REG:
            if (i32(reg[inst.dst]) >= i32(reg[inst.src])) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLT_IMM:
            if ((int64_t)reg[inst.dst] < inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLT_REG:
            if ((int64_t)reg[inst.dst] < (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLT32_IMM:
            if (i32(reg[inst.dst]) < i32(inst.imm)) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLT32_REG:
            if (i32(reg[inst.dst]) < i32(reg[inst.src])) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLE_IMM:
            if ((int64_t)reg[inst.dst] <= inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLE_REG:
            if ((int64_t)reg[inst.dst] <= (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLE32_IMM:
            if (i32(reg[inst.dst]) <= i32(inst.imm)) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLE32_REG:
            if (i32(reg[inst.dst]) <= i32(reg[inst.src])) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_EXIT:
            *bpf_return_value = reg[0];
            return 0;
        case EBPF_OP_CALL:
            reg[0] = vm->ext_funcs[inst.imm](reg[1], reg[2], reg[3], reg[4], reg[5]);
            // Unwind the stack if unwind extension returns success.
            if (inst.imm == vm->unwind_stack_extension_index && reg[0] == 0) {
                *bpf_return_value = reg[0];
                return 0;
            }
            break;
        }
    }
}

static bool
validate(const struct ubpf_vm* vm, const struct ebpf_inst* insts, uint32_t num_insts, char** errmsg)
{
    if (num_insts >= UBPF_MAX_INSTS) {
        *errmsg = ubpf_error("too many instructions (max %u)", UBPF_MAX_INSTS);
        return false;
    }

    int i;
    for (i = 0; i < num_insts; i++) {
        struct ebpf_inst inst = insts[i];
        bool store = false;

        switch (inst.opcode) {
        case EBPF_OP_ADD_IMM:
        case EBPF_OP_ADD_REG:
        case EBPF_OP_SUB_IMM:
        case EBPF_OP_SUB_REG:
        case EBPF_OP_MUL_IMM:
        case EBPF_OP_MUL_REG:
        case EBPF_OP_DIV_REG:
        case EBPF_OP_OR_IMM:
        case EBPF_OP_OR_REG:
        case EBPF_OP_AND_IMM:
        case EBPF_OP_AND_REG:
        case EBPF_OP_LSH_IMM:
        case EBPF_OP_LSH_REG:
        case EBPF_OP_RSH_IMM:
        case EBPF_OP_RSH_REG:
        case EBPF_OP_NEG:
        case EBPF_OP_MOD_REG:
        case EBPF_OP_XOR_IMM:
        case EBPF_OP_XOR_REG:
        case EBPF_OP_MOV_IMM:
        case EBPF_OP_MOV_REG:
        case EBPF_OP_ARSH_IMM:
        case EBPF_OP_ARSH_REG:
            break;

        case EBPF_OP_LE:
        case EBPF_OP_BE:
            if (inst.imm != 16 && inst.imm != 32 && inst.imm != 64) {
                *errmsg = ubpf_error("invalid endian immediate at PC %d", i);
                return false;
            }
            break;

        case EBPF_OP_ADD64_IMM:
        case EBPF_OP_ADD64_REG:
        case EBPF_OP_SUB64_IMM:
        case EBPF_OP_SUB64_REG:
        case EBPF_OP_MUL64_IMM:
        case EBPF_OP_MUL64_REG:
        case EBPF_OP_DIV64_REG:
        case EBPF_OP_OR64_IMM:
        case EBPF_OP_OR64_REG:
        case EBPF_OP_AND64_IMM:
        case EBPF_OP_AND64_REG:
        case EBPF_OP_LSH64_IMM:
        case EBPF_OP_LSH64_REG:
        case EBPF_OP_RSH64_IMM:
        case EBPF_OP_RSH64_REG:
        case EBPF_OP_NEG64:
        case EBPF_OP_MOD64_REG:
        case EBPF_OP_XOR64_IMM:
        case EBPF_OP_XOR64_REG:
        case EBPF_OP_MOV64_IMM:
        case EBPF_OP_MOV64_REG:
        case EBPF_OP_ARSH64_IMM:
        case EBPF_OP_ARSH64_REG:
            break;

        case EBPF_OP_LDXW:
        case EBPF_OP_LDXH:
        case EBPF_OP_LDXB:
        case EBPF_OP_LDXDW:
            break;

        case EBPF_OP_STW:
        case EBPF_OP_STH:
        case EBPF_OP_STB:
        case EBPF_OP_STDW:
        case EBPF_OP_STXW:
        case EBPF_OP_STXH:
        case EBPF_OP_STXB:
        case EBPF_OP_STXDW:
            store = true;
            break;

        case EBPF_OP_LDDW:
            if (inst.src != 0) {
                *errmsg = ubpf_error("invalid source register for LDDW at PC %d", i);
                return false;
            }
            if (i + 1 >= num_insts || insts[i + 1].opcode != 0) {
                *errmsg = ubpf_error("incomplete lddw at PC %d", i);
                return false;
            }
            i++; /* Skip next instruction */
            break;

        case EBPF_OP_JA:
        case EBPF_OP_JEQ_REG:
        case EBPF_OP_JEQ_IMM:
        case EBPF_OP_JGT_REG:
        case EBPF_OP_JGT_IMM:
        case EBPF_OP_JGE_REG:
        case EBPF_OP_JGE_IMM:
        case EBPF_OP_JLT_REG:
        case EBPF_OP_JLT_IMM:
        case EBPF_OP_JLE_REG:
        case EBPF_OP_JLE_IMM:
        case EBPF_OP_JSET_REG:
        case EBPF_OP_JSET_IMM:
        case EBPF_OP_JNE_REG:
        case EBPF_OP_JNE_IMM:
        case EBPF_OP_JSGT_IMM:
        case EBPF_OP_JSGT_REG:
        case EBPF_OP_JSGE_IMM:
        case EBPF_OP_JSGE_REG:
        case EBPF_OP_JSLT_IMM:
        case EBPF_OP_JSLT_REG:
        case EBPF_OP_JSLE_IMM:
        case EBPF_OP_JSLE_REG:
        case EBPF_OP_JEQ32_IMM:
        case EBPF_OP_JEQ32_REG:
        case EBPF_OP_JGT32_IMM:
        case EBPF_OP_JGT32_REG:
        case EBPF_OP_JGE32_IMM:
        case EBPF_OP_JGE32_REG:
        case EBPF_OP_JSET32_REG:
        case EBPF_OP_JSET32_IMM:
        case EBPF_OP_JNE32_IMM:
        case EBPF_OP_JNE32_REG:
        case EBPF_OP_JSGT32_IMM:
        case EBPF_OP_JSGT32_REG:
        case EBPF_OP_JSGE32_IMM:
        case EBPF_OP_JSGE32_REG:
        case EBPF_OP_JLT32_IMM:
        case EBPF_OP_JLT32_REG:
        case EBPF_OP_JLE32_IMM:
        case EBPF_OP_JLE32_REG:
        case EBPF_OP_JSLT32_IMM:
        case EBPF_OP_JSLT32_REG:
        case EBPF_OP_JSLE32_IMM:
        case EBPF_OP_JSLE32_REG:
            if (inst.offset == -1) {
                *errmsg = ubpf_error("infinite loop at PC %d", i);
                return false;
            }
            int new_pc = i + 1 + inst.offset;
            if (new_pc < 0 || new_pc >= num_insts) {
                *errmsg = ubpf_error("jump out of bounds at PC %d", i);
                return false;
            } else if (insts[new_pc].opcode == 0) {
                *errmsg = ubpf_error("jump to middle of lddw at PC %d", i);
                return false;
            }
            break;

        case EBPF_OP_CALL:
            if (inst.imm < 0 || inst.imm >= MAX_EXT_FUNCS) {
                *errmsg = ubpf_error("invalid call immediate at PC %d", i);
                return false;
            }
            if (!vm->ext_funcs[inst.imm]) {
                *errmsg = ubpf_error("call to nonexistent function %u at PC %d", inst.imm, i);
                return false;
            }
            break;

        case EBPF_OP_EXIT:
            break;

        case EBPF_OP_DIV_IMM:
        case EBPF_OP_MOD_IMM:
        case EBPF_OP_DIV64_IMM:
        case EBPF_OP_MOD64_IMM:
            break;

        default:
            *errmsg = ubpf_error("unknown opcode 0x%02x at PC %d", inst.opcode, i);
            return false;
        }

        if (inst.src > 10) {
            *errmsg = ubpf_error("invalid source register at PC %d", i);
            return false;
        }

        if (inst.dst > 9 && !(store && inst.dst == 10)) {
            *errmsg = ubpf_error("invalid destination register at PC %d", i);
            return false;
        }
    }

    return true;
}

static bool
bounds_check(
    const struct ubpf_vm* vm,
    void* addr,
    int size,
    const char* type,
    uint16_t cur_pc,
    void* mem,
    size_t mem_len,
    void* stack)
{
    if (!vm->bounds_check_enabled)
        return true;
    if (mem && (addr >= mem && ((char*)addr + size) <= ((char*)mem + mem_len))) {
        /* Context access */
        return true;
    } else if (addr >= stack && ((char*)addr + size) <= ((char*)stack + UBPF_STACK_SIZE)) {
        /* Stack access */
        return true;
    } else {
        vm->error_printf(
            stderr,
            "uBPF error: out of bounds memory %s at PC %u, addr %p, size %d\nmem %p/%zd stack %p/%d\n",
            type,
            cur_pc,
            addr,
            size,
            mem,
            mem_len,
            stack,
            UBPF_STACK_SIZE);
        return false;
    }
}

char*
ubpf_error(const char* fmt, ...)
{
    char* msg;
    va_list ap;
    va_start(ap, fmt);
    if (vasprintf(&msg, fmt, ap) < 0) {
        msg = NULL;
    }
    va_end(ap);
    return msg;
}

#ifdef DEBUG
void
ubpf_set_registers(struct ubpf_vm* vm, uint64_t* regs)
{
    vm->regs = regs;
}

uint64_t*
ubpf_get_registers(const struct ubpf_vm* vm)
{
    return vm->regs;
}
#else
void
ubpf_set_registers(struct ubpf_vm* vm, uint64_t* regs)
{
    (void)vm;
    (void)regs;
    fprintf(stderr, "uBPF warning: registers are not exposed in release mode. Please recompile in debug mode\n");
}

uint64_t*
ubpf_get_registers(const struct ubpf_vm* vm)
{
    (void)vm;
    fprintf(stderr, "uBPF warning: registers are not exposed in release mode. Please recompile in debug mode\n");
    return NULL;
}

#endif

typedef struct _ebpf_encoded_inst
{
    union
    {
        uint64_t value;
        struct ebpf_inst inst;
    };
} ebpf_encoded_inst;

struct ebpf_inst
ubpf_fetch_instruction(const struct ubpf_vm* vm, uint16_t pc)
{
    // XOR instruction with base address of vm.
    // This makes ROP attack more difficult.
    ebpf_encoded_inst encode_inst;
    encode_inst.inst = vm->insts[pc];
    encode_inst.value ^= (uint64_t)vm->insts;
    encode_inst.value ^= vm->pointer_secret;
    return encode_inst.inst;
}

void
ubpf_store_instruction(const struct ubpf_vm* vm, uint16_t pc, struct ebpf_inst inst)
{
    // XOR instruction with base address of vm.
    // This makes ROP attack more difficult.
    ebpf_encoded_inst encode_inst;
    encode_inst.inst = inst;
    encode_inst.value ^= (uint64_t)vm->insts;
    encode_inst.value ^= vm->pointer_secret;
    vm->insts[pc] = encode_inst.inst;
}

int
ubpf_set_pointer_secret(struct ubpf_vm* vm, uint64_t secret)
{
    if (vm->insts) {
        return -1;
    }
    vm->pointer_secret = secret;
    return 0;
}
