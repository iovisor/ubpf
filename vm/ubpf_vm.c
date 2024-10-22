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
#define _GNU_SOURCE

#include "ubpf.h"
#include "ebpf.h"
#include "ubpf_int.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <endian.h>
#include <unistd.h>

#define SHIFT_MASK_32_BIT(X) ((X) & 0x1f)
#define SHIFT_MASK_64_BIT(X) ((X) & 0x3f)
#define DEFAULT_JITTER_BUFFER_SIZE 65536

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
    void* stack,
    size_t stack_len);

bool
ubpf_toggle_bounds_check(struct ubpf_vm* vm, bool enable)
{
    bool old = vm->bounds_check_enabled;
    vm->bounds_check_enabled = enable;
    return old;
}

bool
ubpf_toggle_undefined_behavior_check(struct ubpf_vm* vm, bool enable)
{
    bool old = vm->undefined_behavior_check_enabled;
    vm->undefined_behavior_check_enabled = enable;
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

    vm->local_func_stack_usage = calloc(UBPF_MAX_INSTS, sizeof(struct ubpf_stack_usage));
    if (vm->local_func_stack_usage == NULL) {
        ubpf_destroy(vm);
        return NULL;
    }

    vm->bounds_check_enabled = true;
    vm->undefined_behavior_check_enabled = false;
    vm->error_printf = fprintf;

#if defined(__x86_64__) || defined(_M_X64)
    vm->jit_translate = ubpf_translate_x86_64;
    vm->jit_update_dispatcher = ubpf_jit_update_dispatcher_x86_64;
    vm->jit_update_helper = ubpf_jit_update_helper_x86_64;
#elif defined(__aarch64__) || defined(_M_ARM64)
    vm->jit_translate = ubpf_translate_arm64;
    vm->jit_update_dispatcher = ubpf_jit_update_dispatcher_arm64;
    vm->jit_update_helper = ubpf_jit_update_helper_arm64;
#else
    vm->translate = ubpf_translate_null;
#endif
    vm->unwind_stack_extension_index = -1;

    vm->jitted_result.compile_result = UBPF_JIT_COMPILE_FAILURE;
    vm->jitter_buffer_size = DEFAULT_JITTER_BUFFER_SIZE;
    return vm;
}

void
ubpf_destroy(struct ubpf_vm* vm)
{
    ubpf_unload_code(vm);
    free(vm->int_funcs);
    free(vm->ext_funcs);
    free(vm->ext_func_names);
    free(vm->local_func_stack_usage);
    free(vm);
}

external_function_t
as_external_function_t(void* f)
{
    return (external_function_t)f;
};

int
ubpf_register(struct ubpf_vm* vm, unsigned int idx, const char* name, external_function_t fn)
{
    if (idx >= MAX_EXT_FUNCS) {
        return -1;
    }

    vm->ext_funcs[idx] = (extended_external_helper_t)fn;
    vm->ext_func_names[idx] = name;

    int success = 0;

    if (vm->jitted_result.compile_result == UBPF_JIT_COMPILE_SUCCESS) {
        if (mprotect(vm->jitted, vm->jitted_size, PROT_READ | PROT_WRITE) < 0) {
            return -1;
        }

        // Now, update!
        if (!vm->jit_update_helper(
                vm,
                (extended_external_helper_t)fn,
                idx,
                (uint8_t*)vm->jitted,
                vm->jitted_size,
                vm->jitted_result.external_helper_offset)) {
            // Can't immediately stop here because we have unprotected memory!
            success = -1;
        }

        if (mprotect(vm->jitted, vm->jitted_size, PROT_READ | PROT_EXEC) < 0) {
            return -1;
        }
    }
    return success;
}

int
ubpf_register_external_dispatcher(
    struct ubpf_vm* vm, external_function_dispatcher_t dispatcher, external_function_validate_t validater)
{
    vm->dispatcher = dispatcher;
    vm->dispatcher_validate = validater;

    int success = 0;

    if (vm->jitted_result.compile_result == UBPF_JIT_COMPILE_SUCCESS) {
        if (mprotect(vm->jitted, vm->jitted_size, PROT_READ | PROT_WRITE) < 0) {
            return -1;
        }

        // Now, update!
        if (!vm->jit_update_dispatcher(
                vm, dispatcher, (uint8_t*)vm->jitted, vm->jitted_size, vm->jitted_result.external_dispatcher_offset)) {
            // Can't immediately stop here because we have unprotected memory!
            success = -1;
        }

        if (mprotect(vm->jitted, vm->jitted_size, PROT_READ | PROT_EXEC) < 0) {
            return -1;
        }
    }
    return success;
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

    if (UBPF_EBPF_STACK_SIZE % sizeof(uint64_t) != 0) {
        *errmsg = ubpf_error("UBPF_EBPF_STACK_SIZE must be a multiple of 8");
        return -1;
    }

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

    vm->int_funcs = (bool*)calloc(vm->num_insts, sizeof(bool));
    if (!vm->int_funcs) {
        *errmsg = ubpf_error("out of memory");
        return -1;
    }

    for (uint32_t i = 0; i < vm->num_insts; i++) {
        /* Mark targets of local call instructions. They
         * represent the beginning of local functions and
         * the jitter may need to do something special with
         * them.
         */
        if (source_inst[i].opcode == EBPF_OP_CALL && source_inst[i].src == 1) {
            uint32_t target = i + source_inst[i].imm + 1;
            vm->int_funcs[target] = true;
        }
        // Store instructions in the vm.
        ubpf_store_instruction(vm, i, source_inst[i]);
    }

    return 0;
}

void
ubpf_unload_code(struct ubpf_vm* vm)
{

    // Reset the stack usage amounts when code is unloaded.
    free(vm->local_func_stack_usage);
    vm->local_func_stack_usage = calloc(UBPF_MAX_INSTS, sizeof(struct ubpf_stack_usage));

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

/**
 * @brief Sign extend immediate value to a signed 64-bit value.
 *
 * @param[in] immediate The signed 32-bit immediate value to sign extend.
 * @return The sign extended 64-bit value.
 */
static int64_t
i64(int32_t immediate)
{
    return (int64_t)immediate;
}

#define IS_ALIGNED(x, a) (((uintptr_t)(x) & ((a) - 1)) == 0)

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

/**
 * @brief Mark the bits in the shadow stack corresponding to the address if it is within the stack bounds.
 *
 * @param[in] stack The base address of the stack.
 * @param[in] shadow_stack The base address of the shadow stack.
 * @param[in] address The address being written to.
 * @param[in] size The number of bytes being written.
 */
static inline void
ubpf_mark_shadow_stack(
    const struct ubpf_vm* vm, uint8_t* stack, uint64_t stack_length, uint8_t* shadow_stack, void* address, size_t size)
{
    if (!vm->undefined_behavior_check_enabled) {
        return;
    }

    uintptr_t access_start = (uintptr_t)address;
    uintptr_t access_end = access_start + size;
    uintptr_t stack_start = (uintptr_t)stack;
    uintptr_t stack_end = stack_start + stack_length;

    if (access_start > access_end) {
        // Overflow
        return;
    }

    if (access_start >= stack_start && access_end <= stack_end) {
        // Shadow stack is a bit array, where each bit corresponds to 1 byte in the stack.
        // If the bit is set, the memory is initialized.
        size_t offset = access_start - stack_start;
        for (size_t test_bit = offset; test_bit < offset + size; test_bit++) {
            // Convert test_bit into offset + mask to test against the shadow stack.
            size_t bit_offset = test_bit / 8;
            size_t bit_mask = 1ull << (test_bit % 8);
            shadow_stack[bit_offset] |= bit_mask;
        }
    }
}

/**
 * @brief Check if the address is within the stack bounds and the shadow stack is marked for the address.
 *
 * @param[in] stack The base address of the stack.
 * @param[in] shadow_stack The base address of the shadow stack.
 * @param[in] address The address being read from.
 * @param[in] size The number of bytes being read.
 * @return true - The read is from initialized memory or is not within the stack bounds.
 * @return false - The read is from uninitialized memory within the stack bounds.
 */
static inline bool
ubpf_check_shadow_stack(
    const struct ubpf_vm* vm, uint8_t* stack, uint64_t stack_length, uint8_t* shadow_stack, void* address, size_t size)
{
    if (!vm->undefined_behavior_check_enabled) {
        return true;
    }

    uintptr_t access_start = (uintptr_t)address;
    uintptr_t access_end = access_start + size;
    uintptr_t stack_start = (uintptr_t)stack;
    uintptr_t stack_end = stack_start + stack_length;

    if (access_start > access_end) {
        // Overflow
        return true;
    }

    if (access_start >= stack_start && access_end <= stack_end) {
        // Shadow stack is a bit array, where each bit corresponds to 1 byte in the stack.
        // If the bit is set, the memory is initialized.
        size_t offset = access_start - stack_start;
        for (size_t test_bit = offset; test_bit < offset + size; test_bit++) {
            // Convert test_bit into offset + mask to test against the shadow stack.
            size_t bit_offset = test_bit / 8;
            size_t bit_mask = 1ull << (test_bit % 8);
            if ((shadow_stack[bit_offset] & bit_mask) == 0) {
                return false;
            }
        }
    }
    return true;
}

#define REGISTER_TO_SHADOW_MASK(reg) (1 << (reg))

/**
 * @brief Check if the registers being accessed by this instruction are initialized and mark the destination register as
 * initialized if it is.
 *
 * @param[in] vm The VM instance.
 * @param[in,out] shadow_registers Storage for the shadow register state.
 * @param[in] inst The instruction being executed.
 * @return true - The registers are initialized.
 * @return false - The registers are not initialized - an error message has been printed.
 */
static inline bool
ubpf_validate_shadow_register(const struct ubpf_vm* vm, uint32_t pc, uint16_t* shadow_registers, struct ebpf_inst inst)
{
    if (!vm->undefined_behavior_check_enabled) {
        return true;
    }

    // Determine which registers are valid before and after the instruction.
    bool source_register_valid_before_instruction = (*shadow_registers) & REGISTER_TO_SHADOW_MASK(inst.src);
    bool destination_register_valid_before_instruction = (*shadow_registers) & REGISTER_TO_SHADOW_MASK(inst.dst);
    bool destination_register_valid_after_instruction = destination_register_valid_before_instruction;

    switch (inst.opcode & EBPF_CLS_MASK) {
    // Load instructions initialize the destination register.
    case EBPF_CLS_LD:
        // Load of immediate values makes the destination register valid.
        destination_register_valid_after_instruction = true;
        break;
    // Load indirect instructions initialize the destination register and require the source register to be initialized.
    case EBPF_CLS_LDX:
        if (!source_register_valid_before_instruction) {
            vm->error_printf(stderr, "Error: %d: Source register r%d is not initialized.\n", pc, inst.src);
            return false;
        }
        destination_register_valid_after_instruction = true;
        break;
    // Store indirect instructions require the destination register to be initialized, but has no source register.
    case EBPF_CLS_ST:
        if (inst.dst != BPF_REG_10 && !destination_register_valid_before_instruction) {
            vm->error_printf(stderr, "Error: %d: Destination register r%d is not initialized.\n", pc, inst.dst);
            return false;
        }
        break;
    // Store indirect instructions require both the source and destination registers to be initialized, except for
    // writes to the stack.
    case EBPF_CLS_STX:
        if (inst.dst != BPF_REG_10 && !source_register_valid_before_instruction) {
            vm->error_printf(stderr, "Error: %d: Source register r%d is not initialized.\n", pc, inst.src);
            return false;
        }
        if (inst.dst != BPF_REG_10 && !destination_register_valid_before_instruction) {
            vm->error_printf(stderr, "Error: %d: Destination register r%d is not initialized.\n", pc, inst.dst);
            return false;
        }
        break;
    // ALU operations either use an immediate value or a source register.
    // If the source register is used, it's initialized state is transferred to the destination register.
    // If it's a unary operation, the initialized state of the source register is unchanged.
    case EBPF_CLS_ALU:
    case EBPF_CLS_ALU64:
        switch (inst.opcode & EBPF_ALU_OP_MASK) {
        // Binary ops.
        case 0x00: // EBPF_OP_ADD
        case 0x10: // EBPF_OP_SUB
        case 0x20: // EBPF_OP_MUL
        case 0x30: // EBPF_OP_DIV
        case 0x40: // EBPF_OP_OR
        case 0x50: // EBPF_OP_AND
        case 0x60: // EBPF_OP_LSH
        case 0x70: // EBPF_OP_RSH
        case 0x90: // EBPF_OP_MOD
        case 0xa0: // EBPF_OP_XOR
        case 0xc0: // EBPF_OP_ARSH
        case 0xb0: // EBPF_OP_MOV
            // Permit operations on uninitialized registers, but mark the destination register as uninitialized.
            if (inst.opcode & EBPF_SRC_REG) {
                destination_register_valid_after_instruction = source_register_valid_before_instruction;
            } else {
                destination_register_valid_after_instruction = true;
            }
            break;
        // Unary ops
        case 0x80: // EBPF_OP_NEG
        case 0xd0: // EBPF_OP_LE
            // Doesn't change the initialized state of the either register.
            break;
        default:
            vm->error_printf(stderr, "Error: %d: Unknown ALU opcode %x.\n", pc, inst.opcode);
            return false;
        }
        break;
    case EBPF_CLS_JMP:
    case EBPF_CLS_JMP32:
        switch (inst.opcode & EBPF_JMP_OP_MASK) {
        // Unconditional jumps don't require any registers to be initialized.
        case EBPF_MODE_CALL:
        case EBPF_MODE_JA:
        case EBPF_MODE_EXIT:
            break;
        // Conditional jumps require the destination register to be initialized and also the source register if it the EBPF_SRC_REG flag is set.
        case EBPF_MODE_JEQ:
        case EBPF_MODE_JGT:
        case EBPF_MODE_JGE:
        case EBPF_MODE_JSET:
        case EBPF_MODE_JNE:
        case EBPF_MODE_JSGT:
        case EBPF_MODE_JSGE:
        case EBPF_MODE_JLT:
        case EBPF_MODE_JLE:
        case EBPF_MODE_JSLT:
        case EBPF_MODE_JSLE:
            // If the jump offset is 0, then this is a no-op.
            if (inst.offset == 0) {
                break;
            }
            if (!destination_register_valid_before_instruction) {
                vm->error_printf(stderr, "Error: %d: Destination register r%d is not initialized.\n", pc, inst.dst);
                return false;
            }
            if (inst.opcode & EBPF_SRC_REG && !source_register_valid_before_instruction) {
                vm->error_printf(stderr, "Error: %d: Source register r%d is not initialized.\n", pc, inst.src);
                return false;
            }
            break;
        default:
            vm->error_printf(stderr, "Error: %d: Unknown JMP opcode %x.\n", pc, inst.opcode);
            return false;
        }
    break;
    default:
        vm->error_printf(stderr, "Error: %d: Unknown opcode %x.\n", pc, inst.opcode);
        return false;
    }

    // Update the shadow register state.
    if (destination_register_valid_after_instruction) {
        *shadow_registers |= REGISTER_TO_SHADOW_MASK(inst.dst);
    } else {
        *shadow_registers &= ~REGISTER_TO_SHADOW_MASK(inst.dst);
    }

    if (inst.opcode == EBPF_OP_CALL) {
        if (inst.src == 0) {
            // Mark the return address register as initialized.
            *shadow_registers |= REGISTER_TO_SHADOW_MASK(0);

            // Mark r1-r5 as uninitialized.
            *shadow_registers &=
                ~(REGISTER_TO_SHADOW_MASK(1) | REGISTER_TO_SHADOW_MASK(2) | REGISTER_TO_SHADOW_MASK(3) |
                  REGISTER_TO_SHADOW_MASK(4) | REGISTER_TO_SHADOW_MASK(5));
        } else if (inst.src == 1) {
            // Do nothing, register state will be handled by the callee on return.
        }
    }

    if (inst.opcode == EBPF_OP_EXIT) {
        if (!(*shadow_registers & REGISTER_TO_SHADOW_MASK(0))) {
            vm->error_printf(stderr, "Error: %d: Return value register r0 is not initialized.\n", pc);
            return false;
        }
        // Mark r1-r5 as uninitialized.
        *shadow_registers &=
            ~(REGISTER_TO_SHADOW_MASK(1) | REGISTER_TO_SHADOW_MASK(2) | REGISTER_TO_SHADOW_MASK(3) |
              REGISTER_TO_SHADOW_MASK(4) | REGISTER_TO_SHADOW_MASK(5));
    }

    return true;
}

int
ubpf_exec_ex(
    const struct ubpf_vm* vm,
    void* mem,
    size_t mem_len,
    uint64_t* bpf_return_value,
    uint8_t* stack_start,
    size_t stack_length)
{
    uint16_t pc = 0;
    const struct ebpf_inst* insts = vm->insts;
    uint64_t* reg;
    uint64_t _reg[16];
    uint64_t stack_frame_index = 0;
    int return_value = -1;
    void* external_dispatcher_cookie = mem;
    void* shadow_stack = NULL;

    if (!insts) {
        /* Code must be loaded before we can execute */
        return -1;
    }

    struct ubpf_stack_frame stack_frames[UBPF_MAX_CALL_DEPTH] = {
        0,
    };

    if (vm->undefined_behavior_check_enabled) {
        shadow_stack = calloc(stack_length / 8, 1);
        if (!shadow_stack) {
            return_value = -1;
            goto cleanup;
        }
    }

#ifdef DEBUG
    if (vm->regs)
        reg = vm->regs;
    else
        reg = _reg;
#else
    reg = _reg;
#endif
    uint16_t shadow_registers = 0; // Bit mask of registers that have been written to.

    reg[1] = (uintptr_t)mem;
    reg[2] = (uint64_t)mem_len;
    reg[10] = (uintptr_t)stack_start + stack_length;

    // Mark r1, r2, r10 as initialized.
    shadow_registers |= REGISTER_TO_SHADOW_MASK(1) | REGISTER_TO_SHADOW_MASK(2) | REGISTER_TO_SHADOW_MASK(10);

    int instruction_limit = vm->instruction_limit;

    while (1) {
        const uint16_t cur_pc = pc;
        if (pc >= vm->num_insts) {
            return_value = -1;
            goto cleanup;
        }
        if (vm->instruction_limit && instruction_limit-- <= 0) {
            return_value = -1;
            vm->error_printf(stderr, "Error: Instruction limit exceeded.\n");
            goto cleanup;
        }

        if ((pc == 0 || vm->int_funcs[pc]) && stack_frame_index < UBPF_MAX_CALL_DEPTH) {
            stack_frames[stack_frame_index].stack_usage = ubpf_stack_usage_for_local_func(vm, pc);
        }

        struct ebpf_inst inst = ubpf_fetch_instruction(vm, pc++);

        if (!ubpf_validate_shadow_register(vm, cur_pc, &shadow_registers, inst)) {
            vm->error_printf(stderr, "Error: Invalid register state at pc %d.\n", cur_pc);
            return_value = -1;
            goto cleanup;
        }

        // Invoke the debug function to allow the user to inspect the state of the VM if it is enabled.
        if (vm->debug_function) {
            vm->debug_function(
                vm->debug_function_context, // The user's context pointer that was passed to ubpf_register_debug_fn.
                cur_pc,                     // The current instruction pointer.
                reg,                        // The array of 11 registers representing the VM state.
                stack_start,                // Pointer to the beginning of the stack.
                stack_length,               // Size of the stack in bytes.
                shadow_registers,      // Bitmask of registers that have been modified since the start of the program.
                (uint8_t*)shadow_stack // Bitmask of the stack that has been modified since the start of the program.
            );
        }

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
            reg[inst.dst] = u32(reg[inst.src]) ? u32(reg[inst.dst]) / u32(reg[inst.src]) : 0;
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
            reg[inst.dst] = (u32(reg[inst.dst]) << SHIFT_MASK_32_BIT(inst.imm) & UINT32_MAX);
            break;
        case EBPF_OP_LSH_REG:
            reg[inst.dst] = (u32(reg[inst.dst]) << SHIFT_MASK_32_BIT(reg[inst.src]) & UINT32_MAX);
            break;
        case EBPF_OP_RSH_IMM:
            reg[inst.dst] = u32(reg[inst.dst]) >> SHIFT_MASK_32_BIT(inst.imm);
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_RSH_REG:
            reg[inst.dst] = u32(reg[inst.dst]) >> SHIFT_MASK_32_BIT(reg[inst.src]);
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
            reg[inst.dst] = (int32_t)reg[inst.dst] >> SHIFT_MASK_32_BIT(inst.imm);
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_ARSH_REG:
            reg[inst.dst] = (int32_t)reg[inst.dst] >> SHIFT_MASK_32_BIT(reg[inst.src]);
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
            reg[inst.dst] <<= SHIFT_MASK_64_BIT(inst.imm);
            break;
        case EBPF_OP_LSH64_REG:
            reg[inst.dst] <<= SHIFT_MASK_64_BIT(reg[inst.src]);
            break;
        case EBPF_OP_RSH64_IMM:
            reg[inst.dst] >>= SHIFT_MASK_64_BIT(inst.imm);
            break;
        case EBPF_OP_RSH64_REG:
            reg[inst.dst] >>= SHIFT_MASK_64_BIT(reg[inst.src]);
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
            reg[inst.dst] = (int64_t)reg[inst.dst] >> SHIFT_MASK_64_BIT(inst.imm);
            break;
        case EBPF_OP_ARSH64_REG:
            reg[inst.dst] = (int64_t)reg[inst.dst] >> SHIFT_MASK_64_BIT(reg[inst.src]);
            break;

            /*
             * HACK runtime bounds check
             *
             * Needed since we don't have a verifier yet.
             */
#define BOUNDS_CHECK_LOAD(size)                                                                           \
    do {                                                                                                  \
        if (!ubpf_check_shadow_stack(                                                                     \
                vm, stack_start, stack_length, shadow_stack, (char*)reg[inst.src] + inst.offset, size)) { \
            return_value = -1;                                                                            \
            goto cleanup;                                                                                 \
        }                                                                                                 \
        if (!bounds_check(                                                                                \
                vm,                                                                                       \
                (char*)reg[inst.src] + inst.offset,                                                       \
                size,                                                                                     \
                "load",                                                                                   \
                cur_pc,                                                                                   \
                mem,                                                                                      \
                mem_len,                                                                                  \
                stack_start,                                                                              \
                stack_length)) {                                                                          \
            return_value = -1;                                                                            \
            goto cleanup;                                                                                 \
        }                                                                                                 \
    } while (0)
#define BOUNDS_CHECK_STORE(size)                                                                                       \
    do {                                                                                                               \
        if (!bounds_check(                                                                                             \
                vm,                                                                                                    \
                (char*)reg[inst.dst] + inst.offset,                                                                    \
                size,                                                                                                  \
                "store",                                                                                               \
                cur_pc,                                                                                                \
                mem,                                                                                                   \
                mem_len,                                                                                               \
                stack_start,                                                                                           \
                stack_length)) {                                                                                       \
            return_value = -1;                                                                                         \
            goto cleanup;                                                                                              \
        }                                                                                                              \
        ubpf_mark_shadow_stack(vm, stack_start, stack_length, shadow_stack, (char*)reg[inst.dst] + inst.offset, size); \
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
            if (reg[inst.dst] == (uint64_t)i64(inst.imm)) {
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
            if (u32(reg[inst.dst]) == u32(reg[inst.src])) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGT_IMM:
            if (reg[inst.dst] > (uint64_t)i64(inst.imm)) {
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
            if (reg[inst.dst] >= (uint64_t)i64(inst.imm)) {
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
            if (reg[inst.dst] < (uint64_t)i64(inst.imm)) {
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
            if (reg[inst.dst] <= (uint64_t)i64(inst.imm)) {
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
            if (reg[inst.dst] & (uint64_t)i64(inst.imm)) {
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
            if (reg[inst.dst] != (uint64_t)i64(inst.imm)) {
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
            if ((int64_t)reg[inst.dst] > i64(inst.imm)) {
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
            if ((int64_t)reg[inst.dst] >= i64(inst.imm)) {
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
            if ((int64_t)reg[inst.dst] < i64(inst.imm)) {
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
            if ((int64_t)reg[inst.dst] <= i64(inst.imm)) {
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
            if (stack_frame_index > 0) {
                stack_frame_index--;
                pc = stack_frames[stack_frame_index].return_address;
                reg[BPF_REG_6] = stack_frames[stack_frame_index].saved_registers[0];
                reg[BPF_REG_7] = stack_frames[stack_frame_index].saved_registers[1];
                reg[BPF_REG_8] = stack_frames[stack_frame_index].saved_registers[2];
                reg[BPF_REG_9] = stack_frames[stack_frame_index].saved_registers[3];
                reg[BPF_REG_10] += stack_frames[stack_frame_index].stack_usage;
                break;
            }
            *bpf_return_value = reg[0];
            return_value = 0;
            goto cleanup;
        case EBPF_OP_CALL:
            // Differentiate between local and external calls -- assume that the
            // program was assembled with the same endianess as the host machine.
            if (inst.src == 0) {
                // Handle call by address to external function.
                if (vm->dispatcher != NULL) {
                    reg[0] =
                        vm->dispatcher(reg[1], reg[2], reg[3], reg[4], reg[5], inst.imm, external_dispatcher_cookie);
                } else {
                    reg[0] =
                        vm->ext_funcs[inst.imm](reg[1], reg[2], reg[3], reg[4], reg[5], external_dispatcher_cookie);
                }
                if (inst.imm == vm->unwind_stack_extension_index && reg[0] == 0) {
                    *bpf_return_value = reg[0];
                    return_value = 0;
                    goto cleanup;
                }
            } else if (inst.src == 1) {
                if (stack_frame_index >= UBPF_MAX_CALL_DEPTH) {
                    vm->error_printf(
                        stderr,
                        "uBPF error: number of nested functions calls (%lu) exceeds max (%lu) at PC %u\n",
                        stack_frame_index + 1,
                        UBPF_MAX_CALL_DEPTH,
                        cur_pc);
                    return_value = -1;
                    goto cleanup;
                }
                stack_frames[stack_frame_index].saved_registers[0] = reg[BPF_REG_6];
                stack_frames[stack_frame_index].saved_registers[1] = reg[BPF_REG_7];
                stack_frames[stack_frame_index].saved_registers[2] = reg[BPF_REG_8];
                stack_frames[stack_frame_index].saved_registers[3] = reg[BPF_REG_9];
                stack_frames[stack_frame_index].return_address = pc;

                reg[BPF_REG_10] -= stack_frames[stack_frame_index].stack_usage;

                stack_frame_index++;
                pc += inst.imm;
                break;
            } else if (inst.src == 2) {
                // Calling external function by BTF ID is not yet supported.
                return_value = -1;
                goto cleanup;
            }
            // Because we have already validated, we can assume that the type code is
            // valid.
            break;
        case EBPF_OP_ATOMIC_STORE: {
            BOUNDS_CHECK_STORE(8);
            bool fetch = inst.imm & EBPF_ATOMIC_OP_FETCH;
            // If this is a fetch instruction, the destination register is used to store the result.
            int fetch_index = inst.src;
            volatile uint64_t* destination = (volatile uint64_t*)(reg[inst.dst] + inst.offset);
            uint64_t value = reg[inst.src];
            uint64_t result;
            switch (inst.imm & EBPF_ALU_OP_MASK) {
            case EBPF_ALU_OP_ADD:
                result = UBPF_ATOMIC_ADD_FETCH(destination, value);
                break;
            case EBPF_ALU_OP_OR:
                result = UBPF_ATOMIC_OR_FETCH(destination, value);
                break;
            case EBPF_ALU_OP_AND:
                result = UBPF_ATOMIC_AND_FETCH(destination, value);
                break;
            case EBPF_ALU_OP_XOR:
                result = UBPF_ATOMIC_XOR_FETCH(destination, value);
                break;
            case (EBPF_ATOMIC_OP_XCHG & ~EBPF_ATOMIC_OP_FETCH):
                result = UBPF_ATOMIC_EXCHANGE(destination, value);
                break;
            case (EBPF_ATOMIC_OP_CMPXCHG & ~EBPF_ATOMIC_OP_FETCH):
                result = UBPF_ATOMIC_COMPARE_EXCHANGE(destination, value, reg[0]);
                // Atomic compare exchange returns the original value in register 0.
                fetch_index = 0;
                break;
            default:
                vm->error_printf(stderr, "Error: unknown atomic opcode %d at PC %d\n", inst.imm, cur_pc);
                return_value = -1;
                goto cleanup;
            }
            if (fetch) {
                reg[fetch_index] = result;
            }
        } break;

        case EBPF_OP_ATOMIC32_STORE: {
            BOUNDS_CHECK_STORE(4);
            bool fetch = (inst.imm & EBPF_ATOMIC_OP_FETCH) || (inst.imm == EBPF_ATOMIC_OP_CMPXCHG) ||
                         (inst.imm == EBPF_ATOMIC_OP_XCHG);
            // If this is a fetch instruction, the destination register is used to store the result.
            int fetch_index = inst.src;
            volatile uint32_t* destination = (volatile uint32_t*)(reg[inst.dst] + inst.offset);
            uint32_t value = u32(reg[inst.src]);
            uint32_t result;
            switch (inst.imm & EBPF_ALU_OP_MASK) {
            case EBPF_ALU_OP_ADD:
                result = UBPF_ATOMIC_ADD_FETCH32(destination, value);
                break;
            case EBPF_ALU_OP_OR:
                result = UBPF_ATOMIC_OR_FETCH32(destination, value);
                break;
            case EBPF_ALU_OP_AND:
                result = UBPF_ATOMIC_AND_FETCH32(destination, value);
                break;
            case EBPF_ALU_OP_XOR:
                result = UBPF_ATOMIC_XOR_FETCH32(destination, value);
                break;
            case (EBPF_ATOMIC_OP_XCHG & ~EBPF_ATOMIC_OP_FETCH):
                result = UBPF_ATOMIC_EXCHANGE32(destination, value);
                break;
            case (EBPF_ATOMIC_OP_CMPXCHG & ~EBPF_ATOMIC_OP_FETCH):
                result = UBPF_ATOMIC_COMPARE_EXCHANGE32(destination, value, u32(reg[0]));
                // Atomic compare exchange returns the original value in register 0.
                fetch_index = 0;
                break;
            default:
                vm->error_printf(stderr, "Error: unknown atomic opcode %d at PC %d\n", inst.imm, cur_pc);
                return_value = -1;
                goto cleanup;
            }
            if (fetch) {
                reg[fetch_index] = result;
            }
        } break;

        default:
            vm->error_printf(stderr, "Error: unknown opcode %d at PC %d\n", inst.opcode, cur_pc);
            return_value = -1;
            goto cleanup;
        }
        if (((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU) && (inst.opcode & EBPF_ALU_OP_MASK) != 0xd0) {
            reg[inst.dst] &= UINT32_MAX;
        }
    }

cleanup:
    if (shadow_stack) {
        free(shadow_stack);
    }
    return return_value;
}

int
ubpf_exec(const struct ubpf_vm* vm, void* mem, size_t mem_len, uint64_t* bpf_return_value)
{
// Windows Kernel mode limits stack usage to 12K, so we need to allocate it dynamically.
#if defined(NTDDI_VERSION) && defined(WINNT)
    uint64_t* stack = NULL;
    stack = calloc(UBPF_EBPF_STACK_SIZE, 1);
    if (!stack) {
        return -1;
    }
#else
    uint64_t stack[UBPF_EBPF_STACK_SIZE / sizeof(uint64_t)];
#endif
    int result = ubpf_exec_ex(vm, mem, mem_len, bpf_return_value, (uint8_t*)stack, UBPF_EBPF_STACK_SIZE);
#if defined(NTDDI_VERSION) && defined(WINNT)
    free(stack);
#endif
    return result;
}

/**
 * @brief Check if the BPF byte code sequence consists of self-contained sub-programs.
 * This means programs that only enter via a call and leave via the EXIT instruction (no jumps out of one program into another).
 *
 * @param[in] insts Array of instructions
 * @param[in] num_insts Count of instructions
 * @param[out] errmsg Error message
 * @retval true if the program consists of self-contained sub-programs.
 * @return false if the program contains jumps out of one program into another.
 */
static bool check_for_self_contained_sub_programs(const struct ebpf_inst* insts, uint32_t num_insts, char** errmsg);

static bool
validate(const struct ubpf_vm* vm, const struct ebpf_inst* insts, uint32_t num_insts, char** errmsg)
{
    if (num_insts >= UBPF_MAX_INSTS) {
        *errmsg = ubpf_error("too many instructions (max %u)", UBPF_MAX_INSTS);
        return false;
    }

    if (!ubpf_calculate_stack_usage_for_local_func(vm, 0, errmsg)) {
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
            break;
        case EBPF_OP_MOV64_IMM:
        case EBPF_OP_MOV64_REG:
            store = true;
            break;
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
            if (inst.src == 0) {
                if (inst.imm < 0) {
                    *errmsg = ubpf_error("invalid call immediate at PC %d", i);
                    return false;
                }
                if ((vm->dispatcher != NULL && !vm->dispatcher_validate(inst.imm, vm)) ||
                    (vm->dispatcher == NULL && (inst.imm >= MAX_EXT_FUNCS || !vm->ext_funcs[inst.imm]))) {
                    *errmsg = ubpf_error("call to nonexistent function %u at PC %d", inst.imm, i);
                    return false;
                }
            } else if (inst.src == 1) {
                int call_target = i + (inst.imm + 1);
                if (call_target < 0 || call_target >= num_insts) {
                    *errmsg =
                        ubpf_error("call to local function (at PC %d) is out of bounds (target: %d)", i, call_target);
                    return false;
                }
                if (!ubpf_calculate_stack_usage_for_local_func(vm, call_target, errmsg)) {
                    return false;
                }
            } else if (inst.src == 2) {
                *errmsg = ubpf_error("call to external function by BTF ID (at PC %d) is not supported", i);
                return false;
            } else {
                *errmsg = ubpf_error("call (at PC %d) contains invalid type value", i);
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

        // 64-bit atomic operations
        case EBPF_OP_ATOMIC_STORE: {
            store = true;
            switch (inst.imm & EBPF_ALU_OP_MASK) {
            case EBPF_ALU_OP_ADD:
                break;
            case EBPF_ALU_OP_OR:
                break;
            case EBPF_ALU_OP_AND:
                break;
            case EBPF_ALU_OP_XOR:
                break;
            case (EBPF_ATOMIC_OP_XCHG & ~EBPF_ATOMIC_OP_FETCH):
                if (!(inst.imm & EBPF_ATOMIC_OP_FETCH)) {
                    *errmsg = ubpf_error("invalid atomic operation at PC %d", i);
                    return false;
                }
                break;
            case (EBPF_ATOMIC_OP_CMPXCHG & ~EBPF_ATOMIC_OP_FETCH):
                if (!(inst.imm & EBPF_ATOMIC_OP_FETCH)) {
                    *errmsg = ubpf_error("invalid atomic operation at PC %d", i);
                    return false;
                }
                break;
            default:
                *errmsg = ubpf_error("invalid atomic operation at PC %d", i);
                return false;
            }
            break;
        }
        // 32-bit atomic operations
        case EBPF_OP_ATOMIC32_STORE: {
            store = true;
            switch (inst.imm & EBPF_ALU_OP_MASK) {
            case EBPF_ALU_OP_ADD:
                break;
            case EBPF_ALU_OP_OR:
                break;
            case EBPF_ALU_OP_AND:
                break;
            case EBPF_ALU_OP_XOR:
                break;
            case (EBPF_ATOMIC_OP_XCHG & ~EBPF_ATOMIC_OP_FETCH):
                if (!(inst.imm & EBPF_ATOMIC_OP_FETCH)) {
                    *errmsg = ubpf_error("invalid atomic operation at PC %d", i);
                    return false;
                }
                break;
            case (EBPF_ATOMIC_OP_CMPXCHG & ~EBPF_ATOMIC_OP_FETCH):
                if (!(inst.imm & EBPF_ATOMIC_OP_FETCH)) {
                    *errmsg = ubpf_error("invalid atomic operation at PC %d", i);
                    return false;
                }
                break;
            default:
                *errmsg = ubpf_error("invalid atomic operation with opcode 0x%02x at PC %d", inst.opcode, i);
                return false;
            }
            break;
        }
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

    // If the program is syntactically valid, check if it consists of self-contained sub-programs.
    return check_for_self_contained_sub_programs(insts, num_insts, errmsg);
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
    void* stack,
    size_t stack_len)
{
    if (!vm->bounds_check_enabled)
        return true;

    uintptr_t access_start = (uintptr_t)addr;
    uintptr_t access_end = access_start + size;
    uintptr_t stack_start = (uintptr_t)stack;
    uintptr_t stack_end = stack_start + stack_len;
    uintptr_t mem_start = (uintptr_t)mem;
    uintptr_t mem_end = mem_start + mem_len;

    // Memory in the range [access_start, access_end) is being accessed.
    // Memory in the range [stack_start, stack_end) is the stack.
    // Memory in the range [mem_start, mem_end) is the memory.

    if (access_start > access_end) {
        vm->error_printf(
            stderr, "uBPF error: invalid memory access %s at PC %u, addr %p, size %d\n", type, cur_pc, addr, size);
        return false;
    }

    // Check if the access is within the memory bounds.
    // Note: The comparison is <= because the end address is one past the last byte for both
    // the access and the memory regions.
    if (access_start >= mem_start && access_end <= mem_end) {
        return true;
    }

    // Check if the access is within the stack bounds.
    // Note: The comparison is <= because the end address is one past the last byte for both
    // the access and the stack regions.
    if (access_start >= stack_start && access_end <= stack_end) {
        return true;
    }

    // The address may be invalid or it may be a region of memory that the caller
    // is aware of but that is not part of the stack or memory.
    // Call any registered bounds check function to determine if the access is valid.
    if (vm->bounds_check_function != NULL &&
        vm->bounds_check_function(vm->bounds_check_user_data, access_start, size)) {
        return true;
    }

    // Memory is neither stack, nor memory, nor valid according to the bounds check function.

    // Access is out of bounds.
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
        UBPF_EBPF_STACK_SIZE);
    return false;
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

int
ubpf_register_data_relocation(struct ubpf_vm* vm, void* user_context, ubpf_data_relocation relocation)
{
    if (vm->data_relocation_function != NULL) {
        return -1;
    }
    vm->data_relocation_function = relocation;
    vm->data_relocation_user_data = user_context;
    return 0;
}

int
ubpf_register_data_bounds_check(struct ubpf_vm* vm, void* user_context, ubpf_bounds_check bounds_check)
{
    if (vm->bounds_check_function != NULL) {
        return -1;
    }
    vm->bounds_check_function = bounds_check;
    vm->bounds_check_user_data = user_context;
    return 0;
}

int
ubpf_set_instruction_limit(struct ubpf_vm* vm, uint32_t limit, uint32_t* previous_limit)
{
    if (previous_limit != NULL) {
        *previous_limit = vm->instruction_limit;
    }
    vm->instruction_limit = limit;
    return 0;
}

bool
ubpf_calculate_stack_usage_for_local_func(const struct ubpf_vm* vm, uint16_t pc, char** errmsg)
{
    if (vm->local_func_stack_usage[pc].stack_usage_calculated == UBPF_STACK_USAGE_UNKNOWN) {
        vm->local_func_stack_usage[pc].stack_usage_calculated = UBPF_STACK_USAGE_DEFAULT;
        if (vm->stack_usage_calculator) {
            vm->local_func_stack_usage[pc].stack_usage =
                (vm->stack_usage_calculator)(vm, pc, vm->stack_usage_calculator_cookie);
            vm->local_func_stack_usage[pc].stack_usage_calculated = UBPF_STACK_USAGE_CUSTOM;
        }
    }

    // Make sure that it is 16-byte aligned.
    if (ubpf_stack_usage_for_local_func(vm, pc) % 16) {
        *errmsg = ubpf_error(
            "local function (at PC %d) has improperly sized stack use (%d)",
            pc,
            vm->local_func_stack_usage[pc].stack_usage);
        return false;
    }
    return true;
}

uint16_t
ubpf_stack_usage_for_local_func(const struct ubpf_vm* vm, uint16_t pc)
{
    assert((vm->local_func_stack_usage[pc].stack_usage_calculated != UBPF_STACK_USAGE_UNKNOWN));

    uint16_t stack_usage = UBPF_EBPF_LOCAL_FUNCTION_STACK_SIZE;
    if (vm->local_func_stack_usage[pc].stack_usage_calculated == UBPF_STACK_USAGE_CUSTOM) {
        stack_usage = vm->local_func_stack_usage[pc].stack_usage;
    }
    return stack_usage;
}

int
ubpf_register_stack_usage_calculator(struct ubpf_vm* vm, stack_usage_calculator_t calculator, void* cookie)
{
    vm->stack_usage_calculator_cookie = cookie;
    vm->stack_usage_calculator = calculator;
    return 0;
}
int
ubpf_register_debug_fn(struct ubpf_vm* vm, void* context, ubpf_debug_fn debug_function)
{
    if ((vm->debug_function != NULL && debug_function != NULL) ||
        (vm->debug_function == NULL && debug_function == NULL)) {
        return -1;
    }

    vm->debug_function = debug_function;
    vm->debug_function_context = context;
    return 0;
}

/**
 * @brief Compare function for sorting an array of uint32_t.
 *
 * @param[in] a Pointer to the first element.
 * @param[in] b Pointer to the second element.
 * @return Comparison result.
 */
static int compare_uint32_t(const void* a, const void* b)
{
    uint32_t value_a = *(uint32_t*)a;
    uint32_t value_b = *(uint32_t*)b;
    if (value_a < value_b) {
        return -1;
    } else if (value_a > value_b) {
        return 1;
    } else {
        return 0;
    }
}

/**
 * @brief Given an array of uint32_t, remove duplicates and update the count.
 *
 * @param[in,out] array Array of uint32_t.
 * @param[in,out] count On input, the number of elements in the array. On output, the number of unique elements.
 */
static void deduplicate_array_of_uint32(uint32_t* array, uint32_t* count)
{
    uint32_t write_index = 0;

    qsort(array, *count, sizeof(uint32_t), compare_uint32_t);

    for (uint32_t read_index = 1; read_index < *count; read_index++) {
        if (array[read_index] != array[write_index]) {
            array[++write_index] = array[read_index];
        }
    }
    *count = write_index + 1;
}

static bool check_for_self_contained_sub_programs(const struct ebpf_inst* insts, uint32_t num_insts, char** errmsg)
{
    uint32_t local_call_count = 0;
    uint32_t sub_program_count = 0;
    uint32_t * sub_program_start_indices = NULL;
    bool result = false;

    // Count the number of calls to local functions as a proxy for the number of sub-programs.
    // Call targets are assumed to define the start of a sub-program and sub-programs are assumed to end at the next call target or at the end of the program.
    for (uint32_t i = 0; i < num_insts; i++) {
        if (insts[i].opcode == EBPF_OP_CALL && insts[i].src == 1) {
            local_call_count++;
        }
    }

    // If there are no calls to local functions, then the program is self-contained.
    if (local_call_count == 0) {
        result = true;
        goto exit;
    }

    sub_program_count = local_call_count + 1;

    // Allocate memory for the sub-program start indices.
    sub_program_start_indices = calloc(sub_program_count, sizeof(uint32_t));
    if (sub_program_start_indices == NULL) {
        *errmsg = ubpf_error("failed to allocate memory for sub-program start indices");
        goto exit;
    }

    int sub_program_index = 0;
    for (uint32_t i = 0; i < num_insts; i++) {
        if (insts[i].opcode == EBPF_OP_CALL && insts[i].src == 1) {
            // Compute jump target:
            uint32_t jump_target = i + 1 + insts[i].imm;
            sub_program_start_indices[sub_program_index++] = jump_target;
        }
    }

    // At this point the sub_program_start_indices array contains the start indices of the sub-programs, but there may be duplicates and the array may not be sorted.

    deduplicate_array_of_uint32(sub_program_start_indices, &sub_program_count);


    // Now that we have the sub-program start indices, we can check if the program is self-contained.
    // For each sub-program, check for jumps that go outside of the sub-program.

    for (uint32_t i = 0; i < sub_program_count; i++) {
        uint32_t start_index = sub_program_start_indices[i]; ///< First instruction of the sub-program.
        uint32_t end_index = (i == sub_program_count - 1) ? num_insts : sub_program_start_indices[i + 1]; ///< First instruction after the sub-program.

        for (uint32_t j = start_index; j < end_index; j++) {
            switch (insts[j].opcode & EBPF_CLS_MASK) {
            // Only jumps with a target in the range [start_index, end_index) are allowed.
            case EBPF_CLS_JMP:
            case EBPF_CLS_JMP32:
                switch (insts[j].opcode) {
                case EBPF_OP_CALL:
                    // Calls to local functions are assumed to be within the same sub-program.
                    break;
                case EBPF_OP_EXIT:
                    // The EXIT instruction is assumed to be the end of the sub-program.
                    break;
                default: {
                    // Compute jump target and bounds:
                    uint32_t jump_target = j + 1 + insts[j].offset;
                    uint32_t jump_target_lower_bound = start_index;
                    uint32_t jump_target_upper_bound = end_index - 1;

                    // All other jumps must to be within the same sub-program.
                    if (jump_target < jump_target_lower_bound || jump_target > jump_target_upper_bound) {
                        *errmsg = ubpf_error("jump out of bounds at PC %d", j);
                        goto exit;
                    }
                } break;
                };
                break;
            default:
                break;
            }
        }
        // Last instruction of the sub-program must be EXIT or a jump to the current program.
        bool ends_with_exit = insts[end_index - 1].opcode == EBPF_OP_EXIT;
        bool ends_with_jump = insts[end_index - 2].opcode == EBPF_OP_JA;

        if (!(ends_with_exit || ends_with_jump)) {
            *errmsg = ubpf_error("sub-program does not end with EXIT at PC %d", end_index - 1);
            goto exit;
        }
    }

    // If we reached here, the program is self-contained.
    result = true;

exit:
    free(sub_program_start_indices);
    return result;
}
