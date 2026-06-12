// Copyright (c) 2026 uBPF contributors
// SPDX-License-Identifier: Apache-2.0

#define _GNU_SOURCE

#include "ubpf.h"
#include "ebpf.h"
#include "ubpf_int.h"

#include <endian.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHIFT_MASK_32_BIT(X) ((X) & 0x1f)
#define SHIFT_MASK_64_BIT(X) ((X) & 0x3f)
#define UBPF_SAFE_REGION_ID_INPUT ((uint32_t)0xfffffffeu)
#define UBPF_SAFE_REGION_ID_STACK ((uint32_t)0xffffffffu)
#define UBPF_SAFE_REGION_PERMISSIONS_MASK (UBPF_SAFE_REGION_READ | UBPF_SAFE_REGION_WRITE | UBPF_SAFE_REGION_ATOMIC)
#define UBPF_SAFE_STACK_ADDRESS_SLACK ((uint64_t)INT16_MAX)
#define IS_ALIGNED(x, a) (((uintptr_t)(x) & ((a) - 1)) == 0)
#define REGISTER_TO_SHADOW_MASK(reg) (1 << (reg))

enum ubpf_safe_value_kind
{
    UBPF_SAFE_VALUE_SCALAR = 0,
    UBPF_SAFE_VALUE_POINTER = 1,
    UBPF_SAFE_VALUE_HANDLE = 2,
};

struct ubpf_safe_tag
{
    enum ubpf_safe_value_kind kind;
    uint32_t region_id;
    uint32_t permissions;
    uint64_t base;
    uint64_t size;
};

struct ubpf_safe_spill_slot
{
    bool valid;
    struct ubpf_safe_tag tag;
};

struct ubpf_safe_frame_state
{
    struct ubpf_safe_tag saved_register_tags[4];
};

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

static int64_t
i64(int32_t immediate)
{
    return (int64_t)immediate;
}

static inline uint64_t
ubpf_mem_load(uint64_t address, size_t size)
{
    if (!IS_ALIGNED(address, size)) {
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

static inline uint64_t
ubpf_mem_load_sx(uint64_t address, size_t size)
{
    if (!IS_ALIGNED(address, size)) {
        uint64_t value = 0;
        memcpy(&value, (void*)address, size);
        switch (size) {
        case 1:
            return (uint64_t)(int64_t)(int8_t)(uint8_t)value;
        case 2:
            return (uint64_t)(int64_t)(int16_t)(uint16_t)value;
        case 4:
            return (uint64_t)(int64_t)(int32_t)(uint32_t)value;
        default:
            abort();
        }
    }

    switch (size) {
    case 1:
        return (uint64_t)(int64_t)(int8_t)*(uint8_t*)address;
    case 2:
        return (uint64_t)(int64_t)(int16_t)*(uint16_t*)address;
    case 4:
        return (uint64_t)(int64_t)(int32_t)*(uint32_t*)address;
    default:
        abort();
    }
}

static inline void
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
        return;
    }

    if (access_start >= stack_start && access_end <= stack_end) {
        size_t offset = access_start - stack_start;
        for (size_t test_bit = offset; test_bit < offset + size; test_bit++) {
            size_t bit_offset = test_bit / 8;
            size_t bit_mask = 1ull << (test_bit % 8);
            shadow_stack[bit_offset] |= bit_mask;
        }
    }
}

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
        return true;
    }

    if (access_start >= stack_start && access_end <= stack_end) {
        size_t offset = access_start - stack_start;
        for (size_t test_bit = offset; test_bit < offset + size; test_bit++) {
            size_t bit_offset = test_bit / 8;
            size_t bit_mask = 1ull << (test_bit % 8);
            if ((shadow_stack[bit_offset] & bit_mask) == 0) {
                return false;
            }
        }
    }
    return true;
}

static inline bool
ubpf_validate_shadow_register(const struct ubpf_vm* vm, uint32_t pc, uint16_t* shadow_registers, struct ebpf_inst inst)
{
    if (!vm->undefined_behavior_check_enabled) {
        return true;
    }

    bool source_register_valid_before_instruction = (*shadow_registers) & REGISTER_TO_SHADOW_MASK(inst.src);
    bool destination_register_valid_before_instruction = (*shadow_registers) & REGISTER_TO_SHADOW_MASK(inst.dst);
    bool destination_register_valid_after_instruction = destination_register_valid_before_instruction;

    switch (inst.opcode & EBPF_CLS_MASK) {
    case EBPF_CLS_LD:
        destination_register_valid_after_instruction = true;
        break;
    case EBPF_CLS_LDX:
        if (!source_register_valid_before_instruction) {
            vm->error_printf(stderr, "Error: %d: Source register r%d is not initialized.\n", pc, inst.src);
            return false;
        }
        destination_register_valid_after_instruction = true;
        break;
    case EBPF_CLS_ST:
        if (inst.dst != BPF_REG_10 && !destination_register_valid_before_instruction) {
            vm->error_printf(stderr, "Error: %d: Destination register r%d is not initialized.\n", pc, inst.dst);
            return false;
        }
        break;
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
    case EBPF_CLS_ALU:
    case EBPF_CLS_ALU64:
        switch (inst.opcode & EBPF_ALU_OP_MASK) {
        case 0x00:
        case 0x10:
        case 0x20:
        case 0x30:
        case 0x40:
        case 0x50:
        case 0x60:
        case 0x70:
        case 0x90:
        case 0xa0:
        case 0xc0:
        case 0xb0:
            if (inst.opcode & EBPF_SRC_REG) {
                destination_register_valid_after_instruction = source_register_valid_before_instruction;
            } else {
                destination_register_valid_after_instruction = true;
            }
            break;
        case 0x80:
        case 0xd0:
            break;
        default:
            vm->error_printf(stderr, "Error: %d: Unknown ALU opcode %x.\n", pc, inst.opcode);
            return false;
        }
        break;
    case EBPF_CLS_JMP:
    case EBPF_CLS_JMP32:
        switch (inst.opcode & EBPF_JMP_OP_MASK) {
        case EBPF_MODE_CALL:
        case EBPF_MODE_JA:
        case EBPF_MODE_EXIT:
            break;
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

    if (destination_register_valid_after_instruction) {
        *shadow_registers |= REGISTER_TO_SHADOW_MASK(inst.dst);
    } else {
        *shadow_registers &= ~REGISTER_TO_SHADOW_MASK(inst.dst);
    }

    if (inst.opcode == EBPF_OP_CALL && inst.src == 0) {
        *shadow_registers |= REGISTER_TO_SHADOW_MASK(0);
        *shadow_registers &=
            ~(REGISTER_TO_SHADOW_MASK(1) | REGISTER_TO_SHADOW_MASK(2) | REGISTER_TO_SHADOW_MASK(3) |
              REGISTER_TO_SHADOW_MASK(4) | REGISTER_TO_SHADOW_MASK(5));
    }

    if (inst.opcode == EBPF_OP_EXIT) {
        if (!(*shadow_registers & REGISTER_TO_SHADOW_MASK(0))) {
            vm->error_printf(stderr, "Error: %d: Return value register r0 is not initialized.\n", pc);
            return false;
        }
        *shadow_registers &=
            ~(REGISTER_TO_SHADOW_MASK(1) | REGISTER_TO_SHADOW_MASK(2) | REGISTER_TO_SHADOW_MASK(3) |
              REGISTER_TO_SHADOW_MASK(4) | REGISTER_TO_SHADOW_MASK(5));
    }

    return true;
}

static struct ubpf_safe_tag
ubpf_safe_scalar_tag(void)
{
    struct ubpf_safe_tag tag = {.kind = UBPF_SAFE_VALUE_SCALAR};
    return tag;
}

static struct ubpf_safe_tag
ubpf_safe_pointer_tag(uint32_t region_id, uint32_t permissions, uint64_t base, uint64_t size)
{
    struct ubpf_safe_tag tag = {
        .kind = UBPF_SAFE_VALUE_POINTER,
        .region_id = region_id,
        .permissions = permissions,
        .base = base,
        .size = size,
    };
    return tag;
}

static struct ubpf_safe_tag
ubpf_safe_handle_tag(uint32_t region_id, uint32_t permissions, uint64_t base, uint64_t size)
{
    struct ubpf_safe_tag tag = {
        .kind = UBPF_SAFE_VALUE_HANDLE,
        .region_id = region_id,
        .permissions = permissions,
        .base = base,
        .size = size,
    };
    return tag;
}

static const struct ubpf_safe_region_internal*
ubpf_safe_find_region_by_id(const struct ubpf_vm* vm, uint32_t region_id)
{
    for (size_t i = 0; i < UBPF_MAX_SAFE_REGIONS; i++) {
        if (vm->safe_regions[i].in_use && vm->safe_regions[i].id == region_id) {
            return &vm->safe_regions[i];
        }
    }
    return NULL;
}

static bool
ubpf_safe_is_stack_pointer(const struct ubpf_safe_tag* tag, uint8_t* stack_start, size_t stack_length)
{
    return tag->kind == UBPF_SAFE_VALUE_POINTER && tag->region_id == UBPF_SAFE_REGION_ID_STACK &&
           tag->base == (uint64_t)(uintptr_t)stack_start && tag->size == stack_length;
}

static bool
ubpf_safe_compute_access(
    const struct ubpf_vm* vm,
    const struct ubpf_safe_tag* tag,
    uint64_t current_address,
    int16_t offset,
    size_t access_size,
    uint16_t cur_pc,
    const char* access_type,
    uint32_t required_permissions,
    uint64_t* effective_address)
{
    uint64_t region_end;
    uint64_t offset_u64;

    if (tag->kind != UBPF_SAFE_VALUE_POINTER) {
        vm->error_printf(stderr, "uBPF safe mode error: %s requires a pointer at PC %u\n", access_type, cur_pc);
        return false;
    }

    if ((tag->permissions & required_permissions) != required_permissions) {
        vm->error_printf(stderr, "uBPF safe mode error: %s is not permitted at PC %u\n", access_type, cur_pc);
        return false;
    }

    if (offset >= 0) {
        if (current_address > UINT64_MAX - (uint64_t)offset) {
            vm->error_printf(stderr, "uBPF safe mode error: address overflow in %s at PC %u\n", access_type, cur_pc);
            return false;
        }
        *effective_address = current_address + (uint64_t)offset;
    } else {
        offset_u64 = (uint64_t)(-(int64_t)offset);
        if (current_address < offset_u64) {
            vm->error_printf(stderr, "uBPF safe mode error: address underflow in %s at PC %u\n", access_type, cur_pc);
            return false;
        }
        *effective_address = current_address - offset_u64;
    }

    if (tag->base > UINT64_MAX - tag->size) {
        vm->error_printf(stderr, "uBPF safe mode error: invalid region metadata in %s at PC %u\n", access_type, cur_pc);
        return false;
    }

    region_end = tag->base + tag->size;
    if (*effective_address < tag->base || *effective_address > region_end) {
        vm->error_printf(stderr, "uBPF safe mode error: %s is out of bounds at PC %u\n", access_type, cur_pc);
        return false;
    }

    if (access_size > tag->size || *effective_address > region_end - access_size) {
        vm->error_printf(stderr, "uBPF safe mode error: %s overruns region at PC %u\n", access_type, cur_pc);
        return false;
    }

    return true;
}

static void
ubpf_safe_invalidate_stack_spill_tags(
    struct ubpf_safe_spill_slot* spill_slots, uint8_t* stack_start, size_t stack_length, uint64_t address, size_t size)
{
    uint64_t stack_base = (uint64_t)(uintptr_t)stack_start;
    uint64_t stack_end = stack_base + stack_length;
    uint64_t access_end = address + size;

    if (address < stack_base || access_end < address || access_end > stack_end) {
        return;
    }

    uint64_t first_slot = (address - stack_base) / sizeof(uint64_t);
    uint64_t last_slot = (access_end - 1 - stack_base) / sizeof(uint64_t);
    for (uint64_t slot = first_slot; slot <= last_slot; slot++) {
        spill_slots[slot].valid = false;
    }
}

static bool
ubpf_safe_apply_pointer_offset(
    const struct ubpf_vm* vm,
    const struct ubpf_safe_tag* pointer_tag,
    uint64_t result,
    uint16_t cur_pc,
    struct ubpf_safe_tag* result_tag)
{
    uint64_t region_end = pointer_tag->base + pointer_tag->size;
    uint64_t lower_bound = pointer_tag->base;
    uint64_t upper_bound = region_end;

    if (pointer_tag->region_id == UBPF_SAFE_REGION_ID_STACK) {
        lower_bound = pointer_tag->base > UBPF_SAFE_STACK_ADDRESS_SLACK ? pointer_tag->base - UBPF_SAFE_STACK_ADDRESS_SLACK : 0;
        upper_bound = region_end > UINT64_MAX - UBPF_SAFE_STACK_ADDRESS_SLACK ? UINT64_MAX : region_end + UBPF_SAFE_STACK_ADDRESS_SLACK;
    }

    if (result < lower_bound || result > upper_bound) {
        vm->error_printf(stderr, "uBPF safe mode error: pointer arithmetic escaped its region at PC %u\n", cur_pc);
        return false;
    }

    *result_tag = *pointer_tag;
    return true;
}

static bool
ubpf_safe_apply_alu(
    const struct ubpf_vm* vm,
    struct ebpf_inst inst,
    uint16_t cur_pc,
    struct ubpf_safe_tag dst_before,
    struct ubpf_safe_tag src_before,
    uint64_t result,
    struct ubpf_safe_tag* dst_after)
{
    bool is_32bit = ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU);
    bool is_reg = ((inst.opcode & EBPF_SRC_REG) == EBPF_SRC_REG);
    uint8_t op = inst.opcode & EBPF_ALU_OP_MASK;

    if (is_32bit) {
        *dst_after = ubpf_safe_scalar_tag();
        return true;
    }

    switch (op) {
    case EBPF_ALU_OP_MOV:
        if (is_reg) {
            if (inst.offset != 0 && src_before.kind != UBPF_SAFE_VALUE_SCALAR) {
                vm->error_printf(stderr, "uBPF safe mode error: sign-ext move requires a scalar source at PC %u\n", cur_pc);
                return false;
            }
            *dst_after = inst.offset == 0 ? src_before : ubpf_safe_scalar_tag();
        } else {
            *dst_after = ubpf_safe_scalar_tag();
        }
        return true;
    case EBPF_ALU_OP_ADD:
        if (!is_reg) {
            if (dst_before.kind == UBPF_SAFE_VALUE_POINTER) {
                return ubpf_safe_apply_pointer_offset(vm, &dst_before, result, cur_pc, dst_after);
            }
            if (dst_before.kind != UBPF_SAFE_VALUE_SCALAR) {
                vm->error_printf(stderr, "uBPF safe mode error: invalid add operand at PC %u\n", cur_pc);
                return false;
            }
            *dst_after = ubpf_safe_scalar_tag();
            return true;
        }
        if (dst_before.kind == UBPF_SAFE_VALUE_POINTER && src_before.kind == UBPF_SAFE_VALUE_SCALAR) {
            return ubpf_safe_apply_pointer_offset(vm, &dst_before, result, cur_pc, dst_after);
        }
        if (dst_before.kind == UBPF_SAFE_VALUE_SCALAR && src_before.kind == UBPF_SAFE_VALUE_POINTER) {
            return ubpf_safe_apply_pointer_offset(vm, &src_before, result, cur_pc, dst_after);
        }
        if (dst_before.kind == UBPF_SAFE_VALUE_SCALAR && src_before.kind == UBPF_SAFE_VALUE_SCALAR) {
            *dst_after = ubpf_safe_scalar_tag();
            return true;
        }
        vm->error_printf(stderr, "uBPF safe mode error: invalid add operand at PC %u\n", cur_pc);
        return false;
    case EBPF_ALU_OP_SUB:
        if (!is_reg) {
            if (dst_before.kind == UBPF_SAFE_VALUE_POINTER) {
                return ubpf_safe_apply_pointer_offset(vm, &dst_before, result, cur_pc, dst_after);
            }
            if (dst_before.kind != UBPF_SAFE_VALUE_SCALAR) {
                vm->error_printf(stderr, "uBPF safe mode error: invalid sub operand at PC %u\n", cur_pc);
                return false;
            }
            *dst_after = ubpf_safe_scalar_tag();
            return true;
        }
        if (dst_before.kind == UBPF_SAFE_VALUE_POINTER && src_before.kind == UBPF_SAFE_VALUE_SCALAR) {
            return ubpf_safe_apply_pointer_offset(vm, &dst_before, result, cur_pc, dst_after);
        }
        if (dst_before.kind == UBPF_SAFE_VALUE_POINTER && src_before.kind == UBPF_SAFE_VALUE_POINTER &&
            dst_before.region_id == src_before.region_id) {
            *dst_after = ubpf_safe_scalar_tag();
            return true;
        }
        if (dst_before.kind == UBPF_SAFE_VALUE_SCALAR && src_before.kind == UBPF_SAFE_VALUE_SCALAR) {
            *dst_after = ubpf_safe_scalar_tag();
            return true;
        }
        vm->error_printf(stderr, "uBPF safe mode error: invalid sub operand at PC %u\n", cur_pc);
        return false;
    case EBPF_ALU_OP_NEG:
    case EBPF_ALU_OP_MUL:
    case EBPF_ALU_OP_DIV:
    case EBPF_ALU_OP_OR:
    case EBPF_ALU_OP_AND:
    case EBPF_ALU_OP_LSH:
    case EBPF_ALU_OP_RSH:
    case EBPF_ALU_OP_MOD:
    case EBPF_ALU_OP_XOR:
    case EBPF_ALU_OP_ARSH:
    case EBPF_ALU_OP_END:
        if (dst_before.kind != UBPF_SAFE_VALUE_SCALAR || (is_reg && src_before.kind != UBPF_SAFE_VALUE_SCALAR)) {
            vm->error_printf(stderr, "uBPF safe mode error: ALU operation requires scalar operands at PC %u\n", cur_pc);
            return false;
        }
        *dst_after = ubpf_safe_scalar_tag();
        return true;
    default:
        *dst_after = ubpf_safe_scalar_tag();
        return true;
    }
}

int
ubpf_set_execution_profile_impl(struct ubpf_vm* vm, enum ubpf_execution_profile profile)
{
    if (profile != UBPF_EXECUTION_PROFILE_LEGACY && profile != UBPF_EXECUTION_PROFILE_SAFE) {
        return -1;
    }

    if (vm->insts != NULL || vm->jitted != NULL || vm->execution_started) {
        return -1;
    }

    vm->execution_profile = profile;
    return 0;
}

int
ubpf_register_safe_helper_impl(struct ubpf_vm* vm, const struct ubpf_safe_helper_descriptor* descriptor)
{
    if (descriptor == NULL || descriptor->index >= MAX_EXT_FUNCS || descriptor->fn == NULL) {
        return -1;
    }

    if (descriptor->result_kind != UBPF_SAFE_HELPER_RESULT_SCALAR &&
        descriptor->result_kind != UBPF_SAFE_HELPER_RESULT_POINTER &&
        descriptor->result_kind != UBPF_SAFE_HELPER_RESULT_HANDLE) {
        return -1;
    }

    if ((descriptor->result_kind == UBPF_SAFE_HELPER_RESULT_POINTER ||
         descriptor->result_kind == UBPF_SAFE_HELPER_RESULT_HANDLE) &&
        descriptor->region_size == 0) {
        return -1;
    }

    if ((descriptor->result_kind == UBPF_SAFE_HELPER_RESULT_POINTER ||
         descriptor->result_kind == UBPF_SAFE_HELPER_RESULT_HANDLE) &&
        (descriptor->region_id == UBPF_SAFE_REGION_ID_INPUT || descriptor->region_id == UBPF_SAFE_REGION_ID_STACK)) {
        return -1;
    }

    if (ubpf_register(vm, descriptor->index, descriptor->name, descriptor->fn) != 0) {
        return -1;
    }

    vm->safe_helpers[descriptor->index].in_use = true;
    vm->safe_helpers[descriptor->index].result_kind = descriptor->result_kind;
    vm->safe_helpers[descriptor->index].region_id = descriptor->region_id;
    vm->safe_helpers[descriptor->index].region_size = descriptor->region_size;
    return 0;
}

int
ubpf_register_safe_region_impl(struct ubpf_vm* vm, const struct ubpf_safe_region* region)
{
    struct ubpf_safe_region_internal* slot = NULL;
    uint64_t end = 0;

    if (region == NULL) {
        return -1;
    }

    if (region->kind != UBPF_SAFE_REGION_POINTER && region->kind != UBPF_SAFE_REGION_HANDLE) {
        return -1;
    }

    if (region->id == UBPF_SAFE_REGION_ID_INPUT || region->id == UBPF_SAFE_REGION_ID_STACK) {
        return -1;
    }

    if (region->size == 0 || region->base == NULL) {
        return -1;
    }

    if ((region->permissions & ~UBPF_SAFE_REGION_PERMISSIONS_MASK) != 0) {
        return -1;
    }

    end = (uint64_t)(uintptr_t)region->base + region->size;
    if (end < (uint64_t)(uintptr_t)region->base) {
        return -1;
    }

    for (size_t i = 0; i < UBPF_MAX_SAFE_REGIONS; i++) {
        if (vm->safe_regions[i].in_use && vm->safe_regions[i].id == region->id) {
            slot = &vm->safe_regions[i];
            break;
        }
        if (!vm->safe_regions[i].in_use && slot == NULL) {
            slot = &vm->safe_regions[i];
        }
    }

    if (slot == NULL) {
        return -1;
    }

    slot->in_use = true;
    slot->id = region->id;
    slot->base = (uint64_t)(uintptr_t)region->base;
    slot->end = end;
    slot->kind = region->kind;
    slot->permissions = region->permissions;
    return 0;
}

int
ubpf_exec_ex_safe(
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
    struct ubpf_safe_tag safe_tags[16];
    size_t shadow_stack_size = (stack_length + 7) / 8;
    size_t spill_slot_count = (stack_length + sizeof(uint64_t) - 1) / sizeof(uint64_t);
    struct ubpf_safe_spill_slot* safe_spill_slots = NULL;
    struct ubpf_safe_frame_state safe_frames[UBPF_MAX_CALL_DEPTH] = {0};
    int64_t dividend64 = 0;
    int64_t divisor64 = 0;
    int32_t dividend32 = 0;
    int32_t divisor32 = 0;
    uint64_t _eff_addr = 0;
    void* _ptr = NULL;
    bool atomic_fetch = false;
    int atomic_fetch_index = 0;
    volatile uint64_t* atomic_dest64 = NULL;
    volatile uint32_t* atomic_dest32 = NULL;
    uint64_t atomic_val64 = 0;
    uint32_t atomic_val32 = 0;
    uint64_t atomic_res64 = 0;
    uint32_t atomic_res32 = 0;

    if (!insts) {
        return -1;
    }

    ((struct ubpf_vm*)vm)->execution_started = true;

    struct ubpf_stack_frame stack_frames[UBPF_MAX_CALL_DEPTH] = {0};

    if (vm->undefined_behavior_check_enabled) {
        shadow_stack = calloc(shadow_stack_size == 0 ? 1 : shadow_stack_size, 1);
        if (!shadow_stack) {
            return_value = -1;
            goto cleanup;
        }
    }

    safe_spill_slots = calloc(spill_slot_count, sizeof(*safe_spill_slots));
    if (!safe_spill_slots) {
        return_value = -1;
        goto cleanup;
    }

#ifdef DEBUG
    if (vm->regs) {
        reg = vm->regs;
    } else {
        reg = _reg;
    }
#else
    reg = _reg;
#endif

    uint16_t shadow_registers = 0;
    for (size_t i = 0; i < 16; i++) {
        safe_tags[i] = ubpf_safe_scalar_tag();
    }

    reg[1] = (uintptr_t)mem;
    reg[2] = (uint64_t)mem_len;
    reg[10] = (uintptr_t)stack_start + stack_length;

    if (mem != NULL && mem_len > 0) {
        safe_tags[1] = ubpf_safe_pointer_tag(
            UBPF_SAFE_REGION_ID_INPUT,
            UBPF_SAFE_REGION_READ | UBPF_SAFE_REGION_WRITE | UBPF_SAFE_REGION_ATOMIC,
            (uint64_t)(uintptr_t)mem,
            mem_len);
    }
    safe_tags[10] = ubpf_safe_pointer_tag(
        UBPF_SAFE_REGION_ID_STACK,
        UBPF_SAFE_REGION_READ | UBPF_SAFE_REGION_WRITE | UBPF_SAFE_REGION_ATOMIC,
        (uint64_t)(uintptr_t)stack_start,
        stack_length);

    shadow_registers |= REGISTER_TO_SHADOW_MASK(1) | REGISTER_TO_SHADOW_MASK(2) | REGISTER_TO_SHADOW_MASK(10);

    int instruction_limit = vm->instruction_limit;

#define SAFE_LOAD(size, sign_extend)                                                                          \
    do {                                                                                                      \
        if (!ubpf_safe_compute_access(                                                                        \
                vm, &safe_tags[inst.src], reg[inst.src], inst.offset, size, cur_pc, "load",                 \
                UBPF_SAFE_REGION_READ, &_eff_addr)) {                                                         \
            return_value = -1;                                                                                \
            goto cleanup;                                                                                     \
        }                                                                                                     \
        _ptr = (void*)_eff_addr;                                                                              \
        if (!ubpf_check_shadow_stack(vm, stack_start, stack_length, shadow_stack, _ptr, size)) {            \
            shadow_registers &= ~REGISTER_TO_SHADOW_MASK(inst.dst);                                           \
        }                                                                                                     \
        reg[inst.dst] = sign_extend ? ubpf_mem_load_sx(_eff_addr, size) : ubpf_mem_load(_eff_addr, size);   \
        safe_tags[inst.dst] = ubpf_safe_scalar_tag();                                                         \
        if (!(sign_extend) && size == 8 &&                                                                    \
            ubpf_safe_is_stack_pointer(&safe_tags[inst.src], stack_start, stack_length) &&                   \
            ((_eff_addr - (uint64_t)(uintptr_t)stack_start) % sizeof(uint64_t)) == 0) {                     \
            size_t safe_slot = (size_t)((_eff_addr - (uint64_t)(uintptr_t)stack_start) / sizeof(uint64_t)); \
            if (safe_spill_slots[safe_slot].valid) {                                                          \
                safe_tags[inst.dst] = safe_spill_slots[safe_slot].tag;                                        \
            }                                                                                                 \
        }                                                                                                     \
    } while (0)

#define SAFE_STORE(size, value, preserve_tag)                                                                 \
    do {                                                                                                      \
        if (!ubpf_safe_compute_access(                                                                        \
                vm, &safe_tags[inst.dst], reg[inst.dst], inst.offset, size, cur_pc, "store",                \
                UBPF_SAFE_REGION_WRITE, &_eff_addr)) {                                                        \
            return_value = -1;                                                                                \
            goto cleanup;                                                                                     \
        }                                                                                                     \
        _ptr = (void*)_eff_addr;                                                                              \
        ubpf_mem_store(_eff_addr, value, size);                                                               \
        ubpf_mark_shadow_stack(vm, stack_start, stack_length, shadow_stack, _ptr, size);                     \
        if (ubpf_safe_is_stack_pointer(&safe_tags[inst.dst], stack_start, stack_length)) {                   \
            ubpf_safe_invalidate_stack_spill_tags(safe_spill_slots, stack_start, stack_length, _eff_addr, size); \
            if (preserve_tag && size == 8 && ((_eff_addr - (uint64_t)(uintptr_t)stack_start) % sizeof(uint64_t)) == 0) { \
                size_t safe_slot = (size_t)((_eff_addr - (uint64_t)(uintptr_t)stack_start) / sizeof(uint64_t)); \
                safe_spill_slots[safe_slot].valid = true;                                                     \
                safe_spill_slots[safe_slot].tag = safe_tags[inst.src];                                        \
            }                                                                                                 \
        }                                                                                                     \
    } while (0)

    while (1) {
        const uint16_t cur_pc = pc;
        struct ebpf_inst inst;
        struct ubpf_safe_tag safe_dst_before;
        struct ubpf_safe_tag safe_src_before;
        bool safe_apply_alu_tag;

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

        inst = ubpf_fetch_instruction(vm, pc++);
        safe_dst_before = safe_tags[inst.dst];
        safe_src_before = safe_tags[inst.src];
        safe_apply_alu_tag = ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU) ||
                             ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU64);

        if (!ubpf_validate_shadow_register(vm, cur_pc, &shadow_registers, inst)) {
            vm->error_printf(stderr, "Error: Invalid register state at pc %d.\n", cur_pc);
            return_value = -1;
            goto cleanup;
        }

        if (vm->debug_function) {
            vm->debug_function(
                vm->debug_function_context,
                cur_pc,
                reg,
                stack_start,
                stack_length,
                shadow_registers,
                (uint8_t*)shadow_stack);
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
            if (inst.offset == 0) {
                reg[inst.dst] = u32(inst.imm) ? u32(reg[inst.dst]) / u32(inst.imm) : 0;
            } else if (inst.offset == 1) {
                dividend32 = (int32_t)reg[inst.dst];
                divisor32 = (int32_t)inst.imm;
                if (divisor32 == 0) {
                    reg[inst.dst] = 0;
                } else if (dividend32 == INT32_MIN && divisor32 == -1) {
                    reg[inst.dst] = (uint32_t)INT32_MIN;
                } else {
                    reg[inst.dst] = (uint32_t)(dividend32 / divisor32);
                }
            }
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_DIV_REG:
            if (inst.offset == 0) {
                reg[inst.dst] = u32(reg[inst.src]) ? u32(reg[inst.dst]) / u32(reg[inst.src]) : 0;
            } else if (inst.offset == 1) {
                dividend32 = (int32_t)reg[inst.dst];
                divisor32 = (int32_t)reg[inst.src];
                if (divisor32 == 0) {
                    reg[inst.dst] = 0;
                } else if (dividend32 == INT32_MIN && divisor32 == -1) {
                    reg[inst.dst] = (uint32_t)INT32_MIN;
                } else {
                    reg[inst.dst] = (uint32_t)(dividend32 / divisor32);
                }
            }
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
            if (inst.offset == 0) {
                reg[inst.dst] = u32(inst.imm) ? u32(reg[inst.dst]) % u32(inst.imm) : u32(reg[inst.dst]);
            } else if (inst.offset == 1) {
                dividend32 = (int32_t)reg[inst.dst];
                divisor32 = (int32_t)inst.imm;
                if (divisor32 != 0) {
                    if (dividend32 == INT32_MIN && divisor32 == -1) {
                        reg[inst.dst] = 0;
                    } else {
                        reg[inst.dst] = (uint32_t)(dividend32 % divisor32);
                    }
                }
            }
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOD_REG:
            if (inst.offset == 0) {
                reg[inst.dst] = u32(reg[inst.src]) ? u32(reg[inst.dst]) % u32(reg[inst.src]) : u32(reg[inst.dst]);
            } else if (inst.offset == 1) {
                dividend32 = (int32_t)reg[inst.dst];
                divisor32 = (int32_t)reg[inst.src];
                if (divisor32 != 0) {
                    if (dividend32 == INT32_MIN && divisor32 == -1) {
                        reg[inst.dst] = 0;
                    } else {
                        reg[inst.dst] = (uint32_t)(dividend32 % divisor32);
                    }
                }
            }
            reg[inst.dst] &= UINT32_MAX;
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
            if (inst.offset == 8) {
                reg[inst.dst] = (int32_t)(int8_t)(uint8_t)reg[inst.src];
            } else if (inst.offset == 16) {
                reg[inst.dst] = (int32_t)(int16_t)(uint16_t)reg[inst.src];
            } else {
                reg[inst.dst] = reg[inst.src];
            }
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
        case EBPF_OP_BSWAP:
            if (inst.imm == 16) {
#ifdef __GNUC__
                reg[inst.dst] = __builtin_bswap16(reg[inst.dst]);
#else
                reg[inst.dst] = (uint16_t)((((reg[inst.dst]) & 0xff00) >> 8) | (((reg[inst.dst]) & 0x00ff) << 8));
#endif
            } else if (inst.imm == 32) {
#ifdef __GNUC__
                reg[inst.dst] = __builtin_bswap32(reg[inst.dst]);
#else
                reg[inst.dst] = (uint32_t)((((reg[inst.dst]) & 0xff000000) >> 24) | (((reg[inst.dst]) & 0x00ff0000) >> 8) |
                                           (((reg[inst.dst]) & 0x0000ff00) << 8) | (((reg[inst.dst]) & 0x000000ff) << 24));
#endif
            } else if (inst.imm == 64) {
#ifdef __GNUC__
                reg[inst.dst] = __builtin_bswap64(reg[inst.dst]);
#else
                reg[inst.dst] = (uint64_t)((((reg[inst.dst]) & 0xff00000000000000ULL) >> 56) |
                                           (((reg[inst.dst]) & 0x00ff000000000000ULL) >> 40) |
                                           (((reg[inst.dst]) & 0x0000ff0000000000ULL) >> 24) |
                                           (((reg[inst.dst]) & 0x000000ff00000000ULL) >> 8) |
                                           (((reg[inst.dst]) & 0x00000000ff000000ULL) << 8) |
                                           (((reg[inst.dst]) & 0x0000000000ff0000ULL) << 24) |
                                           (((reg[inst.dst]) & 0x000000000000ff00ULL) << 40) |
                                           (((reg[inst.dst]) & 0x00000000000000ffULL) << 56));
#endif
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
            if (inst.offset == 0) {
                reg[inst.dst] = inst.imm ? reg[inst.dst] / inst.imm : 0;
            } else if (inst.offset == 1) {
                dividend64 = (int64_t)reg[inst.dst];
                divisor64 = (int64_t)inst.imm;
                if (divisor64 == 0) {
                    reg[inst.dst] = 0;
                } else if (dividend64 == INT64_MIN && divisor64 == -1) {
                    reg[inst.dst] = (uint64_t)INT64_MIN;
                } else {
                    reg[inst.dst] = (uint64_t)(dividend64 / divisor64);
                }
            }
            break;
        case EBPF_OP_DIV64_REG:
            if (inst.offset == 0) {
                reg[inst.dst] = reg[inst.src] ? reg[inst.dst] / reg[inst.src] : 0;
            } else if (inst.offset == 1) {
                dividend64 = (int64_t)reg[inst.dst];
                divisor64 = (int64_t)reg[inst.src];
                if (divisor64 == 0) {
                    reg[inst.dst] = 0;
                } else if (dividend64 == INT64_MIN && divisor64 == -1) {
                    reg[inst.dst] = (uint64_t)INT64_MIN;
                } else {
                    reg[inst.dst] = (uint64_t)(dividend64 / divisor64);
                }
            }
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
            if (inst.offset == 0) {
                reg[inst.dst] = inst.imm ? reg[inst.dst] % inst.imm : reg[inst.dst];
            } else if (inst.offset == 1) {
                dividend64 = (int64_t)reg[inst.dst];
                divisor64 = (int64_t)inst.imm;
                if (divisor64 != 0) {
                    if (dividend64 == INT64_MIN && divisor64 == -1) {
                        reg[inst.dst] = 0;
                    } else {
                        reg[inst.dst] = (uint64_t)(dividend64 % divisor64);
                    }
                }
            }
            break;
        case EBPF_OP_MOD64_REG:
            if (inst.offset == 0) {
                reg[inst.dst] = reg[inst.src] ? reg[inst.dst] % reg[inst.src] : reg[inst.dst];
            } else if (inst.offset == 1) {
                dividend64 = (int64_t)reg[inst.dst];
                divisor64 = (int64_t)reg[inst.src];
                if (divisor64 != 0) {
                    if (dividend64 == INT64_MIN && divisor64 == -1) {
                        reg[inst.dst] = 0;
                    } else {
                        reg[inst.dst] = (uint64_t)(dividend64 % divisor64);
                    }
                }
            }
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
            if (inst.offset == 8) {
                reg[inst.dst] = (int64_t)(int8_t)(uint8_t)reg[inst.src];
            } else if (inst.offset == 16) {
                reg[inst.dst] = (int64_t)(int16_t)(uint16_t)reg[inst.src];
            } else if (inst.offset == 32) {
                reg[inst.dst] = (int64_t)(int32_t)(uint32_t)reg[inst.src];
            } else {
                reg[inst.dst] = reg[inst.src];
            }
            break;
        case EBPF_OP_ARSH64_IMM:
            reg[inst.dst] = (int64_t)reg[inst.dst] >> SHIFT_MASK_64_BIT(inst.imm);
            break;
        case EBPF_OP_ARSH64_REG:
            reg[inst.dst] = (int64_t)reg[inst.dst] >> SHIFT_MASK_64_BIT(reg[inst.src]);
            break;
        case EBPF_OP_LDXW:
            SAFE_LOAD(4, false);
            break;
        case EBPF_OP_LDXH:
            SAFE_LOAD(2, false);
            break;
        case EBPF_OP_LDXB:
            SAFE_LOAD(1, false);
            break;
        case EBPF_OP_LDXDW:
            SAFE_LOAD(8, false);
            break;
        case EBPF_OP_LDXWSX:
            SAFE_LOAD(4, true);
            break;
        case EBPF_OP_LDXHSX:
            SAFE_LOAD(2, true);
            break;
        case EBPF_OP_LDXBSX:
            SAFE_LOAD(1, true);
            break;
        case EBPF_OP_STW:
            SAFE_STORE(4, inst.imm, false);
            break;
        case EBPF_OP_STH:
            SAFE_STORE(2, inst.imm, false);
            break;
        case EBPF_OP_STB:
            SAFE_STORE(1, inst.imm, false);
            break;
        case EBPF_OP_STDW:
            SAFE_STORE(8, inst.imm, false);
            break;
        case EBPF_OP_STXW:
            SAFE_STORE(4, reg[inst.src], false);
            break;
        case EBPF_OP_STXH:
            SAFE_STORE(2, reg[inst.src], false);
            break;
        case EBPF_OP_STXB:
            SAFE_STORE(1, reg[inst.src], false);
            break;
        case EBPF_OP_STXDW:
            SAFE_STORE(8, reg[inst.src], true);
            break;
        case EBPF_OP_LDDW:
            reg[inst.dst] = u32(inst.imm) | ((uint64_t)ubpf_fetch_instruction(vm, pc++).imm << 32);
            safe_tags[inst.dst] = ubpf_safe_scalar_tag();
            break;
        case EBPF_OP_JA:
            pc += inst.offset;
            break;
        case EBPF_OP_JA32:
            pc += inst.imm;
            break;
        case EBPF_OP_JEQ_IMM:
            if (reg[inst.dst] == (uint64_t)i64(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JEQ_REG:
            if (reg[inst.dst] == reg[inst.src]) pc += inst.offset;
            break;
        case EBPF_OP_JEQ32_IMM:
            if (u32(reg[inst.dst]) == u32(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JEQ32_REG:
            if (u32(reg[inst.dst]) == u32(reg[inst.src])) pc += inst.offset;
            break;
        case EBPF_OP_JGT_IMM:
            if (reg[inst.dst] > (uint64_t)i64(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JGT_REG:
            if (reg[inst.dst] > reg[inst.src]) pc += inst.offset;
            break;
        case EBPF_OP_JGT32_IMM:
            if (u32(reg[inst.dst]) > u32(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JGT32_REG:
            if (u32(reg[inst.dst]) > u32(reg[inst.src])) pc += inst.offset;
            break;
        case EBPF_OP_JGE_IMM:
            if (reg[inst.dst] >= (uint64_t)i64(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JGE_REG:
            if (reg[inst.dst] >= reg[inst.src]) pc += inst.offset;
            break;
        case EBPF_OP_JGE32_IMM:
            if (u32(reg[inst.dst]) >= u32(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JGE32_REG:
            if (u32(reg[inst.dst]) >= u32(reg[inst.src])) pc += inst.offset;
            break;
        case EBPF_OP_JLT_IMM:
            if (reg[inst.dst] < (uint64_t)i64(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JLT_REG:
            if (reg[inst.dst] < reg[inst.src]) pc += inst.offset;
            break;
        case EBPF_OP_JLT32_IMM:
            if (u32(reg[inst.dst]) < u32(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JLT32_REG:
            if (u32(reg[inst.dst]) < u32(reg[inst.src])) pc += inst.offset;
            break;
        case EBPF_OP_JLE_IMM:
            if (reg[inst.dst] <= (uint64_t)i64(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JLE_REG:
            if (reg[inst.dst] <= reg[inst.src]) pc += inst.offset;
            break;
        case EBPF_OP_JLE32_IMM:
            if (u32(reg[inst.dst]) <= u32(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JLE32_REG:
            if (u32(reg[inst.dst]) <= u32(reg[inst.src])) pc += inst.offset;
            break;
        case EBPF_OP_JSET_IMM:
            if (reg[inst.dst] & (uint64_t)i64(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JSET_REG:
            if (reg[inst.dst] & reg[inst.src]) pc += inst.offset;
            break;
        case EBPF_OP_JSET32_IMM:
            if (u32(reg[inst.dst]) & u32(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JSET32_REG:
            if (u32(reg[inst.dst]) & u32(reg[inst.src])) pc += inst.offset;
            break;
        case EBPF_OP_JNE_IMM:
            if (reg[inst.dst] != (uint64_t)i64(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JNE_REG:
            if (reg[inst.dst] != reg[inst.src]) pc += inst.offset;
            break;
        case EBPF_OP_JNE32_IMM:
            if (u32(reg[inst.dst]) != u32(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JNE32_REG:
            if (u32(reg[inst.dst]) != u32(reg[inst.src])) pc += inst.offset;
            break;
        case EBPF_OP_JSGT_IMM:
            if ((int64_t)reg[inst.dst] > i64(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JSGT_REG:
            if ((int64_t)reg[inst.dst] > (int64_t)reg[inst.src]) pc += inst.offset;
            break;
        case EBPF_OP_JSGT32_IMM:
            if (i32(reg[inst.dst]) > i32(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JSGT32_REG:
            if (i32(reg[inst.dst]) > i32(reg[inst.src])) pc += inst.offset;
            break;
        case EBPF_OP_JSGE_IMM:
            if ((int64_t)reg[inst.dst] >= i64(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JSGE_REG:
            if ((int64_t)reg[inst.dst] >= (int64_t)reg[inst.src]) pc += inst.offset;
            break;
        case EBPF_OP_JSGE32_IMM:
            if (i32(reg[inst.dst]) >= i32(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JSGE32_REG:
            if (i32(reg[inst.dst]) >= i32(reg[inst.src])) pc += inst.offset;
            break;
        case EBPF_OP_JSLT_IMM:
            if ((int64_t)reg[inst.dst] < i64(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JSLT_REG:
            if ((int64_t)reg[inst.dst] < (int64_t)reg[inst.src]) pc += inst.offset;
            break;
        case EBPF_OP_JSLT32_IMM:
            if (i32(reg[inst.dst]) < i32(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JSLT32_REG:
            if (i32(reg[inst.dst]) < i32(reg[inst.src])) pc += inst.offset;
            break;
        case EBPF_OP_JSLE_IMM:
            if ((int64_t)reg[inst.dst] <= i64(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JSLE_REG:
            if ((int64_t)reg[inst.dst] <= (int64_t)reg[inst.src]) pc += inst.offset;
            break;
        case EBPF_OP_JSLE32_IMM:
            if (i32(reg[inst.dst]) <= i32(inst.imm)) pc += inst.offset;
            break;
        case EBPF_OP_JSLE32_REG:
            if (i32(reg[inst.dst]) <= i32(reg[inst.src])) pc += inst.offset;
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
                safe_tags[BPF_REG_1] = ubpf_safe_scalar_tag();
                safe_tags[BPF_REG_2] = ubpf_safe_scalar_tag();
                safe_tags[BPF_REG_3] = ubpf_safe_scalar_tag();
                safe_tags[BPF_REG_4] = ubpf_safe_scalar_tag();
                safe_tags[BPF_REG_5] = ubpf_safe_scalar_tag();
                safe_tags[BPF_REG_6] = safe_frames[stack_frame_index].saved_register_tags[0];
                safe_tags[BPF_REG_7] = safe_frames[stack_frame_index].saved_register_tags[1];
                safe_tags[BPF_REG_8] = safe_frames[stack_frame_index].saved_register_tags[2];
                safe_tags[BPF_REG_9] = safe_frames[stack_frame_index].saved_register_tags[3];
                break;
            }
            *bpf_return_value = reg[0];
            return_value = 0;
            goto cleanup;
        case EBPF_OP_CALL:
            if (inst.src == 0) {
                const struct ubpf_safe_helper_metadata* helper = NULL;
                const struct ubpf_safe_region_internal* region = NULL;

                if (inst.imm < 0 || inst.imm >= MAX_EXT_FUNCS || !vm->safe_helpers[inst.imm].in_use) {
                    vm->error_printf(
                        stderr, "uBPF safe mode error: helper metadata is missing for helper %d at PC %u\n", inst.imm, cur_pc);
                    return_value = -1;
                    goto cleanup;
                }

                helper = &vm->safe_helpers[inst.imm];
                if (helper->result_kind != UBPF_SAFE_HELPER_RESULT_SCALAR) {
                    region = ubpf_safe_find_region_by_id(vm, helper->region_id);
                    if (region == NULL) {
                        vm->error_printf(
                            stderr,
                            "uBPF safe mode error: helper %d references unknown region %u at PC %u\n",
                            inst.imm,
                            helper->region_id,
                            cur_pc);
                        return_value = -1;
                        goto cleanup;
                    }
                }

                if (vm->dispatcher != NULL) {
                    reg[0] = vm->dispatcher(reg[1], reg[2], reg[3], reg[4], reg[5], inst.imm, external_dispatcher_cookie);
                } else {
                    reg[0] = vm->ext_funcs[inst.imm](reg[1], reg[2], reg[3], reg[4], reg[5], external_dispatcher_cookie);
                }
                if (inst.imm == vm->unwind_stack_extension_index && reg[0] == 0) {
                    *bpf_return_value = reg[0];
                    return_value = 0;
                    goto cleanup;
                }

                safe_tags[BPF_REG_1] = ubpf_safe_scalar_tag();
                safe_tags[BPF_REG_2] = ubpf_safe_scalar_tag();
                safe_tags[BPF_REG_3] = ubpf_safe_scalar_tag();
                safe_tags[BPF_REG_4] = ubpf_safe_scalar_tag();
                safe_tags[BPF_REG_5] = ubpf_safe_scalar_tag();
                switch (helper->result_kind) {
                case UBPF_SAFE_HELPER_RESULT_SCALAR:
                    safe_tags[0] = ubpf_safe_scalar_tag();
                    break;
                case UBPF_SAFE_HELPER_RESULT_POINTER:
                case UBPF_SAFE_HELPER_RESULT_HANDLE: {
                    region = ubpf_safe_find_region_by_id(vm, helper->region_id);
                    if (region == NULL) {
                        vm->error_printf(
                            stderr,
                            "uBPF safe mode error: helper %d references unknown region %u at PC %u\n",
                            inst.imm,
                            helper->region_id,
                            cur_pc);
                        return_value = -1;
                        goto cleanup;
                    }
                    if (reg[0] < region->base || reg[0] > region->end || helper->region_size > (region->end - reg[0])) {
                        vm->error_printf(
                            stderr, "uBPF safe mode error: helper %d returned an out-of-range pointer at PC %u\n", inst.imm, cur_pc);
                        return_value = -1;
                        goto cleanup;
                    }
                    safe_tags[0] =
                        helper->result_kind == UBPF_SAFE_HELPER_RESULT_POINTER
                            ? ubpf_safe_pointer_tag(helper->region_id, region->permissions, reg[0], helper->region_size)
                            : ubpf_safe_handle_tag(helper->region_id, region->permissions, reg[0], helper->region_size);
                    break;
                }
                default:
                    return_value = -1;
                    goto cleanup;
                }
            } else if (inst.src == 1) {
                if (stack_frame_index >= UBPF_MAX_CALL_DEPTH) {
                    vm->error_printf(
                        stderr,
                        "uBPF error: number of nested functions calls (%u) exceeds max (%u) at PC %u\n",
                        (unsigned)(stack_frame_index + 1),
                        (unsigned)UBPF_MAX_CALL_DEPTH,
                        cur_pc);
                    return_value = -1;
                    goto cleanup;
                }
                stack_frames[stack_frame_index].saved_registers[0] = reg[BPF_REG_6];
                stack_frames[stack_frame_index].saved_registers[1] = reg[BPF_REG_7];
                stack_frames[stack_frame_index].saved_registers[2] = reg[BPF_REG_8];
                stack_frames[stack_frame_index].saved_registers[3] = reg[BPF_REG_9];
                stack_frames[stack_frame_index].return_address = pc;
                safe_frames[stack_frame_index].saved_register_tags[0] = safe_tags[BPF_REG_6];
                safe_frames[stack_frame_index].saved_register_tags[1] = safe_tags[BPF_REG_7];
                safe_frames[stack_frame_index].saved_register_tags[2] = safe_tags[BPF_REG_8];
                safe_frames[stack_frame_index].saved_register_tags[3] = safe_tags[BPF_REG_9];

                reg[BPF_REG_10] -= stack_frames[stack_frame_index].stack_usage;

                stack_frame_index++;
                pc += inst.imm;
                break;
            } else if (inst.src == 2) {
                return_value = -1;
                goto cleanup;
            }
            break;
        case EBPF_OP_ATOMIC_STORE:
            if (!ubpf_safe_compute_access(
                    vm,
                    &safe_tags[inst.dst],
                    reg[inst.dst],
                    inst.offset,
                    8,
                    cur_pc,
                    "atomic",
                    UBPF_SAFE_REGION_WRITE | UBPF_SAFE_REGION_ATOMIC,
                    &_eff_addr)) {
                return_value = -1;
                goto cleanup;
            }
            ubpf_safe_invalidate_stack_spill_tags(safe_spill_slots, stack_start, stack_length, _eff_addr, 8);
            atomic_fetch = inst.imm & EBPF_ATOMIC_OP_FETCH;
            atomic_fetch_index = inst.src;
            atomic_dest64 = (volatile uint64_t*)_eff_addr;
            atomic_val64 = reg[inst.src];
            switch (inst.imm & EBPF_ALU_OP_MASK) {
            case EBPF_ALU_OP_ADD:
                atomic_res64 = UBPF_ATOMIC_ADD_FETCH(atomic_dest64, atomic_val64);
                break;
            case EBPF_ALU_OP_OR:
                atomic_res64 = UBPF_ATOMIC_OR_FETCH(atomic_dest64, atomic_val64);
                break;
            case EBPF_ALU_OP_AND:
                atomic_res64 = UBPF_ATOMIC_AND_FETCH(atomic_dest64, atomic_val64);
                break;
            case EBPF_ALU_OP_XOR:
                atomic_res64 = UBPF_ATOMIC_XOR_FETCH(atomic_dest64, atomic_val64);
                break;
            case (EBPF_ATOMIC_OP_XCHG & ~EBPF_ATOMIC_OP_FETCH):
                atomic_res64 = UBPF_ATOMIC_EXCHANGE(atomic_dest64, atomic_val64);
                break;
            case (EBPF_ATOMIC_OP_CMPXCHG & ~EBPF_ATOMIC_OP_FETCH):
                atomic_res64 = UBPF_ATOMIC_COMPARE_EXCHANGE(atomic_dest64, reg[0], atomic_val64);
                atomic_fetch_index = 0;
                break;
            default:
                vm->error_printf(stderr, "Error: unknown atomic opcode %d at PC %d\n", inst.imm, cur_pc);
                return_value = -1;
                goto cleanup;
            }
            if (atomic_fetch) {
                reg[atomic_fetch_index] = atomic_res64;
                safe_tags[atomic_fetch_index] = ubpf_safe_scalar_tag();
            }
            break;
        case EBPF_OP_ATOMIC32_STORE:
            if (!ubpf_safe_compute_access(
                    vm,
                    &safe_tags[inst.dst],
                    reg[inst.dst],
                    inst.offset,
                    4,
                    cur_pc,
                    "atomic",
                    UBPF_SAFE_REGION_WRITE | UBPF_SAFE_REGION_ATOMIC,
                    &_eff_addr)) {
                return_value = -1;
                goto cleanup;
            }
            ubpf_safe_invalidate_stack_spill_tags(safe_spill_slots, stack_start, stack_length, _eff_addr, 4);
            atomic_fetch = (inst.imm & EBPF_ATOMIC_OP_FETCH) || (inst.imm == EBPF_ATOMIC_OP_CMPXCHG) ||
                           (inst.imm == EBPF_ATOMIC_OP_XCHG);
            atomic_fetch_index = inst.src;
            atomic_dest32 = (volatile uint32_t*)_eff_addr;
            atomic_val32 = u32(reg[inst.src]);
            switch (inst.imm & EBPF_ALU_OP_MASK) {
            case EBPF_ALU_OP_ADD:
                atomic_res32 = UBPF_ATOMIC_ADD_FETCH32(atomic_dest32, atomic_val32);
                break;
            case EBPF_ALU_OP_OR:
                atomic_res32 = UBPF_ATOMIC_OR_FETCH32(atomic_dest32, atomic_val32);
                break;
            case EBPF_ALU_OP_AND:
                atomic_res32 = UBPF_ATOMIC_AND_FETCH32(atomic_dest32, atomic_val32);
                break;
            case EBPF_ALU_OP_XOR:
                atomic_res32 = UBPF_ATOMIC_XOR_FETCH32(atomic_dest32, atomic_val32);
                break;
            case (EBPF_ATOMIC_OP_XCHG & ~EBPF_ATOMIC_OP_FETCH):
                atomic_res32 = UBPF_ATOMIC_EXCHANGE32(atomic_dest32, atomic_val32);
                break;
            case (EBPF_ATOMIC_OP_CMPXCHG & ~EBPF_ATOMIC_OP_FETCH):
                atomic_res32 = UBPF_ATOMIC_COMPARE_EXCHANGE32(atomic_dest32, u32(reg[0]), atomic_val32);
                atomic_fetch_index = 0;
                break;
            default:
                vm->error_printf(stderr, "Error: unknown atomic opcode %d at PC %d\n", inst.imm, cur_pc);
                return_value = -1;
                goto cleanup;
            }
            if (atomic_fetch) {
                reg[atomic_fetch_index] = atomic_res32;
                safe_tags[atomic_fetch_index] = ubpf_safe_scalar_tag();
            }
            break;
        default:
            vm->error_printf(stderr, "Error: unknown opcode %d at PC %d\n", inst.opcode, cur_pc);
            return_value = -1;
            goto cleanup;
        }

        if (safe_apply_alu_tag &&
            !ubpf_safe_apply_alu(vm, inst, cur_pc, safe_dst_before, safe_src_before, reg[inst.dst], &safe_tags[inst.dst])) {
            return_value = -1;
            goto cleanup;
        }

        if (((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU) && (inst.opcode & EBPF_ALU_OP_MASK) != 0xd0) {
            reg[inst.dst] &= UINT32_MAX;
        }
    }

cleanup:
    free(safe_spill_slots);
    free(shadow_stack);
    return return_value;
}
