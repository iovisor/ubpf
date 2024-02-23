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

#include <ubpf_config.h>

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <math.h>
#include "ubpf.h"

#include "../bpf/bpf.h"

#if defined(UBPF_HAS_ELF_H)
#if defined(UBPF_HAS_ELF_H_COMPAT)
#include <libelf.h>
#else
#include <elf.h>
#endif
#endif

void
ubpf_set_register_offset(int x);
static void*
readfile(const char* path, size_t maxlen, size_t* len);
static void
register_functions(struct ubpf_vm* vm);

static void
usage(const char* name)
{
    fprintf(stderr, "usage: %s [-h] [-j|--jit] [-m|--mem PATH] BINARY\n", name);
    fprintf(stderr, "\nExecutes the eBPF code in BINARY and prints the result to stdout.\n");
    fprintf(
        stderr, "If --mem is given then the specified file will be read and a pointer\nto its data passed in r1.\n");
    fprintf(stderr, "If --jit is given then the JIT compiler will be used.\n");
    fprintf(stderr, "\nOther options:\n");
    fprintf(stderr, "  -r, --register-offset NUM: Change the mapping from eBPF to x86 registers\n");
    fprintf(
        stderr,
        "  -d, --data: Change from treating R_BPF_64_64 relocations as relocations to maps to relocations to data.\n");
    fprintf(stderr, "  -U, --unload: unload the code and reload it (for testing only)\n");
    fprintf(
        stderr, "  -R, --reload: reload the code, without unloading it first (for testing only, this should fail)\n");
    fprintf(stderr, "  -s, --main-function NAME: Consider the symbol NAME to be the eBPF program's entry point");
}

typedef struct _map_entry
{
    struct bpf_map_def map_definition;
    const char* map_name;
    union
    {
        uint8_t* array;
    };
} map_entry_t;

static map_entry_t* _map_entries = NULL;
static int _map_entries_count = 0;
static int _map_entries_capacity = 0;
static uint8_t* _global_data = NULL;
static uint64_t _global_data_size = 0;

uint64_t
do_data_relocation(
    void* user_context,
    const uint8_t* map_data,
    uint64_t map_data_size,
    const char* symbol_name,
    uint64_t symbol_offset,
    uint64_t symbol_size)
{
    (void)user_context; // unused
    (void)symbol_name;  // unused
    (void)symbol_size;  // unused
    if (_global_data == NULL) {
        _global_data = calloc(map_data_size, sizeof(uint8_t));
        _global_data_size = map_data_size;
        memcpy(_global_data, map_data, map_data_size);
    }

    const uint64_t* target_address = (const uint64_t*)((uint64_t)_global_data + symbol_offset);
    return (uint64_t)target_address;
}

bool
data_relocation_bounds_check_function(void* user_context, uint64_t addr, uint64_t size)
{
    (void)user_context; // unused
    if ((uint64_t)_global_data <= addr && (addr + size) <= ((uint64_t)_global_data + _global_data_size)) {
        return true;
    }
    return false;
}

uint64_t
do_map_relocation(
    void* user_context,
    const uint8_t* map_data,
    uint64_t map_data_size,
    const char* symbol_name,
    uint64_t symbol_offset,
    uint64_t symbol_size)
{
    struct bpf_map_def map_definition = *(struct bpf_map_def*)(map_data + symbol_offset);
    (void)user_context;  // unused
    (void)symbol_offset; // unused
    (void)map_data_size; // unused

    if (symbol_size < sizeof(struct bpf_map_def)) {
        fprintf(stderr, "Invalid map size: %d\n", (int)symbol_size);
        return 0;
    }

    if (map_definition.type != BPF_MAP_TYPE_ARRAY) {
        fprintf(stderr, "Unsupported map type %d\n", map_definition.type);
        return 0;
    }

    if (map_definition.key_size != sizeof(uint32_t)) {
        fprintf(stderr, "Unsupported key size %d\n", map_definition.key_size);
        return 0;
    }

    for (int index = 0; index < _map_entries_count; index++) {
        if (strcmp(_map_entries[index].map_name, symbol_name) == 0) {
            return (uint64_t)&_map_entries[index];
        }
    }

    if (_map_entries_count == _map_entries_capacity) {
        _map_entries_capacity = _map_entries_capacity ? _map_entries_capacity * 2 : 4;
        _map_entries = realloc(_map_entries, _map_entries_capacity * sizeof(map_entry_t));
    }

    _map_entries[_map_entries_count].map_definition = map_definition;
    _map_entries[_map_entries_count].map_name = strdup(symbol_name);
    _map_entries[_map_entries_count].array = calloc(map_definition.max_entries, map_definition.value_size);

    return (uint64_t)&_map_entries[_map_entries_count++];
}

bool
map_relocation_bounds_check_function(void* user_context, uint64_t addr, uint64_t size)
{
    (void)user_context;
    for (int index = 0; index < _map_entries_count; index++) {
        if (addr >= (uint64_t)_map_entries[index].array &&
            addr + size <= (uint64_t)_map_entries[index].array + _map_entries[index].map_definition.max_entries *
                                                                     _map_entries[index].map_definition.value_size) {
            return true;
        }
    }
    return false;
}

int
main(int argc, char** argv)
{
    struct option longopts[] = {
        {
            .name = "help",
            .val = 'h',
        },
        {.name = "mem", .val = 'm', .has_arg = 1},
        {.name = "jit", .val = 'j'},
        {.name = "data", .val = 'd'},
        {.name = "register-offset", .val = 'r', .has_arg = 1},
        {.name = "unload", .val = 'U'}, /* for unit test only */
        {.name = "reload", .val = 'R'}, /* for unit test only */
        {.name = "main-function", .val = 's', .has_arg = 1},
        {0}};

    const char* mem_filename = NULL;
    const char* main_function_name = NULL;
    bool jit = false;
    bool unload = false;
    bool reload = false;
    bool data_relocation = false; // treat R_BPF_64_64 as relocations to maps by default.

    uint64_t secret = (uint64_t)rand() << 32 | (uint64_t)rand();

    int opt;
    while ((opt = getopt_long(argc, argv, "hm:jdr:URs:", longopts, NULL)) != -1) {
        switch (opt) {
        case 'm':
            mem_filename = optarg;
            break;
        case 's':
            main_function_name = optarg;
            break;
        case 'j':
            jit = true;
            break;
        case 'd':
            data_relocation = true;
            break;
        case 'r':
            ubpf_set_register_offset(atoi(optarg));
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        case 'U':
            unload = true;
            break;
        case 'R':
            reload = true;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (unload && reload) {
        fprintf(stderr, "-U and -R can not be used together\n");
        return 1;
    }

    if (argc != optind + 1) {
        usage(argv[0]);
        return 1;
    }

    const char* code_filename = argv[optind];
    size_t code_len;
    void* code = readfile(code_filename, 1024 * 1024, &code_len);
    if (code == NULL) {
        return 1;
    }

    size_t mem_len = 0;
    void* mem = NULL;
    if (mem_filename != NULL) {
        mem = readfile(mem_filename, 1024 * 1024, &mem_len);
        if (mem == NULL) {
            return 1;
        }
    }

    struct ubpf_vm* vm = ubpf_create();
    if (!vm) {
        fprintf(stderr, "Failed to create VM\n");
        return 1;
    }

    if (data_relocation) {
        ubpf_register_data_relocation(vm, NULL, do_data_relocation);
        ubpf_register_data_bounds_check(vm, NULL, data_relocation_bounds_check_function);
    } else {
        ubpf_register_data_relocation(vm, NULL, do_map_relocation);
        ubpf_register_data_bounds_check(vm, NULL, map_relocation_bounds_check_function);
    }

    if (ubpf_set_pointer_secret(vm, secret) != 0) {
        fprintf(stderr, "Failed to set pointer secret\n");
        return 1;
    }

    register_functions(vm);

    /*
     * The ELF magic corresponds to an RSH instruction with an offset,
     * which is invalid.
     */
#if defined(UBPF_HAS_ELF_H)
    bool elf = code_len >= SELFMAG && !memcmp(code, ELFMAG, SELFMAG);
#endif

    char* errmsg;
    int rv;
load:
#if defined(UBPF_HAS_ELF_H)
    if (elf) {
        rv = ubpf_load_elf_ex(vm, code, code_len, main_function_name, &errmsg);
    } else {
#endif
        rv = ubpf_load(vm, code, code_len, &errmsg);
#if defined(UBPF_HAS_ELF_H)
    }
#endif
    if (unload) {
        ubpf_unload_code(vm);
        unload = false;
        goto load;
    }
    if (reload) {
        reload = false;
        goto load;
    }

    free(code);

    if (rv < 0) {
        fprintf(stderr, "Failed to load code: %s\n", errmsg);
        free(errmsg);
        ubpf_destroy(vm);
        return 1;
    }

    uint64_t ret;

    if (jit) {
        ubpf_jit_fn fn = ubpf_compile(vm, &errmsg);
        if (fn == NULL) {
            fprintf(stderr, "Failed to compile: %s\n", errmsg);
            free(errmsg);
            free(mem);
            return 1;
        }
        ret = fn(mem, mem_len);
    } else {
        if (ubpf_exec(vm, mem, mem_len, &ret) < 0)
            ret = UINT64_MAX;
    }

    printf("0x%" PRIx64 "\n", ret);

    ubpf_destroy(vm);
    free(mem);

    return 0;
}

static void*
readfile(const char* path, size_t maxlen, size_t* len)
{
    FILE* file;
    if (!strcmp(path, "-")) {
        file = fdopen(STDIN_FILENO, "r");
    } else {
        file = fopen(path, "r");
    }

    if (file == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return NULL;
    }

    char* data = calloc(maxlen, 1);
    size_t offset = 0;
    size_t rv;
    while ((rv = fread(data + offset, 1, maxlen - offset, file)) > 0) {
        offset += rv;
    }

    if (ferror(file)) {
        fprintf(stderr, "Failed to read %s: %s\n", path, strerror(errno));
        fclose(file);
        free(data);
        return NULL;
    }

    if (!feof(file)) {
        fprintf(stderr, "Failed to read %s because it is too large (max %u bytes)\n", path, (unsigned)maxlen);
        fclose(file);
        free(data);
        return NULL;
    }

    fclose(file);
    if (len) {
        *len = offset;
    }
    return (void*)data;
}

#ifndef __GLIBC__
void*
memfrob(void* s, size_t n)
{
    for (int i = 0; i < n; i++) {
        ((char*)s)[i] ^= 42;
    }
    return s;
}
#endif

static uint64_t
gather_bytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e)
{
    return ((uint64_t)a << 32) | ((uint32_t)b << 24) | ((uint32_t)c << 16) | ((uint16_t)d << 8) | e;
}

static void
trash_registers(void)
{
    /* Overwrite all caller-save registers */
#if __x86_64__
    asm("mov $0xf0, %rax;"
        "mov $0xf1, %rcx;"
        "mov $0xf2, %rdx;"
        "mov $0xf3, %rsi;"
        "mov $0xf4, %rdi;"
        "mov $0xf5, %r8;"
        "mov $0xf6, %r9;"
        "mov $0xf7, %r10;"
        "mov $0xf8, %r11;");
#elif __aarch64__
    asm("mov w0, #0xf0;"
        "mov w1, #0xf1;"
        "mov w2, #0xf2;"
        "mov w3, #0xf3;"
        "mov w4, #0xf4;"
        "mov w5, #0xf5;"
        "mov w6, #0xf6;"
        "mov w7, #0xf7;"
        "mov w8, #0xf8;"
        "mov w9, #0xf9;"
        "mov w10, #0xfa;"
        "mov w11, #0xfb;"
        "mov w12, #0xfc;"
        "mov w13, #0xfd;"
        "mov w14, #0xfe;"
        "mov w15, #0xff;" ::
            : "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15");
#else
    fprintf(stderr, "trash_registers not implemented for this architecture.\n");
    exit(1);
#endif
}

static uint32_t
sqrti(uint32_t x)
{
    return sqrt(x);
}

static uint64_t
unwind(uint64_t i)
{
    return i;
}

static void*
bpf_map_lookup_elem_impl(struct bpf_map* map, const void* key)
{
    map_entry_t* map_entry = (map_entry_t*)map;
    if (map_entry->map_definition.type == BPF_MAP_TYPE_ARRAY) {
        uint32_t index = *(uint32_t*)key;
        if (index >= map_entry->map_definition.max_entries) {
            return NULL;
        }
        return map_entry->array + index * map_entry->map_definition.value_size;
    } else {
        fprintf(stderr, "bpf_map_lookup_elem not implemented for this map type.\n");
        exit(1);
    }
    return NULL;
}

static int
bpf_map_update_elem_impl(struct bpf_map* map, const void* key, const void* value, uint64_t flags)
{
    map_entry_t* map_entry = (map_entry_t*)map;
    (void)flags; // unused
    if (map_entry->map_definition.type == BPF_MAP_TYPE_ARRAY) {
        uint32_t index = *(uint32_t*)key;
        if (index >= map_entry->map_definition.max_entries) {
            return -1;
        }
        memcpy(
            map_entry->array + index * map_entry->map_definition.value_size,
            value,
            map_entry->map_definition.value_size);
        return 0;
    } else {
        fprintf(stderr, "bpf_map_update_elem not implemented for this map type.\n");
        exit(1);
    }
    return 0;
}

static int
bpf_map_delete_elem_impl(struct bpf_map* map, const void* key)
{
    map_entry_t* map_entry = (map_entry_t*)map;
    if (map_entry->map_definition.type == BPF_MAP_TYPE_ARRAY) {
        uint32_t index = *(uint32_t*)key;
        if (index >= map_entry->map_definition.max_entries) {
            return -1;
        }
        memset(
            map_entry->array + index * map_entry->map_definition.value_size, 0, map_entry->map_definition.value_size);
        return 0;
    } else {
        fprintf(stderr, "bpf_map_delete_elem not implemented for this map type.\n");
        exit(1);
    }
}

static void
register_functions(struct ubpf_vm* vm)
{
    ubpf_register(vm, 0, "gather_bytes", as_external_function_t(gather_bytes));
    ubpf_register(vm, 1, "memfrob", as_external_function_t(memfrob));
    ubpf_register(vm, 2, "trash_registers", as_external_function_t(trash_registers));
    ubpf_register(vm, 3, "sqrti", as_external_function_t(sqrti));
    ubpf_register(vm, 4, "strcmp_ext", as_external_function_t(strcmp));
    ubpf_register(vm, 5, "unwind", as_external_function_t(unwind));
    ubpf_set_unwind_function_index(vm, 5);
    ubpf_register(
        vm,
        (unsigned int)(uintptr_t)bpf_map_lookup_elem,
        "bpf_map_lookup_elem",
        as_external_function_t(bpf_map_lookup_elem_impl));
    ubpf_register(
        vm,
        (unsigned int)(uintptr_t)bpf_map_update_elem,
        "bpf_map_update_elem",
        as_external_function_t(bpf_map_update_elem_impl));
    ubpf_register(
        vm,
        (unsigned int)(uintptr_t)bpf_map_delete_elem,
        "bpf_map_delete_elem",
        as_external_function_t(bpf_map_delete_elem_impl));
}
