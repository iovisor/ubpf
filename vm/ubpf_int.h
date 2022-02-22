/*
 * Copyright 2015 Big Switch Networks, Inc
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
 */

#ifndef UBPF_INT_H
#define UBPF_INT_H

#include <ubpf.h>
#include "ebpf.h"

struct ebpf_inst;
typedef uint64_t (*ext_func)(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);

struct ubpf_vm {
    struct ebpf_inst *insts;
    uint16_t num_insts;
    ubpf_jit_fn jitted;
    size_t jitted_size;
    ext_func *ext_funcs;
    const char **ext_func_names;
    bool bounds_check_enabled;
    int (*error_printf)(FILE* stream, const char* format, ...);
    int (*translate)(struct ubpf_vm *vm, uint8_t *buffer, size_t *size, char **errmsg);
    int unwind_stack_extension_index;
};

/* The various JIT targets.  */
int ubpf_translate_x86_64(struct ubpf_vm *vm, uint8_t * buffer, size_t * size, char **errmsg);
int ubpf_translate_null(struct ubpf_vm *vm, uint8_t * buffer, size_t * size, char **errmsg);

char *ubpf_error(const char *fmt, ...);
unsigned int ubpf_lookup_registered_function(struct ubpf_vm *vm, const char *name);

extern const char* ubpf_string_table[1];
#define UBPF_STRING_ID_DIVIDE_BY_ZERO 0

#endif
