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
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include "ubpf_int.h"


int
ubpf_translate(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg)
{
    struct ubpf_jit_result jit_result = vm->jit_translate(vm, buffer, size);
    vm->jitted_result = jit_result;
    if (jit_result.errmsg) {
        *errmsg = jit_result.errmsg;
    }
    return jit_result.compile_result == UBPF_JIT_COMPILE_SUCCESS ? 0 : -1;
}

struct ubpf_jit_result
ubpf_translate_null(struct ubpf_vm* vm, uint8_t* buffer, size_t* size)
{
    struct ubpf_jit_result compile_result;
    compile_result.compile_result = UBPF_JIT_COMPILE_FAILURE;
    compile_result.external_dispatcher_offset = 0;

    /* NULL JIT target - just returns an error. */
    UNUSED_PARAMETER(vm);
    UNUSED_PARAMETER(buffer);
    UNUSED_PARAMETER(size);
    compile_result.errmsg = ubpf_error("Code can not be JITed on this target.");
    return compile_result;
}

bool ubpf_jit_update_dispatcher_null(struct ubpf_vm* vm, external_function_dispatcher_t new_dispatcher, uint8_t* buffer, size_t size, uint32_t offset)
{
    UNUSED_PARAMETER(vm);
    UNUSED_PARAMETER(new_dispatcher);
    UNUSED_PARAMETER(buffer);
    UNUSED_PARAMETER(size);
    UNUSED_PARAMETER(offset);
    return false;
}

bool ubpf_jit_update_helper_null(struct ubpf_vm* vm, ext_func new_helper, unsigned int idx, uint8_t* buffer, size_t size, uint32_t offset)
{
    UNUSED_PARAMETER(vm);
    UNUSED_PARAMETER(new_helper);
    UNUSED_PARAMETER(idx);
    UNUSED_PARAMETER(buffer);
    UNUSED_PARAMETER(size);
    UNUSED_PARAMETER(offset);
    return false;
}

int
ubpf_set_jit_code_size(struct ubpf_vm* vm, size_t code_size)
{
    vm->jitter_buffer_size = code_size;
    return 0;
}

ubpf_jit_fn
ubpf_compile(struct ubpf_vm* vm, char** errmsg)
{
    void* jitted = NULL;
    uint8_t* buffer = NULL;
    size_t jitted_size;

    if (vm->jitted) {
        return vm->jitted;
    }

    *errmsg = NULL;

    if (!vm->insts) {
        *errmsg = ubpf_error("code has not been loaded into this VM");
        return NULL;
    }

    jitted_size = vm->jitter_buffer_size;
    buffer = calloc(jitted_size, 1);
    if (buffer == NULL) {
        *errmsg = ubpf_error("internal uBPF error: calloc failed: %s\n", strerror(errno));
        goto out;
    }

    if (ubpf_translate(vm, buffer, &jitted_size, errmsg) < 0) {
        goto out;
    }

    jitted = mmap(0, jitted_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (jitted == MAP_FAILED) {
        *errmsg = ubpf_error("internal uBPF error: mmap failed: %s\n", strerror(errno));
        goto out;
    }

    memcpy(jitted, buffer, jitted_size);

    if (mprotect(jitted, jitted_size, PROT_READ | PROT_EXEC) < 0) {
        *errmsg = ubpf_error("internal uBPF error: mprotect failed: %s\n", strerror(errno));
        goto out;
    }

    vm->jitted = jitted;
    vm->jitted_size = jitted_size;

out:
    free(buffer);
    if (jitted && vm->jitted == NULL) {
        munmap(jitted, jitted_size);
    }
    return vm->jitted;
}

ubpf_jit_fn
ubpf_copy_jit(struct ubpf_vm *vm, void *buffer, size_t size, char **errmsg)
{
    // If compilation was not successfull or it has not even been attempted,
    // we cannot copy.
    if (vm->jitted_result.compile_result != UBPF_JIT_COMPILE_SUCCESS || !vm->jitted) {
        *errmsg = ubpf_error("Cannot copy JIT'd code before compilation");
        return (ubpf_jit_fn)NULL;
    }

    // If the given buffer is not big enough to contain the JIT'd code,
    // we cannot copy.
    if (vm->jitted_size > size) {
        *errmsg = ubpf_error("Buffer not big enough for copy");
        return (ubpf_jit_fn)NULL;
    }

    // All good. Do the copy!
    memcpy(buffer, vm->jitted, vm->jitted_size);
    *errmsg = NULL;
    return (ubpf_jit_fn)buffer;
}
