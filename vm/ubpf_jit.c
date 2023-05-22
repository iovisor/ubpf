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
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <errno.h>
#include <assert.h>
#include "ubpf_int.h"
#include "ubpf_jit_x86_64.h"

#define UNUSED(x) ((void)x)

int
ubpf_translate(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg)
{
    return vm->translate(vm, buffer, size, errmsg);
}

int
ubpf_translate_null(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg)
{
    /* NULL JIT target - just returns an error. */
    UNUSED(vm);
    UNUSED(buffer);
    UNUSED(size);
    *errmsg = ubpf_error("Code can not be JITed on this target.");
    return -1;
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

    jitted_size = 65536;
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
