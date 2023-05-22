// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stddef.h>

struct bpf_map;

static void* (*bpf_map_lookup_elem)(void* map, const void* key) = (void* (*)(void* map, const void* key))6;
static int (*bpf_map_update_elem)(void* map, const void* key, const void* value, unsigned long flags) =
    (int (*)(void*, const void*, const void*, unsigned long))7;
static int (*bpf_map_delete_elem)(void* map, const void* key) = (int (*)(void*, const void*))8;

#define BPF_MAP_TYPE_ARRAY 2

struct bpf_map_def
{
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
    unsigned int inner_map_idx;
    unsigned int numa_node;
};
