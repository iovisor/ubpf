// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: Apache-2.0

#include "bpf.h"

struct bpf_map_def map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(unsigned long),
    .max_entries = 10,
};

unsigned long
map_test(void* memory, size_t memory_length)
{
    unsigned int key = 5;
    unsigned long new_value = 0x1234567890ABCDEF;
    unsigned long* value = bpf_map_lookup_elem(&map, &key);
    if (value == NULL) {
        return 1;
    }

    if (*value != 0) {
        return 2;
    }

    if (bpf_map_update_elem(&map, &key, &new_value, 0) != 0) {
        return 3;
    }

    value = bpf_map_lookup_elem(&map, &key);
    if (value == NULL) {
        return 4;
    }

    if (*value != new_value) {
        return 5;
    }

    return 0;
}
