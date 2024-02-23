// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include "ubpf.h"
#include <string.h>
#include <cmath>
#include <cstdint>
#include <map>

#if !defined(UNREFERENCED_PARAMETER)
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

static uint64_t
gather_bytes(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    return ((uint64_t)(a & 0xff) << 32) | ((uint64_t)(b & 0xff) << 24) | ((uint64_t)(c & 0xff) << 16) |
           ((uint64_t)(d & 0xff) << 8) | (e & 0xff);
};

static uint64_t
memfrob(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    UNREFERENCED_PARAMETER(c);
    UNREFERENCED_PARAMETER(d);
    UNREFERENCED_PARAMETER(e);

    uint8_t* p = reinterpret_cast<uint8_t*>(a);
    for (uint64_t i = 0; i < b; i++) {
        p[i] ^= 42;
    }
    return 0;
};

static uint64_t
no_op(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    UNREFERENCED_PARAMETER(a);
    UNREFERENCED_PARAMETER(b);
    UNREFERENCED_PARAMETER(c);
    UNREFERENCED_PARAMETER(d);
    UNREFERENCED_PARAMETER(e);

    return 0;
}

static uint64_t
sqrti(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    UNREFERENCED_PARAMETER(b);
    UNREFERENCED_PARAMETER(c);
    UNREFERENCED_PARAMETER(d);
    UNREFERENCED_PARAMETER(e);

    return static_cast<uint64_t>(std::sqrt(a));
}

static uint64_t
strcmp_ext(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    UNREFERENCED_PARAMETER(c);
    UNREFERENCED_PARAMETER(d);
    UNREFERENCED_PARAMETER(e);
    return strcmp(reinterpret_cast<char*>(a), reinterpret_cast<char*>(b));
}

static uint64_t
unwind(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    UNREFERENCED_PARAMETER(b);
    UNREFERENCED_PARAMETER(c);
    UNREFERENCED_PARAMETER(d);
    UNREFERENCED_PARAMETER(e);
    return a;
}

static std::map<uint32_t, external_function_t> helper_functions = {
    {0, gather_bytes},
    {1, memfrob},
    {2, no_op},
    {3, sqrti},
    {4, strcmp_ext},
    {5, unwind},
};