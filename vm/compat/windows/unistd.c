// Copyright (c) 2022 IO Visor Project
// SPDX-License-Identifier: Apache-2.0

/*
  Copyright (c) 2022-present, IO Visor Project
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "unistd.h"

#define _CRT_RAND_S
#include <stdlib.h>

#include <stdio.h>

int
rand_r(unsigned int* seedp)
{
    (void)seedp;

    unsigned int value = 0;
    rand_s(&value);

    return (int)value;
}

int
vasprintf(char** strp, const char* fmt, va_list ap)
{
    int buffer_size = vsnprintf(NULL, 0, fmt, ap);
    if (buffer_size < 0) {
        return -1;
    }

    buffer_size++;

    *strp = (char*)malloc(buffer_size);
    if (*strp == NULL) {
        return -1;
    }

    return vsprintf_s(*strp, buffer_size, fmt, ap);
}
