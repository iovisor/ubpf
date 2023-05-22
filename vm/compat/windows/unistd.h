// Copyright (c) 2022 IO Visor Project
// SPDX-License-Identifier: Apache-2.0

/*
  Copyright (c) 2022-present, IO Visor Project
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <stdarg.h>

#define STDIN_FILENO 0

int
rand_r(unsigned int* seedp);
int
vasprintf(char** strp, const char* fmt, va_list ap);
