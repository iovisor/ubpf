// Copyright (c) 2022 IO Visor Project
// SPDX-License-Identifier: Apache-2.0

/*
  Copyright (c) 2022-present, IO Visor Project
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <stdint.h>

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define MAP_PRIVATE 0
#define MAP_ANONYMOUS 0
#define MAP_FAILED NULL
#define PROT_EXEC 0x4

typedef int64_t off_t;

void*
mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
int
munmap(void* addr, size_t length);
int
mprotect(void* addr, size_t len, int prot);
