/*
  Copyright (c) 2022-present, IO Visor Project
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "mman.h"

#include <stdio.h>

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  (void) addr;
  (void) length;
  (void) prot;
  (void) flags;
  (void) fd;
  (void) offset;

  return NULL;
}

int munmap(void *addr, size_t length) {
  (void) addr;
  (void) length;

  return 0;
}

int mprotect(void *addr, size_t len, int prot) {
  (void) addr;
  (void) len;
  (void) prot;
  
  return 0;
}
