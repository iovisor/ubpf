/*
  Copyright (c) 2022-present, IO Visor Project
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "mman.h"

#include <stdio.h>
#include <windows.h>

#pragma comment(lib, "mincore")

#define PAGE_SIZE 4096
#define ALIGN_PAGE(x) (((x) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

DWORD
translate_mprotect_to_windows(int prot)
{
    DWORD result = 0;

    switch (prot) {
    case PROT_READ:
        result = PAGE_READONLY;
        break;
    case PROT_WRITE:
    case PROT_READ | PROT_WRITE:
        result = PAGE_READWRITE;
        break;
    case PROT_EXEC | PROT_READ:
        result = PAGE_EXECUTE_READ;
        break;
    default:
        fprintf(stderr, "Unsupported mprotect flag: %d\n", prot);
        break;
    }
    return result;
}

void*
mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    (void)addr;
    (void)length;
    (void)prot;
    (void)flags;
    (void)fd;
    (void)offset;

    if (fd != -1) {
        fprintf(stderr, "mmap: fd not supported\n");
        return MAP_FAILED;
    }

    if (flags != (MAP_PRIVATE | MAP_ANONYMOUS)) {
        fprintf(stderr, "mmap: flags not supported\n");
        return MAP_FAILED;
    }

    if (offset != 0) {
        fprintf(stderr, "mmap: offset not supported\n");
        return MAP_FAILED;
    }

    length = ALIGN_PAGE(length);
    prot = translate_mprotect_to_windows(prot);

    void* memory = VirtualAlloc2(GetCurrentProcess(), addr, length, MEM_COMMIT | MEM_RESERVE, prot, NULL, 0);
    if (memory == NULL) {
        fprintf(stderr, "VirtualAlloc2 failed with error %d\n", GetLastError());
        return MAP_FAILED;
    }
    return memory;
}

int
munmap(void* addr, size_t length)
{
    (void)addr;
    if (!VirtualFree(addr, 0, MEM_RELEASE)) {
        fprintf(stderr, "VirtualFree failed with error %d\n", GetLastError());
        return -1;
    } else {
        return 0;
    }
}

int
mprotect(void* addr, size_t len, int prot)
{
    DWORD old_protect;
    if (!VirtualProtect(addr, len, translate_mprotect_to_windows(prot), &old_protect)) {
        fprintf(stderr, "VirtualProtect failed with error %d\n", GetLastError());
        return -1;
    } else {
        return 0;
    }
}
