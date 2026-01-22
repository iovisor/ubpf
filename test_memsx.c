#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "ubpf.h"
#include "ebpf.h"

int test_vm_and_jit(const char* test_name, uint8_t* mem, size_t mem_size, struct ebpf_inst* prog, size_t prog_size, uint64_t expected) {
    int failed = 0;
    
    // Test VM
    struct ubpf_vm *vm = ubpf_create();
    if (!vm) {
        fprintf(stderr, "Failed to create VM\n");
        return 1;
    }

    char *errmsg;
    int rv = ubpf_load(vm, prog, prog_size, &errmsg);
    if (rv < 0) {
        fprintf(stderr, "Failed to load program: %s\n", errmsg);
        free(errmsg);
        ubpf_destroy(vm);
        return 1;
    }

    uint64_t result;
    rv = ubpf_exec(vm, mem, mem_size, &result);
    if (rv < 0) {
        fprintf(stderr, "Failed to execute program (VM)\n");
        ubpf_destroy(vm);
        return 1;
    }

    printf("%s (VM): 0x%016llx ", test_name, (unsigned long long)result);
    if (result == expected) {
        printf("PASS\n");
    } else {
        printf("FAIL (expected 0x%016llx)\n", (unsigned long long)expected);
        failed = 1;
    }

    // Test JIT
    void *jit_fn = ubpf_compile(vm, &errmsg);
    if (!jit_fn) {
        fprintf(stderr, "Failed to compile: %s\n", errmsg);
        free(errmsg);
        ubpf_destroy(vm);
        return 1;
    }

    result = ((uint64_t(*)(void*, uint64_t))jit_fn)(mem, mem_size);
    printf("%s (JIT): 0x%016llx ", test_name, (unsigned long long)result);
    if (result == expected) {
        printf("PASS\n");
    } else {
        printf("FAIL (expected 0x%016llx)\n", (unsigned long long)expected);
        failed = 1;
    }

    ubpf_destroy(vm);
    return failed;
}

int main() {
    int failed = 0;

    // Test LDXBSX (byte sign extension)
    {
        struct ebpf_inst prog[] = {
            {.opcode = EBPF_OP_LDXBSX, .dst = 0, .src = 1, .offset = 2, .imm = 0},
            {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0},
        };
        uint8_t mem[] = {0xaa, 0xbb, 0x81, 0xcc, 0xdd};
        failed |= test_vm_and_jit("LDXBSX negative", mem, sizeof(mem), prog, sizeof(prog), 0xffffffffffffff81ULL);
        
        mem[2] = 0x7f;
        failed |= test_vm_and_jit("LDXBSX positive", mem, sizeof(mem), prog, sizeof(prog), 0x7fULL);
    }

    // Test LDXHSX (halfword sign extension)
    {
        struct ebpf_inst prog[] = {
            {.opcode = EBPF_OP_LDXHSX, .dst = 0, .src = 1, .offset = 2, .imm = 0},
            {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0},
        };
        uint8_t mem[] = {0xaa, 0xbb, 0x01, 0x80, 0xcc, 0xdd};  // 0x8001 = -32767
        failed |= test_vm_and_jit("LDXHSX negative", mem, sizeof(mem), prog, sizeof(prog), 0xffffffffffff8001ULL);
        
        mem[2] = 0xff; mem[3] = 0x7f;  // 0x7fff = 32767
        failed |= test_vm_and_jit("LDXHSX positive", mem, sizeof(mem), prog, sizeof(prog), 0x7fffULL);
    }

    // Test LDXWSX (word sign extension)
    {
        struct ebpf_inst prog[] = {
            {.opcode = EBPF_OP_LDXWSX, .dst = 0, .src = 1, .offset = 2, .imm = 0},
            {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0},
        };
        uint8_t mem[] = {0xaa, 0xbb, 0x01, 0x00, 0x00, 0x80, 0xcc, 0xdd};  // 0x80000001 = -2147483647
        failed |= test_vm_and_jit("LDXWSX negative", mem, sizeof(mem), prog, sizeof(prog), 0xffffffff80000001ULL);
        
        mem[2] = 0xff; mem[3] = 0xff; mem[4] = 0xff; mem[5] = 0x7f;  // 0x7fffffff = 2147483647
        failed |= test_vm_and_jit("LDXWSX positive", mem, sizeof(mem), prog, sizeof(prog), 0x7fffffffULL);
    }

    if (failed) {
        printf("\nSome tests FAILED!\n");
        return 1;
    } else {
        printf("\nAll tests PASSED!\n");
        return 0;
    }
}

