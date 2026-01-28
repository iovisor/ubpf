# Using Verified eBPF Programs with uBPF

## Overview

When using external eBPF verifiers like [PREVAIL](https://github.com/vbpf/ebpf-verifier) with uBPF, it's important to understand the contract between the verifier and the runtime regarding the context pointer.

## Context Pointer Requirements

### What is the Context Pointer?

In eBPF programs, register `r1` contains a pointer to the context when the program starts execution. This context pointer is the first parameter passed to the program and provides access to:

- Input data for the program to process
- Metadata about the execution environment
- Other program-specific information

In uBPF, this context is provided via the `mem` parameter to functions like:
- `ubpf_exec(vm, mem, mem_len, &ret)`
- `ubpf_jit_fn(mem, mem_len)` (compiled functions)

### PREVAIL's Assumptions

PREVAIL and other Linux-based eBPF verifiers make the following assumptions:

1. **The context pointer (r1) is always non-null** - PREVAIL assumes that `r1` points to a valid memory region
2. **The context has a known structure** - For certain program types (e.g., XDP programs), PREVAIL assumes the context has specific fields at known offsets
3. **Memory accesses via the context are bounds-checked** - PREVAIL verifies that accesses through `r1` are within the expected context size

### uBPF's Behavior

The uBPF runtime and test harness have more flexible requirements:

- **Context can be NULL** - If no memory file is specified with `-m`, the test harness passes `NULL` as the context
- **No enforced structure** - uBPF doesn't enforce any particular context layout
- **Memory safety depends on the program** - The program must not dereference NULL or access invalid memory

## The Mismatch and How to Avoid It

### Problem Example

Consider this eBPF program:

```asm
mov64 r0, 0x0
arsh64 r0, r5
ldxw r3, [r1+0x1]    ; Read from context+1
mov64 r4, r1
exit
```

When verified with PREVAIL:
- ✅ PREVAIL says: "Safe - context is valid, access is within bounds"

When executed with uBPF without a memory file:
- ❌ **CRASH** - `r1` is NULL, so `ldxw r3, [r1+0x1]` tries to read from address `0x1`

### Root Cause

1. PREVAIL verifies the program assuming a valid, non-null context
2. The uBPF test harness sets context to NULL when no memory file is provided
3. Programs that access the context will crash at runtime

## Solutions

### For Users Running Verified Programs

If you're running eBPF programs that have been verified with PREVAIL or similar verifiers:

#### ✅ **Always Provide a Context When Required**

When using the `vm/test` utility, always provide a memory file if your program accesses the context:

```bash
# Create a dummy context file if needed
echo -n "dummy_context_data" > context.bin

# Run the program with context
./vm/test -m context.bin program.o
```

#### ✅ **Provide Appropriate Context Structure**

For programs verified against specific context types (e.g., XDP), ensure your context matches the expected structure:

```c
// Example: XDP-like context
struct xdp_context {
    uint64_t data;
    uint64_t data_end;
    // ... other fields
};

struct xdp_context ctx;
ctx.data = (uint64_t)packet_buffer;
ctx.data_end = ctx.data + packet_size;

ubpf_exec(vm, &ctx, sizeof(ctx), &ret);
```

### For Application Developers

If you're integrating uBPF into your application:

#### ✅ **Validate Context Before Execution**

```c
// Ensure non-null context for verified programs
if (program_is_verified && (mem == NULL || mem_len == 0)) {
    fprintf(stderr, "Error: Verified programs require a valid context\n");
    return -1;
}

ubpf_exec(vm, mem, mem_len, &ret);
```

#### ✅ **Provide Default Context**

If your use case allows, provide a default context buffer:

```c
// Provide a minimal default context
static uint8_t default_context[256] = {0};

void* context = user_provided_context;
size_t context_len = user_context_len;

if (context == NULL && program_requires_context) {
    context = default_context;
    context_len = sizeof(default_context);
}

ubpf_exec(vm, context, context_len, &ret);
```

### For Fuzzer/Testing

The uBPF libfuzzer correctly handles this by always providing a proper context structure. See `libfuzzer/libfuzz_harness.cc` for the complete implementation. Here's the essential pattern:

```cpp
// Simplified example - see libfuzz_harness.cc for full implementation
ubpf_context_t context{};
context.data = reinterpret_cast<uint64_t>(memory.data());
context.data_end = context.data + memory.size();
context.stack_start = reinterpret_cast<uint64_t>(stack.data());
context.stack_end = context.stack_start + stack.size();
// ... other fields initialized
```

The fuzzer then executes with this properly initialized context, ensuring programs that access r1 have valid memory to work with.

## When is NULL Context Safe?

A NULL context (or no memory file) is safe **only** when:

1. The eBPF program never accesses register `r1` (the context pointer)
2. The program only uses local registers and the stack
3. The program doesn't call helpers that expect a valid context

Example of a safe program with NULL context:

```asm
mov64 r0, 0x42      ; Use only local registers
add64 r0, 0x10
exit
```

## Summary

| Scenario | PREVAIL Verification | uBPF Execution | Result |
|----------|---------------------|----------------|--------|
| Program accesses context + NULL context | ✅ Verified | ❌ Crash | **Incompatible** |
| Program accesses context + Valid context | ✅ Verified | ✅ Runs | **Compatible** |
| Program doesn't access context + NULL context | N/A (usually not verified) | ✅ Runs | **Safe** |
| Program doesn't access context + Valid context | ✅ Verified | ✅ Runs | **Compatible** |

## Best Practices

1. **Know your program's requirements** - Understand whether your eBPF program accesses the context
2. **Match verifier assumptions** - If verified with PREVAIL, provide context matching PREVAIL's expectations
3. **Test with representative data** - Use realistic context structures when testing
4. **Document your context requirements** - Clearly specify what context your programs expect
5. **Validate at runtime** - Check context validity before executing verified programs

## References

- [PREVAIL Verifier](https://github.com/vbpf/ebpf-verifier)
- [uBPF API Documentation](https://iovisor.github.io/ubpf)
- [BPF Instruction Set Architecture (ISA) - RFC 9669](https://www.rfc-editor.org/rfc/rfc9669.html)
- GitHub issue [vbpf/ebpf-verifier#492](https://github.com/vbpf/ebpf-verifier/issues/492) - Discussion on PREVAIL context assumptions

## Example: Creating Context for XDP-like Programs

If you're running programs verified for XDP context:

```c
#include <stdint.h>
#include <ubpf.h>

// XDP-compatible context structure
typedef struct {
    uint64_t data;
    uint64_t data_end;
    uint64_t data_meta;
    // ... other XDP fields as needed
} xdp_md_t;

int run_xdp_program(struct ubpf_vm* vm, void* packet, size_t packet_len) {
    xdp_md_t ctx = {0};
    ctx.data = (uint64_t)packet;
    ctx.data_end = ctx.data + packet_len;
    ctx.data_meta = ctx.data;  // No metadata by default
    
    uint64_t result;
    int ret = ubpf_exec(vm, &ctx, sizeof(ctx), &result);
    
    if (ret < 0) {
        fprintf(stderr, "Execution failed\n");
        return -1;
    }
    
    return (int)result;  // XDP action (PASS, DROP, etc.)
}
```

## Conclusion

The key to successfully using verified eBPF programs with uBPF is understanding and respecting the contract between the verifier and the runtime. Always provide a valid context when running programs that have been verified with assumptions about the context pointer.
