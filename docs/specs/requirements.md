# uBPF Requirements Specification

**Document Version:** 1.0.0
**Date:** 2026-03-31
**Status:** Draft — Extracted from source code

---

## 1. Overview

This document captures the formal functional and non-functional requirements for the **uBPF** (userspace Berkeley Packet Filter) virtual machine library. uBPF is an Apache 2.0-licensed library that provides:

- An eBPF assembler and disassembler.
- An eBPF interpreter available on all supported platforms.
- JIT compilers for x86-64 and ARM64 architectures.
- ELF object file loading with relocation support.
- Security hardening features including bounds checking, constant blinding, and read-only bytecode.

Requirements in this document are extracted directly from the existing codebase. Every requirement cites source evidence and is tagged with a confidence level.

---

## 2. Scope

### 2.1 In Scope

- VM lifecycle management (creation, destruction, code loading/unloading).
- Raw bytecode loading and validation.
- ELF object file loading with relocation processing.
- eBPF instruction set support (ALU, memory, branching, atomics, calls).
- Interpreter-based execution on all platforms.
- JIT compilation for x86-64 and ARM64.
- Security features: bounds checking, undefined-behavior detection, constant blinding, read-only bytecode, pointer secrets.
- Extensibility: external helper functions, dispatchers, callbacks, debug hooks.
- Configuration: error output, JIT buffer sizing, instruction limits, register state access.
- Platform support: Windows (MSVC), Linux (GCC/Clang), macOS (Clang).

### 2.2 Out of Scope

- Kernel-mode eBPF execution.
- eBPF map implementations (maps are handled externally via data relocation callbacks).
- Network packet processing infrastructure (uBPF is a generic VM).
- Static verification / formal analysis of eBPF programs (handled by external tools such as prevail).
- eBPF BTF (BPF Type Format) support.

---

## 3. Definitions and Glossary

| Term | Definition |
|------|-----------|
| **eBPF** | Extended Berkeley Packet Filter — an instruction set architecture for sandboxed programs. |
| **VM** | Virtual Machine — an instance of the uBPF interpreter/JIT runtime (`struct ubpf_vm`). |
| **JIT** | Just-In-Time compilation — translation of eBPF bytecode to native machine code. |
| **Helper function** | An external native function registered with the VM and callable from eBPF programs. |
| **Dispatcher** | A single callback that dynamically routes all external helper calls. |
| **Local function** | A function defined within the eBPF program itself (CALL with `src==1`). |
| **LDDW** | Load Double-Word — a two-instruction sequence encoding a 64-bit immediate. |
| **Bounds check** | Runtime validation that memory accesses fall within allowed regions. |
| **Constant blinding** | XOR-masking of immediate values in JIT output to mitigate JIT-spraying attacks. |
| **Retpoline** | A Spectre/Meltdown mitigation technique for indirect branches in x86-64. |
| **Shadow stack** | A parallel data structure tracking which stack bytes have been initialized. |
| **ELF** | Executable and Linkable Format — a standard binary format for object files. |
| **W⊕X** | Write XOR Execute — a security policy where memory is never simultaneously writable and executable. |
| **Pointer secret** | A 64-bit XOR key applied to stored instruction data for ROP mitigation. |

---

## 4. Requirements

### 4.1 VM Lifecycle (REQ-LIFE)

#### REQ-LIFE-001: VM Creation

The `ubpf_create()` function MUST allocate and return a fully initialized VM instance. On allocation failure, it MUST return `NULL`.

- **Source:** `vm/ubpf_vm.c:95-145` (`ubpf_create`)
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: A non-NULL pointer is returned when system memory is available.
  - AC-2: On any internal allocation failure (ext_funcs, ext_func_names, local_func_stack_usage), the partially constructed VM is destroyed and NULL is returned.
  - AC-3: The returned VM has no loaded code (`vm->insts == NULL`).

#### REQ-LIFE-002: VM Default State

A newly created VM MUST have the following default configuration:

| Property | Default Value |
|----------|--------------|
| `bounds_check_enabled` | `true` |
| `undefined_behavior_check_enabled` | `false` |
| `readonly_bytecode_enabled` | `true` |
| `constant_blinding_enabled` | `false` |
| `error_printf` | `fprintf` (stderr) |
| `jitter_buffer_size` | `65536` (DEFAULT_JITTER_BUFFER_SIZE) |
| `unwind_stack_extension_index` | `-1` |
| `jitted_result.compile_result` | `UBPF_JIT_COMPILE_FAILURE` |

- **Source:** `vm/ubpf_vm.c:121-143`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Each field above matches the specified default immediately after `ubpf_create()` returns.

#### REQ-LIFE-003: VM Creation — Allocations

`ubpf_create()` MUST allocate:

1. The `ubpf_vm` structure itself (1 instance, zeroed via `calloc`).
2. An `ext_funcs` array of `MAX_EXT_FUNCS` (64) entries.
3. An `ext_func_names` array of `MAX_EXT_FUNCS` (64) entries.
4. A `local_func_stack_usage` array of `UBPF_MAX_INSTS` (65536) entries.

- **Source:** `vm/ubpf_vm.c:98-119`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: The `ext_funcs` array has capacity for 64 helper function pointers.
  - AC-2: The `local_func_stack_usage` array has capacity for 65536 entries.
  - AC-3: All allocations are zero-initialized.

#### REQ-LIFE-004: Platform JIT Selection

`ubpf_create()` MUST select the JIT backend at compile time:

- On x86-64 (`__x86_64__` or `_M_X64`): use `ubpf_translate_x86_64`.
- On ARM64 (`__aarch64__` or `_M_ARM64`): use `ubpf_translate_arm64`.
- On all other architectures: use `ubpf_translate_null` (interpreter-only).

- **Source:** `vm/ubpf_vm.c:127-138`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: On x86-64, `vm->jit_translate` points to `ubpf_translate_x86_64`.
  - AC-2: On ARM64, `vm->jit_translate` points to `ubpf_translate_arm64`.
  - AC-3: On unsupported architectures, `vm->jit_translate` points to `ubpf_translate_null`, and JIT compilation returns an error.

#### REQ-LIFE-005: VM Destruction

`ubpf_destroy(vm)` MUST free all resources associated with the VM:

1. Call `ubpf_unload_code()` to release bytecode and JIT code.
2. Free `vm->int_funcs`.
3. Free `vm->ext_funcs`.
4. Free `vm->ext_func_names`.
5. Free `vm->local_func_stack_usage`.
6. Free the `vm` structure itself.

- **Source:** `vm/ubpf_vm.c:147-156`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: No memory leaks occur after calling `ubpf_destroy()` on a fully initialized VM (verified by tools such as Valgrind or AddressSanitizer).
  - AC-2: After destruction, the VM pointer is no longer valid.

#### REQ-LIFE-006: Code Unloading

`ubpf_unload_code(vm)` MUST:

1. Free and reallocate the `local_func_stack_usage` array.
2. If JIT code exists, unmap (`munmap`) the JIT buffer and reset `vm->jitted` and `vm->jitted_size`.
3. If bytecode is loaded:
   - If `readonly_bytecode_enabled`: unmap via `munmap(vm->insts, vm->insts_alloc_size)`.
   - Otherwise: `free(vm->insts)`.
4. Reset `vm->insts`, `vm->num_insts`, and `vm->insts_alloc_size` to zero/NULL.
5. Free and nullify `vm->int_funcs`.

- **Source:** `vm/ubpf_vm.c:369-394`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: After `ubpf_unload_code()`, the VM is in a state where new code can be loaded via `ubpf_load()`.
  - AC-2: JIT-compiled code is invalidated and cannot be executed.

---

### 4.2 Program Loading — Raw Bytecode (REQ-LOAD)

#### REQ-LOAD-001: Code Length Validation

`ubpf_load()` MUST reject programs where `code_len` is not a multiple of 8 bytes. On rejection, it MUST return `-1` and set `*errmsg` to an appropriate error string.

- **Source:** `vm/ubpf_vm.c:269-272`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Loading 7 bytes of code returns `-1`.
  - AC-2: Loading 16 bytes of valid code returns `0`.
  - AC-3: `*errmsg` contains the text "code_len must be a multiple of 8" on failure.

#### REQ-LOAD-002: Maximum Instruction Count

`ubpf_load()` MUST reject programs with `UBPF_MAX_INSTS` (65536) or more instructions. Because `num_insts` is stored as `uint16_t`, the maximum valid instruction count is 65535.

- **Source:** `vm/inc/ubpf.h:39` (constant), `vm/ubpf_vm.c:274` (validate call)
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Loading a program with exactly 65535 instructions succeeds (assuming valid instructions).
  - AC-2: Loading a program with 65536 instructions returns `-1`.

#### REQ-LOAD-003: Double-Load Prevention

`ubpf_load()` MUST reject loading when code is already loaded into the VM. Callers MUST call `ubpf_unload_code()` before reloading.

- **Source:** `vm/ubpf_vm.c:263-267`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Calling `ubpf_load()` twice without an intervening `ubpf_unload_code()` returns `-1` on the second call.
  - AC-2: The error message references `ubpf_unload_code()`.

#### REQ-LOAD-004: Instruction Validation

`ubpf_load()` MUST validate all instructions via the `validate()` function before accepting the program. Any invalid instruction MUST cause loading to fail with an error message.

- **Source:** `vm/ubpf_vm.c:274-276`, `vm/ubpf_instruction_valid.c:1049-1096`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: A program containing an unrecognized opcode is rejected.
  - AC-2: A program with out-of-range register indices is rejected.
  - AC-3: A program with invalid immediate or offset values is rejected.

#### REQ-LOAD-005: Read-Only Bytecode Storage

When `readonly_bytecode_enabled` is `true` (default), `ubpf_load()` MUST:

1. Allocate page-aligned memory via `mmap` with `PROT_READ | PROT_WRITE`.
2. Copy the validated instructions into the allocation.
3. Change protection to `PROT_READ` only via `mprotect`.

When `readonly_bytecode_enabled` is `false`, `ubpf_load()` MUST allocate via `malloc`.

- **Source:** `vm/ubpf_vm.c:278-364`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: With read-only mode enabled, writing to `vm->insts` after load triggers a segmentation fault / access violation.
  - AC-2: With read-only mode disabled, `vm->insts` is writable.

#### REQ-LOAD-006: Pointer Secret Encoding

`ubpf_load()` MUST XOR-encode each stored instruction with both the base address of the instruction array (`(uint64_t)vm->insts`) and `vm->pointer_secret` when storing. Instruction fetch MUST XOR-decode using the same two values transparently.

- **Source:** `vm/ubpf_vm.c:2266-2290` (`ubpf_fetch_instruction`, `ubpf_store_instruction`), declared in `vm/ubpf_int.h:201-212`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: With a non-zero pointer secret, raw memory at `vm->insts` does not contain valid eBPF opcodes.
  - AC-2: `ubpf_fetch_instruction()` returns the original instruction regardless of the secret value.

#### REQ-LOAD-007: Local Function Marking

During loading, `ubpf_load()` MUST identify instructions that are targets of local CALL instructions (CALL with `src==1`) and mark them in the `vm->int_funcs` boolean array.

- **Source:** `vm/ubpf_vm.c:337-349`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: After loading a program with local calls, `vm->int_funcs[target_pc]` is `true` for each call target.
  - AC-2: Non-target PCs have `vm->int_funcs[pc] == false`.

#### REQ-LOAD-008: Stack Alignment Validation

`ubpf_load()` MUST validate that the stack size for each local function is a multiple of 16 bytes.

- **Source:** `vm/ubpf_vm.c:2332-2348` (`ubpf_calculate_stack_usage_for_local_func`, 16-byte alignment check at line 2344)
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: A local function requiring a non-16-byte-aligned stack causes loading to fail.

#### REQ-LOAD-009: Sub-Program Containment

`ubpf_load()` MUST validate that sub-programs are self-contained: jump targets MUST NOT cross sub-program boundaries, and each sub-program MUST end with an EXIT or unconditional JA instruction.

- **Source:** `vm/ubpf_vm.c:274` (validate), `vm/ubpf_instruction_valid.c`
- **Confidence:** **Medium** — inferred from validation logic and eBPF semantics.
- **Acceptance Criteria:**
  - AC-1: A program with a jump from one sub-program into another is rejected.
  - AC-2: A sub-program that does not end with EXIT or JA is rejected.

#### REQ-LOAD-010: Jump Target Validation

`ubpf_load()` MUST validate that all jump targets are within bounds and that no jump offset equals `-1` (which would create an infinite loop).

- **Source:** `vm/ubpf_vm.c:274` (validate call)
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: A forward jump beyond the last instruction is rejected.
  - AC-2: A jump with offset `-1` (self-loop) is rejected.

#### REQ-LOAD-011: LDDW Pairing Validation

`ubpf_load()` MUST validate that every LDDW instruction is followed by a second 8-byte pseudo-instruction forming the complete 64-bit immediate pair.

- **Source:** `vm/ubpf_instruction_valid.c` (LDDW validation in filter array)
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: An LDDW instruction at the last position (no room for the second half) is rejected.
  - AC-2: A valid LDDW pair loads correctly.

---

### 4.3 Program Execution — Interpreter (REQ-EXEC)

#### REQ-EXEC-001: Interpreter Entry Point

`ubpf_exec(vm, mem, mem_len, bpf_return_value)` MUST execute the loaded eBPF program using the interpreter. It MUST allocate a stack of `UBPF_EBPF_STACK_SIZE` (4096) bytes internally.

- **Source:** `vm/ubpf_vm.c:1753-1771`, `vm/inc/ubpf.h:389-390`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: The function returns `0` on successful execution.
  - AC-2: `*bpf_return_value` contains the value from BPF register R0.
  - AC-3: The function returns `-1` if no code is loaded.

#### REQ-EXEC-002: Extended Interpreter Entry Point

`ubpf_exec_ex(vm, mem, mem_len, bpf_return_value, stack_start, stack_len)` MUST execute using a caller-provided stack buffer instead of allocating one internally.

- **Source:** `vm/ubpf_vm.c:759-766`, `vm/inc/ubpf.h:392-399`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: The eBPF program's R10 (frame pointer) points to `stack_start + stack_len`.
  - AC-2: Stack operations use the provided buffer, not an internally allocated one.

#### REQ-EXEC-003: Register Initialization

At interpreter entry, the VM MUST initialize registers as follows:

- `R1` = pointer to `mem` (input memory).
- `R2` = `mem_len`.
- `R10` = `stack_start + stack_length` (frame pointer, top of stack).

Registers R1, R2, and R10 MUST be marked as initialized in the shadow register mask.

- **Source:** `vm/ubpf_vm.c:825-830`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: On entry, R1 contains the address of the input memory buffer.
  - AC-2: On entry, R2 contains the length of the input memory buffer.
  - AC-3: On entry, R10 points to the end of the stack (grows downward).

#### REQ-EXEC-004: Code-Not-Loaded Guard

Both `ubpf_exec()` and `ubpf_exec_ex()` MUST return `-1` immediately if `vm->insts` is NULL (no code loaded).

- **Source:** `vm/ubpf_vm.c:798-801`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Calling `ubpf_exec()` on a freshly created VM (no load) returns `-1`.

#### REQ-EXEC-005: Instruction Limit Enforcement

When `vm->instruction_limit` is non-zero, the interpreter MUST count executed instructions and return `-1` when the limit is exceeded. When set to `0`, no limit SHALL be enforced.

- **Source:** `vm/ubpf_vm.c:832, 840-843`, `vm/inc/ubpf.h:612-613`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: A program with an infinite loop terminates after the configured number of instructions.
  - AC-2: With `instruction_limit == 0`, no early termination occurs due to instruction count.

#### REQ-EXEC-006: Call Depth Limit

The interpreter MUST enforce a maximum call depth of `UBPF_MAX_CALL_DEPTH` (8). Exceeding this depth MUST cause execution to fail.

- **Source:** `vm/inc/ubpf.h:46`, `vm/ubpf_vm.c:803-805`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: A chain of 8 nested local calls succeeds.
  - AC-2: A chain of 9 nested local calls fails with an error.

#### REQ-EXEC-007: XOR-Decoded Instruction Fetch

During execution, each instruction MUST be fetched via `ubpf_fetch_instruction()`, which XOR-decodes the instruction with `vm->pointer_secret`.

- **Source:** `vm/ubpf_int.h:201-202`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Execution produces correct results regardless of the pointer secret value.

#### REQ-EXEC-008: Unwind Function Support

If a helper function registered at `vm->unwind_stack_extension_index` returns `0`, the interpreter MUST immediately exit the program.

- **Source:** `vm/ubpf_vm.c:228-237` (`ubpf_set_unwind_function_index`), `vm/inc/ubpf.h:501-502`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: When the designated unwind helper returns `0`, execution stops and the program returns.
  - AC-2: When the designated unwind helper returns non-zero, execution continues normally.

#### REQ-EXEC-009: Debug Callback Invocation

When a debug function is registered, the interpreter MUST invoke it before executing each instruction, providing the current PC, register values, stack pointer, stack size, register count, and the debug context.

- **Source:** `vm/inc/ubpf.h:661-680`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: The debug function is called exactly once per instruction executed.
  - AC-2: The register array passed to the debug function contains 16 elements (for API compatibility).

---

### 4.4 JIT Compilation (REQ-JIT)

#### REQ-JIT-001: Basic JIT Compilation

`ubpf_compile(vm, errmsg)` MUST compile the loaded eBPF program to native code and return a `ubpf_jit_fn` function pointer. It operates in `BasicJitMode`. On failure, it MUST return `NULL` and set `*errmsg`.

- **Source:** `vm/ubpf_jit.c:103-107`, `vm/inc/ubpf.h:414-415`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: The returned function pointer, when called with `(mem, mem_len)`, executes the eBPF program and returns the result.
  - AC-2: If no code is loaded, returns NULL with an appropriate error message.

#### REQ-JIT-002: Extended JIT Compilation

`ubpf_compile_ex(vm, errmsg, mode)` MUST support two modes:

- `BasicJitMode`: Returns `ubpf_jit_fn(void* mem, size_t mem_len)`.
- `ExtendedJitMode`: Returns `ubpf_jit_ex_fn(void* mem, size_t mem_len, uint8_t* stack, size_t stack_len)`.

- **Source:** `vm/ubpf_jit.c:109-167`, `vm/inc/ubpf.h:117-121, 433-434`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: In `ExtendedJitMode`, the caller-provided stack is used.
  - AC-2: In `BasicJitMode`, the JIT allocates its own stack.

#### REQ-JIT-003: JIT Result Caching

`ubpf_compile_ex()` MUST cache the JIT result. If called again with the same mode after a successful compilation, it MUST return the previously compiled function pointer without recompiling.

- **Source:** `vm/ubpf_jit.c:116-119`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Two consecutive calls to `ubpf_compile_ex()` with the same mode return the same pointer.
  - AC-2: Calling with a different mode triggers recompilation.

#### REQ-JIT-004: W⊕X Memory Management

The JIT compiler MUST enforce Write XOR Execute memory protection:

1. Allocate a working buffer via `calloc`.
2. Translate eBPF to native code into the working buffer.
3. Allocate executable memory via `mmap` with `PROT_READ | PROT_WRITE`.
4. Copy the translated code.
5. Change protection to `PROT_READ | PROT_EXEC` via `mprotect`.
6. Free the working buffer.

- **Source:** `vm/ubpf_jit.c:134-162`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: The final JIT code resides in memory that is executable but not writable.
  - AC-2: The working buffer is freed after compilation.
  - AC-3: On `mmap` or `mprotect` failure, an error is returned and no memory is leaked.

#### REQ-JIT-005: JIT Buffer Size Configuration

The JIT working buffer size MUST default to `DEFAULT_JITTER_BUFFER_SIZE` (65536 bytes) and MUST be configurable via `ubpf_set_jit_code_size(vm, code_size)`.

- **Source:** `vm/ubpf_vm.c:143` (default), `vm/inc/ubpf.h:598-599`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: The default buffer size is 65536 bytes.
  - AC-2: After calling `ubpf_set_jit_code_size(vm, 131072)`, the JIT uses a 131072-byte buffer.

#### REQ-JIT-006: JIT Code Copy

`ubpf_copy_jit(vm, buffer, size, errmsg)` MUST copy the compiled JIT code into a user-provided buffer without requiring the VM to persist.

- **Source:** `vm/inc/ubpf.h:450-451`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: The copied code can be executed independently of the VM.
  - AC-2: If the buffer is too small, an error is returned.

#### REQ-JIT-007: JIT Translation to Buffer

`ubpf_translate(vm, buffer, size, errmsg)` and `ubpf_translate_ex(vm, buffer, size, errmsg, mode)` MUST translate eBPF bytecode to native machine code in a caller-provided buffer. `*size` MUST be updated with the actual code size.

- **Source:** `vm/inc/ubpf.h:468-469, 487-488`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: On success, returns `0` and `*size` reflects the actual native code size.
  - AC-2: On failure (buffer too small, unsupported platform), returns `-1` with `*errmsg` set.

#### REQ-JIT-008: Instruction Limit Non-Applicability

`ubpf_set_instruction_limit()` MUST NOT affect JIT-compiled execution. The instruction limit applies only to the interpreter.

- **Source:** `vm/inc/ubpf.h:612-613` (documentation comment)
- **Confidence:** **Medium** — documented in API header, not actively enforced by JIT.
- **Acceptance Criteria:**
  - AC-1: A JIT-compiled program with `instruction_limit` set to 1 runs to completion.

#### REQ-JIT-009: x86-64 Calling Convention Support

The x86-64 JIT MUST support both System V ABI (Linux/macOS) and Win64 ABI (Windows) calling conventions:

- System V: parameters in `RDI, RSI, RDX, RCX, R8, R9`.
- Win64: parameters in `RCX, RDX, R8, R9` with home register space.

- **Source:** `vm/ubpf_jit_x86_64.c:91-129`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: JIT-compiled code executes correctly on Linux with System V ABI.
  - AC-2: JIT-compiled code executes correctly on Windows with Win64 ABI.

#### REQ-JIT-010: ARM64 Atomic Operations

The ARM64 JIT MUST implement atomic operations using Load-Exclusive/Store-Exclusive (LDXR/STXR) instruction pairs with retry loops. Supported operations: ADD, OR, AND, XOR, XCHG, CMPXCHG (both 32-bit and 64-bit).

- **Source:** `vm/ubpf_jit_arm64.c:266-273, 753-909`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Atomic ADD on ARM64 produces correct results under contention.
  - AC-2: CMPXCHG compares with R0 and conditionally stores, returning the loaded value.
  - AC-3: The LDXR/STXR loop retries on exclusive store failure.

#### REQ-JIT-011: Post-Compilation Helper Update

`ubpf_register()` MUST support updating helper function pointers after JIT compilation. When JIT code already exists, it MUST:

1. Make JIT memory writable (`mprotect` to `PROT_READ | PROT_WRITE`).
2. Update the helper pointer in the JIT code.
3. Restore executable protection (`mprotect` to `PROT_READ | PROT_EXEC`).

- **Source:** `vm/ubpf_vm.c:176-196`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Registering a new helper after compilation updates the JIT code.
  - AC-2: The JIT-compiled program calls the updated helper on next invocation.

---

### 4.5 ELF Loading (REQ-ELF)

#### REQ-ELF-001: ELF Header Validation

`ubpf_load_elf_ex()` MUST validate the following ELF header fields and reject files that do not conform:

- ELF magic number (`ELFMAG`).
- Class: `ELFCLASS64` (64-bit).
- Data encoding: `ELFDATA2LSB` (little-endian).
- Version: `EI_VERSION == 1`.
- OS/ABI: `ELFOSABI_NONE`.
- Type: `ET_REL` (relocatable object).
- Machine: `EM_NONE` or `EM_BPF`.

- **Source:** `vm/ubpf_loader.c:119-158`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: A big-endian ELF file is rejected.
  - AC-2: An `ET_EXEC` ELF file is rejected.
  - AC-3: An ELF with `EM_X86_64` machine type is rejected.
  - AC-4: A valid eBPF ELF with `EM_BPF` is accepted.

#### REQ-ELF-002: Section Count Limit

`ubpf_load_elf_ex()` MUST reject ELF files with more than `MAX_SECTIONS` (32) sections.

- **Source:** `vm/ubpf_loader.c:160-163`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: An ELF with 33 sections is rejected.
  - AC-2: An ELF with 32 sections is accepted (assuming valid content).

#### REQ-ELF-003: ELF Bounds Checking

`ubpf_load_elf_ex()` MUST validate that all section headers, symbol tables, string tables, and relocations fall within the bounds of the provided ELF buffer.

- **Source:** `vm/ubpf_loader.c:119-123, 168-219`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: A truncated ELF file is rejected with an appropriate error message.
  - AC-2: An ELF with a section header pointing beyond the buffer is rejected.

#### REQ-ELF-004: Data Relocation (R_BPF_64_64)

For `R_BPF_64_64` relocations, `ubpf_load_elf_ex()` MUST invoke the registered `data_relocation_function` callback to resolve data references. If no callback is registered, the relocation MUST fail.

- **Source:** `vm/ubpf_loader.c:394-440`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: A data relocation callback receives the symbol name, section contents, offset, and size.
  - AC-2: Without a registered callback, loading an ELF with data relocations fails.

#### REQ-ELF-005: Helper Function Relocation (R_BPF_64_32)

For `R_BPF_64_32` and legacy relocations, `ubpf_load_elf_ex()` MUST:

- For local function calls: update the call target offset.
- For external helpers: look up the helper by name and set the helper function ID in the instruction immediate field.

- **Source:** `vm/ubpf_loader.c:443-478`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: An ELF referencing a registered helper by name resolves correctly.
  - AC-2: An ELF referencing an unregistered helper name fails with an error.

#### REQ-ELF-006: ELF Wrapper Functions

`ubpf_load_elf(vm, elf, elf_len, errmsg)` MUST be equivalent to calling `ubpf_load_elf_ex(vm, elf, elf_len, NULL, errmsg)` (using the default main section).

- **Source:** `vm/ubpf_loader.c:509-513`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Both functions produce identical results for the same ELF input.

#### REQ-ELF-007: Multi-Function ELF Linking

`ubpf_load_elf_ex()` MUST link multiple function sections from the ELF into a contiguous memory region, adjusting call targets to reflect the final layout.

- **Source:** `vm/ubpf_loader.c:235-311`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: An ELF with multiple `.text` function sections loads with all functions callable.
  - AC-2: Local call targets are adjusted to correct offsets in the linked program.

---

### 4.6 Instruction Set (REQ-ISA)

#### REQ-ISA-001: Instruction Encoding

Each eBPF instruction MUST be 8 bytes with the following layout:

| Field | Bits | Offset |
|-------|------|--------|
| `opcode` | 8 | 0 |
| `dst` | 4 | 8 |
| `src` | 4 | 12 |
| `offset` | 16 | 16 |
| `imm` | 32 | 32 |

- **Source:** `vm/ebpf.h:27-34`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: `sizeof(struct ebpf_inst) == 8`.

#### REQ-ISA-002: Register File

The VM MUST support 11 registers:

- `R0`: Return value.
- `R1`–`R5`: Function parameters.
- `R6`–`R9`: Callee-saved registers.
- `R10`: Frame pointer (read-only).

- **Source:** `vm/ebpf.h:36-50`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Writing to R10 via a MOV or ALU instruction is rejected at load time (`destination_upper_bound = BPF_REG_9` in instruction validation filters).
  - AC-2: R6–R9 are preserved across external helper calls.
  - AC-3: R0 contains the program's return value after EXIT.

#### REQ-ISA-003: ALU Operations (32-bit and 64-bit)

The VM MUST support the following ALU operations in both 32-bit (`EBPF_CLS_ALU`) and 64-bit (`EBPF_CLS_ALU64`) variants, with both immediate and register source operands:

ADD, SUB, MUL, DIV, MOD, OR, AND, XOR, LSH, RSH, NEG, ARSH, MOV.

- **Source:** `vm/ebpf.h:87-155`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Each operation produces the correct result for representative test inputs.
  - AC-2: 32-bit operations zero-extend the result to 64 bits.

#### REQ-ISA-004: Signed Division and Modulo

The VM MUST support signed variants of DIV (`SDIV`) and MOD (`SMOD`). Signed operations are indicated by `offset == 1` on the DIV/MOD instruction.

- **Source:** `vm/ebpf.h:90,96` (ALU_OP_DIV, ALU_OP_MOD), `vm/ubpf_instruction_valid.c` (offset==1 filter entries)
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: `SDIV(-10, 3)` returns `-3` (or implementation-defined signed division behavior).
  - AC-2: `SMOD(-10, 3)` returns `-1` (or implementation-defined signed modulo behavior).

#### REQ-ISA-005: MOV with Sign-Extension (MOVSX)

The VM MUST support MOV with sign-extension. The offset field (8, 16, or 32) specifies the source width for sign-extension.

- **Source:** `vm/ebpf.h:98` (ALU_OP_MOV), `vm/ubpf_instruction_valid.c` (MOVSX filter entries)
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: MOVSX with offset=8 sign-extends the low 8 bits.
  - AC-2: MOVSX with offset=16 sign-extends the low 16 bits.
  - AC-3: MOVSX with offset=32 sign-extends the low 32 bits.

#### REQ-ISA-006: Byte Swap Operations

The VM MUST support byte swap operations:

- `EBPF_OP_LE` / `EBPF_OP_BE`: Legacy endian conversion (16, 32, or 64-bit).
- `EBPF_OP_BSWAP`: Unconditional byte swap.

- **Source:** `vm/ebpf.h:100, 128, 155`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: `LE 16` on a big-endian value converts to little-endian 16-bit.
  - AC-2: `BSWAP` reverses the byte order of the specified width.

#### REQ-ISA-007: Memory Load/Store Operations

The VM MUST support memory operations for 8-bit (B), 16-bit (H), 32-bit (W), and 64-bit (DW) widths:

- `LDX{B,H,W,DW}`: Load from memory via register + offset.
- `ST{B,H,W,DW}`: Store immediate to memory via register + offset.
- `STX{B,H,W,DW}`: Store register to memory via register + offset.
- `LDDW`: Load 64-bit immediate (two-instruction encoding).

- **Source:** `vm/ebpf.h:157-172`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Each load/store width (1, 2, 4, 8 bytes) operates correctly.
  - AC-2: LDDW loads a full 64-bit immediate from a two-instruction pair.

#### REQ-ISA-008: Sign-Extending Loads

The VM MUST support sign-extending memory loads: `LDXSB` (8→64), `LDXSH` (16→64), `LDXSW` (32→64).

- **Source:** `vm/ebpf.h:161-163` (`EBPF_OP_LDXWSX`, `EBPF_OP_LDXHSX`, `EBPF_OP_LDXBSX`)
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Loading `0xFF` via LDXSB produces `0xFFFFFFFFFFFFFFFF`.
  - AC-2: Loading `0x7F` via LDXSB produces `0x000000000000007F`.

#### REQ-ISA-009: Jump Instructions

The VM MUST support the following conditional and unconditional jump instructions in both 64-bit (`EBPF_CLS_JMP`) and 32-bit (`EBPF_CLS_JMP32`) variants:

JA (unconditional), JEQ, JGT, JGE, JLT, JLE, JSET, JNE, JSGT, JSGE, JSLT, JSLE.

Each conditional jump MUST support both immediate and register comparison operands.

- **Source:** `vm/ebpf.h:174-237`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Each jump condition evaluates correctly for both true and false cases.
  - AC-2: 32-bit variants compare only the lower 32 bits.

#### REQ-ISA-010: Atomic Operations

The VM MUST support atomic memory operations via `EBPF_OP_ATOMIC_STORE` (64-bit) and `EBPF_OP_ATOMIC32_STORE` (32-bit):

- ADD, OR, AND, XOR: Atomic read-modify-write.
- XCHG: Atomic exchange.
- CMPXCHG: Atomic compare-and-exchange (comparing with R0).
- Fetch variants: Return the original value in the source register.

- **Source:** `vm/ebpf.h:76-80, 239-240`, `vm/ubpf_int.h:238-265`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Atomic ADD correctly updates the memory location and returns the old value (fetch variant).
  - AC-2: CMPXCHG stores the new value only if the current value matches R0.

#### REQ-ISA-011: CALL Instruction Variants

The CALL instruction MUST support two modes based on the `src` field:

- `src == 0`: External helper function call (dispatched by index).
- `src == 1`: Local function call (relative offset to another eBPF function).

- **Source:** `vm/ebpf.h:182` (`EBPF_MODE_CALL`), `vm/ubpf_vm.c:337-349` (int_funcs marking)
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: `CALL` with `src==0` invokes the external helper at the specified index.
  - AC-2: `CALL` with `src==1` transfers control to the local function at `pc + offset + 1`.

#### REQ-ISA-012: EXIT Instruction

The EXIT instruction MUST terminate program execution. The return value is taken from register R0.

- **Source:** `vm/ebpf.h:183` (`EBPF_MODE_EXIT`)
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: After EXIT, `*bpf_return_value == R0`.

---

### 4.7 Security Features (REQ-SEC)

#### REQ-SEC-001: Bounds Checking

When bounds checking is enabled (default), the interpreter MUST validate all memory loads and stores against:

1. The input memory region (`mem`, `mem_len`).
2. The stack region.

Out-of-bounds accesses MUST cause execution to fail.

- **Source:** `vm/ubpf_vm.c:121` (default enabled), `vm/inc/ubpf.h:146-147`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Reading 1 byte past the end of the memory region fails.
  - AC-2: Writing to a stack address below the allocated stack fails.
  - AC-3: Disabling bounds checking allows unrestricted memory access.

#### REQ-SEC-002: Bounds Check Toggle

`ubpf_toggle_bounds_check(vm, enable)` MUST return the previous state and set the new state. Default is `true` (enabled).

- **Source:** `vm/ubpf_vm.c:54-60`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: `ubpf_toggle_bounds_check(vm, false)` returns `true` (the previous default).
  - AC-2: After disabling, bounds checking is not enforced.

#### REQ-SEC-003: Undefined Behavior Detection

When enabled, the interpreter MUST track register and stack initialization using:

1. A **shadow register bitmask** (16-bit) — one bit per register.
2. A **shadow stack** — allocated proportionally to the stack size.

Reading an uninitialized register or stack location MUST cause execution to fail.

- **Source:** `vm/ubpf_vm.c:807-813, 823, 829-830`, `vm/inc/ubpf.h:625-626`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Reading R3 before any write to R3 fails (when enabled).
  - AC-2: Reading from an uninitialized stack location fails (when enabled).
  - AC-3: When disabled, no shadow tracking occurs and no overhead is added.

#### REQ-SEC-004: Constant Blinding (JIT)

When enabled, the JIT compiler MUST XOR all immediate values with cryptographically random constants, loading the blinded value and recovering the original at runtime via XOR.

- **Source:** `vm/ubpf_jit_x86_64.c:462-492` (x86-64), `vm/ubpf_jit_arm64.c:544-564` (ARM64)
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: With constant blinding enabled, no eBPF immediate values appear in the JIT output as literal constants.
  - AC-2: Program behavior is identical with and without constant blinding.
  - AC-3: ARM64 constant blinding applies to fewer instruction forms than x86-64 (per source analysis of `vm/ubpf_jit_arm64.c` vs. `vm/ubpf_jit_x86_64.c`).

#### REQ-SEC-005: Read-Only Bytecode

When enabled (default), loaded bytecode MUST reside in memory mapped as `PROT_READ` only. Writing to bytecode memory MUST cause a fault.

- **Source:** `vm/ubpf_vm.c:123, 278-364`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: After loading, `vm->insts` is not writable.
  - AC-2: `ubpf_toggle_readonly_bytecode()` MUST be called before `ubpf_load()` to take effect.

#### REQ-SEC-006: Pointer Secret

`ubpf_set_pointer_secret(vm, secret)` MUST set a 64-bit XOR key used to obfuscate stored instructions. It MUST be called before `ubpf_load()`.

- **Source:** `vm/ubpf_vm.c:2289-2297`, `vm/inc/ubpf.h:530-531`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Calling `ubpf_set_pointer_secret()` after loading code returns `-1` and does not modify the secret.
  - AC-2: With a non-zero secret, stored instruction bytes differ from the original bytecode.

#### REQ-SEC-007: Retpoline (x86-64 JIT)

The x86-64 JIT SHOULD support retpoline as a Spectre v2 mitigation for indirect branches.

- **Source:** `vm/ubpf_jit_x86_64.c:1540-1578`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: When retpoline is enabled, indirect branches use the retpoline trampoline pattern.
  - AC-2: The retpoline pattern includes `PAUSE` + `JMP` speculative capture loop.

#### REQ-SEC-008: W⊕X for JIT Code

The JIT MUST never have memory that is simultaneously writable and executable. The compilation flow MUST use a staging buffer, then copy to read-execute memory.

- **Source:** `vm/ubpf_jit.c:134-156`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: At no point during compilation is memory marked as `PROT_WRITE | PROT_EXEC`.
  - AC-2: The final JIT code memory is `PROT_READ | PROT_EXEC`.

#### REQ-SEC-009: Custom Bounds Check Callback

`ubpf_register_data_bounds_check(vm, context, callback)` MUST allow users to register a custom bounds-checking function for non-standard memory regions. The callback receives `(context, addr, size)` and returns `bool`.

- **Source:** `vm/inc/ubpf.h:572-584`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: When registered, the custom callback is invoked for memory accesses outside the standard mem and stack regions.
  - AC-2: If the callback returns `false`, the access is denied.

---

### 4.8 Extensibility (REQ-EXT)

#### REQ-EXT-001: Helper Function Registration

`ubpf_register(vm, idx, name, fn)` MUST register an external helper function at the specified index. The index MUST be less than `UBPF_MAX_EXT_FUNCS` (64). The function signature is `uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t)`. An implicit 6th parameter (`void*` context pointer — the `mem` pointer passed to `ubpf_exec`/`ubpf_exec_ex`) is appended by the VM at the call site and MAY be accessed by the helper.

- **Source:** `vm/ubpf_vm.c:164-198`, `vm/inc/ubpf.h:217-218`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Registering at index 63 succeeds.
  - AC-2: Registering at index 64 fails with return value `-1`.
  - AC-3: The registered function is callable from eBPF via `CALL idx`.

#### REQ-EXT-002: Helper Function Limit

The VM MUST support a maximum of `UBPF_MAX_EXT_FUNCS` (64) external helper functions, indexed 0 through 63.

- **Source:** `vm/inc/ubpf.h:72`, `vm/ubpf_vm.c:167-169`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: All 64 slots can be filled simultaneously.

#### REQ-EXT-003: External Dispatcher

`ubpf_register_external_dispatcher(vm, dispatcher, validator)` MUST register a dynamic dispatch function that routes all external helper calls. The dispatcher signature is `uint64_t (*)(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, unsigned int index, void *cookie)`.

When a dispatcher is registered, it takes precedence over individually registered helpers.

- **Source:** `vm/inc/ubpf.h:223-249`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: With a dispatcher registered, all CALL instructions route through the dispatcher.
  - AC-2: The dispatcher receives the helper index and cookie parameter.
  - AC-3: The optional validator is called to check if a given index is valid.

#### REQ-EXT-004: Data Relocation Callback

`ubpf_register_data_relocation(vm, context, callback)` MUST register a callback for resolving `R_BPF_64_64` ELF relocations. The callback receives the user context, symbol name, section data, offset, and size.

- **Source:** `vm/inc/ubpf.h:545-561`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: The callback is invoked during ELF loading for each data relocation.
  - AC-2: The callback's return value is used to populate the instruction immediate fields.

#### REQ-EXT-005: Stack Usage Calculator

`ubpf_register_stack_usage_calculator(vm, calculator, cookie)` MUST register a function that determines per-function stack allocation. The calculator receives `(vm, pc, cookie)` and MUST return a value that is a multiple of 16.

- **Source:** `vm/inc/ubpf.h:256-282`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: The calculator is called for each local function during loading/execution.
  - AC-2: A return value that is not 16-byte aligned causes an error.

#### REQ-EXT-006: Debug Function Registration

`ubpf_register_debug_fn(vm, context, callback)` MUST register a debug callback invoked before each interpreter instruction. The callback receives the PC, registers (16 elements), stack pointer, stack size, register count, and user context.

- **Source:** `vm/inc/ubpf.h:661-680`, `vm/ubpf_vm.c:2373-2384`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: The callback is called exactly once per instruction in interpreter mode.
  - AC-2: The callback is NOT invoked during JIT execution. `[ASSUMPTION: Debug callbacks are interpreter-only based on API documentation]`

#### REQ-EXT-007: Unwind Function Index

`ubpf_set_unwind_function_index(vm, idx)` MUST designate a helper function index as the "unwind" function. When a CALL to this index returns `0`, the program MUST exit immediately.

- **Source:** `vm/ubpf_vm.c:228-237`, `vm/inc/ubpf.h:501-502`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: After setting unwind index to 5, calling helper 5 that returns 0 terminates the program.
  - AC-2: Calling helper 5 that returns non-zero continues execution.

---

### 4.9 Configuration (REQ-CFG)

#### REQ-CFG-001: Error Output Configuration

`ubpf_set_error_print(vm, error_printf)` MUST set the function used for runtime error reporting. The default MUST be `fprintf` (to stderr).

- **Source:** `vm/ubpf_vm.c:86-93, 125`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: After setting a custom error function, runtime errors are reported via that function.
  - AC-2: The default outputs to stderr.

#### REQ-CFG-002: JIT Code Size Configuration

`ubpf_set_jit_code_size(vm, code_size)` MUST set the working buffer size for JIT compilation. The default is `DEFAULT_JITTER_BUFFER_SIZE` (65536).

- **Source:** `vm/inc/ubpf.h:598-599`, `vm/ubpf_vm.c:143`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Setting `code_size` to 131072 causes the JIT to use a 131072-byte buffer.
  - AC-2: A program that exceeds the configured buffer size fails to compile with an error.

#### REQ-CFG-003: Instruction Limit Configuration

`ubpf_set_instruction_limit(vm, limit, previous_limit)` MUST set the maximum number of instructions the interpreter will execute. When `limit == 0`, no limit is enforced. The previous limit MUST be returned via `*previous_limit` (if non-NULL).

- **Source:** `vm/inc/ubpf.h:612-613`, `vm/ubpf_vm.c:2321-2329`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Setting limit to 100 causes an infinite loop program to terminate after 100 instructions.
  - AC-2: `*previous_limit` contains the prior value.

#### REQ-CFG-004: Register State Access

`int ubpf_set_registers(struct ubpf_vm* vm, uint64_t* regs)` and `uint64_t* ubpf_get_registers(const struct ubpf_vm* vm)` provide access to the VM's register state for debugging.

- In DEBUG builds, `ubpf_set_registers()` MUST override the VM's internal register storage with the user-provided array, and `ubpf_get_registers()` MUST return a pointer to the current register storage (user-provided or internal).
- In non-DEBUG builds, both functions MUST emit a diagnostic warning indicating that register access is not available, `ubpf_get_registers()` MUST return `NULL`, and `ubpf_set_registers()` MUST NOT modify the VM's register state.

- **Source:** `vm/inc/ubpf.h:510-520`, `vm/ubpf_vm.c:815-822`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: In a DEBUG build, after `ubpf_set_registers()`, the interpreter uses the provided register array for execution, and `ubpf_get_registers()` returns the same active register array.
  - AC-2: In a non-DEBUG build, calling `ubpf_get_registers()` returns `NULL` and a diagnostic warning is emitted, and calling `ubpf_set_registers()` leaves the VM's register state unchanged while emitting a diagnostic warning.

---

### 4.10 Platform Support (REQ-PLAT)

#### REQ-PLAT-001: Windows Support

uBPF MUST compile and run on Windows with MSVC. Platform compatibility MUST be provided via:

- `mmap`/`munmap`/`mprotect` emulation (`vm/compat/windows/sys/mman.h`).
- Endianness helpers (`vm/compat/windows/endian.h`).
- POSIX compatibility (`vm/compat/windows/unistd.h`).
- MSVC atomics for interpreter atomic operations.
- `BCryptGenRandom` for cryptographic random generation.
- Linking against `Ws2_32.lib` and the `win-c` submodule.

- **Source:** `vm/compat/windows/`, `vm/compat/CMakeLists.txt:9-30`, `vm/ubpf_int.h:238-249` (MSVC atomics)
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: The project builds with MSVC on Windows without errors.
  - AC-2: `mmap`/`mprotect` emulation provides equivalent W⊕X semantics.
  - AC-3: Interpreter atomic operations function correctly on Windows.

#### REQ-PLAT-002: Linux Support

uBPF MUST compile and run on Linux with GCC or Clang. Linux-specific dependencies:

- `libelf` for ELF loading.
- `libm` for math functions.
- Native `mmap`/`mprotect` for memory management.
- `getrandom` for cryptographic random generation.
- GCC/Clang built-in atomics for interpreter atomic operations.

- **Source:** `cmake/platform.cmake:13-14`, `vm/CMakeLists.txt:69-78`, `vm/ubpf_int.h:253-265`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: The project builds with GCC and Clang on Linux.
  - AC-2: ELF loading works with the system `libelf`.

#### REQ-PLAT-003: macOS Support

uBPF MUST compile and run on macOS with Clang. macOS-specific compatibility MUST be provided via:

- ELF compatibility headers (`compat/macOS/`).
- Endianness macros using `OSByteOrder.h` (`vm/compat/macos/endian.h`).
- `arc4random_buf` for cryptographic random generation.

- **Source:** `cmake/platform.cmake:11-12`, `vm/compat/macos/endian.h:14-26`, `compat/macOS/`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: The project builds with Clang on macOS.
  - AC-2: Byte-order conversion macros work correctly via `OSSwapHost*` functions.

#### REQ-PLAT-004: JIT Architecture Support

JIT compilation MUST be available on x86-64 and ARM64. On all other architectures, JIT compilation MUST fail with an error, and only interpreter execution SHALL be available.

- **Source:** `vm/ubpf_vm.c:127-138`, `vm/ubpf_int.h:172-184` (`ubpf_translate_null`)
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: `ubpf_compile()` succeeds on x86-64.
  - AC-2: `ubpf_compile()` succeeds on ARM64.
  - AC-3: `ubpf_compile()` returns NULL with an error message on unsupported architectures.
  - AC-4: `ubpf_exec()` works on all platforms regardless of JIT availability.

#### REQ-PLAT-005: Cryptographic Random Generation

The JIT MUST use platform-appropriate cryptographically secure random number generators:

- Windows: `BCryptGenRandom`.
- Linux: `getrandom`.
- macOS: `arc4random_buf`.
- Fallback: `rand()`. `[ASSUMPTION: rand() fallback exists for platforms without CSPRNG; this is not cryptographically secure]`

- **Source:** `vm/ubpf_jit_support.c:173-210` (`ubpf_generate_blinding_constant` implementation), declared in `vm/ubpf_jit_support.h:211`
- **Confidence:** **Medium** — platform implementations inferred from build configuration.
- **Acceptance Criteria:**
  - AC-1: On each supported platform, `ubpf_generate_blinding_constant()` returns non-deterministic 64-bit values.
  - AC-2: The fallback `rand()` is used only when no CSPRNG is available.

#### REQ-PLAT-006: Platform Atomic Operations

The interpreter MUST use platform-appropriate atomic operations:

- Windows (MSVC): `InterlockedExchangeAdd64`, `InterlockedOr64`, `InterlockedAnd64`, `InterlockedXor64`, `InterlockedExchange64`, `InterlockedCompareExchange64` (and 32-bit variants).
- GCC/Clang: `__sync_fetch_and_add`, `__sync_fetch_and_or`, `__sync_fetch_and_and`, `__sync_fetch_and_xor`, `__sync_lock_test_and_set`, `__sync_val_compare_and_swap` (and 32-bit variants).

- **Source:** `vm/ubpf_int.h:238-265`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Atomic operations produce correct results under concurrent access on each platform.
  - AC-2: Both 32-bit and 64-bit atomic variants are provided.

---

### 4.11 Error Handling (REQ-ERR) — Cross-Cutting

#### REQ-ERR-001: Error Message Allocation

`ubpf_error(fmt, ...)` MUST allocate and return a dynamically formatted error string via `vasprintf`. The caller is responsible for freeing the returned string. If allocation fails, NULL MUST be returned.

- **Source:** `vm/ubpf_vm.c:2212-2223`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: The returned string is heap-allocated and contains the formatted message.
  - AC-2: The caller can `free()` the returned string without error.

#### REQ-ERR-002: API Return Conventions

Functions returning `int` MUST return `0` on success and `-1` on failure, with `*errmsg` set to a descriptive error string.

Functions returning pointers MUST return `NULL` on failure, with `*errmsg` set.

Toggle functions MUST return the previous boolean state.

- **Source:** `vm/ubpf_vm.c` (throughout), `vm/inc/ubpf.h` (function declarations)
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: `ubpf_load()` returns 0 on success, -1 on failure.
  - AC-2: `ubpf_compile()` returns a non-NULL pointer on success, NULL on failure.
  - AC-3: `ubpf_toggle_bounds_check()` returns the previous value.

#### REQ-ERR-003: Runtime Error Reporting

Runtime errors during execution MUST be reported via `vm->error_printf`, which defaults to `fprintf(stderr, ...)`. Users MAY override this via `ubpf_set_error_print()`.

- **Source:** `vm/ubpf_vm.c:86-93, 125`
- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Division by zero in the interpreter produces an error message on stderr (default).
  - AC-2: With a custom error function, the message is routed to that function instead.

---

### 4.12 Constants and Limits (REQ-CONST) — Cross-Cutting

#### REQ-CONST-001: Key System Constants

The following constants MUST be defined and used consistently throughout the implementation:

| Constant | Value | Source |
|----------|-------|--------|
| `UBPF_MAX_INSTS` | 65536 | `vm/inc/ubpf.h:39` |
| `UBPF_MAX_CALL_DEPTH` | 8 | `vm/inc/ubpf.h:46` |
| `UBPF_EBPF_STACK_SIZE` | 4096 | `vm/inc/ubpf.h:53` |
| `UBPF_EBPF_LOCAL_FUNCTION_STACK_SIZE` | 256 | `vm/inc/ubpf.h:65` |
| `UBPF_MAX_EXT_FUNCS` | 64 | `vm/inc/ubpf.h:72` |
| `UBPF_EBPF_NONVOLATILE_SIZE` | 40 | `vm/inc/ubpf.h:75` |
| `DEFAULT_JITTER_BUFFER_SIZE` | 65536 | `vm/ubpf_vm.c:143` |

- **Confidence:** **High**
- **Acceptance Criteria:**
  - AC-1: Each constant has the specified value at compile time.

---

## 5. Dependencies

#### DEP-001: win-c Submodule (Windows)

The Windows build depends on the `win-c` git submodule for POSIX compatibility functions.

- **Source:** `vm/compat/CMakeLists.txt` (links `external::win-c`)
- **Confidence:** **High**

#### DEP-002: bpf_conformance Submodule (Testing)

The test suite depends on the `bpf_conformance` git submodule for RFC 9669 conformance testing.

- **Source:** `external/` directory
- **Confidence:** **High**

#### DEP-003: ebpf-verifier / prevail Submodule (Fuzzing)

The fuzzer build depends on the `ebpf-verifier` (prevail) git submodule for program verification.

- **Source:** `build-fuzz-prevail/`, `external/`
- **Confidence:** **High**

#### DEP-004: Python Test Dependencies

The test framework requires Python packages: `parcon` (parser), `nose` (test runner), `pyelftools` (ELF handling).

- **Source:** `requirements.txt`
- **Confidence:** **Medium** — inferred from file existence.

#### DEP-005: System Libraries (Linux)

Linux builds depend on `libelf` for ELF loading and `libm` for math functions.

- **Source:** `vm/CMakeLists.txt:69-78`
- **Confidence:** **High**

#### DEP-006: System Libraries (Windows)

Windows builds depend on `Ws2_32.lib` for network-related functions.

- **Source:** `vm/compat/CMakeLists.txt:28-30`
- **Confidence:** **High**

---

## 6. Assumptions

#### ASM-001: Little-Endian Host

The VM assumes a little-endian host architecture. ELF loading explicitly validates `ELFDATA2LSB`. Byte-swap operations are provided for big-endian data handling within programs.

- **Source:** `vm/ubpf_loader.c:135-138`
- **Confidence:** **High**

#### ASM-002: 64-Bit Host

The VM assumes a 64-bit host architecture. ELF loading validates `ELFCLASS64`. Pointer-sized operations assume 64-bit pointers.

- **Source:** `vm/ubpf_loader.c:130-133`
- **Confidence:** **High**

#### ASM-003: Single-Threaded VM Access

`[ASSUMPTION]` The VM is assumed to be accessed by a single thread at a time. No internal synchronization (mutexes, locks) is provided for concurrent `ubpf_exec()` or `ubpf_compile()` calls on the same VM instance. Atomic operations within eBPF programs are for guest-visible memory, not VM internal state.

- **Confidence:** **Medium** — no locking observed in codebase.

#### ASM-004: Caller Manages Error Strings

`[ASSUMPTION]` Error strings returned via `*errmsg` parameters are heap-allocated via `vasprintf`. The caller is responsible for calling `free()` on non-NULL error strings.

- **Source:** `vm/ubpf_vm.c:2212-2223`
- **Confidence:** **High**

#### ASM-005: Stack Growth Direction

`[ASSUMPTION]` The eBPF stack grows downward. R10 (frame pointer) points to the top of the stack, and stack allocations grow toward lower addresses.

- **Source:** `vm/ubpf_vm.c:827` (`reg[10] = stack_start + stack_length`)
- **Confidence:** **High**

---

## 7. Risks

#### RISK-001: rand() Fallback for Random Generation

On platforms without a CSPRNG (`BCryptGenRandom`, `getrandom`, `arc4random_buf`), the implementation falls back to `rand()`, which is NOT cryptographically secure. This weakens constant blinding and pointer secret effectiveness.

- **Severity:** Medium
- **Mitigation:** Document the fallback behavior; ensure all supported platforms use CSPRNG.

#### RISK-002: Partial ARM64 Constant Blinding

ARM64 constant blinding is documented as partial. Some instruction forms may expose immediate values in JIT output, reducing the effectiveness of JIT-spraying mitigations on ARM64.

- **Severity:** Low
- **Mitigation:** Document the limitation; complete ARM64 constant blinding coverage in a future release.

#### RISK-003: JIT Buffer Size Overflow

If the JIT-compiled native code exceeds the configured `jitter_buffer_size`, compilation fails. There is no automatic retry with a larger buffer.

- **Severity:** Low
- **Mitigation:** Allow users to configure buffer size via `ubpf_set_jit_code_size()`. Document sizing guidelines.

#### RISK-004: Post-JIT Helper Update Atomicity

Updating helper function pointers after JIT compilation requires temporarily making the JIT code writable. This creates a brief window where the code is writable, potentially exploitable in multi-threaded scenarios.

- **Severity:** Medium
- **Mitigation:** Document that helper updates are not thread-safe relative to JIT execution.

#### RISK-005: No Formal Verification of JIT Output

The JIT compiler generates native code without formal verification of equivalence to the interpreter semantics. JIT bugs could produce different behavior than the interpreter.

- **Severity:** Medium
- **Mitigation:** Rely on the bpf_conformance test suite for regression testing against RFC 9669.

---

## 8. Revision History

| Version | Date | Author | Description |
|---------|------|--------|-------------|
| 1.0.0 | 2026-03-31 | Extracted from source | Initial requirements extraction from uBPF codebase. All requirements derived from source code analysis of the public API (`vm/inc/ubpf.h`), VM implementation (`vm/ubpf_vm.c`), instruction validator (`vm/ubpf_instruction_valid.c`), ELF loader (`vm/ubpf_loader.c`), JIT compilers (`vm/ubpf_jit_x86_64.c`, `vm/ubpf_jit_arm64.c`, `vm/ubpf_jit.c`), internal headers (`vm/ubpf_int.h`, `vm/ebpf.h`), and build configuration (`CMakeLists.txt`, `cmake/`). |
