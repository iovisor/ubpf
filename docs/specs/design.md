# uBPF Design Specification

**Document Version:** 1.0.0
**Date:** 2026-03-31
**Status:** Draft — Extracted from source code

---

## 1. Overview

This document describes the design and architecture of the **uBPF** (userspace Berkeley Packet Filter) virtual machine library. uBPF is an Apache 2.0-licensed C library that executes eBPF programs outside the Linux kernel, providing:

- A portable interpreter for all supported platforms
- JIT compilers for x86-64 and ARM64 with security hardening
- An ELF loader with relocation support
- A modular extensibility framework for helper functions

**Design Philosophy:**
- **Correctness over performance** — the interpreter is the reference implementation; the JIT must produce identical results.
- **Defense in depth** — multiple independent security mechanisms (bounds checking, constant blinding, W⊕X, read-only bytecode, retpolines).
- **Platform portability** — core logic is platform-agnostic; platform differences are isolated in compatibility layers.
- **Minimal API surface** — a single opaque `struct ubpf_vm*` type with functional accessors.

**Confidence:** High — design philosophy is directly observable from code structure and API design.
**Source:** `vm/inc/ubpf.h`, `vm/ubpf_vm.c`, `vm/ubpf_int.h`

---

## 2. Requirements Summary

This design addresses the following requirement categories (see `docs/specs/requirements.md`):

| Category | REQ-IDs | Key Concerns |
|----------|---------|--------------|
| VM Lifecycle | REQ-LIFE-001 – 006 | Creation, destruction, resource management, defaults |
| Program Loading | REQ-LOAD-001 – 011 | Bytecode validation, memory modes, XOR encoding |
| Execution | REQ-EXEC-001 – 009 | Interpreter loop, register model, bounds checking |
| JIT Compilation | REQ-JIT-001 – 011 | Dual modes, code caching, W⊕X, platform ABIs |
| ELF Loading | REQ-ELF-001 – 007 | ELF validation, relocations, function linking |
| Instruction Set | REQ-ISA-001 – 012 | RFC 9669 compliance, ALU, memory, atomics |
| Security | REQ-SEC-001 – 009 | Bounds, blinding, retpolines, UB detection |
| Extensibility | REQ-EXT-001 – 007 | Helpers, dispatchers, debug hooks, callbacks |
| Configuration | REQ-CFG-001 – 004 | Error output, buffer sizing, limits |
| Platform | REQ-PLAT-001 – 006 | Windows, Linux, macOS, x86-64, ARM64 |

---

## 3. Architecture

### 3.1 High-Level Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                     APPLICATION LAYER                          │
│           (User code calling ubpf_* functions)                 │
└───────────────────────┬────────────────────────────────────────┘
                        │ Public API (ubpf.h)
┌───────────────────────▼────────────────────────────────────────┐
│                     API LAYER                                  │
│  ubpf_create/destroy · ubpf_load/load_elf · ubpf_exec         │
│  ubpf_compile · ubpf_register · ubpf_toggle_*                 │
├────────────┬──────────────┬──────────────┬─────────────────────┤
│ INTERPRETER│ JIT FRAMEWORK│  ELF LOADER  │  INSTRUCTION        │
│ ubpf_vm.c  │ ubpf_jit.c   │ ubpf_loader.c│  VALIDATOR          │
│            │              │              │ ubpf_instruction_    │
│ XOR-decode │ ┌──────────┐ │ ELF parsing  │  valid.c            │
│ fetch loop │ │x86-64 JIT│ │ Relocations  │                     │
│ Shadow     │ │ARM64 JIT │ │ Linking      │ Per-opcode filters  │
│ stack/regs │ └──────────┘ │              │ Sub-program checks  │
├────────────┴──────────────┴──────────────┴─────────────────────┤
│                   SUPPORT LAYER                                │
│  ubpf_jit_support.c — jit_state, patchable targets, RNG       │
│  ubpf_int.h — struct ubpf_vm, internal state                  │
│  ebpf.h — struct ebpf_inst, opcodes, register definitions     │
├────────────────────────────────────────────────────────────────┤
│                 PLATFORM ABSTRACTION                           │
│  vm/compat/windows/ — mmap, unistd, endian (via win-c)        │
│  vm/compat/macos/ — endian                                    │
│  compat/macOS/ — ELF headers (elfdefinitions, gelf, libelf)   │
└────────────────────────────────────────────────────────────────┘
```

**Confidence:** High
**Source:** Directory structure, `vm/CMakeLists.txt`, `#include` dependencies

### 3.2 Component Boundaries

| Boundary | Interface | Trust Level |
|----------|-----------|-------------|
| Application → API | `ubpf.h` public functions | Trusted (caller controls VM) |
| API → Interpreter | Internal function calls | Trusted |
| API → JIT | `vm->jit_translate` function pointer | Trusted |
| VM → eBPF Program | Bytecode execution | **Untrusted** (program may be adversarial) |
| VM → Helper Functions | `ext_funcs[]` / dispatcher | Semi-trusted (registered by application) |
| VM → Platform | `mmap`, `mprotect`, RNG | Trusted (OS services) |

**Confidence:** High — trust boundaries are directly evidenced by validation and bounds-checking placement.

### 3.3 Component Inventory

| Component | File(s) | Responsibility | Requirements |
|-----------|---------|----------------|--------------|
| Public API | `vm/inc/ubpf.h` | Type definitions, function declarations | All REQ-* |
| VM State | `vm/ubpf_int.h` | `struct ubpf_vm` definition | REQ-LIFE-001–006 |
| Instruction Defs | `vm/ebpf.h` | `struct ebpf_inst`, opcodes, registers | REQ-ISA-001–012 |
| Interpreter | `vm/ubpf_vm.c` | Execution loop, memory access, calls | REQ-EXEC-001–009 |
| Instruction Validator | `vm/ubpf_instruction_valid.c` | Per-opcode validation, sub-program checks | REQ-LOAD-004, REQ-LOAD-008–011 |
| ELF Loader | `vm/ubpf_loader.c` | ELF parsing, relocations, linking | REQ-ELF-001–007 |
| JIT Framework | `vm/ubpf_jit.c` | Mode selection, buffer management, W⊕X | REQ-JIT-001–008 |
| JIT Support | `vm/ubpf_jit_support.c` | `jit_state`, patchable targets, RNG | REQ-JIT-001–011 |
| x86-64 JIT | `vm/ubpf_jit_x86_64.c` | Native code gen, calling conventions | REQ-JIT-009, REQ-PLAT-004 |
| ARM64 JIT | `vm/ubpf_jit_arm64.c` | Native code gen, ARM64 ABI | REQ-JIT-010, REQ-PLAT-004 |
| Windows Compat | `vm/compat/windows/` | mmap/mprotect/unistd emulation | REQ-PLAT-001 |
| macOS Compat | `vm/compat/macos/`, `compat/macOS/` | Endian helpers, ELF headers | REQ-PLAT-003 |

---

## 4. Detailed Design

### 4.1 Central Data Structure: `struct ubpf_vm`

*Implements: REQ-LIFE-001, REQ-LIFE-002*

`struct ubpf_vm` (defined in `vm/ubpf_int.h`) is the single opaque type representing a VM instance. It is never exposed to users — only a pointer is returned from `ubpf_create()`.

**Field Groups:**

```
INSTRUCTION STORAGE
├── insts: struct ebpf_inst*        // Loaded instructions (XOR-encoded)
├── num_insts: uint16_t             // Instruction count
├── insts_alloc_size: size_t        // Allocation size (page-aligned if read-only)
├── readonly_bytecode_enabled: bool // Storage mode flag
└── pointer_secret: uint64_t        // XOR key for instruction obfuscation

JIT STATE
├── jitted: ubpf_jit_ex_fn          // Compiled native function pointer
├── jitted_size: size_t             // Size of compiled code
├── jitter_buffer_size: size_t      // Working buffer size (default: 65536)
├── jitted_result: struct ubpf_jit_result  // Compilation metadata
├── jit_translate: fn ptr           // Platform-specific code generator
├── jit_update_dispatcher: fn ptr   // Hot-patch dispatcher in JIT code
└── jit_update_helper: fn ptr       // Hot-patch helper in JIT code

EXTERNAL FUNCTIONS
├── ext_funcs: extended_external_helper_t*  // Helper function table [64]
├── ext_func_names: const char**    // Function names for debugging/ELF lookup
├── int_funcs: bool*                // Local function markers
├── dispatcher: external_function_dispatcher_t  // Dynamic dispatch callback
├── dispatcher_validate: fn ptr     // Dispatcher validation callback
└── dispatcher_cookie: void*        // Dispatcher context

LOCAL FUNCTION STACK
├── local_func_stack_usage: struct ubpf_stack_usage*  // Per-function stack sizes
├── stack_usage_calculator: fn ptr  // Custom stack size callback
└── stack_usage_calculator_cookie: void*

SECURITY FLAGS
├── bounds_check_enabled: bool      // Default: true
├── undefined_behavior_check_enabled: bool  // Default: false
├── constant_blinding_enabled: bool // Default: false
└── instruction_limit: int          // Default: 0 (unlimited)

CALLBACKS
├── data_relocation_function: fn ptr    // R_BPF_64_64 relocation callback
├── bounds_check_function: fn ptr       // Custom bounds check callback
├── debug_function: ubpf_debug_fn       // Per-instruction debug hook
├── debug_function_context: void*
├── error_printf: fn ptr                // Error output (default: fprintf(stderr))
└── unwind_stack_extension_index: int   // Tail-call helper index
```

**Confidence:** High
**Source:** `vm/ubpf_int.h:67-119`

### 4.2 Instruction Representation

*Implements: REQ-ISA-001, REQ-ISA-002*

```c
struct ebpf_inst {
    uint8_t opcode;     // Instruction opcode (class | operation | source)
    uint8_t dst : 4;    // Destination register (0-10)
    uint8_t src : 4;    // Source register (0-10)
    int16_t offset;     // Signed offset for jumps/memory
    int32_t imm;        // 32-bit signed immediate
};  // 8 bytes total
```

**Register Model (BPF_REG enum):**
- `r0`: Return value
- `r1–r5`: Function parameters (caller-saved)
- `r6–r9`: Callee-saved across calls
- `r10`: Frame pointer (read-only in bytecode, points to top of current stack frame)

**Opcode Encoding:** `class (3 bits) | operation (4 bits) | source (1 bit)`

**Confidence:** High
**Source:** `vm/ebpf.h:15-30`, `vm/ebpf.h:32-110`

### 4.3 VM Lifecycle

*Implements: REQ-LIFE-001 through REQ-LIFE-006*

#### Creation (`ubpf_create`)

1. `calloc` a `struct ubpf_vm` (zero-initialized)
2. Allocate `ext_funcs` array (UBPF_MAX_EXT_FUNCS = 64 entries)
3. Allocate `ext_func_names` array
4. Allocate `local_func_stack_usage` table (UBPF_MAX_INSTS entries)
5. Set defaults:
   - `bounds_check_enabled = true`
   - `undefined_behavior_check_enabled = false`
   - `constant_blinding_enabled = false`
   - `readonly_bytecode_enabled = true`
   - `error_printf = fprintf`
   - `jitter_buffer_size = 65536`
6. Select platform JIT at compile time:
   ```
   #if x86_64 → jit_translate = ubpf_translate_x86_64
   #elif aarch64 → jit_translate = ubpf_translate_arm64
   #else → jit_translate = ubpf_translate_null (returns error)
   ```

**Confidence:** High
**Source:** `vm/ubpf_vm.c:ubpf_create`

#### Destruction (`ubpf_destroy`)

1. Call `ubpf_unload_code()` to free bytecode and JIT code
2. Free `ext_funcs`, `ext_func_names`, `local_func_stack_usage`
3. Free the VM struct itself

**Confidence:** High
**Source:** `vm/ubpf_vm.c:ubpf_destroy`

#### Code Unloading (`ubpf_unload_code`)

1. If read-only mode: `munmap(insts, insts_alloc_size)`; else: `free(insts)`
2. If JIT code exists: `munmap(jitted, jitted_size)`
3. Free `int_funcs` array
4. Reset `num_insts = 0`, reinitialize stack usage table
5. Free any JIT error message

**Confidence:** High
**Source:** `vm/ubpf_vm.c:ubpf_unload_code`

### 4.4 Program Loading Flow

*Implements: REQ-LOAD-001 through REQ-LOAD-011*

```
ubpf_load(vm, code, code_len, errmsg)
    │
    ├── Validate: code_len % 8 == 0
    ├── Validate: num_insts < UBPF_MAX_INSTS (65536)
    ├── Validate: no code already loaded
    │
    ├── validate(vm, insts, num_insts, errmsg)
    │   ├── For each instruction:
    │   │   ├── ubpf_is_valid_instruction(inst, errmsg)
    │   │   │   └── Check against per-opcode filter tables:
    │   │   │       opcode, dst range, src range, offset bounds, imm bounds
    │   │   ├── Jump target bounds check
    │   │   ├── Jump offset != -1 (no infinite loops)
    │   │   ├── LDDW pairing check
    │   │   └── Local function target validation
    │   │
    │   ├── Stack usage calculation (must be 16-byte aligned)
    │   └── Self-contained sub-program verification:
    │       ├── Identify sub-program boundaries (CALL src==1 targets)
    │       ├── Verify no cross-program jumps
    │       └── Each sub-program ends with EXIT or JA
    │
    ├── Allocate instruction storage:
    │   ├── Read-only mode (default):
    │   │   ├── Calculate page-aligned size
    │   │   ├── mmap(PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS)
    │   │   └── After loading: mprotect(PROT_READ)
    │   └── Writable mode:
    │       └── malloc(code_len)
    │
    ├── Store instructions with XOR encoding:
    │   └── ubpf_store_instruction(vm, pc, inst)
    │       └── inst XOR'd with (uint64_t)vm->insts, then XOR'd with vm->pointer_secret
    │
    └── Mark local functions in int_funcs[] array
```

**Confidence:** High
**Source:** `vm/ubpf_vm.c:ubpf_load`, `vm/ubpf_vm.c:validate`

### 4.5 Interpreter Execution

*Implements: REQ-EXEC-001 through REQ-EXEC-009*

#### Register Initialization

```
r0 = 0                  (return value, initially zero)
r1 = (uintptr_t)mem     (context pointer)
r2 = (uint64_t)mem_len  (context size)
r3–r9 = 0               (cleared)
r10 = stack + stack_len  (frame pointer, top of stack)
```

#### Execution Loop

```
while (pc < num_insts):
    1. inst = ubpf_fetch_instruction(vm, pc)     // XOR-decode
    2. if (undefined_behavior_check_enabled):
           validate shadow registers for src/dst
    3. if (debug_function != NULL):
           invoke debug_function(context, pc, regs, stack, ...)
    4. switch (inst.opcode):
           // ALU64 operations: full 64-bit arithmetic
           // ALU32 operations: 32-bit, result masked to UINT32_MAX
           // Memory loads: COMPUTE_EFFECTIVE_ADDR + BOUNDS_CHECK_LOAD
           // Memory stores: COMPUTE_EFFECTIVE_ADDR + BOUNDS_CHECK_STORE
           // Jumps: relative offset, conditional on comparison
           // CALL src==0: external helper dispatch
           // CALL src==1: local function call (save r6-r9, adjust r10)
           // EXIT: return r0 (or pop local call frame)
           // Atomic: platform-specific atomics
    5. pc++
    6. if (instruction_limit > 0 && count >= limit): error
```

#### Local Function Call Mechanics

```
CALL src==1, imm=offset:
    stack_frames[depth].saved_registers = {r6, r7, r8, r9}
    stack_frames[depth].return_address = pc
    stack_frames[depth].stack_usage = ubpf_stack_usage_for_local_func(vm, target)
    r10 -= stack_usage         // Grow stack downward
    depth++                    // Max: UBPF_MAX_CALL_DEPTH (8)
    pc += imm                  // Jump to function

EXIT (when depth > 0):
    depth--
    r6, r7, r8, r9 = stack_frames[depth].saved_registers
    r10 += stack_frames[depth].stack_usage
    pc = stack_frames[depth].return_address
```

#### External Function Call Mechanics

```
CALL src==0, imm=index:
    if (dispatcher != NULL):
        r0 = dispatcher(r1, r2, r3, r4, r5, index, cookie)
    else:
        r0 = ext_funcs[index](r1, r2, r3, r4, r5, cookie)

    if (index == unwind_stack_extension_index && r0 == 0):
        exit program immediately
```

**Confidence:** High
**Source:** `vm/ubpf_vm.c:ubpf_exec_ex` (lines ~758-1751)

### 4.6 JIT Compilation Pipeline

*Implements: REQ-JIT-001 through REQ-JIT-011*

#### Compilation Flow

```
ubpf_compile_ex(vm, errmsg, mode)
    │
    ├── Check: code loaded?
    ├── Check: cached? (same mode → return cached)
    │
    ├── Allocate working buffer (jitter_buffer_size bytes, heap)
    ├── ubpf_translate_ex(vm, buffer, &size, mode)
    │   └── vm->jit_translate(vm, buffer, &size, mode)
    │       ├── Emit function prologue (ABI-specific)
    │       ├── For each eBPF instruction:
    │       │   ├── Map to native instruction sequence
    │       │   ├── Apply constant blinding (if enabled)
    │       │   ├── Record patchable targets (jumps, loads, calls)
    │       │   └── Emit retpoline stubs (if enabled, x86-64)
    │       ├── Emit function epilogue
    │       ├── Emit helper table / dispatcher pointer
    │       └── Resolve all patchable targets
    │
    ├── Allocate executable buffer:
    │   └── mmap(size, PROT_READ|PROT_WRITE)
    ├── memcpy(exec_buffer, working_buffer, size)
    ├── mprotect(exec_buffer, PROT_READ|PROT_EXEC)  // W⊕X
    ├── Free working buffer
    └── Cache result: vm->jitted = exec_buffer
```

#### JIT Modes

| Mode | Signature | Stack | Use Case |
|------|-----------|-------|----------|
| BasicJitMode | `uint64_t(void* mem, size_t mem_len)` | Auto-allocated in prologue | Simple embedding |
| ExtendedJitMode | `uint64_t(void* mem, size_t mem_len, uint8_t* stack, size_t stack_len)` | Caller-provided | Resource-constrained, external stack management |

**Confidence:** High
**Source:** `vm/ubpf_jit.c:ubpf_compile_ex`, `vm/ubpf_jit.c:ubpf_translate_ex`

#### JIT State Management

`struct jit_state` (`vm/ubpf_jit_support.c`) tracks code generation:

```
buf: uint8_t*           // Output buffer
offset: uint32_t        // Current write position
size: uint32_t          // Buffer capacity
pc_locs: uint32_t*      // eBPF PC → native offset mapping
exit_loc: uint32_t      // Native offset of exit sequence
retpoline_loc: uint32_t // Native offset of retpoline gadget
dispatcher_loc: uint32_t // Offset of dispatcher function pointer
helper_table_loc: uint32_t // Offset of helper function pointer table
jumps[]: patchable_relative    // Jump fixup records
loads[]: patchable_relative    // Load fixup records
local_calls[]: patchable_relative // Local call fixup records
```

**Patchable Target Resolution:**
1. During code generation, emit placeholder offsets and record in fixup tables
2. After all code emitted, resolve each target:
   - Regular targets: look up `pc_locs[target_pc]`
   - Special targets: `exit_loc`, `retpoline_loc`, `dispatcher_loc`, etc.
3. Patch the placeholder with the actual relative offset

**Confidence:** High
**Source:** `vm/ubpf_jit_support.c`, `vm/ubpf_jit_support.h`

### 4.7 x86-64 JIT Backend

*Implements: REQ-JIT-009, REQ-PLAT-004, REQ-SEC-004, REQ-SEC-007*

#### Register Mapping

| BPF Register | System V (Linux/macOS) | Windows x64 |
|---|---|---|
| r0 (return) | RAX | RAX |
| r1 (param 1) | RDI | RCX |
| r2 (param 2) | RSI | RDX |
| r3 (param 3) | RDX | R8 |
| r4 (param 4) | RCX | R9 |
| r5 (param 5) | R8 | Stack |
| r6–r9 (callee) | RBX, R13, R14, R15 | RBX, R13, R14, R15 |
| r10 (frame ptr) | RBP | RBP |

#### Constant Blinding (x86-64)

For each immediate value in the instruction stream:
1. Generate cryptographic random value `R`
2. Emit `MOV reg, (imm XOR R)` — the blinded value
3. Emit `XOR reg, R` — recover the original value

This prevents an attacker from controlling immediate bytes in JIT output.

**RNG Sources:** BCryptGenRandom (Windows), getrandom (Linux), arc4random_buf (macOS), rand() fallback.

**Confidence:** High
**Source:** `vm/ubpf_jit_x86_64.c` (constant blinding functions, ~lines 462-707)

#### Retpoline Support (x86-64)

Mitigates Spectre variant 2 (branch target injection) on indirect calls:

```asm
retpoline:
    call .Lfuture        ; Push return address
.Lpause:
    pause                ; CPU hint: speculative execution trap
    lfence               ; Serialize instruction stream
    jmp .Lpause          ; Loop (never reached in practice)
.Lfuture:
    ; Actual indirect call happens via return stack buffer
```

Configurable via `UBPF_DISABLE_RETPOLINES` CMake option (default: enabled).

**Confidence:** High
**Source:** `vm/ubpf_jit_x86_64.c:emit_retpoline`, `cmake/options.cmake`

### 4.8 ARM64 JIT Backend

*Implements: REQ-JIT-010, REQ-PLAT-004*

#### Register Mapping

| BPF Register | ARM64 Register |
|---|---|
| r0 (return) | x5 |
| r1–r5 (params) | x0–x4 |
| r6–r10 (callee) | x19–x23 |
| Temp registers | x24, x25, x26 |

#### ARM64-Specific Features

- **Immediate loading:** ARM64 has limited immediate encoding; complex values use MOVZ + MOVK sequences
- **Atomic operations:** LDAXR/STLXR exclusive-access loops (vs x86-64 LOCK prefix)
- **Division:** Native SDIV/UDIV instructions (simpler than x86-64 which requires RDX:RAX setup)
- **Constant blinding:** Partial support — applies to MOVZ sequences but `[UNKNOWN: full coverage scope on ARM64]`

**Confidence:** High (general), Medium (constant blinding completeness)
**Source:** `vm/ubpf_jit_arm64.c`

### 4.9 ELF Loading

*Implements: REQ-ELF-001 through REQ-ELF-007*

#### ELF Validation

Required ELF properties:
- Magic: `0x7f 'E' 'L' 'F'`
- Class: ELFCLASS64
- Data: ELFDATA2LSB (little-endian)
- Version: 1
- OS/ABI: ELFOSABI_NONE
- Type: ET_REL (relocatable)
- Machine: EM_NONE or EM_BPF (247)

#### Relocation Processing

**R_BPF_64_64 (Data Relocation):**
- Used for 64-bit immediate values pointing to data sections (e.g., maps)
- Requires user-registered callback via `ubpf_register_data_relocation()`
- Callback receives: data section pointer, symbol name/offset/size
- Returns: 64-bit value to load into LDDW instruction

**R_BPF_64_32 / R_BPF_64_32_LEGACY (Code Relocation):**
- `src==1` (local function call): Calculate relative PC offset to target function
- `src!=1` (external helper): Look up helper name via `ubpf_lookup_registered_function()`

#### Function Linking

1. Identify main function (by name parameter or first `.text` symbol)
2. Collect all function symbols pointing to executable sections (`SHF_ALLOC | SHF_EXECINSTR`)
3. Relocate all functions into contiguous memory (main function first)
4. Update all CALL offsets to reflect new positions
5. Pass linked bytecode to `ubpf_load()`

**Confidence:** High
**Source:** `vm/ubpf_loader.c`

### 4.10 Security Architecture

*Implements: REQ-SEC-001 through REQ-SEC-009*

#### Threat Model

**Attacker Model:** Untrusted eBPF program loaded into the VM by a trusted application. The attacker controls the bytecode but not the host application.

**Threats and Mitigations:**

| Threat | Mitigation | Default | REQ |
|--------|------------|---------|-----|
| Out-of-bounds memory access | Bounds checking on every load/store | Enabled | REQ-SEC-001 |
| Use of uninitialized data | Shadow stack + shadow registers | Disabled | REQ-SEC-003 |
| JIT spraying (embedding shellcode in immediates) | Constant blinding (XOR with random) | Disabled | REQ-SEC-004 |
| Bytecode modification after validation | Read-only mmap'd pages | Enabled | REQ-SEC-005 |
| ROP gadget harvesting from bytecode | XOR encoding with pointer secret | Enabled | REQ-SEC-006 |
| Spectre v2 (branch target injection) | Retpolines for indirect calls | Enabled | REQ-SEC-007 |
| Executable memory modification | W⊕X (separate R|W and R|X phases) | Always | REQ-SEC-008 |

#### Bounds Checking Detail

Memory access validation checks:
1. Compute effective address: `base_reg + offset`
2. Check for address computation overflow
3. Verify: `addr >= mem_start && addr + size <= mem_end` (for context memory)
4. Verify: `addr >= stack_start && addr + size <= stack_end` (for stack)
5. If custom bounds_check_function registered, also call it

**Confidence:** High
**Source:** `vm/ubpf_vm.c` (BOUNDS_CHECK_LOAD/BOUNDS_CHECK_STORE macros)

#### Shadow Stack / Shadow Registers (UB Detection)

- **Shadow stack:** Bit array (1 bit per byte of stack). Bits set on write, checked on read.
- **Shadow registers:** Bitmask tracking which registers have been written. Checked before use.
- Performance impact: significant (additional tracking per instruction)
- Default: disabled

**Confidence:** High
**Source:** `vm/ubpf_vm.c` (shadow stack allocation, check_shadow_stack/check_shadow_register functions)

### 4.11 Extensibility Framework

*Implements: REQ-EXT-001 through REQ-EXT-007*

#### Helper Function Registration

Two models:

1. **Static table** (`ubpf_register`): Register function at index 0–63.
   - Signature: `uint64_t fn(uint64_t r1, r2, r3, r4, r5)`
   - Implicit 6th parameter: `void*` context (mem pointer)
   - Can update JIT'd code without recompilation via `jit_update_helper`

2. **Dynamic dispatcher** (`ubpf_register_external_dispatcher`): Single callback handles all helper calls.
   - Signature: `uint64_t dispatcher(uint64_t r1-r5, unsigned int index, void* cookie)`
   - Validator: `bool validator(unsigned int index, const struct ubpf_vm* vm)`
   - Can update JIT'd code without recompilation via `jit_update_dispatcher`

#### Callback Hooks

| Hook | Purpose | When Called |
|------|---------|-------------|
| `data_relocation_function` | Resolve R_BPF_64_64 ELF relocations | During `ubpf_load_elf_ex` |
| `bounds_check_function` | Custom memory region validation | During interpreter memory access |
| `stack_usage_calculator` | Per-function stack sizing | During `ubpf_load` validation |
| `debug_function` | Per-instruction instrumentation | Before each interpreter instruction |
| `error_printf` | Error output redirection | On any error |

**Confidence:** High
**Source:** `vm/ubpf_vm.c`, `vm/inc/ubpf.h`

---

## 5. Tradeoff Analysis

### 5.1 Interpreter vs. JIT

| Aspect | Interpreter | JIT |
|--------|-------------|-----|
| Portability | All platforms | x86-64 and ARM64 only |
| Performance | Slower (switch dispatch) | Faster (native code) |
| Security features | All (bounds, UB, debug) | Partial (no UB detection, no debug hooks) |
| Attack surface | Smaller (no code generation) | Larger (executable memory, code gen bugs) |
| Determinism | Fully deterministic | Platform-dependent behavior possible |

**Decision:** Provide both. Interpreter is reference; JIT is optional performance optimization.
`[ASSUMPTION]` The JIT is assumed to produce semantically identical results to the interpreter for all valid programs. This is enforced by fuzzing (differential testing).

**Confidence:** High
**Source:** `libfuzzer/libfuzz_harness.cc` (interpreter vs JIT comparison)

### 5.2 Read-Only vs. Writable Bytecode

| Aspect | Read-Only (default) | Writable |
|--------|-------------------|----------|
| Security | Prevents post-validation modification | Bytecode modifiable at runtime |
| Memory overhead | Page-aligned allocation (up to 4KB waste) | Exact allocation |
| Compatibility | Requires mmap/mprotect support | Works everywhere |

**Decision:** Default to read-only for security. Provide toggle for environments without mmap.

**Confidence:** High
**Source:** `vm/ubpf_vm.c:ubpf_load`, `vm/inc/ubpf.h:ubpf_toggle_readonly_bytecode`

### 5.3 Retpolines: Security vs. Performance

**Decision:** Enabled by default. Configurable at build time (`UBPF_DISABLE_RETPOLINES`). The performance cost on modern CPUs with hardware mitigations is minimal, while the security benefit on older CPUs is significant.

**Confidence:** Medium — `[ASSUMPTION]` performance impact is "minimal" based on general knowledge of modern CPUs; no benchmarks in the codebase.
**Source:** `cmake/options.cmake`, `vm/ubpf_jit_x86_64.c:emit_retpoline`

### 5.4 Static Helper Table vs. Dynamic Dispatcher

| Aspect | Static Table | Dynamic Dispatcher |
|--------|-------------|-------------------|
| Lookup cost | O(1) array index | Function call overhead |
| Flexibility | Fixed at registration | Runtime routing |
| JIT integration | Direct call to known address | Indirect call through pointer |
| Max functions | 64 (UBPF_MAX_EXT_FUNCS) | Unlimited |

**Decision:** Support both. Static table for performance; dispatcher for runtimes with dynamic function sets.

**Confidence:** High
**Source:** `vm/ubpf_vm.c` (dual dispatch path in CALL handling)

---

## 6. Security Considerations

### 6.1 Trust Boundaries

```
TRUSTED                    │  UNTRUSTED
                           │
Application code           │  eBPF bytecode
Helper functions           │  Program behavior
VM configuration           │  Memory access patterns
OS services (mmap, RNG)    │  Control flow
                           │
── Validation barrier ─────┤
   (ubpf_load validates    │
    before any execution)  │
```

### 6.2 Security Invariants

1. **No eBPF instruction can access memory outside designated regions** (when bounds checking enabled)
2. **No JIT output contains attacker-controlled byte sequences** (when constant blinding enabled)
3. **Bytecode cannot be modified after validation** (when read-only mode enabled)
4. **JIT code pages are never simultaneously writable and executable** (W⊕X always enforced)
5. **Instruction pointers stored in memory are obfuscated** (when pointer secret is set)

### 6.3 Known Limitations

- **No formal verification** of the JIT compiler — correctness relies on differential testing
- **No control-flow integrity** beyond basic instruction validation
- **Thread safety is undocumented** — `[UNKNOWN: thread safety guarantees for concurrent ubpf_exec on same VM]`
- **Constant blinding on ARM64 is partial** — `[UNKNOWN: which instruction types lack blinding on ARM64]`

**Confidence:** High (invariants), Low (limitations — inferred from absence of documentation)

---

## 7. Operational Considerations

### 7.1 Build System

- **CMake 3.16+** with Ninja (preferred) or Visual Studio generators
- **Presets:** `tests`, `fuzzing`, `fuzzing-windows`, `all-testing`
- **Version:** 1.0.0 (defined in `cmake/version.cmake`)

### 7.2 CI/CD Pipeline

7 GitHub Actions workflows providing:
- Windows (Debug/Release, with/without retpolines)
- Linux (Debug/Release, coverage, ASan/UBSan, Valgrind, scan-build, CodeQL)
- macOS (Debug/Release)
- ARM64 (cross-compilation + QEMU)
- Fuzzing (1-hour daily, corpus regression)
- Documentation (Doxygen → gh-pages)
- Security (dependency review, OSSF Scorecard)

### 7.3 Packaging

- DEB, RPM, TGZ (Linux)
- TGZ (macOS, Windows)
- Relocatable packages with separate debug info

**Confidence:** High
**Source:** `.github/workflows/`, `cmake/packaging.cmake`, `CMakePresets.json`

---

## 8. Open Questions

| ID | Question | Impact | Priority |
|----|----------|--------|----------|
| OQ-1 | What is the thread-safety model for `struct ubpf_vm`? `ubpf_exec` takes `const struct ubpf_vm*` suggesting read-sharing is intended, but mutable JIT state and helper registration complicate this. | API correctness | High |
| OQ-2 | What specific ARM64 instruction types lack constant blinding? | Security gap assessment | Medium |
| OQ-3 | Is BTF call support (CALL src==2) planned? Instruction validation mentions it as "not yet supported." | Future compatibility | Low |
| OQ-4 | What is the intended behavior when `ubpf_register` is called after `ubpf_compile` — does the JIT hot-patch always work, or are there race conditions? | API correctness | Medium |
| OQ-5 | Should the `rand()` fallback for RNG be removed? It's not cryptographically secure and may weaken constant blinding. | Security | Medium |
| OQ-6 | What is the intended relationship between `UBPF_EBPF_NONVOLATILE_SIZE` (40) and the JIT register save area? | Design clarity | Low |

---

## 9. Revision History

| Version | Date | Author | Description |
|---------|------|--------|-------------|
| 1.0.0 | 2026-03-31 | Extracted by AI | Initial draft — extracted from uBPF source code analysis |
