# uBPF Validation Plan

**Document Version:** 1.0.0
**Date:** 2026-03-31
**Status:** Draft — Extracted from existing test infrastructure

---

## 1. Overview

### 1.1 Objectives

This validation plan defines how the uBPF virtual machine library is verified against its requirements specification (`docs/specs/requirements.md`). It maps existing tests to requirements, identifies coverage gaps, and provides a framework for ongoing validation.

### 1.2 System Under Test

The uBPF library including:
- Core VM interpreter (`vm/ubpf_vm.c`)
- JIT compilers (`vm/ubpf_jit_x86_64.c`, `vm/ubpf_jit_arm64.c`)
- ELF loader (`vm/ubpf_loader.c`)
- Instruction validator (`vm/ubpf_instruction_valid.c`)
- Public API (`vm/inc/ubpf.h`)
- Python assembler/disassembler (`ubpf/`)

### 1.3 Validation Approach

uBPF uses a multi-layered testing strategy:
1. **Data-driven tests** — `.data` files parsed by Python test framework
2. **Custom C++ tests** — targeted scenarios for specific features
3. **Conformance suite** — BPF ISA standard compliance (313 tests)
4. **Differential fuzzing** — interpreter vs. JIT comparison with PREVAIL verifier
5. **Static analysis** — CodeQL, scan-build, cpplint, pylint
6. **Dynamic analysis** — ASan, UBSan, Valgrind

---

## 2. Scope of Validation

### 2.1 In Scope

- All public API functions in `ubpf.h`
- Interpreter execution correctness
- JIT compilation correctness (x86-64, ARM64)
- ELF loading and relocation processing
- Instruction validation and error handling
- Security feature effectiveness
- Platform-specific behavior (Windows, Linux, macOS)
- Python assembler/disassembler correctness

### 2.2 Out of Scope

- Performance benchmarking (no perf regression tests exist)
- Thread safety / concurrency testing
- Formal verification of JIT output
- External verifier (PREVAIL) correctness
- Stress testing (large programs, deep recursion)

### 2.3 Constraints

- ARM64 JIT tests require QEMU on x86-64 hosts or native ARM64 hardware
- Fuzzing requires Clang (libFuzzer integration)
- Some tests require environment variables (e.g., `UBPF_ENABLE_CONSTANT_BLINDING=1`)
- Valgrind only available on Linux

---

## 3. Test Strategy

### 3.1 Test Levels

| Level | Description | Tools | Coverage |
|-------|-------------|-------|----------|
| **Unit** | Individual instruction execution | `.data` files + test_vm.py | ISA compliance |
| **Integration** | VM lifecycle + loading + execution | Custom C++ tests | API interactions |
| **System** | Full pipeline (load ELF → compile → execute) | test_elf.py, ubpf_plugin | End-to-end |
| **Regression** | Prevent reintroduction of fixed bugs | Full CTest suite | All areas |
| **Fuzzing** | Find edge cases and differential bugs | libFuzzer + PREVAIL | Interpreter/JIT parity |

### 3.2 Test Techniques

| Technique | Application |
|-----------|-------------|
| **Equivalence partitioning** | ALU operations by operand type (reg/imm, 32/64-bit) |
| **Boundary value analysis** | Register ranges (0, 9, 10), instruction count limits, stack boundaries |
| **Error guessing** | Division by zero, stack overflow, invalid opcodes |
| **Differential testing** | Interpreter vs. JIT output comparison (fuzzer) |
| **Mutation testing** | Register offset variations (20 per test in JIT) |
| **Conformance testing** | BPF ISA standard (RFC 9669) compliance |

### 3.3 Test Infrastructure

**Python Framework (`test_framework/`):**
- `testdata.py` — Parses `.data` files into test parameters
- `test_vm.py` — Interpreter execution (1 test per `.data` file)
- `test_jit.py` — JIT compilation (20 register-offset variants per `.data` file)
- `test_elf.py` — ELF format loading
- `test_assembler.py` — Assembly → binary verification
- `test_disassembler.py` — Binary → assembly verification
- `test_roundtrip.py` — Assembler → binary → disassembler consistency

**Custom Tests (`custom_tests/`):**
- 17 C++20 test programs with markdown descriptors
- Each returns 0 (pass) or non-zero (fail)
- Some read input from stdin via `.input` data files

**Conformance Suite (`external/bpf_conformance/`):**
- 313 `.data` files for standard eBPF instruction semantics
- Executed via `ubpf_plugin` for both interpreter and JIT

**Fuzzer (`libfuzzer/libfuzz_harness.cc`):**
- Differential testing: interpreter vs. JIT
- Optional PREVAIL verifier integration
- Configurable via environment variables

---

## 4. Requirements Traceability Matrix

### 4.1 VM Lifecycle

| REQ-ID | Requirement | Test Cases | Coverage |
|--------|-------------|------------|----------|
| REQ-LIFE-001 | VM creation | TC-LIFE-001 | **High** — implicitly tested by all tests |
| REQ-LIFE-005 | VM destruction | TC-LIFE-002 | **Medium** — Valgrind checks, reload_code_memleak |
| REQ-LIFE-006 | Code unloading | TC-LIFE-003 | **High** — unload_reload.data, reload.data |
| REQ-LIFE-002 | Default configuration | TC-LIFE-004 | **Medium** — tested indirectly via default behavior |
| REQ-LIFE-004 | Platform JIT selection | TC-LIFE-005 | **High** — CI runs on x86-64, ARM64, macOS |
| REQ-LIFE-003 | Memory allocation failure | TC-LIFE-006 | **Low** — `[GAP: no explicit OOM tests]` |

### 4.2 Program Loading

| REQ-ID | Requirement | Test Cases | Coverage |
|--------|-------------|------------|----------|
| REQ-LOAD-003 | Load API contract | TC-LOAD-001 | **High** — all .data tests call ubpf_load |
| REQ-LOAD-001 | Code size validation | TC-LOAD-002 | **Medium** — `[GAP: no test for non-multiple-of-8]` |
| REQ-LOAD-002 | Instruction count limit | TC-LOAD-003 | **Low** — `[GAP: no test with 65536+ instructions]` |
| REQ-LOAD-004 | Instruction validation | TC-LOAD-004 | **High** — tests/errors/*, atomic_validate custom test |
| REQ-LOAD-008 | Stack alignment | TC-LOAD-005 | **High** — custom_local_function_stack_size tests |
| REQ-LOAD-009 | Self-contained sub-programs | TC-LOAD-006 | **Medium** — tested via local call tests |
| REQ-LOAD-005 | Read-only bytecode storage | TC-LOAD-007 | **High** — readonly_bytecode custom test |
| REQ-LOAD-005 | Writable bytecode storage | TC-LOAD-008 | **Medium** — readonly_bytecode test toggles mode |
| REQ-LOAD-006 | XOR instruction encoding | TC-LOAD-009 | **Medium** — `[GAP: no direct test of XOR encoding correctness]` |
| REQ-LOAD-007 | Local function marking | TC-LOAD-010 | **High** — call_local_use_stack.data, factorial.data |
| REQ-LOAD-003 | Code replacement | TC-LOAD-011 | **High** — reload.data, unload_reload.data, reload_code_memleak |

### 4.3 Program Execution

| REQ-ID | Requirement | Test Cases | Coverage |
|--------|-------------|------------|----------|
| REQ-EXEC-001 | exec API contract | TC-EXEC-001 | **High** — test_vm.py runs all .data files |
| REQ-EXEC-002 | exec_ex API (external stack) | TC-EXEC-002 | **Medium** — `[GAP: limited direct exec_ex tests]` |
| REQ-EXEC-003 | Register initialization | TC-EXEC-003 | **High** — mem/result comparison in all tests |
| REQ-EXEC-007 | Interpreter loop correctness | TC-EXEC-004 | **High** — 360+ .data tests + fuzzer |
| REQ-ISA-003 | ALU semantics | TC-EXEC-005 | **High** — alu.data, alu64.data, 100+ conformance tests |
| REQ-SEC-001 | Memory bounds enforcement | TC-EXEC-006 | **High** — err-stack-oob, err-address-overflow, etc. |
| REQ-EXEC-006 | Local function calls | TC-EXEC-007 | **High** — factorial.data, call_local_use_stack.data, stack tests |
| REQ-EXEC-008 | External function calls | TC-EXEC-008 | **High** — call.data, call-memfrob.data, call-save.data |
| REQ-EXEC-005 | Instruction limit | TC-EXEC-009 | **Low** — `[GAP: no direct instruction limit test]` |

### 4.4 JIT Compilation

| REQ-ID | Requirement | Test Cases | Coverage |
|--------|-------------|------------|----------|
| REQ-JIT-001 | compile API | TC-JIT-001 | **High** — test_jit.py runs all .data files through JIT |
| REQ-JIT-002 | compile_ex API | TC-JIT-002 | **Medium** — tested via plugin in ExtendedJitMode |
| REQ-JIT-002 | BasicJitMode | TC-JIT-003 | **High** — default mode in test_jit.py |
| REQ-JIT-002 | ExtendedJitMode | TC-JIT-004 | **Medium** — ubpf_plugin with --jit flag |
| REQ-JIT-003 | Code caching | TC-JIT-005 | **Low** — `[GAP: no explicit caching test]` |
| REQ-JIT-004 | Executable memory (W⊕X) | TC-JIT-006 | **Medium** — implicitly tested; ASan would catch violations |
| REQ-JIT-007 | translate API | TC-JIT-007 | **Low** — `[GAP: no direct translate API test]` |
| REQ-JIT-006 | copy_jit API | TC-JIT-008 | **Low** — `[GAP: no direct copy_jit test]` |
| REQ-JIT-009 | x86-64 calling conventions | TC-JIT-009 | **High** — CI tests on Windows + Linux (different ABIs) |
| REQ-JIT-010 | ARM64 ABI | TC-JIT-010 | **High** — CI tests on ARM64 (native + QEMU) |
| REQ-JIT-005 | JIT buffer sizing | TC-JIT-011 | **High** — jit_buffer_too_small custom test |

### 4.5 ELF Loading

| REQ-ID | Requirement | Test Cases | Coverage |
|--------|-------------|------------|----------|
| REQ-ELF-006 | load_elf API | TC-ELF-001 | **High** — test_elf.py |
| REQ-ELF-001 | ELF header validation | TC-ELF-002 | **Medium** — `[GAP: no tests with malformed ELF headers]` |
| REQ-ELF-003 | Section parsing | TC-ELF-003 | **High** — tests/elf/ directory |
| REQ-ELF-004 | R_BPF_64_64 data relocation | TC-ELF-004 | **High** — bpf/rel_64_32.bpf.c, tests/elf/ |
| REQ-ELF-005 | R_BPF_64_32 helper relocation | TC-ELF-005 | **High** — conformance suite helper tests |
| REQ-ELF-007 | Function linking | TC-ELF-006 | **Medium** — tested via multi-function ELF programs |
| REQ-ELF-007 | Main function selection | TC-ELF-007 | **Medium** — `[GAP: no explicit named-main test]` |

### 4.6 Instruction Set

| REQ-ID | Requirement | Test Cases | Coverage |
|--------|-------------|------------|----------|
| REQ-ISA-001 | Instruction format (8 bytes) | TC-ISA-001 | **High** — assembler/raw comparison in all .data tests |
| REQ-ISA-002 | Register model (r0-r10) | TC-ISA-002 | **High** — frame_pointer custom test, JIT register offset variants |
| REQ-ISA-003 | ALU64 operations | TC-ISA-003 | **High** — alu64.data, 50+ conformance tests (add64, sub64, etc.) |
| REQ-ISA-003 | ALU32 operations | TC-ISA-004 | **High** — alu.data, 50+ conformance tests (add32, sub32, etc.) |
| REQ-ISA-007 | Memory load/store | TC-ISA-005 | **High** — ldx.data, st.data, stx.data, 80+ conformance tests |
| REQ-ISA-007 | LDDW (64-bit immediate) | TC-ISA-006 | **High** — lddw.data, conformance tests |
| REQ-ISA-008 | Sign-extending loads | TC-ISA-007 | **High** — ldxsb-positive.data, ldxsh.data, conformance tests |
| REQ-ISA-005 | MOVSX (sign-extending move) | TC-ISA-008 | **High** — conformance movsx tests |
| REQ-ISA-009 | Jump instructions | TC-ISA-009 | **High** — jmp.data, 40+ conformance tests |
| REQ-ISA-009 | JMP32 (32-bit jumps) | TC-ISA-010 | **High** — conformance jmp32 tests |
| REQ-ISA-010 | Atomic operations | TC-ISA-011 | **Medium** — atomic_validate custom test (validation only) |
| REQ-ISA-011 | CALL and EXIT | TC-ISA-012 | **High** — call.data, factorial.data, early-exit.data |

### 4.7 Security

| REQ-ID | Requirement | Test Cases | Coverage |
|--------|-------------|------------|----------|
| REQ-SEC-001 | Bounds checking | TC-SEC-001 | **High** — 10+ error tests (err-stack-oob, err-address-*) |
| REQ-SEC-003 | Undefined behavior detection | TC-SEC-002 | **Low** — `[GAP: no explicit UB detection tests]` |
| REQ-SEC-004 | Constant blinding | TC-SEC-003 | **High** — constant_blinding custom test, CI env var |
| REQ-SEC-005 | Read-only bytecode | TC-SEC-004 | **High** — readonly_bytecode custom test |
| REQ-SEC-006 | Pointer secret / XOR encoding | TC-SEC-005 | **Low** — `[GAP: no test verifying XOR encoding effectiveness]` |
| REQ-SEC-007 | Retpolines | TC-SEC-006 | **Medium** — CI runs with/without retpolines; no functional test |
| REQ-SEC-008 | W⊕X enforcement | TC-SEC-007 | **Medium** — implicitly tested by JIT execution |
| REQ-SEC-003 | Shadow stack | TC-SEC-008 | **Low** — `[GAP: no explicit shadow stack correctness test]` |
| REQ-SEC-003 | Shadow registers | TC-SEC-009 | **Low** — `[GAP: no explicit shadow register test]` |

### 4.8 Extensibility

| REQ-ID | Requirement | Test Cases | Coverage |
|--------|-------------|------------|----------|
| REQ-EXT-001 | Helper registration | TC-EXT-001 | **High** — call.data, call-memfrob.data, update_helpers |
| REQ-EXT-003 | External dispatcher | TC-EXT-002 | **High** — 3 dispatcher custom tests |
| REQ-EXT-007 | Unwind function | TC-EXT-003 | **High** — call_unwind.data |
| REQ-EXT-004 | Data relocation callback | TC-EXT-004 | **Medium** — tested via ELF loading |
| REQ-SEC-009 | Custom bounds check callback | TC-EXT-005 | **Low** — `[GAP: no explicit custom bounds check test]` |
| REQ-EXT-005 | Stack usage calculator | TC-EXT-006 | **High** — 3 custom_local_function_stack_size tests |
| REQ-EXT-006 | Debug function | TC-EXT-007 | **High** — debug_function custom test |

### 4.9 Configuration

| REQ-ID | Requirement | Test Cases | Coverage |
|--------|-------------|------------|----------|
| REQ-CFG-001 | Error print redirection | TC-CFG-001 | **Medium** — used in custom tests but not directly tested |
| REQ-CFG-002 | JIT buffer sizing | TC-CFG-002 | **High** — jit_buffer_too_small custom test |
| REQ-CFG-003 | Instruction limit | TC-CFG-003 | **Low** — `[GAP: no instruction limit test]` |
| REQ-CFG-004 | Register access (get/set) | TC-CFG-004 | **Low** — `[GAP: no get/set register test]` |

### 4.10 Platform

| REQ-ID | Requirement | Test Cases | Coverage |
|--------|-------------|------------|----------|
| REQ-PLAT-001 | Windows support | TC-PLAT-001 | **High** — CI: windows-2022, Debug + Release |
| REQ-PLAT-002 | Linux support | TC-PLAT-002 | **High** — CI: ubuntu-latest, coverage + sanitizers |
| REQ-PLAT-003 | macOS support | TC-PLAT-003 | **High** — CI: macos-latest |
| REQ-PLAT-004 | x86-64 JIT | TC-PLAT-004 | **High** — CI on all x86-64 platforms |
| REQ-PLAT-004 | ARM64 JIT | TC-PLAT-005 | **High** — CI: ubuntu-24.04-arm + QEMU |
| REQ-PLAT-004 | Interpreter-only fallback | TC-PLAT-006 | **Medium** — `[GAP: no test on non-JIT platform]` |

### 4.11 Error Handling

| REQ-ID | Requirement | Test Cases | Coverage |
|--------|-------------|------------|----------|
| REQ-ERR-001 | Error message allocation | TC-ERR-001 | **High** — error tests check stderr output |
| REQ-ERR-002 | Error output function | TC-ERR-002 | **Medium** — used but not directly validated |
| REQ-ERR-003 | Toggle return values | TC-ERR-003 | **Medium** — toggles used in custom tests |

### 4.12 Constants

| REQ-ID | Requirement | Test Cases | Coverage |
|--------|-------------|------------|----------|
| REQ-CONST-001 | System constants | TC-CONST-001 | **Medium** — constants used throughout tests but not boundary-tested |

---

## 5. Test Cases

### TC-LIFE — VM Lifecycle

#### TC-LIFE-001: VM Creation
- **Traces to:** REQ-LIFE-001
- **Level:** Unit
- **Confidence:** High
- **Evidence:** Every test implicitly calls `ubpf_create()` / `ubpf_destroy()`
- **Pass criteria:** VM pointer is non-NULL, all subsequent operations succeed
- **Existing tests:** All test_vm.py, test_jit.py tests

#### TC-LIFE-002: VM Destruction / Memory Leaks
- **Traces to:** REQ-LIFE-005
- **Level:** Integration
- **Confidence:** Medium
- **Evidence:** `custom_tests/srcs/ubpf_test_reload_code_memleak.cc`, Valgrind CI job
- **Pass criteria:** No memory leaks reported by Valgrind; reload_code_memleak returns 0
- **Existing tests:** reload_code_memleak-Custom, Valgrind CI workflow

#### TC-LIFE-003: Code Unloading and Reloading
- **Traces to:** REQ-LIFE-006, REQ-LOAD-003
- **Level:** Integration
- **Confidence:** High
- **Evidence:** `tests/reload.data`, `tests/unload_reload.data`
- **Pass criteria:** VM accepts new code after unload; second execution produces correct result
- **Existing tests:** test_vm reload/unload_reload tests

#### TC-LIFE-004: Default Configuration Values
- **Traces to:** REQ-LIFE-002
- **Level:** Unit
- **Confidence:** Medium
- **Evidence:** Tested indirectly — defaults produce expected behavior in standard tests
- **Pass criteria:** Bounds checking enabled, constant blinding disabled, read-only mode enabled
- **`[GAP]`:** No test explicitly verifies each default value after `ubpf_create()`

#### TC-LIFE-005: Platform JIT Selection
- **Traces to:** REQ-LIFE-004
- **Level:** System
- **Confidence:** High
- **Evidence:** CI matrix runs JIT tests on x86-64 (Windows/Linux/macOS) and ARM64
- **Pass criteria:** JIT compilation succeeds on supported platforms

#### TC-LIFE-006: Memory Allocation Failure
- **Traces to:** REQ-LIFE-003
- **Level:** Unit
- **Confidence:** Low
- **`[GAP]`:** No test injects allocation failures. Would require mock allocator or ulimit.

### TC-EXEC — Execution

#### TC-EXEC-001: Interpreter Execution (Data-Driven)
- **Traces to:** REQ-EXEC-001, REQ-EXEC-003, REQ-EXEC-007
- **Level:** Unit
- **Confidence:** High
- **Evidence:** `test_framework/test_vm.py` — runs every `.data` file through interpreter
- **Pass criteria:** Return value matches `-- result` section; errors match `-- error` section
- **Existing tests:** ~47 root .data + 313 conformance tests = ~360 test cases

#### TC-EXEC-005: ALU Operations
- **Traces to:** REQ-ISA-003, REQ-ISA-004
- **Level:** Unit
- **Confidence:** High
- **Evidence:** `tests/alu.data`, `tests/alu64.data`, `tests/sdiv32.data`, `tests/sdiv64.data`, `tests/smod32.data`, `tests/smod64.data`, `tests/arsh*.data`, 100+ conformance ALU tests
- **Pass criteria:** Correct arithmetic results for all operations, all operand types
- **Existing tests:** Comprehensive coverage of ADD, SUB, MUL, DIV, MOD, OR, AND, XOR, LSH, RSH, ARSH, NEG, MOV, SDIV, SMOD

#### TC-EXEC-006: Memory Bounds Checking
- **Traces to:** REQ-SEC-001
- **Level:** Unit
- **Confidence:** High
- **Evidence:** `tests/errors/err-stack-oob.data`, `tests/errors/err-address-overflow-offset.data`, `tests/errors/err-address-underflow.data`, `tests/errors/err-integer-overflow-bounds.data`
- **Pass criteria:** Out-of-bounds access produces error (non-zero exit, error message)
- **Existing tests:** 4+ dedicated error tests

#### TC-EXEC-007: Local Function Calls
- **Traces to:** REQ-EXEC-006
- **Level:** Integration
- **Confidence:** High
- **Evidence:** `tests/factorial.data`, `tests/extensions/call_local_use_stack.data`, `tests/stack2.data`, `tests/stack3.data`, custom_local_function_stack_size tests
- **Pass criteria:** Correct return values; callee-saved registers (r6-r9) preserved; frame pointer (r10) adjusted correctly
- **Existing tests:** 5+ tests covering local calls

#### TC-EXEC-008: External Helper Calls
- **Traces to:** REQ-EXEC-008, REQ-EXT-001
- **Level:** Integration
- **Confidence:** High
- **Evidence:** `tests/helpers/call.data`, `tests/helpers/call-memfrob.data`, `tests/helpers/call-save.data`
- **Pass criteria:** Helper receives correct parameters; return value propagated to r0
- **Existing tests:** 3 dedicated helper tests + conformance call tests

### TC-JIT — JIT Compilation

#### TC-JIT-001: JIT Execution Correctness
- **Traces to:** REQ-JIT-001, REQ-JIT-002
- **Level:** System
- **Confidence:** High
- **Evidence:** `test_framework/test_jit.py` — runs every `.data` file through JIT with 20 register-offset variants
- **Pass criteria:** JIT output matches interpreter output for all tests
- **Existing tests:** ~360 × 20 = ~7200 JIT test executions

#### TC-JIT-009: x86-64 Dual ABI
- **Traces to:** REQ-JIT-009
- **Level:** System
- **Confidence:** High
- **Evidence:** CI runs JIT tests on both Windows (Win64 ABI) and Linux (System V ABI)
- **Pass criteria:** Same tests pass on both platforms
- **Existing tests:** CI matrix covers both ABIs

#### TC-JIT-011: JIT Buffer Too Small
- **Traces to:** REQ-JIT-005, REQ-CFG-002
- **Level:** Unit
- **Confidence:** High
- **Evidence:** `custom_tests/srcs/ubpf_test_jit_buffer_too_small.cc`
- **Pass criteria:** JIT compilation fails gracefully with error message
- **Existing tests:** jit_buffer_too_small-Custom

### TC-SEC — Security

#### TC-SEC-001: Bounds Check Enforcement
- **Traces to:** REQ-SEC-001
- **Level:** Unit
- **Confidence:** High
- **Evidence:** `tests/errors/err-stack-oob.data` and related error tests
- **Pass criteria:** OOB access rejected with error
- **Existing tests:** 10+ error condition tests

#### TC-SEC-003: Constant Blinding
- **Traces to:** REQ-SEC-004
- **Level:** Integration
- **Confidence:** High
- **Evidence:** `custom_tests/srcs/ubpf_test_constant_blinding.cc`, CI runs with `UBPF_ENABLE_CONSTANT_BLINDING=1`
- **Pass criteria:** JIT produces correct results with blinding enabled; all CTest passes with blinding
- **Existing tests:** constant_blinding-Custom, CI environment flag

#### TC-SEC-004: Read-Only Bytecode
- **Traces to:** REQ-SEC-005
- **Level:** Unit
- **Confidence:** High
- **Evidence:** `custom_tests/srcs/ubpf_test_readonly_bytecode.cc`
- **Pass criteria:** Bytecode stored in read-only pages; toggling mode works correctly
- **Existing tests:** readonly_bytecode-Custom

### TC-EXT — Extensibility

#### TC-EXT-002: External Dispatcher
- **Traces to:** REQ-EXT-003
- **Level:** Integration
- **Confidence:** High
- **Evidence:** `custom_tests/srcs/ubpf_test_external_dispatcher_simple_context.cc`, `ubpf_test_external_dispatcher_context_overwrite.cc`, `ubpf_test_default_dispatcher_helper_context.cc`, `ubpf_test_update_dispatcher.cc`
- **Pass criteria:** Dispatcher receives correct parameters; context handling correct; updates work
- **Existing tests:** 4 custom tests

#### TC-EXT-006: Stack Usage Calculator
- **Traces to:** REQ-EXT-005
- **Level:** Unit
- **Confidence:** High
- **Evidence:** `custom_tests/srcs/ubpf_test_custom_local_function_stack_size.cc`, `*_unaligned.cc`, `*_zero.cc`, `*_default.cc`
- **Pass criteria:** Custom stack sizes applied; unaligned rejected; zero accepted; default works
- **Existing tests:** 4 custom tests

### TC-FUZZ — Fuzzing

#### TC-FUZZ-001: Differential Interpreter/JIT Testing
- **Traces to:** REQ-EXEC-007, REQ-JIT-001
- **Level:** System
- **Confidence:** High
- **Evidence:** `libfuzzer/libfuzz_harness.cc`
- **Pass criteria:** Interpreter and JIT produce identical results for all generated inputs
- **Existing tests:** Daily 1-hour fuzzing runs, corpus regression in CI

#### TC-FUZZ-002: PREVAIL Verifier Integration
- **Traces to:** REQ-EXEC-007
- **Level:** System
- **Confidence:** Medium
- **Evidence:** `libfuzzer/libfuzz_harness.cc` with `UBPF_FUZZER_VERIFY_BYTE_CODE=1`
- **Pass criteria:** Verifier-approved programs execute without crashes
- **Existing tests:** Fuzzer with verifier enabled

---

## 6. Risk-Based Test Prioritization

### 6.1 Risk Categories

| Risk ID | Category | Impact | Likelihood | Priority |
|---------|----------|--------|------------|----------|
| R1 | JIT produces incorrect results | **Critical** — silent data corruption | Medium | **P1** |
| R2 | Bounds check bypass | **Critical** — arbitrary memory access | Low | **P1** |
| R3 | Memory corruption in VM | **Critical** — host process crash | Medium | **P1** |
| R4 | ELF loader accepts malformed input | **High** — potential code execution | Medium | **P2** |
| R5 | Constant blinding bypass | **High** — JIT spraying attack | Low | **P2** |
| R6 | Platform-specific failures | **Medium** — limited to one platform | Medium | **P2** |
| R7 | Helper function parameter corruption | **Medium** — incorrect helper behavior | Low | **P3** |
| R8 | Stack overflow in local calls | **Medium** — program crash | Low | **P3** |
| R9 | Configuration API misuse | **Low** — unexpected behavior | Medium | **P3** |

### 6.2 Prioritization Rationale

**P1 (Must test):** JIT correctness, bounds checking, memory safety — these are the core security and correctness guarantees.
- **Covered by:** Differential fuzzing (TC-FUZZ-001), error tests (TC-SEC-001), sanitizers (ASan/UBSan), Valgrind

**P2 (Should test):** ELF robustness, constant blinding effectiveness, platform parity — important but lower likelihood.
- **Covered by:** CI matrix (TC-PLAT-*), constant blinding tests (TC-SEC-003), some ELF tests
- **Gap:** No adversarial ELF fuzzing

**P3 (Nice to test):** Helper correctness, stack depth, configuration edge cases — lower impact.
- **Covered by:** Helper tests (TC-EXT-001), stack tests (TC-EXEC-007)
- **Gaps:** Instruction limit, register get/set, deep call chains

---

## 7. Pass/Fail Criteria

### 7.1 Entry Criteria

Before test execution:
- Code compiles successfully on all target platforms
- All submodules initialized (`git submodule update --init --recursive`)
- Test dependencies installed (Python: parcon, nose, pyelftools)
- Environment configured (platform-specific build prerequisites)

### 7.2 Exit Criteria

Test suite passes when:
- **All CTest tests pass** on every CI platform (Windows, Linux, macOS, ARM64)
- **Zero ASan/UBSan violations** in sanitizer builds
- **Zero Valgrind errors** (Linux)
- **Fuzzer runs for 1 hour** without finding new crashes
- **Code coverage does not decrease** vs. previous baseline (Coveralls)

### 7.3 Acceptance Thresholds

| Metric | Threshold | Current Status |
|--------|-----------|----------------|
| CTest pass rate | 100% | Enforced by CI |
| ASan violations | 0 | Enforced by CI |
| Valgrind errors | 0 | Enforced by CI (Linux) |
| Fuzzer crashes | 0 new | Enforced by CI |
| Code coverage | Non-decreasing | Tracked by Coveralls |

---

## 8. Coverage Gap Summary

### 8.1 High-Priority Gaps

| Gap | REQ-IDs Affected | Risk | Recommendation |
|-----|-----------------|------|----------------|
| No UB detection tests | REQ-SEC-003 | Medium | Add tests enabling UB checks, verify shadow stack/register detection |
| No instruction limit test | REQ-CFG-003 | Low | Add test setting limit and verifying execution stops |
| No malformed ELF tests | REQ-ELF-001 | Medium | Fuzz the ELF loader with invalid headers/sections |
| No register get/set tests | REQ-CFG-004 | Low | Add test calling ubpf_set_registers/ubpf_get_registers |
| No custom bounds check test | REQ-SEC-009 | Medium | Add test registering custom bounds check callback |

### 8.2 Medium-Priority Gaps

| Gap | REQ-IDs Affected | Risk | Recommendation |
|-----|-----------------|------|----------------|
| No OOM handling tests | REQ-LIFE-003 | Low | Test with constrained memory or mock allocator |
| No explicit exec_ex test | REQ-EXEC-002 | Low | Add test calling ubpf_exec_ex with custom stack |
| No translate/copy_jit tests | REQ-JIT-007, REQ-JIT-006 | Low | Add tests for these less-used APIs |
| No JIT caching verification | REQ-JIT-003 | Low | Verify compile returns same pointer on second call |
| No XOR encoding verification | REQ-LOAD-006, REQ-SEC-006 | Medium | Verify instructions are XOR-encoded in memory |

### 8.3 Structural Gaps

| Gap | Impact | Recommendation |
|-----|--------|----------------|
| No concurrency tests | Unknown thread safety | Define thread-safety model, add tests |
| No stress tests | Unknown scalability limits | Test with MAX_INSTS programs, deep call chains |
| No performance regression | Silent performance degradation | Add benchmark suite |
| No adversarial ELF fuzzing | Potential loader vulnerabilities | Add ELF-specific fuzzer |
| Atomic operations: validation only | Correctness unverified at runtime | Add atomic execution correctness tests |

---

## 9. Revision History

| Version | Date | Author | Description |
|---------|------|--------|-------------|
| 1.0.0 | 2026-03-31 | Extracted by AI | Initial draft — mapped existing tests to requirements, identified gaps |
