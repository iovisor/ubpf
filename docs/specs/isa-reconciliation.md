# uBPF ISA Unified Requirements — Reconciliation with RFC 9669

**Document Version:** 1.0.0
**Date:** 2026-03-31
**Status:** Draft — Reconciled from implementation specification and IETF standard

---

## 1. Overview

This document reconciles the uBPF implementation's Instruction Set Architecture (ISA) behavior against RFC 9669, the IETF Standards Track BPF ISA specification. It catalogs every ISA-relevant requirement from both sources, maps them to one another, classifies their compatibility, and documents all divergences with interoperability impact analysis.

The goal is to produce a unified "most compatible" specification that tells uBPF maintainers exactly where the implementation conforms to RFC 9669, where it extends beyond it, and where it diverges. Both sources are treated as equal inputs — divergences are documented, not judged.

**Sources consulted:**
- **Source 1 — uBPF Implementation Specification** (`docs/specs/requirements.md`): A requirements document reverse-engineered from the uBPF source code (v1.0.0, 2026-03-31). ISA requirements are in Section 4.6 (REQ-ISA-001 through REQ-ISA-012) with ISA-adjacent requirements in Sections 4.3, 4.7, and 4.8.
- **Source 2 — RFC 9669** (October 2024): IETF Standards Track specification of the BPF ISA, covering instruction encoding, arithmetic/jump/load/store operations, atomics, byte swaps, 64-bit immediates, conformance groups, and legacy packet access.
- **Implementation verification**: Key behaviors verified against `vm/ubpf_vm.c`, `vm/ebpf.h`, and `vm/ubpf_instruction_valid.c`.

---

## 2. Scope

### 2.1 In Scope

- Instruction encoding format (basic and wide)
- Register model (R0–R10)
- ALU operations (32-bit and 64-bit), including signed variants
- Division-by-zero and modulo-by-zero semantics
- Shift masking behavior
- ALU32 zero-extension of upper 32 bits
- Jump and branch instructions (conditional and unconditional)
- Memory load/store operations (regular and sign-extending)
- Atomic operations (32-bit and 64-bit)
- Byte swap / endianness conversion instructions
- 64-bit immediate loading (LDDW) and src_reg subtypes
- Function call instructions (external helper, local, BTF)
- EXIT instruction
- Legacy packet access instructions
- Conformance group coverage
- Unused field validation
- Stack management constraints relevant to ISA execution

### 2.2 Out of Scope

- VM lifecycle management (creation, destruction) — not ISA behavior.
- JIT compilation internals — ISA semantics are identical; JIT is an implementation strategy.
- ELF loading and relocation — a loading concern, not an ISA concern.
- Security features (bounds checking, constant blinding, pointer secrets) — runtime policy, not ISA definition.
- Helper function API signatures — platform-specific, outside RFC 9669 scope.
- BPF map semantics — explicitly deferred by RFC 9669.
- BPF Type Format (BTF) details — explicitly deferred by RFC 9669.

---

## 3. Definitions and Glossary

| Term | Definition |
|------|-----------|
| **RFC 9669** | IETF Standards Track document specifying the BPF Instruction Set Architecture (October 2024). |
| **uBPF** | Userspace BPF virtual machine — an Apache 2.0-licensed library providing an eBPF interpreter and JIT compilers. |
| **ALU** | Arithmetic Logic Unit — instruction class 0x04 for 32-bit operations. |
| **ALU64** | 64-bit ALU — instruction class 0x07 for 64-bit operations. |
| **JMP** | Jump instruction class 0x05 for 64-bit comparisons. |
| **JMP32** | Jump instruction class 0x06 for 32-bit comparisons. |
| **LDDW** | Load Double Word — a wide (128-bit) instruction encoding a 64-bit immediate. |
| **Conformance group** | A named set of instructions that an implementation MUST fully support if it claims the group. |
| **Truncated division** | Signed division where the result is truncated toward zero: `-13 / 3 == -4`, `-13 % 3 == -1`. |
| **UNIVERSAL** | Both sources specify the same behavior with compatible keyword strength. |
| **MAJORITY** | Sources mostly agree; minor differences documented. |
| **DIVERGENT** | Sources actively disagree on behavior or semantics. |
| **EXTENSION** | Only one source defines this requirement. |
| **src_reg** | The 4-bit source register field in the instruction encoding. |
| **dst_reg** | The 4-bit destination register field in the instruction encoding. |

---

## 4. Requirements

### Reconciliation Summary

| Metric | Count |
|--------|-------|
| Total unified requirements | 47 |
| UNIVERSAL | 29 |
| MAJORITY | 4 |
| DIVERGENT | 6 |
| EXTENSION (uBPF-only) | 5 |
| EXTENSION (RFC 9669-only) | 3 |

---

### 4.1 Instruction Encoding (ENC)

#### REQ-UBPF-ISA-ENC-001: Basic Instruction Format

Each BPF instruction MUST be encoded as 64 bits (8 bytes) with the following layout:

| Field | Width | Bit Offset | Type |
|-------|-------|------------|------|
| opcode | 8 bits | 0 | unsigned |
| dst_reg | 4 bits | 8 | unsigned |
| src_reg | 4 bits | 12 | unsigned |
| offset | 16 bits | 16 | signed |
| imm | 32 bits | 32 | signed |

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF REQ-ISA-001 ↔ RFC 9669 §3.1
- **Acceptance Criteria:**
  - AC-1: `sizeof(struct ebpf_inst) == 8`.
  - AC-2: Field positions match the layout above on little-endian hosts.

---

#### REQ-UBPF-ISA-ENC-002: Wide Instruction Format

Wide instructions (LDDW) MUST use 128 bits: a basic 64-bit instruction followed by a pseudo-instruction whose opcode, dst_reg, src_reg, and offset fields are zero, containing a second 32-bit immediate (`next_imm`).

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF REQ-ISA-007 (LDDW portion), REQ-LOAD-011 ↔ RFC 9669 §3.2
- **Acceptance Criteria:**
  - AC-1: LDDW consumes two instruction slots.
  - AC-2: The second slot's opcode, dst, src, and offset fields are zero.

---

#### REQ-UBPF-ISA-ENC-003: Register Byte Ordering

On little-endian hosts, the `regs` byte MUST encode `src_reg` in the upper nibble and `dst_reg` in the lower nibble. On big-endian hosts, the order MUST be reversed.

- **Compatibility:** MAJORITY
- **Source mapping:** (implicit in uBPF) ↔ RFC 9669 §3.1
- **Divergence notes:** uBPF is little-endian only (per REQ-ELF-001: `ELFDATA2LSB` required). RFC 9669 defines both orderings. uBPF does not support big-endian register encoding.

---

#### REQ-UBPF-ISA-ENC-004: Unused Fields Shall Be Zero

Unused fields in an instruction SHALL be cleared to zero.

- **Compatibility:** MAJORITY
- **Source mapping:** uBPF (validation in `ubpf_instruction_valid.c`) ↔ RFC 9669 §3.1
- **Divergence notes:** RFC 9669 uses SHALL (normative). uBPF validates field bounds via its instruction filter table (`ubpf_instruction_valid.c:1049-1119`) which checks each field against per-opcode bounds. Fields with bounds `[0, 0]` effectively require zero. However, not all "unused" fields are constrained to zero in uBPF's filter table — some have wider bounds for future compatibility.
- **Acceptance Criteria:**
  - AC-1: An instruction with a non-zero unused field is rejected during validation when the filter table constrains that field to zero.

---

#### REQ-UBPF-ISA-ENC-005: Instruction Classes

The three least significant bits of `opcode` MUST encode the instruction class:

| Class | Value | Description |
|-------|-------|-------------|
| LD | 0x0 | Non-standard load operations |
| LDX | 0x1 | Load into register |
| ST | 0x2 | Store from immediate |
| STX | 0x3 | Store from register |
| ALU | 0x4 | 32-bit arithmetic |
| JMP | 0x5 | 64-bit jump |
| JMP32 | 0x6 | 32-bit jump |
| ALU64 | 0x7 | 64-bit arithmetic |

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF `vm/ebpf.h` (EBPF_CLS_* constants) ↔ RFC 9669 §3.3
- **Acceptance Criteria:**
  - AC-1: All eight instruction classes are recognized.

---

### 4.2 Register Model (REG)

#### REQ-UBPF-ISA-REG-001: Register File

The VM MUST provide 11 64-bit registers:

| Register | Purpose |
|----------|---------|
| R0 | Return value |
| R1–R5 | Function arguments (caller-saved) |
| R6–R9 | Callee-saved |
| R10 | Frame pointer (read-only) |

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF REQ-ISA-002 ↔ RFC 9669 §4.3.2 (implicit in CALL/EXIT semantics)
- **Acceptance Criteria:**
  - AC-1: Writing to R10 via MOV or ALU is rejected at load time.
  - AC-2: R6–R9 are preserved across external helper calls.
  - AC-3: R0 holds the return value after EXIT.

---

### 4.3 ALU Operations (ALU)

#### REQ-UBPF-ISA-ALU-001: Core ALU Operations

The VM MUST support the following arithmetic operations in both ALU (32-bit) and ALU64 (64-bit) variants, with both immediate (K) and register (X) source operands:

ADD, SUB, MUL, DIV, MOD, OR, AND, XOR, LSH, RSH, NEG, ARSH, MOV.

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF REQ-ISA-003 ↔ RFC 9669 §4.1 (Table 5)
- **Acceptance Criteria:**
  - AC-1: Each operation produces the correct result for representative inputs.
  - AC-2: Both immediate and register source variants work correctly.

---

#### REQ-UBPF-ISA-ALU-002: ALU32 Zero-Extension

32-bit ALU operations MUST zero-extend the result to 64 bits (upper 32 bits of the destination register are cleared).

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF REQ-ISA-003 AC-2 ↔ RFC 9669 §4.1 (e.g., `dst = (u32)((u32)dst + (u32)src)`)
- **Implementation evidence:** `vm/ubpf_vm.c:874` — explicit `reg[inst.dst] &= UINT32_MAX` after each 32-bit ALU operation. Also a catch-all at `vm/ubpf_vm.c:1741-1743` masking all ALU-class results except byte-swap.
- **Acceptance Criteria:**
  - AC-1: After `{ADD, K, ALU}` with dst=0xFFFFFFFF00000001 and imm=1, dst == 0x00000002.

---

#### REQ-UBPF-ISA-ALU-003: Overflow and Underflow

Arithmetic overflow and underflow MUST be allowed — values wrap at 64-bit or 32-bit boundaries.

- **Compatibility:** UNIVERSAL
- **Source mapping:** (implicit in uBPF C semantics) ↔ RFC 9669 §4.1 ("Underflow and overflow are allowed during arithmetic operations")
- **Acceptance Criteria:**
  - AC-1: `0xFFFFFFFFFFFFFFFF + 1 == 0` (64-bit wrap).
  - AC-2: `(u32)0xFFFFFFFF + 1 == 0` (32-bit wrap, zero-extended).

---

#### REQ-UBPF-ISA-ALU-004: NEG Source Operand Restriction

The NEG instruction negates the destination register (`dst = -dst`).

- **Compatibility:** DIVERGENT
- **Source mapping:** uBPF REQ-ISA-003 (NEG) ↔ RFC 9669 §4.1 ("The NEG instruction is only defined when the source bit is clear (K)")
- **uBPF behavior:** NEG accepts any `src_reg` value — the src field is ignored at runtime (`vm/ubpf_vm.c:958-960`). Validation does not constrain `src_reg` for NEG (`vm/ubpf_instruction_valid.c`).
- **RFC 9669 behavior:** NEG is only defined for source=K (source bit = 0). NEG with source=X is undefined.
- **Interoperability impact:** A program with NEG and source=X would execute on uBPF but is technically undefined per RFC 9669. A strict RFC-conforming validator would reject it.
- **Resolution options:**
  - Conservative: Reject NEG with source=X during validation (match RFC 9669).
  - Permissive: Accept any src value and ignore it (current uBPF behavior).
  - Most interoperable: Reject NEG with source=X to ensure programs are portable.
- **Acceptance Criteria:**
  - AC-1: `NEG dst` produces `dst = -dst`.
  - AC-2: [DIVERGENT] Whether NEG with source=X is accepted or rejected depends on resolution.

---

### 4.4 Division and Modulo Semantics (DIV)

#### REQ-UBPF-ISA-DIV-001: Unsigned Division by Zero

If unsigned division by zero would occur, the destination register MUST be set to zero.

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF (implicit in `vm/ubpf_vm.c:898,914,1097,1112`) ↔ RFC 9669 §4.1 (`dst = (src != 0) ? (dst / src) : 0`)
- **Implementation evidence:** `vm/ubpf_vm.c:898`: `reg[inst.dst] = u32(inst.imm) ? u32(reg[inst.dst]) / u32(inst.imm) : 0;`
- **Acceptance Criteria:**
  - AC-1: `DIV_REG` with src=0 sets dst=0 (both 32-bit and 64-bit).
  - AC-2: `DIV_IMM` with imm=0 sets dst=0 (both 32-bit and 64-bit).

---

#### REQ-UBPF-ISA-DIV-002: Unsigned Modulo by Zero

If unsigned modulo by zero would occur:
- For ALU64: the destination register MUST be unchanged.
- For ALU: the lower 32 bits of the destination register MUST be unchanged and the upper 32 bits MUST be zeroed.

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF (`vm/ubpf_vm.c:964,980,1154,1169`) ↔ RFC 9669 §4.1 (`dst = (src != 0) ? (dst % src) : dst`, with ALU zero-extension)
- **Implementation evidence:**
  - ALU64 MOD by zero (`vm/ubpf_vm.c:1154`): `reg[inst.dst] = inst.imm ? reg[inst.dst] % inst.imm : reg[inst.dst];` — register unchanged.
  - ALU MOD by zero (`vm/ubpf_vm.c:964`): `reg[inst.dst] = u32(inst.imm) ? u32(reg[inst.dst]) % u32(inst.imm) : u32(reg[inst.dst]);` followed by `reg[inst.dst] &= UINT32_MAX;` at line 976 — lower 32 bits preserved, upper 32 bits zeroed.
- **Acceptance Criteria:**
  - AC-1: `{MOD, K, ALU64}` with imm=0 leaves dst unchanged (all 64 bits).
  - AC-2: `{MOD, K, ALU}` with imm=0 preserves lower 32 bits of dst and zeroes upper 32 bits.

---

#### REQ-UBPF-ISA-DIV-003: Signed Division and Modulo (SDIV / SMOD)

The VM MUST support signed division (SDIV, offset=1 on DIV opcode) and signed modulo (SMOD, offset=1 on MOD opcode) in both ALU and ALU64 variants.

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF REQ-ISA-004 ↔ RFC 9669 §4.1 (Table 5: SDIV offset=1, SMOD offset=1)
- **Acceptance Criteria:**
  - AC-1: `SDIV(-10, 3)` returns `-3`.
  - AC-2: `SMOD(-10, 3)` returns `-1`.

---

#### REQ-UBPF-ISA-DIV-004: Truncated Division Semantics

Signed modulo MUST use truncated division semantics: `a % n = a - n * trunc(a / n)`. For example, `-13 % 3 == -1`.

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF REQ-ISA-004 ↔ RFC 9669 §4.1 ("signed modulo MUST use truncated division (where -13 % 3 == -1)")
- **Implementation evidence:** uBPF uses C's `%` operator on signed types (`vm/ubpf_vm.c:973`), which implements truncated division in C99+.
- **Acceptance Criteria:**
  - AC-1: `-13 % 3 == -1` (not `-13 % 3 == 2` as in Python/Ruby floored division).
  - AC-2: `13 % -3 == 1`.

---

#### REQ-UBPF-ISA-DIV-005: Signed Division/Modulo — Overflow Guard

Signed division and modulo MUST handle the overflow case where the dividend is the minimum value for the type and the divisor is -1 (e.g., `INT32_MIN / -1`).

- **Compatibility:** EXTENSION (uBPF-only)
- **Source mapping:** uBPF (`vm/ubpf_vm.c:903-907`) ↔ RFC 9669 (not specified)
- **uBPF behavior:**
  - SDIV: `INT32_MIN / -1` → `INT32_MIN` (wraps, avoids undefined behavior).
  - SMOD: `INT32_MIN % -1` → `0`.
- **RFC 9669 behavior:** Not specified — RFC 9669 does not address the `INT_MIN / -1` edge case.
- **Rationale:** This is a defensive measure against C undefined behavior. Without it, the interpreter could crash.
- **Acceptance Criteria:**
  - AC-1: `SDIV(INT32_MIN, -1)` produces `INT32_MIN` (32-bit) or `INT64_MIN` (64-bit).
  - AC-2: `SMOD(INT32_MIN, -1)` produces `0`.

---

#### REQ-UBPF-ISA-DIV-006: Signed Division by Zero

If signed division by zero would occur, the destination register MUST be set to zero. If signed modulo by zero would occur, the destination register MUST be unchanged (with ALU32 zero-extension applied for ALU-class).

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF (`vm/ubpf_vm.c:901,968-969`) ↔ RFC 9669 §4.1 (SDIV: `(src != 0) ? (dst s/ src) : 0`; SMOD: `(src != 0) ? (dst s% src) : dst`)
- **Acceptance Criteria:**
  - AC-1: SDIV with divisor=0 sets dst=0.
  - AC-2: SMOD with divisor=0 leaves dst unchanged (64-bit) or zero-extends (32-bit).

---

#### REQ-UBPF-ISA-DIV-007: Unsigned Immediate Interpretation for DIV/MOD

For unsigned DIV and MOD operations:
- ALU: `imm` is interpreted as a 32-bit unsigned value.
- ALU64: `imm` is first sign-extended from 32 to 64 bits, then interpreted as a 64-bit unsigned value.

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF (implicit in C cast semantics) ↔ RFC 9669 §4.1
- **Acceptance Criteria:**
  - AC-1: `{DIV, K, ALU}` with imm=0xFFFFFFFF divides by `4294967295` (not `-1`).
  - AC-2: `{DIV, K, ALU64}` with imm=0xFFFFFFFF divides by `0xFFFFFFFFFFFFFFFF` (sign-extended, then unsigned).

---

### 4.5 Shift Operations (ALU — continued)

#### REQ-UBPF-ISA-ALU-005: Shift Amount Masking

Shift operations (LSH, RSH, ARSH) MUST mask the shift amount:
- 64-bit operations: mask with `0x3F` (63).
- 32-bit operations: mask with `0x1F` (31).

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF (`vm/ubpf_vm.c:36-37`, macros `SHIFT_MASK_32_BIT`, `SHIFT_MASK_64_BIT`) ↔ RFC 9669 §4.1 ("Shift operations use a mask of 0x3F (63) for 64-bit operations and 0x1F (31) for 32-bit operations")
- **Implementation evidence:**
  - `#define SHIFT_MASK_32_BIT(X) ((X) & 0x1f)` (line 36)
  - `#define SHIFT_MASK_64_BIT(X) ((X) & 0x3f)` (line 37)
- **Acceptance Criteria:**
  - AC-1: `{LSH, K, ALU64}` with imm=65 shifts by `65 & 0x3F = 1`.
  - AC-2: `{LSH, K, ALU}` with imm=33 shifts by `33 & 0x1F = 1`.

---

#### REQ-UBPF-ISA-ALU-006: MOV with Sign-Extension (MOVSX)

The MOVSX instruction MUST move the source register to the destination with sign extension. The `offset` field specifies the source width: 8, 16, or 32. MOVSX is only defined for register source operands (X).

- For ALU: sign-extends 8-bit or 16-bit operands into 32 bits, then zero-extends to 64 bits.
- For ALU64: sign-extends 8-bit, 16-bit, or 32-bit operands into 64 bits.

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF REQ-ISA-005 ↔ RFC 9669 §4.1 (MOVSX rows in Table 5)
- **Acceptance Criteria:**
  - AC-1: `{MOVSX, X, ALU}` with offset=8 and src=0x80 produces dst=0x00000000FFFFFF80.
  - AC-2: `{MOVSX, X, ALU64}` with offset=32 and src=0x80000000 produces dst=0xFFFFFFFF80000000.

---

#### REQ-UBPF-ISA-ALU-007: MOV K ALU64 Sign-Extension

`{MOV, K, ALU64}` MUST sign-extend the 32-bit immediate to 64 bits: `dst = (s64)imm`.

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF (implicit) ↔ RFC 9669 §4.1 (`{MOV, K, ALU64} means: dst = (s64)imm`)
- **Acceptance Criteria:**
  - AC-1: `{MOV, K, ALU64}` with imm=-1 (0xFFFFFFFF) sets dst=0xFFFFFFFFFFFFFFFF.

---

### 4.6 Byte Swap Operations (SWAP)

#### REQ-UBPF-ISA-SWAP-001: Endianness Conversion

The VM MUST support byte swap instructions:
- `{END, LE, ALU}`: Convert between host byte order and little-endian (imm = 16, 32, or 64).
- `{END, BE, ALU}`: Convert between host byte order and big-endian (imm = 16, 32, or 64).
- `{END, TO, ALU64}`: Unconditional byte swap (bswap, imm = 16, 32, or 64).

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF REQ-ISA-006 ↔ RFC 9669 §4.2
- **Acceptance Criteria:**
  - AC-1: `{END, BE, ALU}` with imm=16 converts a 16-bit value to big-endian.
  - AC-2: `{END, TO, ALU64}` with imm=32 unconditionally swaps byte order of a 32-bit value.
  - AC-3: imm values other than 16, 32, 64 are rejected.

---

#### REQ-UBPF-ISA-SWAP-002: Byte Swap Conformance Groups

Width-64 swap operations belong to the base64 conformance group. Other swap widths (16, 32) belong to base32.

- **Compatibility:** EXTENSION (RFC 9669-only)
- **Source mapping:** — ↔ RFC 9669 §4.2
- **Notes:** uBPF does not use the conformance group model; it supports all swap widths unconditionally. This is compatible — uBPF exceeds the minimum (base32) by also supporting 64-bit swaps.

---

### 4.7 Jump Instructions (JMP)

#### REQ-UBPF-ISA-JMP-001: Conditional Jump Instructions

The VM MUST support the following conditional jumps in both JMP (64-bit comparison) and JMP32 (32-bit comparison) classes, with both immediate (K) and register (X) operands:

JEQ, JGT, JGE, JSET, JNE, JSGT, JSGE, JLT, JLE, JSLT, JSLE.

Jump offset is in units of 64-bit instructions, relative to the instruction following the jump.

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF REQ-ISA-009 ↔ RFC 9669 §4.3 (Table 7)
- **Acceptance Criteria:**
  - AC-1: Each condition evaluates correctly for true and false cases.
  - AC-2: JMP32 variants compare only the lower 32 bits.
  - AC-3: Jump offsets are relative to the next instruction (PC + 1 + offset).

---

#### REQ-UBPF-ISA-JMP-002: Unconditional Jump (JA) — 16-bit Offset

`{JA, K, JMP}` MUST perform an unconditional jump using the 16-bit `offset` field: `PC += offset`.

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF REQ-ISA-009 (JA) ↔ RFC 9669 §4.3
- **Acceptance Criteria:**
  - AC-1: JA with offset=5 skips 5 instructions forward.

---

#### REQ-UBPF-ISA-JMP-003: Unconditional Jump (JA32) — 32-bit Offset

`{JA, K, JMP32}` (opcode 0x06) MUST perform an unconditional jump using the 32-bit `imm` field: `PC += imm`.

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF (`vm/ubpf_vm.c:1375-1377`, `vm/ebpf.h: EBPF_OP_JA32`) ↔ RFC 9669 §4.3 (`{JA, K, JMP32} means: gotol +imm`)
- **Acceptance Criteria:**
  - AC-1: JA32 with imm=70000 jumps forward by 70000 instructions (exceeding 16-bit range).

---

#### REQ-UBPF-ISA-JMP-004: JA Conformance

All CALL and JA instructions belong to the base32 conformance group.

- **Compatibility:** EXTENSION (RFC 9669-only)
- **Source mapping:** — ↔ RFC 9669 §4.3 ("All CALL and JA instructions belong to the base32 conformance group")
- **Notes:** uBPF does not use conformance groups but supports all JA and CALL variants.

---

### 4.8 Memory Operations (MEM)

#### REQ-UBPF-ISA-MEM-001: Regular Load and Store

The VM MUST support memory load/store operations for widths B (1 byte), H (2 bytes), W (4 bytes), and DW (8 bytes):

- `{MEM, <size>, STX}`: `*(size *)(dst + offset) = src`
- `{MEM, <size>, ST}`: `*(size *)(dst + offset) = imm`
- `{MEM, <size>, LDX}`: `dst = *(unsigned size *)(src + offset)`

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF REQ-ISA-007 ↔ RFC 9669 §5.1
- **Acceptance Criteria:**
  - AC-1: Each width (1, 2, 4, 8 bytes) loads and stores correctly.
  - AC-2: LDX loads are zero-extended to the register width.

---

#### REQ-UBPF-ISA-MEM-002: Sign-Extension Loads

The VM MUST support sign-extending memory loads:

- `{MEMSX, B, LDX}`: `dst = *(s8 *)(src + offset)` (sign-extend 8→64)
- `{MEMSX, H, LDX}`: `dst = *(s16 *)(src + offset)` (sign-extend 16→64)
- `{MEMSX, W, LDX}`: `dst = *(s32 *)(src + offset)` (sign-extend 32→64)

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF REQ-ISA-008 ↔ RFC 9669 §5.2
- **Acceptance Criteria:**
  - AC-1: Loading `0xFF` via LDXSB produces `0xFFFFFFFFFFFFFFFF`.
  - AC-2: Loading `0x7F` via LDXSB produces `0x000000000000007F`.

---

#### REQ-UBPF-ISA-MEM-003: DW Operations Conformance

Instructions using DW (double word / 8 bytes) belong to the base64 conformance group.

- **Compatibility:** EXTENSION (RFC 9669-only)
- **Source mapping:** — ↔ RFC 9669 §5 ("Instructions using DW belong to the base64 conformance group")
- **Notes:** uBPF supports DW operations unconditionally.

---

### 4.9 Atomic Operations (ATOM)

#### REQ-UBPF-ISA-ATOM-001: Simple Atomic Operations

The VM MUST support atomic read-modify-write operations on memory:

- `{ATOMIC, W, STX}` for 32-bit and `{ATOMIC, DW, STX}` for 64-bit.
- Supported operations (encoded in `imm`): ADD (0x00), OR (0x40), AND (0x50), XOR (0xa0).

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF REQ-ISA-010 ↔ RFC 9669 §5.3 (Tables 10, 11)
- **Acceptance Criteria:**
  - AC-1: Atomic ADD correctly updates the memory location.
  - AC-2: 8-bit and 16-bit atomic operations are not supported.

---

#### REQ-UBPF-ISA-ATOM-002: Fetch Modifier

The FETCH modifier (0x01 OR'd into `imm`) MUST cause the operation to return the old memory value in the source register.

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF REQ-ISA-010 ↔ RFC 9669 §5.3
- **Acceptance Criteria:**
  - AC-1: `{ATOMIC, DW, STX}` with imm=ADD|FETCH returns old value in src_reg.

---

#### REQ-UBPF-ISA-ATOM-003: XCHG and CMPXCHG

- XCHG (imm = 0xe0 | FETCH): Atomically exchanges `src` with `*(dst + offset)`.
- CMPXCHG (imm = 0xf0 | FETCH): Atomically compares `*(dst + offset)` with R0. If equal, stores `src`. In either case, loads the old value into R0 (zero-extended).

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF REQ-ISA-010 ↔ RFC 9669 §5.3
- **Acceptance Criteria:**
  - AC-1: XCHG swaps the register and memory values atomically.
  - AC-2: CMPXCHG stores only when `*addr == R0`; always loads old value into R0.

---

### 4.10 64-bit Immediate Instructions (LDDW)

#### REQ-UBPF-ISA-LDDW-001: Basic 64-bit Immediate Load

`{IMM, DW, LD}` with src_reg=0 MUST load a 64-bit immediate: `dst = (next_imm << 32) | imm`.

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF REQ-ISA-007 ↔ RFC 9669 §5.4 (Table 12, src_reg=0)
- **Acceptance Criteria:**
  - AC-1: LDDW with imm=0x11223344 and next_imm=0xAABBCCDD produces dst=0xAABBCCDD11223344.

---

#### REQ-UBPF-ISA-LDDW-002: LDDW src_reg Subtypes (1–6)

RFC 9669 defines LDDW src_reg values 1–6 for map references, platform variables, and code addresses:

| src_reg | Semantics |
|---------|-----------|
| 1 | `dst = map_by_fd(imm)` |
| 2 | `dst = map_val(map_by_fd(imm)) + next_imm` |
| 3 | `dst = var_addr(imm)` |
| 4 | `dst = code_addr(imm)` |
| 5 | `dst = map_by_idx(imm)` |
| 6 | `dst = map_val(map_by_idx(imm)) + next_imm` |

- **Compatibility:** DIVERGENT
- **Source mapping:** uBPF REQ-ISA-007 ↔ RFC 9669 §5.4
- **uBPF behavior:** Only src_reg=0 is accepted. The instruction validation filter table (`ubpf_instruction_valid.c`) allows src_reg 0–6, but the runtime `validate()` function in `ubpf_vm.c` rejects any LDDW with `inst.src != 0`.
- **RFC 9669 behavior:** All seven src_reg values (0–6) are defined, though 1–6 depend on platform capabilities (maps, variables).
- **Interoperability impact:** Programs using LDDW with src_reg 1–6 (common in Linux BPF for map references) will fail to load on uBPF. This is consistent with uBPF's design: maps are handled externally via data relocation callbacks during ELF loading, which rewrite LDDW instructions to src_reg=0 with resolved addresses.
- **Resolution options:**
  - Conservative: Keep current behavior — ELF loader resolves map references before VM sees them.
  - Permissive: Implement src_reg 1–6 with callback-based resolution.
  - Most interoperable: Support src_reg 1–6 behind optional callbacks.
- **Acceptance Criteria:**
  - AC-1: LDDW with src_reg=0 loads the 64-bit immediate correctly.
  - AC-2: [DIVERGENT] LDDW with src_reg=1–6 is rejected by uBPF but valid per RFC 9669.

---

### 4.11 Function Calls (CALL)

#### REQ-UBPF-ISA-CALL-001: External Helper Call (src_reg=0)

`{CALL, K, JMP}` with src_reg=0 MUST invoke an external helper function identified by the static ID in the `imm` field.

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF REQ-ISA-011 ↔ RFC 9669 §4.3 (Table 7), §4.3.1
- **Acceptance Criteria:**
  - AC-1: `CALL` with src=0 and imm=5 invokes the helper registered at index 5.

---

#### REQ-UBPF-ISA-CALL-002: Program-Local Function Call (src_reg=1)

`{CALL, K, JMP}` with src_reg=1 MUST call a program-local function at `PC + imm + 1`. An EXIT within the local function MUST return to the caller.

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF REQ-ISA-011 ↔ RFC 9669 §4.3 (Table 7), §4.3.2
- **Acceptance Criteria:**
  - AC-1: CALL with src=1 transfers control to the local function.
  - AC-2: EXIT within the local function returns to the instruction after the CALL.

---

#### REQ-UBPF-ISA-CALL-003: BTF-Based Helper Call (src_reg=2)

`{CALL, K, JMP}` with src_reg=2 MUST invoke a helper function identified by BTF ID in the `imm` field.

- **Compatibility:** DIVERGENT
- **Source mapping:** uBPF (not supported) ↔ RFC 9669 §4.3 (Table 7), §4.3.1
- **uBPF behavior:** CALL with src_reg=2 is rejected during validation. The instruction filter table constrains src_reg to [0, 1] for CALL (`ubpf_instruction_valid.c`). At runtime, if reached, it returns -1 (`vm/ubpf_vm.c:1651-1655`).
- **RFC 9669 behavior:** src_reg=2 identifies a helper by BTF ID rather than static ID. BTF support is documented but details are deferred.
- **Interoperability impact:** Programs compiled with BTF-based helper calls (common in newer Linux BPF toolchains) cannot run on uBPF. This is consistent with uBPF's stated out-of-scope: "eBPF BTF (BPF Type Format) support" (requirements doc §2.2).
- **Resolution options:**
  - Conservative: Maintain current rejection — BTF is explicitly out of scope.
  - Permissive: Accept src_reg=2 and dispatch via the same helper lookup mechanism.
  - Most interoperable: Implement BTF ID resolution via a new callback.
- **Acceptance Criteria:**
  - AC-1: [DIVERGENT] CALL with src_reg=2 is rejected by uBPF but valid per RFC 9669.

---

#### REQ-UBPF-ISA-CALL-004: EXIT Instruction

The EXIT instruction (opcode 0x95) MUST terminate execution of the current function. The return value is in R0. For program-local functions, EXIT returns to the caller. For the main program, EXIT ends execution.

- **Compatibility:** UNIVERSAL
- **Source mapping:** uBPF REQ-ISA-012 ↔ RFC 9669 §4.3 (Table 7, EXIT row)
- **Acceptance Criteria:**
  - AC-1: After EXIT, the value in R0 is the program's return value.
  - AC-2: EXIT from a local function resumes execution after the CALL instruction.

---

### 4.12 Stack Management (STK)

#### REQ-UBPF-ISA-STK-001: Stack Size

The VM MUST provide a stack of at least 512 bytes per function frame. uBPF provides `UBPF_EBPF_STACK_SIZE` (4096) bytes for the initial frame.

- **Compatibility:** MAJORITY
- **Source mapping:** uBPF REQ-EXEC-001 (4096 bytes) ↔ RFC 9669 (512 bytes implied by convention, not specified in RFC)
- **Divergence notes:** RFC 9669 does not specify a stack size — it is left to the implementation. uBPF uses 4096 bytes, exceeding the Linux kernel's 512-byte convention. This is compatible.
- **Acceptance Criteria:**
  - AC-1: R10 points to the top of the stack at program entry.
  - AC-2: At least 4096 bytes of stack are available in uBPF.

---

#### REQ-UBPF-ISA-STK-002: Stack Alignment

Stack allocations for local functions MUST be a multiple of 16 bytes.

- **Compatibility:** EXTENSION (uBPF-only)
- **Source mapping:** uBPF REQ-LOAD-008 ↔ RFC 9669 (not specified)
- **Notes:** RFC 9669 does not specify stack alignment requirements.
- **Acceptance Criteria:**
  - AC-1: A local function with a non-16-byte-aligned stack requirement is rejected.

---

#### REQ-UBPF-ISA-STK-003: Call Depth Limit

The interpreter MUST enforce a maximum call depth.

- **Compatibility:** EXTENSION (uBPF-only)
- **Source mapping:** uBPF REQ-EXEC-006 (max depth = 8) ↔ RFC 9669 (not specified)
- **Notes:** RFC 9669 does not specify a call depth limit. Linux kernel uses 8. uBPF uses `UBPF_MAX_CALL_DEPTH` = 8.
- **Acceptance Criteria:**
  - AC-1: A chain of 8 nested local calls succeeds.
  - AC-2: A chain of 9 nested local calls fails.

---

### 4.13 Legacy Packet Access (MISC)

#### REQ-UBPF-ISA-MISC-001: Legacy BPF Packet Access (ABS / IND)

Legacy packet access instructions use instruction class LD with mode ABS or IND.

- **Compatibility:** DIVERGENT
- **Source mapping:** uBPF (not supported) ↔ RFC 9669 §5.5 ("these instructions are deprecated and SHOULD no longer be used")
- **uBPF behavior:** ABS/IND instructions are not recognized by the interpreter or validator. They would be rejected as unknown opcodes.
- **RFC 9669 behavior:** Deprecated (SHOULD NOT use), but defined in the "packet" conformance group (Historical status). Implementations claiming the "packet" group must support them.
- **Interoperability impact:** Low. These instructions are deprecated and rarely used in modern BPF programs. uBPF is designed as a generic VM, not a packet filter.
- **Resolution options:**
  - Conservative: Do not implement (current behavior) — they are deprecated.
  - Permissive: Implement behind the "packet" conformance group flag.
  - Most interoperable: Not implementing is the most interoperable choice for modern programs.
- **Acceptance Criteria:**
  - AC-1: [DIVERGENT] ABS/IND instructions are rejected by uBPF. RFC 9669 deprecates but defines them.

---

### 4.14 Conformance Groups (MISC)

#### REQ-UBPF-ISA-MISC-002: Conformance Group Model

RFC 9669 defines conformance groups: base32 (mandatory), base64, atomic32, atomic64, divmul32, divmul64, packet.

- **Compatibility:** DIVERGENT
- **Source mapping:** uBPF (no formal conformance claims) ↔ RFC 9669 §2.4
- **uBPF effective coverage:**

| Group | Status in uBPF | Notes |
|-------|---------------|-------|
| base32 | ✓ Supported | All base32 instructions implemented |
| base64 | ✓ Supported | All 64-bit base instructions implemented |
| atomic32 | ✓ Supported | 32-bit atomics implemented |
| atomic64 | ✓ Supported | 64-bit atomics implemented |
| divmul32 | ✓ Supported | 32-bit div/mul/mod implemented |
| divmul64 | ✓ Supported | 64-bit div/mul/mod implemented |
| packet | ✗ Not supported | Legacy packet access not implemented |

- **Divergence notes:** uBPF does not declare conformance groups but effectively supports all groups except "packet" (which has Historical status). uBPF should formally declare its supported conformance groups for interoperability.
- **Acceptance Criteria:**
  - AC-1: uBPF supports all instructions in base32, base64, atomic32, atomic64, divmul32, and divmul64.
  - AC-2: uBPF does not support the packet group.

---

#### REQ-UBPF-ISA-MISC-003: Big-Endian Host Support

RFC 9669 defines instruction encoding variants for big-endian hosts (reversed register nibble order, big-endian multi-byte fields).

- **Compatibility:** DIVERGENT
- **Source mapping:** uBPF REQ-ELF-001 (little-endian only) ↔ RFC 9669 §3.1
- **uBPF behavior:** uBPF only supports little-endian hosts. The ELF loader requires `ELFDATA2LSB`. Instruction encoding always uses little-endian field order.
- **RFC 9669 behavior:** Defines both little-endian and big-endian encoding.
- **Interoperability impact:** Programs compiled for big-endian BPF targets cannot be loaded into uBPF. This affects a small set of platforms (e.g., s390x, some MIPS).
- **Resolution options:**
  - Conservative: Document as a known limitation.
  - Permissive: Add big-endian support.
  - Most interoperable: Document; most BPF programs target little-endian.
- **Acceptance Criteria:**
  - AC-1: uBPF operates correctly on little-endian hosts.
  - AC-2: [DIVERGENT] Big-endian host encoding is not supported.

---

### 4.15 Execution Constraints (MISC)

#### REQ-UBPF-ISA-MISC-004: Register Initialization

At program entry, the VM MUST initialize: R1 = pointer to input memory, R2 = input memory length, R10 = frame pointer (top of stack).

- **Compatibility:** MAJORITY
- **Source mapping:** uBPF REQ-EXEC-003 ↔ RFC 9669 (convention, not specified in RFC)
- **Divergence notes:** RFC 9669 does not specify register initialization — it is platform-specific. uBPF's convention (R1=mem, R2=mem_len) is the de facto standard shared with Linux kernel BPF.
- **Acceptance Criteria:**
  - AC-1: R1 contains the input memory address on entry.
  - AC-2: R2 contains the input memory length on entry.
  - AC-3: R10 points to the top of the stack.

---

#### REQ-UBPF-ISA-MISC-005: Maximum Instruction Count

The VM MUST enforce a maximum program size.

- **Compatibility:** EXTENSION (uBPF-only)
- **Source mapping:** uBPF REQ-LOAD-002 (65535 instructions max) ↔ RFC 9669 (not specified)
- **Notes:** RFC 9669 does not impose a program size limit. uBPF limits programs to 65535 instructions (stored as `uint16_t`).
- **Acceptance Criteria:**
  - AC-1: A program with 65535 instructions loads successfully.
  - AC-2: A program with 65536 instructions is rejected.

---

#### REQ-UBPF-ISA-MISC-006: Instruction Limit (Runtime)

The interpreter MAY enforce a runtime instruction execution limit.

- **Compatibility:** EXTENSION (uBPF-only)
- **Source mapping:** uBPF REQ-EXEC-005 ↔ RFC 9669 (not specified)
- **Notes:** RFC 9669 does not define runtime instruction limits. uBPF supports a configurable limit via `ubpf_set_instruction_limit()`.
- **Acceptance Criteria:**
  - AC-1: When set, the interpreter terminates after the configured number of instructions.
  - AC-2: When set to 0, no limit is enforced.

---

## 5. Dependencies

| ID | Dependency | Reason | Impact if Unavailable |
|----|-----------|--------|----------------------|
| DEP-001 | RFC 9669 (IETF Standards Track) | Normative reference for BPF ISA semantics | Cannot assess conformance |
| DEP-002 | uBPF source code (`vm/ubpf_vm.c`, `vm/ebpf.h`, `vm/ubpf_instruction_valid.c`) | Implementation verification for actual behavior | Must rely on requirements doc alone |
| DEP-003 | C99+ language standard | uBPF's signed division/modulo semantics depend on C's truncated division | Different compiler behavior would change SDIV/SMOD results |

---

## 6. Assumptions

| ID | Assumption | Impact if Wrong |
|----|-----------|-----------------|
| ASM-001 | uBPF targets only little-endian host platforms. | Big-endian encoding analysis would need to be added. |
| ASM-002 | The C compiler used for uBPF implements truncated division for signed integer types (C99+ mandated). | SDIV/SMOD would produce incorrect results on non-conforming compilers. |
| ASM-003 | uBPF's ELF loader rewrites LDDW map references (src_reg 1–6) to src_reg=0 before the VM sees them. | Programs loaded via raw bytecode with src_reg 1–6 would be rejected. |
| ASM-004 | The "packet" conformance group (legacy ABS/IND) is not needed for uBPF's target use cases. | Programs relying on legacy packet access would fail. |
| ASM-005 | uBPF does not need BTF support (CALL src_reg=2) for its intended applications. | Programs compiled with BTF-based calls would fail to load. |

---

## 7. Risks

### 7.1 Interoperability Hotspots

| Risk ID | Area | Description | Likelihood | Impact | Mitigation |
|---------|------|-------------|------------|--------|------------|
| RISK-001 | LDDW subtypes | Programs using LDDW src_reg 1–6 (map references) cannot run on uBPF without ELF relocation preprocessing. Raw bytecode loading of such programs will fail. | High | High | Document that LDDW map references require ELF loading with a data relocation callback. Consider implementing a raw-bytecode LDDW callback. |
| RISK-002 | BTF calls | Programs compiled with BTF-based CALL (src_reg=2) — increasingly common in modern toolchains — will be rejected. | Medium | High | Monitor BTF adoption in target ecosystems. Implement src_reg=2 dispatch via callback if needed. |
| RISK-003 | NEG source field | uBPF accepts NEG with any src field value. Programs written for uBPF might use non-zero src on NEG and fail on strict implementations. | Low | Low | Add validation to reject NEG with source=X for portability. |
| RISK-004 | Big-endian programs | Programs compiled for big-endian BPF targets cannot load on uBPF. | Low | Medium | Document limitation. Big-endian BPF is rare in practice. |
| RISK-005 | Conformance declaration | uBPF does not formally declare which RFC 9669 conformance groups it supports. Tools cannot auto-discover capabilities. | Medium | Medium | Add API or metadata to declare supported conformance groups: base32, base64, atomic32, atomic64, divmul32, divmul64. |
| RISK-006 | Unused field strictness | uBPF's unused-field validation may differ from RFC 9669's SHALL requirement. Some programs with non-zero unused fields might be accepted by uBPF but rejected by strict implementations, or vice versa. | Low | Low | Audit validation filter table against RFC 9669's per-instruction field constraints. |
| RISK-007 | INT_MIN / -1 overflow | uBPF handles SDIV(INT_MIN, -1) defensively (returns INT_MIN). RFC 9669 does not specify this case. Other implementations may crash or return different values. | Low | Medium | Document uBPF's behavior as an extension. Propose to RFC editors for clarification. |

### 7.2 Compatibility Score

- **UNIVERSAL requirements:** 29 / 47 = **61.7%**
- **UNIVERSAL + MAJORITY:** 33 / 47 = **70.2%**
- **DIVERGENT requirements:** 6 / 47 = **12.8%**
- **EXTENSION requirements:** 8 / 47 = **17.0%**

### 7.3 Risk Summary by Functional Area

| Area | UNIVERSAL | MAJORITY | DIVERGENT | EXTENSION | Risk Level |
|------|-----------|----------|-----------|-----------|------------|
| Encoding | 2 | 2 | 0 | 0 | Low |
| Registers | 1 | 0 | 0 | 0 | Low |
| ALU | 4 | 0 | 1 | 0 | Low (NEG only) |
| Division/Modulo | 5 | 0 | 0 | 1 | Low |
| Byte Swap | 1 | 0 | 0 | 1 | Low |
| Jump | 3 | 0 | 0 | 1 | Low |
| Memory | 2 | 0 | 0 | 1 | Low |
| Atomics | 3 | 0 | 0 | 0 | Low |
| LDDW | 1 | 0 | 1 | 0 | **High** |
| CALL / EXIT | 2 | 0 | 1 | 0 | **Medium** |
| Stack | 0 | 1 | 0 | 2 | Low |
| Legacy/Misc | 0 | 1 | 3 | 1 | **Medium** |

### 7.4 Priority Recommendations

1. **RISK-001 (LDDW subtypes)** — Highest priority. Document the ELF-loader-based workaround prominently. Consider a callback mechanism for raw bytecode loading.
2. **RISK-005 (Conformance declaration)** — Medium priority. Adding conformance group metadata would improve toolchain integration.
3. **RISK-002 (BTF calls)** — Medium priority. Monitor and plan for BTF adoption.
4. **RISK-003 (NEG source field)** — Low priority but easy fix. Tighten validation.

---

## 8. Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-03-31 | Generated via reconciliation workflow | Initial reconciliation of uBPF requirements (v1.0.0) against RFC 9669 (October 2024). |

---

## Appendix A: Full Alignment Matrix

| Unified REQ-ID | Class | uBPF Source | RFC 9669 Source |
|---------------|-------|-------------|-----------------|
| REQ-UBPF-ISA-ENC-001 | UNIVERSAL | REQ-ISA-001 | §3.1 |
| REQ-UBPF-ISA-ENC-002 | UNIVERSAL | REQ-ISA-007, REQ-LOAD-011 | §3.2 |
| REQ-UBPF-ISA-ENC-003 | MAJORITY | REQ-ELF-001 (implicit) | §3.1 |
| REQ-UBPF-ISA-ENC-004 | MAJORITY | Validation logic | §3.1 |
| REQ-UBPF-ISA-ENC-005 | UNIVERSAL | ebpf.h EBPF_CLS_* | §3.3 |
| REQ-UBPF-ISA-REG-001 | UNIVERSAL | REQ-ISA-002 | §4.3.2 (implicit) |
| REQ-UBPF-ISA-ALU-001 | UNIVERSAL | REQ-ISA-003 | §4.1 |
| REQ-UBPF-ISA-ALU-002 | UNIVERSAL | REQ-ISA-003 AC-2 | §4.1 |
| REQ-UBPF-ISA-ALU-003 | UNIVERSAL | (implicit) | §4.1 |
| REQ-UBPF-ISA-ALU-004 | DIVERGENT | REQ-ISA-003 | §4.1 |
| REQ-UBPF-ISA-ALU-005 | UNIVERSAL | ubpf_vm.c:36-37 | §4.1 |
| REQ-UBPF-ISA-ALU-006 | UNIVERSAL | REQ-ISA-005 | §4.1 |
| REQ-UBPF-ISA-ALU-007 | UNIVERSAL | (implicit) | §4.1 |
| REQ-UBPF-ISA-DIV-001 | UNIVERSAL | ubpf_vm.c:898 | §4.1 |
| REQ-UBPF-ISA-DIV-002 | UNIVERSAL | ubpf_vm.c:964 | §4.1 |
| REQ-UBPF-ISA-DIV-003 | UNIVERSAL | REQ-ISA-004 | §4.1 |
| REQ-UBPF-ISA-DIV-004 | UNIVERSAL | ubpf_vm.c:973 | §4.1 |
| REQ-UBPF-ISA-DIV-005 | EXTENSION | ubpf_vm.c:903-907 | — |
| REQ-UBPF-ISA-DIV-006 | UNIVERSAL | ubpf_vm.c:901,968 | §4.1 |
| REQ-UBPF-ISA-DIV-007 | UNIVERSAL | (implicit) | §4.1 |
| REQ-UBPF-ISA-SWAP-001 | UNIVERSAL | REQ-ISA-006 | §4.2 |
| REQ-UBPF-ISA-SWAP-002 | EXTENSION | — | §4.2 |
| REQ-UBPF-ISA-JMP-001 | UNIVERSAL | REQ-ISA-009 | §4.3 |
| REQ-UBPF-ISA-JMP-002 | UNIVERSAL | REQ-ISA-009 | §4.3 |
| REQ-UBPF-ISA-JMP-003 | UNIVERSAL | ubpf_vm.c:1375-1377 | §4.3 |
| REQ-UBPF-ISA-JMP-004 | EXTENSION | — | §4.3 |
| REQ-UBPF-ISA-MEM-001 | UNIVERSAL | REQ-ISA-007 | §5.1 |
| REQ-UBPF-ISA-MEM-002 | UNIVERSAL | REQ-ISA-008 | §5.2 |
| REQ-UBPF-ISA-MEM-003 | EXTENSION | — | §5 |
| REQ-UBPF-ISA-ATOM-001 | UNIVERSAL | REQ-ISA-010 | §5.3 |
| REQ-UBPF-ISA-ATOM-002 | UNIVERSAL | REQ-ISA-010 | §5.3 |
| REQ-UBPF-ISA-ATOM-003 | UNIVERSAL | REQ-ISA-010 | §5.3 |
| REQ-UBPF-ISA-LDDW-001 | UNIVERSAL | REQ-ISA-007 | §5.4 |
| REQ-UBPF-ISA-LDDW-002 | DIVERGENT | REQ-ISA-007 | §5.4 |
| REQ-UBPF-ISA-CALL-001 | UNIVERSAL | REQ-ISA-011 | §4.3, §4.3.1 |
| REQ-UBPF-ISA-CALL-002 | UNIVERSAL | REQ-ISA-011 | §4.3, §4.3.2 |
| REQ-UBPF-ISA-CALL-003 | DIVERGENT | — | §4.3, §4.3.1 |
| REQ-UBPF-ISA-CALL-004 | UNIVERSAL | REQ-ISA-012 | §4.3 |
| REQ-UBPF-ISA-STK-001 | MAJORITY | REQ-EXEC-001 | — (convention) |
| REQ-UBPF-ISA-STK-002 | EXTENSION | REQ-LOAD-008 | — |
| REQ-UBPF-ISA-STK-003 | EXTENSION | REQ-EXEC-006 | — |
| REQ-UBPF-ISA-MISC-001 | DIVERGENT | — | §5.5 |
| REQ-UBPF-ISA-MISC-002 | DIVERGENT | — | §2.4 |
| REQ-UBPF-ISA-MISC-003 | DIVERGENT | REQ-ELF-001 | §3.1 |
| REQ-UBPF-ISA-MISC-004 | MAJORITY | REQ-EXEC-003 | — (convention) |
| REQ-UBPF-ISA-MISC-005 | EXTENSION | REQ-LOAD-002 | — |
| REQ-UBPF-ISA-MISC-006 | EXTENSION | REQ-EXEC-005 | — |

---

## Appendix B: Source Inventory

### Source 1 — uBPF Implementation Specification

- **Origin:** `docs/specs/requirements.md` (v1.0.0, reverse-engineered from source)
- **ISA requirement count:** 12 (REQ-ISA-001 through REQ-ISA-012)
- **ISA-adjacent requirements:** ~10 (REQ-EXEC-001/003/005/006, REQ-LOAD-002/008/009/010/011, REQ-ELF-001)
- **Keyword distribution:** Predominantly MUST
- **Categories covered:** Instruction encoding, register model, ALU (32/64), signed div/mod, MOVSX, byte swap, memory load/store, sign-extending loads, jumps, atomics, CALL variants, EXIT

### Source 2 — RFC 9669

- **Origin:** IETF Standards Track (October 2024, D. Thaler, Ed.)
- **Sections covering ISA:** §2–§5, Appendix A
- **Keyword distribution:** MUST, SHALL, SHOULD (for deprecated features), MAY
- **Categories covered:** Instruction encoding (basic and wide), instruction classes, ALU (32/64), signed div/mod, MOVSX, byte swap, jump instructions, load/store, sign-extension loads, atomic operations, 64-bit immediates (LDDW with src_reg 0–6), helper/local/BTF calls, EXIT, legacy packet access, conformance groups
- **Conformance groups defined:** base32, base64, atomic32, atomic64, divmul32, divmul64, packet
