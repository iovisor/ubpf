# uBPF JIT Backend Specification: BPF ISA → MIPS64

**Document Version:** 1.0.0
**Date:** 2026-04-01
**Status:** Proposed — No implementation exists yet

---

## 1. Overview

This document specifies the proposed mapping from BPF ISA instructions to MIPS64 Release 6 native instructions for a uBPF JIT backend. It follows the same structure as the existing x86-64 (`jit-x86-64.md`) and ARM64 (`jit-arm64.md`) backend specifications.

**Target ISA:** MIPS64 Release 6 (MIPS64r6)

**Why MIPS64r6:** Release 6 eliminates branch delay slots (compact branches), adds native division/modulo instructions (DDIV/DMOD without HI/LO registers), and simplifies several instruction encodings. Pre-R6 MIPS would require delay slot handling and HI/LO register management, significantly complicating the JIT.

**ABI:** N64 (64-bit pointers, 64-bit registers, 8 argument registers)

> All mappings in this document are marked **[PROPOSED]** — they require validation through implementation and testing.

---

## 2. Register Mapping

### 2.1 BPF → MIPS64 Register Mapping

> **Cross-reference:** REQ-UBPF-ISA-REG-001 (Register File)

| BPF Register | MIPS64 Register | Name | Rationale |
|---|---|---|---|
| R0 (return) | `$v0` ($2) | Return value | Natural N64 return register |
| R1 (param 1) | `$a0` ($4) | Argument 0 | Zero-cost helper call marshaling |
| R2 (param 2) | `$a1` ($5) | Argument 1 | Zero-cost helper call marshaling |
| R3 (param 3) | `$a2` ($6) | Argument 2 | Zero-cost helper call marshaling |
| R4 (param 4) | `$a3` ($7) | Argument 3 | Zero-cost helper call marshaling |
| R5 (param 5) | `$a4` ($8) | Argument 4 | Zero-cost helper call marshaling |
| R6 (callee-saved) | `$s0` ($16) | Saved 0 | Callee-saved in N64 ABI |
| R7 (callee-saved) | `$s1` ($17) | Saved 1 | Callee-saved in N64 ABI |
| R8 (callee-saved) | `$s2` ($18) | Saved 2 | Callee-saved in N64 ABI |
| R9 (callee-saved) | `$s3` ($19) | Saved 3 | Callee-saved in N64 ABI |
| R10 (frame ptr) | `$s4` ($20) | Saved 4 | Callee-saved, BPF frame pointer |

**[PROPOSED]** This mapping places BPF parameters (R1–R5) directly in MIPS64 ABI argument registers (`$a0`–`$a4`), eliminating parameter shuffling for external helper calls — the same strategy used by the ARM64 backend.

### 2.2 Scratch/Temporary Registers

| MIPS64 Register | Name | Usage |
|---|---|---|
| `$t0` ($12) | Temp 1 | Large immediate materialization, constant blinding |
| `$t1` ($13) | Temp 2 | Division scratch, address computation |
| `$t2` ($14) | Temp 3 | Atomic operation scratch, offset materialization |
| `$t3` ($15) | Temp 4 | Backup scratch for complex sequences |
| `$at` ($1) | Assembler temp | **RESERVED** — not used by JIT |
| `$k0`–`$k1` ($26–$27) | Kernel | **RESERVED** — not used by JIT |
| `$gp` ($28) | Global pointer | **RESERVED** — not used by JIT |
| `$ra` ($31) | Return address | Used for JALR calls, saved in prologue |
| `$sp` ($29) | Stack pointer | Stack management |
| `$fp` ($30) | Frame pointer | Native frame pointer (not BPF R10) |

**[DECISION NEEDED]:** Should `$v1` ($3) be used as an additional scratch register, or reserved for future use?

---

## 3. Instruction Mapping

### 3.1 ALU64 Operations

> **Cross-reference:** REQ-UBPF-ISA-ALU-001 (Core ALU Operations)

All 64-bit ALU operations use MIPS64 doubleword instructions.

| BPF Instruction | MIPS64 Sequence | Notes |
|---|---|---|
| `ADD64 dst, src` | `DADDU dst, dst, src` | Unsigned add (no trap on overflow) |
| `ADD64 dst, imm` | `DADDIU dst, dst, imm` | If \|imm\| ≤ 32767; else materialize imm in `$t0` then `DADDU` |
| `SUB64 dst, src` | `DSUBU dst, dst, src` | |
| `SUB64 dst, imm` | `DADDIU dst, dst, -imm` | If \|imm\| ≤ 32768; else materialize and `DSUBU` |
| `MUL64 dst, src` | `DMUL dst, dst, src` | MIPS64r6 native |
| `MUL64 dst, imm` | Materialize imm → `$t0`; `DMUL dst, dst, $t0` | |
| `DIV64 dst, src` | See §3.3 | Division-by-zero check required |
| `MOD64 dst, src` | See §3.3 | |
| `OR64 dst, src` | `OR dst, dst, src` | |
| `OR64 dst, imm` | `ORI dst, dst, imm` | If 0 ≤ imm ≤ 65535; else materialize |
| `AND64 dst, src` | `AND dst, dst, src` | |
| `AND64 dst, imm` | `ANDI dst, dst, imm` | If 0 ≤ imm ≤ 65535; else materialize |
| `XOR64 dst, src` | `XOR dst, dst, src` | |
| `XOR64 dst, imm` | `XORI dst, dst, imm` | If 0 ≤ imm ≤ 65535; else materialize |
| `LSH64 dst, src` | `DSLLV dst, dst, src` | Shift amount masked to 0–63 by hardware |
| `LSH64 dst, imm` | `DSLL dst, dst, imm` | imm 0–31; `DSLL32` for 32–63 |
| `RSH64 dst, src` | `DSRLV dst, dst, src` | Logical right shift |
| `RSH64 dst, imm` | `DSRL dst, dst, imm` | imm 0–31; `DSRL32` for 32–63 |
| `ARSH64 dst, src` | `DSRAV dst, dst, src` | Arithmetic right shift |
| `ARSH64 dst, imm` | `DSRA dst, dst, imm` | imm 0–31; `DSRA32` for 32–63 |
| `NEG64 dst` | `DSUBU dst, $zero, dst` | Negate via subtract from zero |
| `MOV64 dst, src` | `OR dst, src, $zero` | Move via OR with zero (MIPS idiom) |
| `MOV64 dst, imm` | See §3.9 (immediate materialization) | |

**[PROPOSED]** Shift masking: MIPS64 `DSLLV`/`DSRLV`/`DSRAV` use only the low 6 bits of the shift amount register, which matches BPF's 0x3F mask for 64-bit shifts.

### 3.2 ALU32 Operations

> **Cross-reference:** REQ-UBPF-ISA-ALU-002 (ALU32 Zero-Extension)

32-bit ALU operations use MIPS64 word-sized instructions (`ADDU`, `SUBU`, etc.) with W-suffix variants where available.

**[CHALLENGE: 32-bit zero-extension]** On MIPS64, 32-bit ALU instructions (e.g., `ADDU`) **sign-extend** the result to 64 bits, NOT zero-extend. BPF requires zero-extension. Every 32-bit ALU result MUST be explicitly zero-extended:

```asm
# BPF: ADD32 dst, src
ADDU  dst, dst, src       # 32-bit add (result sign-extended to 64)
DINSU dst, $zero, 32, 32  # Zero upper 32 bits
# Alternative: DSLL32 + DSRL32 (two-instruction sequence)
# DSLL32 dst, dst, 0      # Shift left 32
# DSRL32 dst, dst, 0      # Shift right 32 (zero-extends)
```

**[DECISION NEEDED]:** `DINSU` (R2+) vs `DSLL32`+`DSRL32` for zero-extension. `DINSU` is a single instruction but only available on MIPS64r2+. The shift pair is universally available.

| BPF Instruction | MIPS64 Sequence | Notes |
|---|---|---|
| `ADD32 dst, src` | `ADDU dst, dst, src` + zero-ext | |
| `SUB32 dst, src` | `SUBU dst, dst, src` + zero-ext | |
| `MUL32 dst, src` | `MUL dst, dst, src` + zero-ext | MIPS64r6 |
| `OR32 dst, src` | `OR dst, dst, src` + zero-ext | |
| `AND32 dst, src` | `AND dst, dst, src` + zero-ext | |
| `XOR32 dst, src` | `XOR dst, dst, src` + zero-ext | |
| `LSH32 dst, src` | `SLLV dst, dst, src` + zero-ext | 32-bit shift, mask 0x1F |
| `RSH32 dst, src` | `SRLV dst, dst, src` + zero-ext | |
| `ARSH32 dst, src` | `SRAV dst, dst, src` + zero-ext | |
| `NEG32 dst` | `SUBU dst, $zero, dst` + zero-ext | |
| `MOV32 dst, src` | `ADDU dst, src, $zero` + zero-ext | Or `SLL dst, src, 0` |

### 3.3 Signed Arithmetic (SDIV, SMOD)

> **Cross-reference:** REQ-UBPF-ISA-DIV-003 (Signed Division), REQ-UBPF-ISA-DIV-004 (Signed Modulo)

MIPS64r6 has native `DDIV`/`DMOD` (64-bit) and `DIV`/`MOD` (32-bit) instructions that write results directly to a GPR (no HI/LO registers).

```asm
# BPF: SDIV64 dst, src (offset==1)
BNEC  src, $zero, .Lnonzero   # Check division by zero
OR    dst, $zero, $zero        # dst = 0 (div-by-zero result per RFC 9669)
BC    .Ldone                   # Skip division
.Lnonzero:
DDIV  dst, dst, src            # Signed 64-bit division
.Ldone:
```

**Division by zero:** RFC 9669 specifies `dst = 0` for division by zero. The JIT must emit an explicit zero-check branch.

**Signed modulo:** `DMOD`/`MOD` on MIPS64r6 uses truncated division semantics (`-13 % 3 == -1`), matching RFC 9669.

**[CHALLENGE: INT_MIN / -1]:** MIPS64r6 `DDIV` behavior for `INT64_MIN / -1` is implementation-defined. The JIT should emit a check: if `src == -1` and `dst == INT64_MIN`, set `dst = INT64_MIN` (matching uBPF interpreter behavior).

### 3.4 Sign-Extension MOV (MOVSX)

> **Cross-reference:** REQ-UBPF-ISA-ALU-006 (MOV with Sign-Extension)

| BPF Instruction | MIPS64 Sequence | Notes |
|---|---|---|
| `MOVSX dst, src, 8` | `SEB dst, src` | Sign-extend byte (MIPS64r2+) |
| `MOVSX dst, src, 16` | `SEH dst, src` | Sign-extend halfword (MIPS64r2+) |
| `MOVSX dst, src, 32` | `SLL dst, src, 0` | Sign-extend word (MIPS64 native behavior) |

**[PROPOSED]** `SLL rd, rs, 0` sign-extends a 32-bit value to 64 bits on MIPS64, which is the standard idiom for word sign-extension.

### 3.5 Byte Swap Operations

> **Cross-reference:** REQ-UBPF-ISA-SWAP-001 (Endianness Conversion), REQ-UBPF-ISA-SWAP-002 (Unconditional Byte Swap)

**[CHALLENGE: No single byte-reverse instruction]** MIPS64 requires multi-instruction sequences for byte reversal.

| BPF Instruction | MIPS64 Sequence | Notes |
|---|---|---|
| `BSWAP16 dst` | `WSBH dst, dst` then `ANDI dst, dst, 0xFFFF` | WSBH swaps bytes in each halfword |
| `BSWAP32 dst` | `WSBH dst, dst` then `ROTR dst, dst, 16` then zero-ext | |
| `BSWAP64 dst` | `DSBH dst, dst` then `DSHD dst, dst` | DSBH+DSHD = full 64-bit byte reverse |
| `LE16/LE32/LE64` | No-op on little-endian MIPS, full swap on big-endian | `[DECISION NEEDED]`: Target LE or BE MIPS? |
| `BE16/BE32/BE64` | Full swap on little-endian, no-op on big-endian | |

**[DECISION NEEDED]:** MIPS can be either big-endian or little-endian. The JIT must target a specific endianness or emit conditional sequences. Most modern MIPS64 embedded systems are little-endian.

### 3.6 Memory Loads

> **Cross-reference:** REQ-UBPF-ISA-MEM-001 (Regular Load/Store)

| BPF Instruction | MIPS64 Instruction | Notes |
|---|---|---|
| `LDXB dst, [src+off]` | `LBU dst, off(src)` | Zero-extending byte load |
| `LDXH dst, [src+off]` | `LHU dst, off(src)` | Zero-extending halfword load |
| `LDXW dst, [src+off]` | `LWU dst, off(src)` | Zero-extending word load |
| `LDXDW dst, [src+off]` | `LD dst, off(src)` | Doubleword load |

**Offset range:** Signed 16-bit (-32768 to +32767). For offsets outside this range:
```asm
# Large offset: materialize in $t0, then add
LUI   $t0, %hi(offset)
ORI   $t0, $t0, %lo(offset)
DADDU $t0, src, $t0
LD    dst, 0($t0)
```

### 3.7 Sign-Extending Loads

> **Cross-reference:** REQ-UBPF-ISA-MEM-002 (Sign-Extension Loads)

| BPF Instruction | MIPS64 Instruction | Notes |
|---|---|---|
| `LDXSB dst, [src+off]` | `LB dst, off(src)` | Sign-extending byte load |
| `LDXSH dst, [src+off]` | `LH dst, off(src)` | Sign-extending halfword load |
| `LDXSW dst, [src+off]` | `LW dst, off(src)` | Sign-extending word load (native on MIPS64) |

### 3.8 Memory Stores

> **Cross-reference:** REQ-UBPF-ISA-MEM-001 (Regular Load/Store)

| BPF Instruction | MIPS64 Instruction | Notes |
|---|---|---|
| `STXB [dst+off], src` | `SB src, off(dst)` | Store byte |
| `STXH [dst+off], src` | `SH src, off(dst)` | Store halfword |
| `STXW [dst+off], src` | `SW src, off(dst)` | Store word |
| `STXDW [dst+off], src` | `SD src, off(dst)` | Store doubleword |
| `STB [dst+off], imm` | Materialize imm → `$t0`; `SB $t0, off(dst)` | MIPS has no store-immediate |
| `STH [dst+off], imm` | Materialize imm → `$t0`; `SH $t0, off(dst)` | |
| `STW [dst+off], imm` | Materialize imm → `$t0`; `SW $t0, off(dst)` | |
| `STDW [dst+off], imm` | Materialize imm → `$t0`; `SD $t0, off(dst)` | |

**[CHALLENGE: No store-immediate]** Unlike x86-64, MIPS has no instruction to store an immediate value directly to memory. All immediate stores require materializing the value in a temporary register first.

### 3.9 64-bit Immediate (LDDW)

> **Cross-reference:** REQ-UBPF-ISA-LDDW-001 (Basic 64-bit Immediate Load)

The LDDW instruction combines two BPF instruction slots into a 64-bit immediate. The JIT materializes this as:

```asm
# Full 64-bit immediate materialization (worst case: 6 instructions)
LUI   dst, bits[63:48]       # Load upper 16 bits
ORI   dst, dst, bits[47:32]  # OR in next 16 bits
DSLL  dst, dst, 16           # Shift left 16
ORI   dst, dst, bits[31:16]  # OR in next 16 bits
DSLL  dst, dst, 16           # Shift left 16
ORI   dst, dst, bits[15:0]   # OR in lowest 16 bits
```

**Optimization:** If the immediate fits in fewer bits, shorter sequences can be used:
- 16-bit: `ORI dst, $zero, imm` (1 instruction)
- 32-bit: `LUI dst, hi` + `ORI dst, dst, lo` (2 instructions)
- 48-bit: 4 instructions (LUI + ORI + DSLL + ORI)

### 3.10 Jump Instructions

> **Cross-reference:** REQ-UBPF-ISA-JMP-001 (Conditional Jumps), REQ-UBPF-ISA-JMP-002 (Unconditional JA)

MIPS64r6 compact branches (NO delay slots):

| BPF Instruction | MIPS64 Sequence | Notes |
|---|---|---|
| `JA +offset` | `BC target` | 26-bit signed offset (compact, no delay slot) |
| `JEQ dst, src` | `BEQC dst, src, target` | 16-bit offset |
| `JNE dst, src` | `BNEC dst, src, target` | 16-bit offset |
| `JGT dst, src` | `BLTUC src, dst, target` | Unsigned: dst > src ⟺ src < dst |
| `JGE dst, src` | `BGEUC dst, src, target` | Unsigned greater-or-equal |
| `JLT dst, src` | `BLTUC dst, src, target` | Unsigned less-than |
| `JLE dst, src` | `BGEUC src, dst, target` | Unsigned: dst ≤ src ⟺ src ≥ dst |
| `JSGT dst, src` | `BLTC src, dst, target` | Signed: dst > src ⟺ src < dst |
| `JSGE dst, src` | `BGEC dst, src, target` | Signed greater-or-equal |
| `JSLT dst, src` | `BLTC dst, src, target` | Signed less-than |
| `JSLE dst, src` | `BGEC src, dst, target` | Signed: dst ≤ src ⟺ src ≥ dst |
| `JSET dst, src` | `AND $t0, dst, src` then `BNEZC $t0, target` | 2-instruction sequence |
| `JEQ dst, imm` | Materialize imm → `$t0`; `BEQC dst, $t0, target` | |

**Branch range:** Compact conditional branches (`BEQC`, etc.) have a 16-bit signed offset (±32K instructions = ±128KB). The unconditional `BC` has a 26-bit offset (±256M). For programs exceeding conditional branch range, a trampoline pattern is needed:

```asm
# Branch trampoline for out-of-range conditional
BNEC  dst, src, .Lskip    # Inverted condition, short range
BC    far_target           # Long-range unconditional
.Lskip:
```

### 3.11 Atomic Operations

> **Cross-reference:** REQ-UBPF-ISA-ATOM-001 (Simple Atomics), REQ-UBPF-ISA-ATOM-002 (Complex Atomics)

MIPS64 uses Load-Linked/Store-Conditional (LL/SC) for atomics, similar to ARM64's LDXR/STXR:

```asm
# Atomic ADD64 (FETCH variant)
DADDIU $t2, dst, offset       # Address computation
.Lretry:
LLD    $t0, 0($t2)            # Load-linked doubleword
DADDU  $t1, $t0, src          # Compute new value
SCD    $t1, 0($t2)            # Store-conditional
BEQZC  $t1, .Lretry           # Retry if SC failed (R6: no delay slot)
OR     src, $t0, $zero        # FETCH: return old value in src
```

| BPF Atomic | MIPS64 Op in Loop | 32-bit Variant |
|---|---|---|
| ADD | `DADDU $t1, $t0, src` | `ADDU` with `LL`/`SC` |
| OR | `OR $t1, $t0, src` | Same with `LL`/`SC` |
| AND | `AND $t1, $t0, src` | Same with `LL`/`SC` |
| XOR | `XOR $t1, $t0, src` | Same with `LL`/`SC` |
| XCHG | `OR $t1, src, $zero` | Direct exchange |
| CMPXCHG | Compare `$t0` with `$v0` (R0), conditional store | Compare with BPF R0 |

**CMPXCHG pattern:**
```asm
DADDIU $t2, dst, offset
.Lretry:
LLD    $t0, 0($t2)
BNEC   $t0, $v0, .Lfail      # Compare with BPF R0 ($v0)
OR     $t1, src, $zero        # New value = src
SCD    $t1, 0($t2)
BEQZC  $t1, .Lretry
.Lfail:
OR     $v0, $t0, $zero        # R0 = old value (always)
```

### 3.12 CALL Instructions

> **Cross-reference:** REQ-UBPF-ISA-CALL-001 (External Helper), REQ-UBPF-ISA-CALL-002 (Program-Local Function)

**External helper call:**
```asm
# BPF R1-R5 already in $a0-$a4 (zero-cost mapping)
# Load 6th parameter (context cookie) into $a5 ($9)
OR    $a5, $context_reg, $zero  # Cookie/context pointer
# Load function pointer
LD    $t0, helper_table_offset($gp_or_base)
JALR  $ra, $t0                  # Indirect call
# Return value already in $v0 = BPF R0
```

**Local function call:** See §7.

### 3.13 EXIT Instruction

> **Cross-reference:** REQ-UBPF-ISA-CALL-003 (EXIT)

```asm
# Return value already in $v0 (BPF R0)
# Branch to epilogue
BC    .Lexit
```

---

## 4. Function Prologue and Epilogue

### 4.1 BasicJitMode

**[PROPOSED]** Prologue:
```asm
# Save callee-saved registers
DADDIU $sp, $sp, -frame_size
SD     $ra, frame_size-8($sp)     # Save return address
SD     $fp, frame_size-16($sp)    # Save frame pointer
SD     $s0, frame_size-24($sp)    # BPF R6
SD     $s1, frame_size-32($sp)    # BPF R7
SD     $s2, frame_size-40($sp)    # BPF R8
SD     $s3, frame_size-48($sp)    # BPF R9
SD     $s4, frame_size-56($sp)    # BPF R10 (frame pointer)

# Setup BPF frame pointer (R10 = top of BPF stack)
DADDIU $s4, $sp, bpf_stack_offset

# Initialize BPF registers
# R1 ($a0) = mem, R2 ($a1) = mem_len — already in place from caller
```

**[PROPOSED]** Epilogue:
```asm
.Lexit:
# Restore callee-saved registers
LD     $s4, frame_size-56($sp)
LD     $s3, frame_size-48($sp)
LD     $s2, frame_size-40($sp)
LD     $s1, frame_size-32($sp)
LD     $s0, frame_size-24($sp)
LD     $fp, frame_size-16($sp)
LD     $ra, frame_size-8($sp)
DADDIU $sp, $sp, frame_size

# Return value in $v0 (BPF R0)
JR     $ra
```

### 4.2 ExtendedJitMode

Same as BasicJitMode, except:
- BPF stack is caller-provided via additional parameters (`$a2` = stack_start, `$a3` = stack_len)
- `$s4` (BPF R10) is set to `$a2 + $a3` (top of provided stack)
- No internal stack allocation for BPF stack space

---

## 5. Security Features

### 5.1 Constant Blinding

**[PROPOSED]** Same approach as ARM64 — XOR immediates with a CSPRNG-generated random value:

```asm
# Blinded immediate load (64-bit value V, random R)
# Emit: load (V XOR R), then XOR with R to recover V
LUI   $t0, %hi(R)
ORI   $t0, $t0, %lo(R)
# ... full 64-bit materialization of R ...
LUI   dst, %hi(V^R)
ORI   dst, dst, %lo(V^R)
# ... full 64-bit materialization of V^R ...
XOR   dst, dst, $t0           # dst = (V^R) ^ R = V
```

**[CHALLENGE: Instruction count]** Constant blinding doubles the instruction count for every immediate load (two full 64-bit materializations + XOR). On MIPS this is 6+6+1 = 13 instructions for a 64-bit blinded load, vs. 6 unblinded.

### 5.2 W⊕X Memory Management

Same framework as x86-64 and ARM64 — handled by `ubpf_jit.c`:
1. Allocate writable working buffer
2. Emit code into working buffer
3. Allocate executable buffer (`mmap` with `PROT_READ|PROT_WRITE`)
4. Copy code to executable buffer
5. `mprotect` to `PROT_READ|PROT_EXEC`

**[PROPOSED]** MIPS may require cache coherence operations (`synci` + `sync`) after `mprotect` to ensure the instruction cache sees the new code. This is platform-dependent.

---

## 6. Helper Function Dispatch

### 6.1 Static Table Dispatch

```asm
# Load helper function pointer from table
LD     $t0, helper_table_base    # Base of helper pointer array
DSLL   $t1, $zero, 3             # index * 8 (computed from imm field)
DADDIU $t1, $t1, (imm * 8)      # Offset into table
DADDU  $t0, $t0, $t1
LD     $t0, 0($t0)               # Load function pointer
# BPF R1-R5 already in $a0-$a4
OR     $a5, $context, $zero      # 6th param: context cookie
JALR   $ra, $t0                  # Call helper
# Result in $v0 = BPF R0
```

### 6.2 Dynamic Dispatcher

```asm
# Load dispatcher function pointer
LD     $t0, dispatcher_offset     # Load dispatcher pointer
# $a0-$a4 = BPF R1-R5 (already mapped)
OR     $a5, $zero, imm_index     # 6th param: helper index
OR     $a6, $context, $zero      # 7th param: context cookie
JALR   $ra, $t0                  # Call dispatcher
# Result in $v0 = BPF R0
```

---

## 7. Local Function Calls

> **Cross-reference:** REQ-UBPF-ISA-CALL-002 (Program-Local Function)

```asm
# Save callee-saved BPF registers (R6-R9)
SD     $s0, -8($s4)              # Save R6 at current frame
SD     $s1, -16($s4)             # Save R7
SD     $s2, -24($s4)             # Save R8
SD     $s3, -32($s4)             # Save R9

# Adjust BPF frame pointer
DADDIU $s4, $s4, -stack_usage    # R10 -= local function stack size

# Branch to local function
BAL    target_offset             # Branch-and-link (saves PC+4 in $ra)
```

**Return from local function (EXIT with call depth > 0):**
```asm
# Restore BPF frame pointer
DADDIU $s4, $s4, stack_usage

# Restore callee-saved BPF registers
LD     $s0, -8($s4)
LD     $s1, -16($s4)
LD     $s2, -24($s4)
LD     $s3, -32($s4)

# Return to caller (JR $ra from the BAL)
JR     $ra
```

---

## 8. MIPS64-Specific Constraints

### 8.1 Immediate Encoding

| Instruction Type | Immediate Width | Range | Example |
|---|---|---|---|
| I-type (DADDIU, ORI, etc.) | 16-bit signed | -32768 to +32767 | `DADDIU dst, src, imm` |
| I-type unsigned (ORI, ANDI, XORI) | 16-bit unsigned | 0 to 65535 | `ORI dst, src, imm` |
| LUI | 16-bit | Upper 16 bits | `LUI dst, imm` |
| Shift (DSLL, etc.) | 5-bit | 0 to 31 | `DSLL dst, src, sa` |

**Impact:** Most BPF immediates (32-bit signed) require 2-instruction LUI+ORI sequences. 64-bit immediates require up to 6 instructions. This is the largest code-size overhead vs. x86-64.

### 8.2 Load/Store Offset Ranges

Signed 16-bit: -32768 to +32767 bytes. BPF offsets are signed 16-bit, so they always fit in MIPS load/store offsets. **No out-of-range handling needed for BPF memory operations.**

### 8.3 Branch Range

| Branch Type | Offset Width | Range (instructions) | Range (bytes) |
|---|---|---|---|
| `BC` (unconditional compact) | 26-bit signed | ±33M instructions | ±128MB |
| `BEQC`/`BNEC` (conditional compact) | 16-bit signed | ±32K instructions | ±128KB |
| `BEQZC`/`BNEZC` (compare-zero compact) | 21-bit signed | ±1M instructions | ±4MB |

For programs exceeding 32K instructions, conditional branches may need trampoline sequences (see §3.10).

### 8.4 Delay Slots (R6 vs Pre-R6)

**MIPS64r6:** Compact branches (`BC`, `BEQC`, `BNEC`, etc.) have **NO delay slots**. This specification targets R6 exclusively.

**Pre-R6 MIPS:** Traditional branches (`BEQ`, `BNE`, `J`, etc.) have delay slots — the instruction after the branch is always executed. Supporting pre-R6 would require inserting NOP in every delay slot or scheduling useful instructions. **[DECISION NEEDED]:** Should pre-R6 support be a goal?

---

## 9. Patchable Targets and Fixups

**[PROPOSED]** Follow the same `jit_state` framework as x86-64 and ARM64:

1. **During code emission:** Record jump/call locations in `patchable_relative` arrays with placeholder offsets
2. **After emission:** Resolve each placeholder:
   - For `BC`: Compute `(target - source) >> 2`, encode in 26-bit field
   - For `BEQC`/`BNEC`: Compute offset, encode in 16-bit field; emit trampoline if out of range
   - For `BAL` (local calls): Compute `pc_locs[target_pc] - source`
3. **Data references:** Use `ADR`-equivalent (computed `LUI`+`ORI`+`DADDU`) to reach helper table and dispatcher pointer

**[CHALLENGE: No PC-relative data access]** MIPS lacks x86-64's RIP-relative addressing and ARM64's LDR literal. Data references (helper table, dispatcher pointer) must use absolute addresses or a base register. Options:
- Embed data at a known offset from code start, use a base register loaded in the prologue
- Use `BALC` (Branch and Link Compact) to get PC, then add offset

---

## 10. Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0.0 | 2026-04-01 | Proposed specification | Initial MIPS64r6 JIT backend specification — all mappings [PROPOSED], no implementation exists |
