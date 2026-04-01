# uBPF JIT Backend Specification: BPF ISA → MIPS64r6

**Document Version:** 1.0.0
**Date:** 2026-04-01
**Status:** Draft — Forward-looking specification (no implementation yet)

---

## 1. Overview

This document specifies the proposed mapping from BPF ISA instructions to MIPS64 Release 6 (MIPS64r6) native instructions for a uBPF JIT backend. It follows the same structure as the existing x86-64 (`jit-x86-64.md`) and ARM64 (`jit-arm64.md`) backend specifications.

**Target ISA:** MIPS64 Release 6 (MIPS64r6), little-endian (mipsel64r6)

**ISA Reference:** MIPS64® Architecture for Programmers Volume II: The MIPS64® Instruction Set, Revision 6.06, December 15, 2016 (MIPS Open license).

**ABI:** n64 (64-bit pointers, 64-bit GPRs, 8 argument registers in `$a0`–`$a7`)

**Key MIPS64r6 advantages over pre-R6:**
- Compact branches (`BC`, `BEQC`, `BNEC`, etc.) — **no delay slots** (KNOWN: ISA ref, compact branch descriptions)
- Native `DDIV`/`DMOD`/`DDIVU`/`DMODU` — results in GPR directly, no HI/LO registers (KNOWN: ISA ref, "DDIV" page)
- `DMUL`/`DMUH` — 64-bit multiply with direct GPR result (KNOWN: ISA ref, "DMUL" page)

**Compilation model:** Single-pass code emission into a working buffer, followed by a fixup pass to resolve forward references (jumps, branches, data references). The buffer is then copied to a `PROT_READ|PROT_EXEC` mapping. This is the same pipeline used by the x86-64 and ARM64 backends (KNOWN: `jit-x86-64.md` §1, `jit-arm64.md` §1).

---

## 2. Register Mapping

### 2.1 BPF → MIPS64r6 Register Mapping

> **Cross-reference:** REQ-UBPF-ISA-REG-001 (Register File)

| BPF Register | MIPS64r6 Register | Name | Role | Notes |
|---|---|---|---|---|
| R0 (return) | `$v0` ($2) | Return value | Function return | Natural n64 return register |
| R1 (param 1) | `$a0` ($4) | Argument 0 | Context pointer | Zero-cost helper call marshaling |
| R2 (param 2) | `$a1` ($5) | Argument 1 | Context length | Zero-cost helper call marshaling |
| R3 (param 3) | `$a2` ($6) | Argument 2 | Helper param 3 | Zero-cost helper call marshaling |
| R4 (param 4) | `$a3` ($7) | Argument 3 | Helper param 4 | Zero-cost helper call marshaling |
| R5 (param 5) | `$a4` ($8) | Argument 4 | Helper param 5 | Zero-cost helper call marshaling |
| R6 (callee-saved) | `$s0` ($16) | Saved 0 | Callee-saved | Preserved across calls (n64 ABI) |
| R7 (callee-saved) | `$s1` ($17) | Saved 1 | Callee-saved | Preserved across calls (n64 ABI) |
| R8 (callee-saved) | `$s2` ($18) | Saved 2 | Callee-saved | Preserved across calls (n64 ABI) |
| R9 (callee-saved) | `$s3` ($19) | Saved 3 | Callee-saved | Preserved across calls (n64 ABI) |
| R10 (frame ptr) | `$s4` ($20) | Saved 4 | BPF frame pointer | Callee-saved; read-only in BPF |

`[DESIGN DECISION]` BPF R1–R5 are mapped to `$a0`–`$a4` (the first 5 of 8 n64 argument registers) so that external helper calls require no parameter shuffling — the same strategy used by the ARM64 backend (KNOWN: `jit-arm64.md` §2.1). BPF R0 maps to `$v0` (the natural return register in n64).

### 2.2 Scratch/Temporary Registers

| MIPS64r6 Register | Name | Usage |
|---|---|---|
| `$t4` ($12) | Temp 0 | Large immediate materialization, constant blinding XOR key |
| `$t5` ($13) | Temp 1 | Division scratch, atomic operation scratch |
| `$t6` ($14) | Temp 2 | Address computation for out-of-range offsets, atomic address |
| `$t7` ($15) | Temp 3 | Additional scratch for complex instruction sequences |
| `$s5` ($21) | Saved 5 | `[DESIGN DECISION]` Helper table base register (loaded in prologue) |
| `$s6` ($22) | Saved 6 | `[DESIGN DECISION]` Context/cookie pointer (preserved across helper calls) |

**Reserved registers (NOT used by JIT):**

| Register | Reason |
|---|---|
| `$zero` ($0) | Hardwired zero (KNOWN: ISA ref) |
| `$at` ($1) | Assembler temporary — reserved by convention |
| `$k0`–`$k1` ($26–$27) | Kernel reserved — must not be modified by user code |
| `$gp` ($28) | Global pointer — reserved for ABI use |
| `$ra` ($31) | Return address — used by JALR, saved/restored in prologue/epilogue |
| `$sp` ($29) | Stack pointer — managed by prologue/epilogue |
| `$fp` ($30) | Frame pointer — native frame pointer (saved/restored) |

### 2.3 Callee-Saved Registers (must preserve in prologue/epilogue)

Per n64 ABI: `$s0`–`$s7` ($16–$23), `$fp` ($30), `$ra` ($31).

The JIT uses `$s0`–`$s6` ($16–$22) and must save/restore them plus `$fp` and `$ra`.

---

## 3. Instruction Mapping

### 3.1 ALU64 Operations

> **Cross-reference:** REQ-UBPF-ISA-ALU-001 (Core ALU Operations)

All 64-bit ALU operations use MIPS64 doubleword instructions. These do NOT trap on overflow (using unsigned variants like `DADDU`/`DSUBU`).

| BPF Instruction | MIPS64r6 Instruction | Notes |
|---|---|---|
| `ADD64_REG dst, src` | `DADDU dst, dst, src` | No overflow trap (KNOWN: ISA ref, "DADDU") |
| `ADD64_IMM dst, imm` | `DADDIU dst, dst, imm` | 16-bit signed imm (KNOWN: ISA ref, "DADDIU"). For \|imm\| > 32767: materialize in `$t4`, then `DADDU` |
| `SUB64_REG dst, src` | `DSUBU dst, dst, src` | No overflow trap (KNOWN: ISA ref, "DSUBU") |
| `SUB64_IMM dst, imm` | `DADDIU dst, dst, -imm` | If -32768 ≤ -imm ≤ 32767; else materialize and `DSUBU` |
| `MUL64_REG dst, src` | `DMUL dst, dst, src` | R6 native (KNOWN: ISA ref, "DMUL"). Result in GPR, no HI/LO |
| `MUL64_IMM dst, imm` | Materialize imm → `$t4`; `DMUL dst, dst, $t4` | |
| `DIV64_REG dst, src` | See §3.3 | Division-by-zero check required |
| `MOD64_REG dst, src` | See §3.3 | |
| `OR64_REG dst, src` | `OR dst, dst, src` | (KNOWN: ISA ref, "OR") |
| `OR64_IMM dst, imm` | `ORI dst, dst, imm` | 16-bit unsigned imm (0–65535). Larger: materialize + `OR` |
| `AND64_REG dst, src` | `AND dst, dst, src` | (KNOWN: ISA ref, "AND") |
| `AND64_IMM dst, imm` | `ANDI dst, dst, imm` | 16-bit unsigned imm. Larger: materialize + `AND` |
| `XOR64_REG dst, src` | `XOR dst, dst, src` | (KNOWN: ISA ref, "XOR") |
| `XOR64_IMM dst, imm` | `XORI dst, dst, imm` | 16-bit unsigned imm. Larger: materialize + `XOR` |
| `LSH64_REG dst, src` | `DSLLV dst, dst, src` | Low 6 bits of src used as shift amount (KNOWN: ISA ref, "DSLLV") |
| `LSH64_IMM dst, imm` | `DSLL dst, dst, imm` (imm 0–31) or `DSLL32 dst, dst, imm-32` (imm 32–63) | (KNOWN: ISA ref, "DSLL", "DSLL32") |
| `RSH64_REG dst, src` | `DSRLV dst, dst, src` | Logical right shift (KNOWN: ISA ref, "DSRLV") |
| `RSH64_IMM dst, imm` | `DSRL dst, dst, imm` or `DSRL32 dst, dst, imm-32` | (KNOWN: ISA ref, "DSRL", "DSRL32") |
| `ARSH64_REG dst, src` | `DSRAV dst, dst, src` | Arithmetic right shift (KNOWN: ISA ref, "DSRAV") |
| `ARSH64_IMM dst, imm` | `DSRA dst, dst, imm` or `DSRA32 dst, dst, imm-32` | (KNOWN: ISA ref, "DSRA", "DSRA32") |
| `NEG64 dst` | `DSUBU dst, $zero, dst` | Negate via subtract from zero |
| `MOV64_REG dst, src` | `OR dst, src, $zero` | MIPS move idiom |
| `MOV64_IMM dst, imm` | See §3.9 (immediate materialization) | |

**Shift masking:** MIPS64 `DSLLV`/`DSRLV`/`DSRAV` use the low 6 bits (0–63) of the shift amount register (KNOWN: ISA ref, "DSLLV" — "The bit-shift amount is specified by the low-order 6 bits of GPR rs"). This matches BPF's 0x3F mask for 64-bit shifts.

### 3.2 ALU32 Operations

> **Cross-reference:** REQ-UBPF-ISA-ALU-002 (ALU32 Zero-Extension)

32-bit ALU operations use MIPS64 word-sized instructions (`ADDU`, `SUBU`, `MUL`, etc.).

**CRITICAL: 32-bit sign-extension vs. zero-extension**

The MIPS64 ISA states: *"the 32-bit result is sign-extended and placed into GPR rt"* (KNOWN: ISA ref, "ADDIU" Restrictions — "If GPR rs does not contain a sign-extended 32-bit value, the result of the operation is UNPREDICTABLE"). BPF requires 32-bit ALU results to be **zero-extended** to 64 bits.

`[DESIGN DECISION]` **Strategy: Use 64-bit operations with explicit 32-bit masking.** Rather than using 32-bit word instructions (`ADDU`/`ADDIU`) which require sign-extended inputs and produce sign-extended outputs (violating BPF's zero-extension contract), the JIT SHOULD use 64-bit doubleword instructions (`DADDU`/`DADDIU`) and then zero-extend the result. This avoids the UNPREDICTABLE behavior restriction entirely:

**ALU32 implementation pattern:**
```asm
# BPF: ADD32 dst, src
DADDU   dst, dst, src            # 64-bit add (always well-defined, no input restriction)
DSLL32  dst, dst, 0              # Zero-extend: shift left 32 (keeps low 32 in high position)
DSRL32  dst, dst, 0              # Shift right 32 (restores low 32, zeros upper 32)
```

This is 3 instructions per ALU32 op (vs. 3 using `ADDU` + zero-ext), but is always correct regardless of input register state. The shift pair is universally available on all MIPS64 implementations.

**Exception:** `SLLV`/`SRLV`/`SRAV` (32-bit shifts) are still used since they naturally operate on 32-bit values and produce sign-extended results which the subsequent zero-extension corrects.

| BPF Instruction | MIPS64r6 Sequence | Notes |
|---|---|---|
| `ADD32_REG dst, src` | `DADDU dst, dst, src` + zero-ext | 64-bit add avoids UNPREDICTABLE |
| `ADD32_IMM dst, imm` | `DADDIU dst, dst, imm` + zero-ext | 16-bit signed imm; larger: materialize in `$t4`, `DADDU` |
| `SUB32_REG dst, src` | `DSUBU dst, dst, src` + zero-ext | |
| `SUB32_IMM dst, imm` | `DADDIU dst, dst, -imm` + zero-ext | If fits; else materialize and `DSUBU` |
| `MUL32_REG dst, src` | `DMUL dst, dst, src` + zero-ext | 64-bit mul, zero-ext truncates to 32-bit result |
| `MUL32_IMM dst, imm` | Materialize imm → `$t4`; `DMUL dst, dst, $t4` + zero-ext | |
| `DIV32_REG dst, src` | See §3.3 (32-bit division) + zero-ext | |
| `MOD32_REG dst, src` | See §3.3 (32-bit modulo) + zero-ext | |
| `OR32_REG dst, src` | `OR dst, dst, src` + zero-ext | Bitwise ops are width-agnostic |
| `OR32_IMM dst, imm` | `ORI dst, dst, imm` + zero-ext | 16-bit unsigned; larger: materialize + `OR` |
| `AND32_REG dst, src` | `AND dst, dst, src` + zero-ext | |
| `AND32_IMM dst, imm` | `ANDI dst, dst, imm` + zero-ext | 16-bit unsigned; larger: materialize + `AND` |
| `XOR32_REG dst, src` | `XOR dst, dst, src` + zero-ext | |
| `XOR32_IMM dst, imm` | `XORI dst, dst, imm` + zero-ext | 16-bit unsigned; larger: materialize + `XOR` |
| `LSH32_REG dst, src` | `SLLV dst, dst, src` + zero-ext | Low 5 bits used (KNOWN: ISA ref, "SLLV") |
| `LSH32_IMM dst, imm` | `SLL dst, dst, imm` + zero-ext | 5-bit immediate (KNOWN: ISA ref, "SLL") |
| `RSH32_REG dst, src` | `SRLV dst, dst, src` + zero-ext | |
| `RSH32_IMM dst, imm` | `SRL dst, dst, imm` + zero-ext | |
| `ARSH32_REG dst, src` | `SRAV dst, dst, src` + zero-ext | |
| `ARSH32_IMM dst, imm` | `SRA dst, dst, imm` + zero-ext | |
| `NEG32 dst` | `SUBU dst, $zero, dst` + zero-ext | |
| `MOV32_REG dst, src` | `ADDU dst, src, $zero` + zero-ext | |
| `MOV32_IMM dst, imm` | Materialize imm → `dst` + zero-ext | |

**Shift masking (32-bit):** `SLLV`/`SRLV`/`SRAV` use the low 5 bits (0–31) of the shift amount (KNOWN: ISA ref), matching BPF's 0x1F mask.

### 3.3 Signed Arithmetic (SDIV, SMOD)

> **Cross-reference:** REQ-UBPF-ISA-DIV-001 through DIV-007

MIPS64r6 has native `DDIV`/`DMOD` (64-bit) and `DIV`/`MOD` (32-bit) that write results directly to a GPR (KNOWN: ISA ref, "DDIV", "DMOD", "DIV", "MOD"). No HI/LO register management needed (R6-specific improvement).

**Division-by-zero handling (required by BPF: dst = 0):**
```asm
# BPF: DIV64 dst, src (unsigned, offset==0)
BNEC   src, $zero, .Lnonzero  # R6 compact branch, no delay slot
OR     dst, $zero, $zero      # dst = 0 (div-by-zero result per RFC 9669)
BC     .Ldone                  # R6 compact unconditional branch
.Lnonzero:
DDIVU  dst, dst, src          # Unsigned 64-bit division (KNOWN: ISA ref, "DDIVU")
.Ldone:
```

**32-bit division-by-zero handling:**
```asm
# BPF: DIV32 dst, src (unsigned, offset==0)
BNEC   src, $zero, .Lnonzero
OR     dst, $zero, $zero      # dst = 0
BC     .Ldone
.Lnonzero:
DIVU   dst, dst, src          # Unsigned 32-bit division (KNOWN: ISA ref, "DIVU")
.Ldone:
# + zero-extension (DSLL32 + DSRL32)
```

**Modulo-by-zero handling (required by BPF: dst unchanged for 64-bit, upper 32 bits zeroed for 32-bit):**
```asm
# BPF: MOD64 dst, src (unsigned, offset==0)
BNEC   src, $zero, .Lnonzero
BC     .Ldone                  # dst unchanged (mod-by-zero per RFC 9669)
.Lnonzero:
DMODU  dst, dst, src          # Unsigned 64-bit modulo (KNOWN: ISA ref, "DMODU")
.Ldone:
```

**32-bit modulo-by-zero handling:**
```asm
# BPF: MOD32 dst, src (unsigned, offset==0)
# Per RFC 9669: for ALU (32-bit), mod-by-zero preserves low 32 bits but zeros upper 32 bits
BNEC   src, $zero, .Lnonzero
# dst unchanged but must zero-extend (upper 32 cleared per RFC 9669 ALU mod-by-zero)
BC     .Lzeroext
.Lnonzero:
MODU   dst, dst, src          # Unsigned 32-bit modulo (KNOWN: ISA ref, "MODU")
.Lzeroext:
# + zero-extension (DSLL32 + DSRL32)
```

**Signed variants (offset==1):** Use `DDIV`/`DMOD` (signed). MIPS64r6 `DDIV` uses truncated division semantics where `-13 / 3 == -4` and `DMOD` gives `-13 % 3 == -1` (KNOWN: ISA ref — MIPS division follows C99/truncated semantics), matching RFC 9669.

**INT_MIN / -1 handling:** `[DESIGN DECISION]` Emit an explicit check: if `src == -1` and `dst == INT64_MIN`, set `dst = INT64_MIN`. MIPS64r6 `DDIV` behavior for this case is implementation-defined per the ISA ref. The uBPF interpreter returns `INT64_MIN` for this case.

### 3.4 Sign-Extension MOV (MOVSX)

> **Cross-reference:** REQ-UBPF-ISA-ALU-006 (MOV with Sign-Extension)

| BPF Instruction | MIPS64r6 Instruction | Notes |
|---|---|---|
| `MOVSX dst, src, 8` | `SEB dst, src` | Sign-extend byte (KNOWN: ISA ref, "SEB" — R2+/R6) |
| `MOVSX dst, src, 16` | `SEH dst, src` | Sign-extend halfword (KNOWN: ISA ref, "SEH" — R2+/R6) |
| `MOVSX dst, src, 32` | `SLL dst, src, 0` | Sign-extend word. MIPS64 `SLL` sign-extends its 32-bit result to 64 bits (KNOWN: ISA ref, "SLL" — result is sign-extended) |

### 3.5 Byte Swap Operations

> **Cross-reference:** REQ-UBPF-ISA-SWAP-001 (Endianness Conversion), REQ-UBPF-ISA-SWAP-002 (Unconditional Byte Swap)

This spec targets little-endian MIPS64r6 (mipsel64r6).

| BPF Instruction | MIPS64r6 Sequence | Notes |
|---|---|---|
| `LE16 dst` | No-op (+ truncate: `ANDI dst, dst, 0xFFFF`) | Already little-endian |
| `LE32 dst` | No-op (+ zero-ext: `DSLL32`+`DSRL32`) | Already little-endian |
| `LE64 dst` | No-op | Already little-endian |
| `BE16 dst` | `WSBH dst, dst` then `ANDI dst, dst, 0xFFFF` | WSBH swaps bytes within halfwords (KNOWN: ISA ref, "WSBH") |
| `BE32 dst` | `WSBH dst, dst` then `ROTR dst, dst, 16` then zero-ext | ROTR rotates right (KNOWN: ISA ref, "ROTR") |
| `BE64 dst` | `DSBH dst, dst` then `DSHD dst, dst` | Full 64-bit byte reverse (KNOWN: ISA ref, "DSBH" + "DSHD" — "can be used to convert doubleword data of one endianness to another") |
| `BSWAP16 dst` | Same as BE16 | |
| `BSWAP32 dst` | Same as BE32 | |
| `BSWAP64 dst` | Same as BE64 | |

### 3.6 Memory Loads

> **Cross-reference:** REQ-UBPF-ISA-MEM-001 (Regular Load/Store)

| BPF Instruction | MIPS64r6 Instruction | Notes |
|---|---|---|
| `LDXB dst, [src+off]` | `LBU dst, off(src)` | Zero-extending byte load (KNOWN: ISA ref, "LBU") |
| `LDXH dst, [src+off]` | `LHU dst, off(src)` | Zero-extending halfword load (KNOWN: ISA ref, "LHU") |
| `LDXW dst, [src+off]` | `LWU dst, off(src)` | Zero-extending word load (KNOWN: ISA ref, "LWU") |
| `LDXDW dst, [src+off]` | `LD dst, off(src)` | Doubleword load (KNOWN: ISA ref, "LD") |

**Offset range:** Signed 16-bit (-32768 to +32767). BPF load/store offsets are also signed 16-bit, so all BPF memory operations fit natively — no out-of-range handling needed.

### 3.7 Sign-Extending Loads

> **Cross-reference:** REQ-UBPF-ISA-MEM-002 (Sign-Extension Loads)

| BPF Instruction | MIPS64r6 Instruction | Notes |
|---|---|---|
| `LDXSB dst, [src+off]` | `LB dst, off(src)` | Sign-extending byte load (KNOWN: ISA ref, "LB") |
| `LDXSH dst, [src+off]` | `LH dst, off(src)` | Sign-extending halfword load (KNOWN: ISA ref, "LH") |
| `LDXSW dst, [src+off]` | `LW dst, off(src)` | Sign-extending word load — MIPS64 `LW` sign-extends to 64 bits (KNOWN: ISA ref, "LW") |

### 3.8 Memory Stores

> **Cross-reference:** REQ-UBPF-ISA-MEM-001 (Regular Load/Store)

| BPF Instruction | MIPS64r6 Instruction | Notes |
|---|---|---|
| `STXB [dst+off], src` | `SB src, off(dst)` | Store byte (KNOWN: ISA ref, "SB") |
| `STXH [dst+off], src` | `SH src, off(dst)` | Store halfword (KNOWN: ISA ref, "SH") |
| `STXW [dst+off], src` | `SW src, off(dst)` | Store word (KNOWN: ISA ref, "SW") |
| `STXDW [dst+off], src` | `SD src, off(dst)` | Store doubleword (KNOWN: ISA ref, "SD") |
| `STB [dst+off], imm` | Materialize imm → `$t4`; `SB $t4, off(dst)` | No store-immediate on MIPS |
| `STH [dst+off], imm` | Materialize imm → `$t4`; `SH $t4, off(dst)` | |
| `STW [dst+off], imm` | Materialize imm → `$t4`; `SW $t4, off(dst)` | |
| `STDW [dst+off], imm` | Materialize imm → `$t4`; `SD $t4, off(dst)` | |

`[DESIGN DECISION]` MIPS has no store-immediate instruction (unlike x86-64's `mov [mem], imm`). All `ST_IMM` variants require materializing the immediate in a temporary register first. This adds 1–6 instructions per immediate store depending on the immediate size.

### 3.9 64-bit Immediate (LDDW)

> **Cross-reference:** REQ-UBPF-ISA-LDDW-001 (Basic 64-bit Immediate Load)

BPF LDDW combines two instruction slots into a 64-bit immediate `V = (next_imm << 32) | imm`.

**Full 64-bit materialization (worst case: 6 instructions):**
```asm
LUI    dst, V[63:48]          # Load bits 63–48 into upper half of lower 32
ORI    dst, dst, V[47:32]     # OR in bits 47–32
DSLL   dst, dst, 16           # Shift left 16
ORI    dst, dst, V[31:16]     # OR in bits 31–16
DSLL   dst, dst, 16           # Shift left 16
ORI    dst, dst, V[15:0]      # OR in bits 15–0
```

**Optimized shorter sequences:**
- Zero: `OR dst, $zero, $zero` (1 instruction)
- 16-bit unsigned (0–65535): `ORI dst, $zero, imm` (1 instruction)
- 16-bit signed (-32768 to 32767): `DADDIU dst, $zero, imm` (1 instruction)
- 32-bit: `LUI dst, upper16` + `ORI dst, dst, lower16` (2 instructions)
- 48-bit: `LUI` + `ORI` + `DSLL` + `ORI` (4 instructions)

### 3.10 Jump Instructions

> **Cross-reference:** REQ-UBPF-ISA-JMP-001 (Conditional Jumps), REQ-UBPF-ISA-JMP-002 (Unconditional JA)

MIPS64r6 compact branches have **no delay slots** (KNOWN: ISA ref — compact branches are a Release 6 feature).

| BPF Instruction | MIPS64r6 Instruction | Notes |
|---|---|---|
| `JA +offset` | `BC target` | 26-bit signed offset (KNOWN: ISA ref, "BC") |
| `JEQ dst, src` | `BEQC dst, src, target` | 16-bit offset (KNOWN: ISA ref, "BEQC") |
| `JNE dst, src` | `BNEC dst, src, target` | (KNOWN: ISA ref, "BNEC") |
| `JGT dst, src` | `BLTUC src, dst, target` | Unsigned dst > src ⟺ src < dst (KNOWN: ISA ref, "BLTUC") |
| `JGE dst, src` | `BGEUC dst, src, target` | (KNOWN: ISA ref, "BGEUC") |
| `JLT dst, src` | `BLTUC dst, src, target` | (KNOWN: ISA ref, "BLTUC") |
| `JLE dst, src` | `BGEUC src, dst, target` | Unsigned dst ≤ src ⟺ src ≥ dst |
| `JSGT dst, src` | `BLTC src, dst, target` | Signed (KNOWN: ISA ref, "BLTC") |
| `JSGE dst, src` | `BGEC dst, src, target` | (KNOWN: ISA ref, "BGEC") |
| `JSLT dst, src` | `BLTC dst, src, target` | |
| `JSLE dst, src` | `BGEC src, dst, target` | |
| `JSET dst, src` | `AND $t4, dst, src` then `BNEZC $t4, target` | 2-instruction sequence; BNEZC has 21-bit offset (KNOWN: ISA ref, "BNEZC") |
| `JEQ dst, imm` | Materialize imm → `$t4`; `BEQC dst, $t4, target` | |
| `JA32 +imm` | `BC target` | Use imm field for 32-bit offset range |

**JMP32 (32-bit comparisons):**

JMP32 instructions compare only the lower 32 bits of operands. On MIPS64, this requires zero-extending both operands to 32-bit before comparison, or using 32-bit compare instructions:

| BPF JMP32 Instruction | MIPS64r6 Sequence | Notes |
|---|---|---|
| `JEQ32 dst, src` | `SLL $t4, dst, 0; SLL $t5, src, 0; BEQC $t4, $t5, target` | Sign-extend to canonical 32-bit, then compare |
| `JNE32 dst, src` | `SLL $t4, dst, 0; SLL $t5, src, 0; BNEC $t4, $t5, target` | |
| `JGT32 dst, src` | `SLL $t4, dst, 0; SLL $t5, src, 0; BLTUC $t5, $t4, target` | Unsigned 32-bit compare |
| `JSGT32 dst, src` | `SLL $t4, dst, 0; SLL $t5, src, 0; BLTC $t5, $t4, target` | Signed 32-bit compare |
| `JSET32 dst, src` | `AND $t4, dst, src; SLL $t4, $t4, 0; BNEZC $t4, target` | Test low 32 bits |

`[DESIGN DECISION]` Using `SLL rd, rs, 0` to canonicalize 32-bit values before comparison. This ensures the comparison operands are proper sign-extended 32-bit values, which is required for MIPS64 compare instructions to behave correctly on 32-bit data.

**Branch ranges (KNOWN: ISA ref):**

| Branch Type | Offset Field | Range (instructions) | Range (bytes) |
|---|---|---|---|
| `BC` (unconditional) | 26-bit signed | ±33M | ±128MB |
| `BEQC`/`BNEC` (register compare) | 16-bit signed | ±32K | ±128KB |
| `BNEZC`/`BEQZC` (compare with zero) | 21-bit signed | ±1M | ±4MB |

**Branch trampoline for out-of-range conditional:**
```asm
BNEC   dst, src, .Lskip      # Inverted condition, short range
BC     far_target             # Long-range unconditional (26-bit)
.Lskip:
```

### 3.11 Atomic Operations

> **Cross-reference:** REQ-UBPF-ISA-ATOM-001 (Simple Atomics), REQ-UBPF-ISA-ATOM-002 (Complex Atomics)

MIPS64r6 uses Load-Linked/Store-Conditional (`LLD`/`SCD` for 64-bit, `LL`/`SC` for 32-bit) to implement atomic operations (KNOWN: ISA ref — "The LLD and SCD instructions provide primitives to implement atomic read-modify-write (RMW) operations").

**Atomic ADD64 pattern (with FETCH):**
```asm
DADDIU  $t6, dst, offset          # Compute address in $t6
.Lretry:
LLD     $t4, 0($t6)              # Load-linked doubleword (KNOWN: ISA ref, "LLD")
DADDU   $t5, $t4, src            # Compute new value
SCD     $t5, 0($t6)              # Store-conditional (KNOWN: ISA ref, "SCD")
BEQZC   $t5, .Lretry             # Retry if SC failed ($t5 == 0 on failure)
OR      src, $t4, $zero          # FETCH: return old value in src register
```

| BPF Atomic | Operation in LL/SC Loop | 32-bit: use `LL`/`SC` |
|---|---|---|
| ADD | `DADDU $t5, $t4, src` | `ADDU` |
| OR | `OR $t5, $t4, src` | Same |
| AND | `AND $t5, $t4, src` | Same |
| XOR | `XOR $t5, $t4, src` | Same |
| XCHG | `OR $t5, src, $zero` (direct exchange) | Same |
| CMPXCHG | Compare `$t4` with `$v0` (BPF R0); conditional store | Same |

**CMPXCHG pattern:**
```asm
DADDIU  $t6, dst, offset
.Lretry:
LLD     $t4, 0($t6)
BNEC    $t4, $v0, .Lfail         # Compare with BPF R0 ($v0)
OR      $t5, src, $zero          # New value = src
SCD     $t5, 0($t6)
BEQZC   $t5, .Lretry             # Retry if SC failed
.Lfail:
OR      $v0, $t4, $zero          # R0 = old value (always, per BPF spec)
```

**Non-FETCH simple atomics** (no return value): Same LL/SC loop but omit the final `OR src, $t4, $zero`.

### 3.12 CALL Instructions

> **Cross-reference:** REQ-UBPF-ISA-CALL-001 (External Helper), REQ-UBPF-ISA-CALL-002 (Program-Local Function)

**External helper call:**

`[DESIGN DECISION]` **$ra preservation:** `JALR` clobbers `$ra`. When executing inside a local function (call depth > 0), the return address from `BALC` (used for local calls, §7) would be lost. The JIT MUST save `$ra` to the native stack before every helper call and restore it afterwards:

```asm
# BPF R1-R5 already in $a0-$a4 (zero-cost mapping)
SD     $ra, ra_save_offset($sp)    # Save $ra (clobbered by JALR)
OR     $a5, $s6, $zero             # 6th param: context cookie ($s6 = preserved context register)
# Load function pointer from helper table via $s5 (base register)
DADDIU $t4, $zero, (index * 8)     # Offset = helper index * 8
DADDU  $t4, $s5, $t4               # $s5 = helper table base (loaded in prologue)
LD     $t4, 0($t4)                 # Load function pointer
JALR   $ra, $t4                    # Indirect call (saves return address in $ra)
LD     $ra, ra_save_offset($sp)    # Restore $ra
# Result in $v0 = BPF R0
```

**Dynamic dispatcher call:**
```asm
# Load dispatcher function pointer from data section via $s5
SD     $ra, ra_save_offset($sp)     # Save $ra (clobbered by JALR)
LD     $t4, dispatcher_offset($s5)
# $a0-$a4 = BPF R1-R5 (already mapped)
# 6th param: helper index — concrete instruction depends on index size:
#   If index fits in 16-bit unsigned: ORI $a5, $zero, index
#   If index needs 32-bit:            LUI $a5, index[31:16]; ORI $a5, $a5, index[15:0]
ORI    $a5, $zero, index            # (assuming index < 65536; else LUI+ORI)
OR     $a6, $s6, $zero             # 7th param: context cookie
JALR   $ra, $t4                    # Call dispatcher
LD     $ra, ra_save_offset($sp)    # Restore $ra
```

**Local function call:** See §7.

### 3.13 EXIT Instruction

> **Cross-reference:** REQ-UBPF-ISA-CALL-003 (EXIT)

```asm
# Return value already in $v0 (BPF R0)
BC     .Lexit                     # Branch to epilogue
```

---

## 4. Function Prologue and Epilogue

### 4.1 BasicJitMode

**Prologue:**
```asm
DADDIU  $sp, $sp, -frame_size     # Allocate stack frame (16-byte aligned)
SD      $ra, frame_size-8($sp)    # Save return address
SD      $fp, frame_size-16($sp)   # Save native frame pointer
OR      $fp, $sp, $zero           # Set $fp = $sp
SD      $s0, frame_size-24($sp)   # Save BPF R6
SD      $s1, frame_size-32($sp)   # Save BPF R7
SD      $s2, frame_size-40($sp)   # Save BPF R8
SD      $s3, frame_size-48($sp)   # Save BPF R9
SD      $s4, frame_size-56($sp)   # Save BPF R10
SD      $s5, frame_size-64($sp)   # Save helper table base
SD      $s6, frame_size-72($sp)   # Save context register

# Load helper table base into $s5
# [DESIGN DECISION]: Helper table pointer is embedded in the JIT data section.
# Use BALC to get PC, then add known offset to reach the data section.
BALC    .Lpc                       # $ra = PC + 4 (KNOWN: ISA ref, "BALC")
.Lpc:
# If data_offset fits in 16-bit signed (±32KB):
DADDIU  $s5, $ra, data_offset     # $s5 = address of helper table base
# If data_offset exceeds ±32KB (large JIT output):
#   LUI    $t4, data_offset[31:16]
#   ORI    $t4, $t4, data_offset[15:0]
#   DADDU  $s5, $ra, $t4

# Setup BPF frame pointer (R10 = top of BPF stack)
DADDIU  $s4, $sp, bpf_stack_offset
# Save context pointer for helper calls
# [DESIGN DECISION]: $s6 preserves the mem/context pointer across the
# entire BPF program execution, since BPF code may overwrite $a0 (BPF R1).
OR      $s6, $a0, $zero           # $s6 = context pointer (from caller's $a0)
# BPF R1 ($a0) = mem, R2 ($a1) = mem_len — already in place from caller
```

**Epilogue:**
```asm
.Lexit:
LD      $s6, frame_size-72($sp)
LD      $s5, frame_size-64($sp)
LD      $s4, frame_size-56($sp)
LD      $s3, frame_size-48($sp)
LD      $s2, frame_size-40($sp)
LD      $s1, frame_size-32($sp)
LD      $s0, frame_size-24($sp)
LD      $fp, frame_size-16($sp)
LD      $ra, frame_size-8($sp)
DADDIU  $sp, $sp, frame_size
JR      $ra                        # Return ($v0 holds BPF R0)
```

### 4.2 ExtendedJitMode

Same as BasicJitMode except:
- BPF stack is caller-provided: `$a2` = stack_start, `$a3` = stack_len
- `$s4` (BPF R10) = `$a2 + $a3` (top of provided stack, via `DADDU`)
- No BPF stack space allocated on the native stack

---

## 5. Security Features

### 5.1 Constant Blinding

Same XOR approach as x86-64 and ARM64 backends (KNOWN: `jit-x86-64.md` §5.1, `jit-arm64.md` §5.1):

```asm
# Blinded 64-bit immediate load: value V, random key R
# Step 1: Materialize (V XOR R) into dst (up to 6 instructions)
LUI    dst, (V^R)[63:48]
ORI    dst, dst, (V^R)[47:32]
DSLL   dst, dst, 16
ORI    dst, dst, (V^R)[31:16]
DSLL   dst, dst, 16
ORI    dst, dst, (V^R)[15:0]
# Step 2: Materialize R into $t4 (up to 6 instructions)
LUI    $t4, R[63:48]
ORI    $t4, $t4, R[47:32]
DSLL   $t4, $t4, 16
ORI    $t4, $t4, R[31:16]
DSLL   $t4, $t4, 16
ORI    $t4, $t4, R[15:0]
# Step 3: Recover V
XOR    dst, dst, $t4              # dst = (V^R) ^ R = V
```

**Cost:** Worst case 13 instructions per blinded 64-bit load (vs. ~3 on x86-64). Shorter sequences for smaller immediates.

**RNG:** Same `ubpf_generate_blinding_constant()` from `ubpf_jit_support.c` — platform-appropriate CSPRNG (KNOWN: `jit-x86-64.md` §5.1).

### 5.2 W⊕X Memory Management

Same framework from `ubpf_jit.c` as x86-64 and ARM64 (KNOWN: `jit-x86-64.md` §5.3):
1. Allocate writable working buffer
2. Emit code
3. Allocate executable buffer (`mmap` `PROT_READ|PROT_WRITE`)
4. Copy code
5. `mprotect` to `PROT_READ|PROT_EXEC`

**MIPS64r6-specific: Cache coherence** — After `mprotect`, the instruction cache may still contain stale data. The JIT MUST execute `SYNCI` (Synchronize Caches to Make Instruction Writes Effective) over the code region, followed by `SYNC` (KNOWN: ISA ref, "SYNCI" — "refer to the SYNCI instruction for cache coherence after code modification").

```asm
# Cache coherence after mprotect (executed by the JIT framework, not the JIT'd code)
# Loop SYNCI over every cache line in the code region
loop:
    SYNCI  0(addr)
    DADDIU addr, addr, cache_line_size
    BLTUC  addr, end, loop
SYNC                               # Ensure all SYNCI operations complete
```

`[DESIGN DECISION]` Cache line size detection: use `sysconf(_SC_LEVEL1_ICACHE_LINESIZE)` on Linux, or a conservative default (e.g., 32 bytes).

---

## 6. Helper Function Dispatch

### 6.1 Static Table Dispatch

See §3.12. Helper function pointers are stored in a table embedded in the JIT data section. The base address is loaded into `$s5` during the prologue.

### 6.2 Dynamic Dispatcher

See §3.12. The dispatcher function pointer is stored at a known offset from the helper table base.

### 6.3 Parameter Marshaling

| BPF Parameter | MIPS64r6 Register | n64 ABI Role | Cost |
|---|---|---|---|
| R1 (arg 1) | `$a0` ($4) | 1st argument | Zero (already mapped) |
| R2 (arg 2) | `$a1` ($5) | 2nd argument | Zero |
| R3 (arg 3) | `$a2` ($6) | 3rd argument | Zero |
| R4 (arg 4) | `$a3` ($7) | 4th argument | Zero |
| R5 (arg 5) | `$a4` ($8) | 5th argument | Zero |
| Context cookie | `$a5` ($9) | 6th argument | 1 instruction (`OR`) |
| Helper index (dispatcher) | `$a5`/`$a6` | 6th/7th argument | 1–2 instructions |

---

## 7. Local Function Calls

> **Cross-reference:** REQ-UBPF-ISA-CALL-002 (Program-Local Function)

```asm
# Save callee-saved BPF registers (R6-R9) to BPF stack
SD      $s0, -8($s4)             # Save BPF R6
SD      $s1, -16($s4)            # Save BPF R7
SD      $s2, -24($s4)            # Save BPF R8
SD      $s3, -32($s4)            # Save BPF R9
# Adjust BPF frame pointer
DADDIU  $s4, $s4, -stack_usage   # R10 -= local function stack size (16-byte aligned)
# Branch-and-link to local function
BALC    target_offset            # R6 compact branch-and-link (KNOWN: ISA ref, "BALC")
                                  # Saves return address in $ra
```

**Return from local function (EXIT with call depth > 0):**
```asm
DADDIU  $s4, $s4, stack_usage    # Restore BPF frame pointer
LD      $s0, -8($s4)             # Restore BPF R6
LD      $s1, -16($s4)            # Restore BPF R7
LD      $s2, -24($s4)            # Restore BPF R8
LD      $s3, -32($s4)            # Restore BPF R9
JR      $ra                      # Return to caller
```

---

## 8. MIPS64r6-Specific Constraints

### 8.1 Immediate Encoding

| Instruction Type | Width | Range | Impact |
|---|---|---|---|
| Arithmetic immediate (DADDIU) | 16-bit signed | -32768 to +32767 | BPF imm32 needs materialization for large values |
| Logical immediate (ORI, ANDI, XORI) | 16-bit unsigned | 0 to 65535 | |
| LUI | 16-bit | Sets bits [31:16] | Used with ORI for 32-bit constants |
| Shift amount (DSLL) | 5-bit | 0 to 31 | DSLL32 for shifts 32–63 |

**Impact:** Most BPF 32-bit immediates require 2-instruction `LUI`+`ORI` sequences. 64-bit values need up to 6 instructions. This is the largest code-size overhead vs. x86-64.

### 8.2 Load/Store Offset Ranges

Signed 16-bit: -32768 to +32767. BPF offsets are signed 16-bit, so all BPF memory operations fit natively. No out-of-range handling needed for `LDX*`/`STX*`.

### 8.3 Branch Range

See §3.10. Conditional compact branches are limited to ±32K instructions (±128KB). For programs exceeding this, branch trampolines are required.

### 8.4 Removed Instructions in R6

MIPS64r6 removes several pre-R6 instructions. This spec does NOT use any removed instructions:
- No `BEQL`/`BNEL` (branch-likely with delay slots) — using `BEQC`/`BNEC` instead
- No `MOVN`/`MOVZ` (conditional move) — removed in R6
- No HI/LO register access (`MFHI`/`MFLO`) — R6 uses direct GPR results for MUL/DIV
- No legacy branch instructions with delay slots — using compact branches exclusively

### 8.5 Cache Coherence

See §5.2. MIPS requires explicit `SYNCI` + `SYNC` after writing code to memory, as the instruction cache is not coherent with data writes on most MIPS implementations (KNOWN: ISA ref, "SYNCI").

---

## 9. Patchable Targets and Fixups

Same `jit_state` framework as x86-64 and ARM64 (KNOWN: `ubpf_jit_support.c`):

1. **During emission:** Record branch/call locations in `patchable_relative` arrays with placeholder offsets
2. **After emission:** Resolve each placeholder:
   - For `BC`: Compute `(target - source) / 4`, encode in 26-bit field
   - For `BEQC`/`BNEC`: Compute offset, encode in 16-bit field; emit trampoline if out of range
   - For `BALC` (local calls): Compute `(target - source) / 4`
3. **Data references:** Use `$s5` base register (loaded via `BALC` + offset in prologue) to reach helper table and dispatcher pointer. This avoids position-dependent absolute addresses.

`[DESIGN DECISION]` Using `BALC` (Branch and Link Compact) to capture PC for position-independent data access, since MIPS lacks x86-64's RIP-relative addressing and ARM64's `ADR`/`LDR literal`. This is a standard MIPS PIC technique.

---

## 10. Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0.0 | 2026-04-01 | Generated via JIT backend spec workflow | Initial MIPS64r6 specification. ISA details verified against MIPS64 Architecture for Programmers Vol II, Rev 6.06. |
