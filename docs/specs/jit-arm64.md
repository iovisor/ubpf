# uBPF JIT Backend Specification: BPF ISA → ARM64

**Document Version:** 1.0.0
**Date:** 2026-04-01
**Status:** Draft — Extracted from implementation source code
**Source:** `vm/ubpf_jit_arm64.c` (primary), with supporting files listed below

---

## 1. Overview

This document specifies the complete mapping from the BPF Instruction Set Architecture to ARM64 (AArch64) machine code as implemented by the uBPF JIT compiler backend. It is intended to serve as the authoritative reference for:

- Understanding the ARM64 JIT's code generation strategy
- Auditing correctness and security properties
- Serving as a template for future RISC-V and MIPS backends

**Source files consulted:**

| File | Purpose |
|------|---------|
| `vm/ubpf_jit_arm64.c` | ARM64 JIT backend — primary source for all mappings |
| `vm/ubpf_jit.c` | JIT compilation framework (mmap, mprotect, W⊕X) |
| `vm/ubpf_jit_support.c` | Shared JIT utilities (patchable targets, constant blinding RNG) |
| `vm/ubpf_jit_support.h` | Shared data structures (`jit_state`, `PatchableTarget`, etc.) |
| `vm/ebpf.h` | BPF opcode definitions and instruction format |
| `vm/ubpf_int.h` | VM internals (`ubpf_vm` struct, JIT result types) |
| `vm/inc/ubpf.h` | Public API (JitMode enum, `ubpf_compile`, constant blinding toggle) |

**AArch64 reference:** [ArmARM-A H.a] (DDI 0487/Ha) — cited in source header.

---

## 2. Register Mapping

### 2.1 BPF → ARM64 Register Mapping

The register map is defined at `ubpf_jit_arm64.c:107–119` in the `register_map[]` array. Translation is performed by `map_register()` at line 122.

| BPF Register | ARM64 Register | Role | Notes |
|:---:|:---:|---|---|
| R0 | x5 | Return value | Mapped to x5 during execution; moved to x0 in epilogue (line 629). AArch64 ABI uses x0 for return values and first parameter — using x5 avoids conflicts with helper calls. |
| R1 | x0 | Argument 1 / caller-saved | Natural ABI alignment: BPF R1–R5 map directly to AArch64 x0–x4 for zero-cost helper calls. |
| R2 | x1 | Argument 2 / caller-saved | |
| R3 | x2 | Argument 3 / caller-saved | |
| R4 | x3 | Argument 4 / caller-saved | |
| R5 | x4 | Argument 5 / caller-saved | |
| R6 | x19 | Callee-saved | AArch64 callee-saved register. Saved/restored in local calls (lines 735–744). |
| R7 | x20 | Callee-saved | |
| R8 | x21 | Callee-saved | |
| R9 | x22 | Callee-saved | |
| R10 | x23 | Frame pointer | Points to top of BPF stack. Callee-saved. |

> **Cross-reference:** REQ-UBPF-ISA-REG-001 (Register File) — all 11 BPF registers (R0–R10) are mapped.

### 2.2 Scratch/Temporary Registers

Defined at `ubpf_jit_arm64.c:84–90`:

| ARM64 Register | Variable Name | Purpose |
|:---:|---|---|
| x24 | `temp_register` | General-purpose scratch for loading 32/64-bit immediates into register form (line 84) |
| x25 | `temp_div_register` | Quotient in modulo calculations; also STXR status register in atomic ops (line 86) |
| x26 | `offset_register` | Large load/store offsets that exceed ±256 range (line 88) |
| x26 | `VOLATILE_CTXT` | Saves initial context pointer (x0 on entry) for helper dispatch (line 90). Aliases `offset_register`. |
| x8 | (inline) | Scratch for atomic ALU operation results — chosen because it is caller-saved and unmapped (line 870) |
| x29 | FP | Frame pointer — saved/restored as part of prologue/epilogue |
| x30 | LR | Link register — saved/restored for call/return sequences |

**Callee-saved registers** saved on function entry (`ubpf_jit_arm64.c:80`):

```
x19, x20, x21, x22, x23, x24, x25, x26
```

These are saved/restored as pairs via `STP`/`LDP` instructions in the prologue (line 597–600) and epilogue (line 637–640).

---

## 3. Instruction Mapping

### 3.1 ALU64 Operations

All ALU64 operations use 64-bit (X) register forms. The `sz()` function (line 172–176) sets bit 31 to 1 for 64-bit operations.

> **Cross-reference:** REQ-UBPF-ISA-ALU-001 (Core ALU Operations)

#### 3.1.1 ADD / SUB

**Source:** `ubpf_jit_arm64.c:1312–1323`

| BPF Instruction | ARM64 Emission | Condition |
|---|---|---|
| `ADD64_IMM` (simple, 0 ≤ imm < 0x1000) | `ADD Xd, Xd, #imm12` | `is_simple_imm()` returns true, blinding disabled |
| `ADD64_IMM` (complex or blinding) | `MOVZ/MOVK Xtemp, #imm` → `ADD Xd, Xd, Xtemp` | Immediate loaded into `temp_register` (x24), opcode converted to register form |
| `ADD64_REG` | `ADD Xd, Xd, Xm` | Direct register-register via `emit_addsub_register()` |
| `SUB64_IMM` | Same as ADD64_IMM but with `SUB` opcode | |
| `SUB64_REG` | `SUB Xd, Xd, Xm` | |

ARM64 encoding: `emit_addsub_immediate()` (line 179–211) supports shifted 12-bit immediates. For values ≥ 0x1000 that have lower 12 bits clear, the `sh` bit (bit 22) is set and the immediate is right-shifted by 12.

#### 3.1.2 MUL

**Source:** `ubpf_jit_arm64.c:1333–1336`

| BPF Instruction | ARM64 Emission |
|---|---|
| `MUL64_REG` | `MADD Xd, Xd, Xm, XZR` |
| `MUL64_IMM` | Load imm → `temp_register`, then `MADD Xd, Xd, Xtemp, XZR` |

`MADD` (multiply-add) with `Ra = XZR` computes `Rd = Rn × Rm + 0`. Encoding via `emit_dataprocessing_threesource()` (line 477–488), opcode `DP3_MADD = 0x1b000000`.

#### 3.1.3 DIV / MOD (Unsigned)

**Source:** `divmod()` function at `ubpf_jit_arm64.c:1697–1713`

> **Cross-reference:** REQ-UBPF-ISA-DIV-001 (Division by zero returns 0), REQ-UBPF-ISA-DIV-002 (Modulo by zero returns dividend)

| BPF Instruction | ARM64 Sequence |
|---|---|
| `DIV64_REG` | `UDIV Xd, Xn, Xm` |
| `MOD64_REG` | `UDIV Xtemp25, Xn, Xm` → `MSUB Xd, Xm, Xtemp25, Xn` |
| `DIV64_IMM` | Load imm → `temp_register`, then as register form |
| `MOD64_IMM` | Load imm → `temp_register`, then as register form |

**Modulo implementation:** `remainder = dividend - (divisor × quotient)`, computed via:
```asm
UDIV  x25, Xn, Xm        ; quotient in temp_div_register
MSUB  Xd, Xm, x25, Xn    ; Xd = Xn - (Xm * x25)
```

**Division by zero:** ARM64 `UDIV` natively returns 0 when dividing by zero (line 1706–1707 comment), so no explicit check is needed. For `MOD`, `MSUB` computes `Xn - (Xm × 0) = Xn`, returning the dividend as required by BPF semantics.

#### 3.1.4 OR / AND / XOR

**Source:** `ubpf_jit_arm64.c:1343–1350`

| BPF Instruction | ARM64 Instruction | Encoding |
|---|---|---|
| `OR64_REG` | `ORR Xd, Xd, Xm` | `LOG_ORR = 0x20000000` |
| `AND64_REG` | `AND Xd, Xd, Xm` | `LOG_AND = 0x00000000` |
| `XOR64_REG` | `EOR Xd, Xd, Xm` | `LOG_EOR = 0x40000000` |
| `OR64_IMM` / `AND64_IMM` / `XOR64_IMM` | Load imm → `temp_register`, then register form | `is_simple_imm()` always returns `false` for logical ops (line 997–1003) |

Note: ARM64 logical immediate encoding (bitmask immediates) is NOT used. All logical immediates are materialized into `temp_register` and the register form is used. This is a simplification that avoids the complex bitmask immediate encoding scheme.

#### 3.1.5 LSH / RSH / ARSH (Shifts)

**Source:** `ubpf_jit_arm64.c:1324–1332`

| BPF Instruction | ARM64 Instruction | Opcode Constant |
|---|---|---|
| `LSH64_REG` | `LSLV Xd, Xd, Xm` | `DP2_LSLV = 0x1ac02000` |
| `RSH64_REG` | `LSRV Xd, Xd, Xm` | `DP2_LSRV = 0x1ac02400` |
| `ARSH64_REG` | `ASRV Xd, Xd, Xm` | `DP2_ASRV = 0x1ac02800` |
| `LSH64_IMM` / `RSH64_IMM` / `ARSH64_IMM` | Load imm → `temp_register`, then register form | `is_simple_imm()` returns `false` for shifts (line 1004–1010) |

> **Cross-reference:** REQ-UBPF-ISA-ALU-005 (Shift masking) — ARM64 `LSLV`/`LSRV`/`ASRV` natively mask the shift amount to 6 bits (mod 64) for X registers and 5 bits (mod 32) for W registers.

#### 3.1.6 NEG

**Source:** `ubpf_jit_arm64.c:1351–1354`

```asm
SUB Xd, XZR, Xd          ; Negate: Xd = 0 - Xd
```

Emitted via `emit_addsub_register(state, sixty_four, AS_SUB, dst, RZ, dst)`.

> **Cross-reference:** REQ-UBPF-ISA-ALU-004 (NEG source operand — src_reg field is unused)

#### 3.1.7 MOV

**Source:** `ubpf_jit_arm64.c:1355–1382`

| BPF Instruction | ARM64 Emission |
|---|---|
| `MOV64_IMM` | `MOVZ Xd, #imm16` + `MOVK Xd, #imm16, LSL #N` (up to 4 instructions) |
| `MOV64_REG` (offset=0) | `ORR Xd, XZR, Xm` |

The `MOVZ`/`MOVK` sequence is generated by `emit_movewide_immediate()` (line 500–538). See §3.9 for the encoding algorithm.

### 3.2 ALU32 Operations

ALU32 operations use the same instruction patterns as ALU64 but with 32-bit (W) register forms. The `sz()` function returns 0 for 32-bit mode (bit 31 = 0), which selects W-register encoding in all ARM64 data processing instructions.

> **Cross-reference:** REQ-UBPF-ISA-ALU-002 (ALU32 zero-extension) — ARM64 natively zero-extends the upper 32 bits of the destination X register when writing to a W register. No additional instruction is needed.

**Source:** `is_alu64_op()` at line 958–963 returns `false` for `EBPF_CLS_ALU` (class 0x04), causing `sixty_four` to be `false` and all emitters to use W-register encodings.

Examples:
```asm
ADD  Wd, Wd, Wm           ; ADD_REG (32-bit)
SUB  Wd, WZR, Wd          ; NEG (32-bit)
MADD Wd, Wd, Wm, WZR      ; MUL_REG (32-bit)
UDIV Wd, Wn, Wm           ; DIV_REG (32-bit unsigned)
```

### 3.3 Signed Arithmetic (SDIV, SMOD)

**Source:** `divmod()` at `ubpf_jit_arm64.c:1697–1713`

> **Cross-reference:** REQ-UBPF-ISA-DIV-003 (Signed division), REQ-UBPF-ISA-DIV-004 (Truncated semantics), REQ-UBPF-ISA-DIV-005 (Overflow guard), REQ-UBPF-ISA-DIV-006 (Signed division by zero)

Signed operations are selected when `inst.offset == 1` (line 1702):

| BPF Instruction | ARM64 Sequence |
|---|---|
| SDIV64 (`offset=1`) | `SDIV Xd, Xn, Xm` |
| SMOD64 (`offset=1`) | `SDIV x25, Xn, Xm` → `MSUB Xd, Xm, x25, Xn` |
| SDIV (`offset=1`, 32-bit) | `SDIV Wd, Wn, Wm` |
| SMOD (`offset=1`, 32-bit) | `SDIV w25, Wn, Wm` → `MSUB Wd, Wm, w25, Wn` |

ARM64 `SDIV` provides truncated-toward-zero semantics natively, matching BPF requirements. `SDIV` also returns 0 for division by zero and handles the `INT_MIN / -1` overflow case by returning `INT_MIN` (AArch64 architecture guarantee), matching REQ-UBPF-ISA-DIV-005.

### 3.4 Sign-Extension MOV (MOVSX)

**Source:** `ubpf_jit_arm64.c:1361–1382` (within `EBPF_OP_MOV_REG` / `EBPF_OP_MOV64_REG` case)

> **Cross-reference:** REQ-UBPF-ISA-ALU-006 (MOV with sign-extension)

The `offset` field of the MOV instruction selects the sign-extension width:

| Offset | Operation | ARM64 Instruction | Encoding |
|:---:|---|---|---|
| 8 | SXTB (sign-extend byte) | `SBFM Xd, Xn, #0, #7` (64-bit) / `SBFM Wd, Wn, #0, #7` (32-bit) | `0x93401C00` / `0x13001C00` |
| 16 | SXTH (sign-extend halfword) | `SBFM Xd, Xn, #0, #15` (64-bit) / `SBFM Wd, Wn, #0, #15` (32-bit) | `0x93403C00` / `0x13003C00` |
| 32 | SXTW (sign-extend word) | `SBFM Xd, Wn, #0, #31` (64-bit only) | `0x93407C00` |
| 0 | Normal MOV | `ORR Xd, XZR, Xm` | Standard logical register |

The `SBFM` (Signed Bitfield Move) instruction performs sign-extension with the `immr=0` and `imms` set to the source width minus one.

### 3.5 Byte Swap Operations

**Source:** `ubpf_jit_arm64.c:1383–1419`

> **Cross-reference:** REQ-UBPF-ISA-SWAP-001 (Endianness conversion), REQ-UBPF-ISA-SWAP-002 (Byte swap conformance)

#### LE (Little-Endian, `EBPF_OP_LE`)

On a **little-endian host** (the common case for AArch64):

| imm | ARM64 Sequence | Notes |
|:---:|---|---|
| 16 | `UXTH Wd, Wd` | Zero-extend 16-bit. Encoding: `0x53003c00 \| (dst << 5) \| dst` |
| 32 | `UXTW Wd, Wd` | Zero-extend 32-bit. Encoding: `0x53007c00 \| (dst << 5) \| dst` |
| 64 | (no-op) | Already in correct order |

On a **big-endian host**, a `REV` instruction precedes the zero-extension.

#### BE (Big-Endian, `EBPF_OP_BE`)

On a **little-endian host**:

| imm | ARM64 Sequence | Notes |
|:---:|---|---|
| 16 | `REV16 Wd, Wd` → `UXTH Wd, Wd` | Byte-swap 16-bit, then zero-extend |
| 32 | `REV32 Wd, Wd` | Byte-swap 32-bit |
| 64 | `REV Xd, Xd` | Byte-swap 64-bit. Note: `DP1_REV64 = 0xdac00c00` |

#### BSWAP (`EBPF_OP_BSWAP`, ALU64 class)

**Source:** `ubpf_jit_arm64.c:1409–1419`

Unconditional byte-swap regardless of host endianness:

| imm | ARM64 Sequence |
|:---:|---|
| 16 | `REV16 Wd, Wd` → `UXTH Wd, Wd` |
| 32 | `REV32 Wd, Wd` → `UXTW Wd, Wd` |
| 64 | `REV Xd, Xd` |

The `REV` instruction variants are defined as `DP1Opcode` enum values (line 429–435):
- `DP1_REV16 = 0x5ac00400`
- `DP1_REV32 = 0x5ac00800`
- `DP1_REV64 = 0xdac00c00`

### 3.6 Memory Loads

**Source:** `ubpf_jit_arm64.c:1507–1536`, opcode mapping at `to_loadstore_opcode()` (line 1145–1179)

> **Cross-reference:** REQ-UBPF-ISA-MEM-001 (Regular load/store), REQ-UBPF-ISA-MEM-003 (DW operations)

| BPF Instruction | ARM64 Instruction | Opcode Constant |
|---|---|---|
| `LDXB` (load byte) | `LDRB Wt, [Xn, #offset]` | `LS_LDRB = 0x00400000` |
| `LDXH` (load halfword) | `LDRH Wt, [Xn, #offset]` | `LS_LDRH = 0x40400000` |
| `LDXW` (load word) | `LDR Wt, [Xn, #offset]` | `LS_LDRW = 0x80400000` |
| `LDXDW` (load doubleword) | `LDR Xt, [Xn, #offset]` | `LS_LDRX = 0xc0400000` |

**Addressing mode:** Unscaled immediate (`emit_loadstore_immediate()`, line 256–264). The `imm9` field supports offsets in the range **-256 ≤ offset < 256**.

**Large offset handling** (line 1514–1536): When `offset` is outside the ±256 range:

1. If `|offset| < 0x1000` (4096): compute address with `ADD`/`SUB` immediate:
   ```asm
   ADD  x25, Xsrc, #abs_offset    ; or SUB for negative
   LDR  Xdst, [x25, #0]
   ```
2. If `|offset| ≥ 0x1000`: materialize offset via `MOVZ`/`MOVK` into `offset_register` (x26):
   ```asm
   MOVZ x26, #abs_offset          ; (with MOVK if needed)
   ADD  x25, Xsrc, x26            ; or SUB for negative
   LDR  Xdst, [x25, #0]
   ```

The temporary register used for address computation is `temp_div_register` (x25) to avoid conflict with `temp_register` (x24) which may hold a blinded immediate.

### 3.7 Sign-Extending Loads

**Source:** `ubpf_jit_arm64.c:1511–1513`, opcode mapping at line 1157–1163

> **Cross-reference:** REQ-UBPF-ISA-MEM-002 (Sign-extension loads)

| BPF Instruction | ARM64 Instruction | Opcode Constant |
|---|---|---|
| `LDXBSX` (load byte, sign-extend) | `LDRSB Xt, [Xn, #offset]` | `LS_LDRSBX = 0x00800000` |
| `LDXHSX` (load halfword, sign-extend) | `LDRSH Xt, [Xn, #offset]` | `LS_LDRSHX = 0x40800000` |
| `LDXWSX` (load word, sign-extend) | `LDRSW Xt, [Xn, #offset]` | `LS_LDRSW = 0x80800000` |

These instructions sign-extend the loaded value to fill the full 64-bit destination register. The same offset range limitations and large-offset handling from §3.6 apply.

### 3.8 Memory Stores

**Source:** `ubpf_jit_arm64.c:1498–1536` (STX), `ubpf_jit_arm64.c:1618–1628` (ST)

#### Register stores (STX)

The STX instructions swap `dst` and `src` (line 1502–1505) because BPF uses `[dst+offset] = src` while the ARM64 encoding uses `STR Rt, [Rn, #offset]`:

| BPF Instruction | ARM64 Instruction | Opcode Constant |
|---|---|---|
| `STXB` | `STRB Wt, [Xn, #offset]` | `LS_STRB = 0x00000000` |
| `STXH` | `STRH Wt, [Xn, #offset]` | `LS_STRH = 0x40000000` |
| `STXW` | `STR Wt, [Xn, #offset]` | `LS_STRW = 0x80000000` |
| `STXDW` | `STR Xt, [Xn, #offset]` | `LS_STRX = 0xc0000000` |

Same offset range handling as loads (§3.6).

#### Immediate stores (ST)

ST instructions store an immediate value to memory. These are always converted to register form: the immediate is loaded into `temp_register` (x24) via `EMIT_MOVEWIDE_IMMEDIATE`, and then the register store form is used. This conversion happens in the main `is_imm_op()` / `to_reg_op()` path (line 1302–1309) where `EBPF_CLS_ST` is converted to `EBPF_CLS_STX`.

`is_simple_imm()` always returns `false` for ST instructions (line 1021–1025), so the immediate is always materialized.

### 3.9 64-bit Immediate (LDDW)

**Source:** `ubpf_jit_arm64.c:1611–1616`

> **Cross-reference:** REQ-UBPF-ISA-LDDW-001 (Basic 64-bit immediate load)

```c
struct ebpf_inst inst2 = ubpf_fetch_instruction(vm, ++i);
uint64_t imm = (uint32_t)inst.imm | ((uint64_t)inst2.imm << 32);
EMIT_MOVEWIDE_IMMEDIATE(vm, state, true, dst, imm);
```

The two 32-bit halves from the consecutive LDDW instruction pair are combined into a single 64-bit value, then emitted via the MOVZ/MOVK sequence.

#### MOVZ/MOVK Encoding Algorithm

**Source:** `emit_movewide_immediate()` at `ubpf_jit_arm64.c:500–538`

The algorithm optimizes for minimum instruction count:

1. **Count 0x0000 and 0xFFFF blocks:** For each 16-bit block of the immediate, count how many are all-zeros vs all-ones.
2. **Choose base instruction:** If more blocks are 0xFFFF, use `MOVN` (move NOT) as the base; otherwise use `MOVZ` (move zero).
3. **Emit base + MOVK sequence:** Skip blocks that match the base pattern (all-zeros for MOVZ, all-ones for MOVN). For remaining blocks, emit `MOVK` with the appropriate `hw` shift amount.
4. **Edge cases:** If the value is 0 or -1, a single `MOVZ`/`MOVN` instruction is emitted with `imm16=0`.

Opcode encodings (line 490–496):
- `MW_MOVN = 0x12800000`
- `MW_MOVZ = 0x52800000`
- `MW_MOVK = 0x72800000`

**Maximum instructions:** 4 for 64-bit values, 2 for 32-bit values.

### 3.10 Jump Instructions

**Source:** `ubpf_jit_arm64.c:1422–1476`

> **Cross-reference:** REQ-UBPF-ISA-JMP-001 (Conditional jumps), REQ-UBPF-ISA-JMP-002 (JA 16-bit), REQ-UBPF-ISA-JMP-003 (JA32 32-bit)

#### 3.10.1 Unconditional Jumps

| BPF Instruction | ARM64 Emission |
|---|---|
| `JA` (offset field) | `B target` — `UBR_B = 0x14000000`, 26-bit signed offset (±128 MB) |
| `JA32` (imm field) | `B target` — same encoding, target = `i + imm + 1` (line 1284–1286) |

#### 3.10.2 Conditional Jumps (64-bit comparison)

All conditional jumps follow a two-instruction pattern:

1. **Compare:** `SUBS XZR, Xdst, Xsrc` (register) or `SUBS XZR, Xdst, #imm12` (immediate)
2. **Branch:** `B.cond target`

| BPF Jump | ARM64 Condition | Condition Code | Source Mapping |
|---|---|:---:|---|
| `JEQ` | `B.EQ` | `COND_EQ = 0` | `to_condition()` line 1186–1187 |
| `JGT` (unsigned >) | `B.HI` | `COND_HI = 8` | line 1188–1189 |
| `JGE` (unsigned ≥) | `B.HS` | `COND_HS = COND_CS = 2` | line 1190–1191 |
| `JLT` (unsigned <) | `B.LO` | `COND_LO = COND_CC = 3` | line 1192–1193 |
| `JLE` (unsigned ≤) | `B.LS` | `COND_LS = 9` | line 1194–1195 |
| `JNE` | `B.NE` | `COND_NE = 1` | line 1198–1199 |
| `JSGT` (signed >) | `B.GT` | `COND_GT = 12` | line 1200–1201 |
| `JSGE` (signed ≥) | `B.GE` | `COND_GE = 10` | line 1202–1203 |
| `JSLT` (signed <) | `B.LT` | `COND_LT = 11` | line 1204–1205 |
| `JSLE` (signed ≤) | `B.LE` | `COND_LE = 13` | line 1206–1207 |

**JSET** (bitwise test): Uses `ANDS` instead of `SUBS`:

```asm
ANDS XZR, Xdst, Xsrc     ; TST (aliases ANDS with Rd=XZR)
B.NE target               ; Branch if any bit set
```

Source: `emit_logical_register(state, sixty_four, LOG_ANDS, RZ, dst, src)` at line 1474.

**Immediate comparison:** For "simple" immediates (0 ≤ imm < 0x1000, blinding disabled), the immediate is used directly in `SUBS`:
```asm
SUBS XZR, Xdst, #imm12
B.cond target
```

For complex immediates or when blinding is enabled, the immediate is first loaded into `temp_register`.

#### 3.10.3 JMP32 Conditional Jumps

JMP32 jumps use W-register comparisons. `is_alu64_op()` returns `false` for `EBPF_CLS_JMP32` (class 0x06), so `sixty_four = false` and all compare/branch instructions use W registers:

```asm
SUBS WZR, Wdst, Wsrc      ; 32-bit compare
B.cond target
```

The condition code mapping is identical to 64-bit jumps. The same opcodes in `to_condition()` handle both JMP and JMP32 via the shared `EBPF_JMP_OP_MASK`.

**Note:** `is_alu64_op()` (line 958–963) returns `true` for `EBPF_CLS_JMP` (class 0x05) but `false` for `EBPF_CLS_JMP32` (class 0x06). This is correct — JMP uses 64-bit register comparisons while JMP32 uses 32-bit.

#### 3.10.4 Branch Encoding

Conditional branches use `BR_Bcond = 0x54000000` (line 409) with a 19-bit signed offset field (±1 MB range). Unconditional branches use `UBR_B = 0x14000000` (line 362) with a 26-bit signed offset field (±128 MB range).

### 3.11 Atomic Operations

**Source:** `emit_atomic_operation()` at `ubpf_jit_arm64.c:752–909`, used by `EBPF_OP_ATOMIC_STORE` (line 1539–1573) and `EBPF_OP_ATOMIC32_STORE` (line 1575–1609)

> **Cross-reference:** REQ-UBPF-ISA-ATOM-001 (Simple atomics), REQ-UBPF-ISA-ATOM-002 (Fetch modifier), REQ-UBPF-ISA-ATOM-003 (XCHG/CMPXCHG)

All atomic operations use ARM64 Load-Exclusive / Store-Exclusive instructions (LDXR/STXR) in a compare-and-swap loop pattern.

#### 3.11.1 Register Allocation for Atomics

| Register | Role |
|---|---|
| `temp_register` (x24) | Holds loaded value from exclusive load |
| `temp_div_register` (x25) | STXR status register (0 = success) |
| `offset_register` (x26) or `temp_div_register` (x25) | Address computation temp (`addr_temp`, chosen to avoid aliasing with status register, line 771–772) |
| x8 | ALU operation result (line 870) |

#### 3.11.2 Exclusive Access Instructions

| ARM64 Instruction | Opcode Constant | Purpose |
|---|---|---|
| `LDXR Wt, [Xn]` | `LSE_LDXRW = 0x885f7c00` | 32-bit exclusive load |
| `STXR Ws, Wt, [Xn]` | `LSE_STXRW = 0x88007c00` | 32-bit exclusive store |
| `LDXR Xt, [Xn]` | `LSE_LDXRX = 0xc85f7c00` | 64-bit exclusive load |
| `STXR Ws, Xt, [Xn]` | `LSE_STXRX = 0xc8007c00` | 64-bit exclusive store |

#### 3.11.3 Atomic ADD/OR/AND/XOR Pattern

```asm
    ; Address computation (if offset != 0)
    ADD  x26, Xbase, #offset       ; or via MOVZ/ADD for large offsets (address in x26, avoiding x25)
retry:
    LDXR Xload, [x26]             ; Exclusive load (x24 = temp_register)
    ADD  x8, Xload, Xvalue        ; (or ORR/AND/EOR for OR/AND/XOR)
    STXR W25, x8, [x26]           ; Exclusive store (status in W25, address in x26)
    SUBS WZR, W25, #0             ; Check status
    B.NE retry                     ; Retry if exclusive monitor lost
    ; If FETCH: MOV result_reg, Xload  (copy old value)
```

Source: lines 864–908.

#### 3.11.4 XCHG Pattern

```asm
retry:
    LDXR Xload, [Xaddr]
    STXR Wstatus, Xvalue, [Xaddr]  ; Store new value directly
    SUBS WZR, Wstatus, #0
    B.NE retry
    MOV  result_reg, Xload          ; Return old value (always FETCH)
```

Source: lines 844–862. XCHG always has implicit fetch semantics (line 859).

#### 3.11.5 CMPXCHG Pattern

```asm
retry:
    LDXR  Xload, [Xaddr]           ; Load current value
    SUBS  XZR, Xload, Xexpected    ; Compare with expected (BPF R0)
    B.NE  skip_store                ; If not equal, don't store
    STXR  Wstatus, Xnew, [Xaddr]   ; Store new value
    SUBS  WZR, Wstatus, #0
    B.NE  retry                     ; Retry if exclusive failed
skip_store:
    MOV   result_reg, Xload         ; Always return loaded value in R0
```

Source: lines 811–842. For CMPXCHG, the expected value is in `map_register(0)` (BPF R0, ARM64 x5) and the result is written back to `map_register(0)`.

#### 3.11.6 32-bit vs 64-bit Atomics

Both `EBPF_OP_ATOMIC_STORE` (64-bit, line 1539) and `EBPF_OP_ATOMIC32_STORE` (32-bit, line 1575) dispatch to `emit_atomic_operation()` with `is_64bit` set to `true` or `false` respectively. The `is_64bit` parameter selects between `LDXRX`/`STXRX` and `LDXRW`/`STXRW`, and between X-register and W-register ALU operations.

### 3.12 CALL Instructions

**Source:** `ubpf_jit_arm64.c:1477–1492`

> **Cross-reference:** REQ-UBPF-ISA-CALL-001 (External helper), REQ-UBPF-ISA-CALL-002 (Local function call)

#### 3.12.1 External Helper Call (`src == 0`)

**Source:** `emit_dispatched_external_helper_call()` at `ubpf_jit_arm64.c:649–722`

The dispatch has two paths:

**Path 1 — External Dispatcher (priority):**
1. Load dispatcher address via PC-relative literal load: `LDR Xtemp, [PC + disp_offset]` (line 667)
2. Test if non-null: `SUBS x24, x24, #0` (line 670)
3. If non-null, branch to dispatcher setup (line 674)
4. Set up arguments: BPF R1–R5 already in x0–x4 (natural mapping), `idx` in x5, context in x6 (line 702–706)
5. Call: `BLR x24` (line 712)

**Path 2 — Static Helper Table:**
1. Compute table offset: `idx << 3` (multiply by 8 for pointer size) using `LSLV` (line 679)
2. Load helper table base via `ADR` instruction (line 683)
3. Add offset: `ADD x24, x24, x5` (line 684)
4. Load function pointer: `LDR x24, [x24, #0]` (line 685)
5. Set implicit 6th parameter (context): `ORR x5, XZR, x26` (line 688)
6. Call: `BLR x24` (line 712)

**Post-call:** If `map_register(0) != R0` (i.e., BPF R0 is not ARM64 x0), copy result: `ORR x5, XZR, x0` (line 717). Save/restore LR around the call (lines 661–662, 720–721).

**Unwind extension:** After calling the unwind helper (line 1481–1484), a check is emitted:
```asm
SUBS XZR, x5, #0          ; Test return value (BPF R0)
B.EQ exit                  ; Exit if zero
```

#### 3.12.2 Local Function Call (`src == 1`)

**Source:** `emit_local_call()` at `ubpf_jit_arm64.c:724–749`

```asm
; 1. Retrieve stack usage of current function and adjust BPF frame pointer
LDR  x24, [SP, #0]              ; Load current function's stack usage
SUB  x23, x23, x24              ; Adjust BPF frame pointer (R10) down

; 2. Save callee-saved state (48 bytes, aligned to 16)
SUB  SP, SP, #48
STR  x30, [SP, #0]              ; Save link register
STR  x24, [SP, #8]              ; Save stack usage value
STP  x19, x20, [SP, #16]        ; Save BPF R6, R7
STP  x21, x22, [SP, #32]        ; Save BPF R8, R9

; 3. Branch-and-link to target function
BL   target_pc                   ; UBR_BL = 0x94000000

; 4. Restore callee-saved state
LDR  x30, [SP, #0]
LDR  x24, [SP, #8]
LDP  x19, x20, [SP, #16]
LDP  x21, x22, [SP, #32]
ADD  SP, SP, #48

; 5. Restore BPF frame pointer
ADD  x23, x23, x24
```

The `BL` instruction's target is adjusted during resolution by subtracting `bpf_function_prolog_size` (line 1848) to account for the function prolog that each BPF function emits (stack usage push at lines 1260–1263).

### 3.13 EXIT Instruction

**Source:** `ubpf_jit_arm64.c:1493–1496`

```asm
ADD  SP, SP, #16           ; Pop local function's stack usage slot
RET                        ; Return to caller (BR_RET = 0xd65f0000 with x30)
```

This pops the 16-byte stack usage slot pushed in the function prolog (line 1261–1262) and returns via `RET` (which branches to the address in LR/x30).

For the outermost function, control returns to the prologue's `BL entry` call site, which then falls through to `B exit` (line 618), reaching the epilogue.

---

## 4. Function Prologue and Epilogue

### 4.1 BasicJitMode

**Source:** `emit_jit_prologue()` at `ubpf_jit_arm64.c:587–620`

**Prologue sequence:**
```asm
; 1. Save frame pointer and link register
SUB  SP, SP, #16
STP  x29, x30, [SP, #0]

; 2. Save callee-saved registers (x19-x26, 4 pairs = 64 bytes)
SUB  SP, SP, #64
STP  x19, x20, [SP, #0]
STP  x21, x22, [SP, #16]
STP  x23, x24, [SP, #32]
STP  x25, x26, [SP, #48]

; 3. Set up frame pointer
ADD  x29, SP, #0

; 4. Set up BPF frame pointer (R10 = x23) pointing to current SP
ADD  x23, SP, #0

; 5. Allocate BPF stack (UBPF_EBPF_STACK_SIZE = UBPF_MAX_CALL_DEPTH * 512)
SUB  SP, SP, #UBPF_EBPF_STACK_SIZE

; 6. Save context pointer (x0 on entry → VOLATILE_CTXT/x26)
ORR  x26, XZR, x0

; 7. Call entry point and branch to exit
BL   entry                      ; entry_loc set at line 619
B    exit                       ; Unconditional jump to epilogue
```

**Stack layout (BasicJitMode):**
```
High addresses
┌─────────────────────────┐
│  x29 (FP), x30 (LR)    │  ← Original SP - 16
├─────────────────────────┤
│  x19, x20               │
│  x21, x22               │
│  x23, x24               │
│  x25, x26               │  ← SP after callee-save = x29
├─────────────────────────┤
│  BPF Stack               │
│  (UBPF_EBPF_STACK_SIZE) │
│                          │  ← SP after stack allocation
└─────────────────────────┘
Low addresses
```

### 4.2 ExtendedJitMode

**Source:** `ubpf_jit_arm64.c:607–610`

In ExtendedJitMode, the BPF stack is provided by the caller via arguments. `ubpf_jit_ex_fn` takes 4 parameters: `(void* mem, size_t mem_len, uint8_t* stack, size_t stack_len)` arriving in ARM64 x0–x3 respectively.

```asm
; Instead of allocating stack from SP:
ADD  x23, x2, #0           ; R10 = stack base (x2 = 3rd ABI param = stack ptr)
ADD  x23, x23, x3          ; R10 += stack_length (x3 = 4th ABI param), points to top
```

The BPF frame pointer (R10/x23) is set to `stack + stack_len`, pointing to the top of the externally-provided stack, growing downward.

### 4.3 Epilogue

**Source:** `emit_jit_epilogue()` at `ubpf_jit_arm64.c:622–647`

```asm
; exit_loc target:
; 1. Copy BPF R0 to ARM64 return register
ORR  x0, XZR, x5            ; Move BPF R0 (x5) to ABI return register (x0)

; 2. Restore SP from frame pointer (handles any stack state)
ADD  SP, x29, #0

; 3. Restore callee-saved registers
LDP  x19, x20, [SP, #0]
LDP  x21, x22, [SP, #16]
LDP  x23, x24, [SP, #32]
LDP  x25, x26, [SP, #48]
ADD  SP, SP, #64

; 4. Restore frame pointer and link register
LDP  x29, x30, [SP, #0]
ADD  SP, SP, #16

; 5. Return
RET
```

### 4.4 Per-Function Prolog

**Source:** `ubpf_jit_arm64.c:1258–1268`

Each BPF function (including the entry function and all local functions) emits a prolog that pushes the function's stack usage:

```asm
MOVZ x24, #stack_usage         ; Stack usage for this function (not blinded)
SUB  SP, SP, #16
STP  x24, x24, [SP, #0]        ; Store twice for 16-byte alignment
```

This value is read during local calls to adjust the BPF frame pointer (line 727–728). The prolog size is constant across all functions (asserted at line 1267) and is subtracted when resolving local call branch offsets (line 1848).

---

## 5. Security Features

### 5.1 Constant Blinding

**Source:** `emit_movewide_immediate_blinded()` at `ubpf_jit_arm64.c:544–564`, macro at line 567–574

Constant blinding prevents JIT spray attacks by ensuring attacker-controlled immediate values never appear directly in the emitted machine code.

**Mechanism:**
```c
uint64_t random = ubpf_generate_blinding_constant();  // Crypto-secure RNG
uint64_t blinded = imm ^ random;
```

ARM64 emission:
```asm
MOVZ/MOVK  Rd, #blinded       ; Load XOR'd value
MOVZ/MOVK  Rscratch, #random  ; Load random key
EOR        Rd, Rd, Rscratch   ; Recover original: blinded ^ random = imm
```

**Scratch register selection** (line 554): To avoid clobbering live values, the scratch register is chosen opposite to `Rd`:
- If `Rd == temp_div_register` (x25), use `temp_register` (x24)
- Otherwise, use `temp_div_register` (x25)

**Random number generation:** `ubpf_generate_blinding_constant()` in `ubpf_jit_support.c:172–204` uses platform-specific crypto-secure RNG:
- Windows: `BCryptGenRandom`
- Linux: `getrandom()` syscall
- macOS: `arc4random_buf()`
- Fallback: `rand()` (not crypto-secure)

#### 5.1.1 Coverage Analysis

The `EMIT_MOVEWIDE_IMMEDIATE` macro gates on `vm->constant_blinding_enabled` (line 569) and is used for all attacker-controlled immediates:

**Blinded when enabled:**

| Context | Source Location | Notes |
|---|---|---|
| ALU/JMP immediate operands (converted to register form) | Line 1306 | Main path: all non-simple and all blinding-enabled immediates |
| MOV_IMM / MOV64_IMM | Line 1357 | Handled directly (not via `to_reg_op` conversion) |
| LDDW 64-bit immediate | Line 1614 | Full 64-bit value |
| Helper index in dispatcher | Lines 677, 702 | Index used to look up helper function |
| Large load/store offsets | Line 1531 | Offsets ≥ 0x1000 materialized via MOVZ/MOVK |
| Large atomic offsets | Line 790 | Offsets in atomic address computation |

**NOT blinded (internal constants, not attacker-controlled):**

| Context | Source Location | Reason |
|---|---|---|
| Constant `3` for shift in dispatcher | Line 678 | Internal JIT computation, not derived from BPF immediate |
| Constant `0` for ADR target init | Line 681 | Placeholder, not attacker-controlled |
| Stack usage value per local function | Line 1260 | Derived from static analysis, not from BPF instruction |
| Inline `ADD`/`SUB` immediates (simple path, blinding disabled) | Lines 1316, etc. | Only when blinding is disabled; when enabled, these are converted to register form too |

> **IMPORTANT — Documentation discrepancy (ARM64):** The public API header (`vm/inc/ubpf.h:160`) states _"ARM64: Not yet implemented — enabling on ARM64 will have no effect."_ This is **outdated**. The ARM64 JIT backend **does** implement constant blinding via the `EMIT_MOVEWIDE_IMMEDIATE` macro and `emit_movewide_immediate_blinded()` function. The coverage is comprehensive — all BPF-program-controlled immediates are blinded when the feature is enabled. A follow-up change should update `vm/inc/ubpf.h` to accurately reflect this; until then, this specification is authoritative for ARM64 constant blinding.

### 5.2 W⊕X Memory Management

**Source:** `ubpf_jit.c:103–167` (`ubpf_compile_ex()`)

The JIT compilation follows a strict Write XOR Execute flow:

1. **Allocate writable buffer:** `calloc(jitted_size, 1)` (line 136)
2. **Translate:** Generate ARM64 code into the writable buffer (line 141)
3. **Map executable memory:** `mmap(PROT_READ | PROT_WRITE)` (line 145)
4. **Copy:** `memcpy(jitted, buffer, jitted_size)` (line 151)
5. **Make executable:** `mprotect(jitted, jitted_size, PROT_READ | PROT_EXEC)` (line 153)
6. **Free writable buffer:** `free(buffer)` (line 162)

At no point is memory simultaneously writable and executable. This is identical across x86-64 and ARM64 backends — the W⊕X logic is in the shared `ubpf_jit.c` framework.

---

## 6. Helper Function Dispatch

**Source:** `emit_dispatched_external_helper_call()` at `ubpf_jit_arm64.c:649–722`

### 6.1 Dispatch Architecture

The ARM64 backend supports two dispatch mechanisms, checked at runtime in priority order:

1. **External Dispatcher** (dynamic): A function pointer stored in the JIT'd code's data section. If non-null, all helper calls are routed through it.
2. **Static Helper Table**: An array of `MAX_EXT_FUNCS` (64) function pointers embedded in the JIT'd code. Each slot corresponds to a helper index.

### 6.2 Parameter Marshaling

BPF uses R1–R5 for helper parameters. Due to the register mapping (§2.1), BPF R1–R5 map directly to ARM64 x0–x4:

| BPF Parameter | ARM64 Register | ABI Role |
|:---:|:---:|---|
| R1 | x0 | 1st argument |
| R2 | x1 | 2nd argument |
| R3 | x2 | 3rd argument |
| R4 | x3 | 4th argument |
| R5 | x4 | 5th argument |

This is a **natural mapping** — no parameter shuffling is needed for helper calls. The register map was designed specifically for this zero-cost call convention.

### 6.3 Additional Parameters

**For static helper table dispatch:**
- 6th parameter (context): `ORR x5, XZR, x26` — copies `VOLATILE_CTXT` to x5 (line 688)

**For external dispatcher:**
- 6th parameter (helper index): `MOVZ x5, #idx` (line 702) — with constant blinding if enabled
- 7th parameter (context): `ORR x6, XZR, x26` — copies `VOLATILE_CTXT` to x6 (line 706)

### 6.4 Return Value Handling

After `BLR`, the helper's return value is in ARM64 x0. Since BPF R0 maps to x5, the result must be copied:
```asm
ORR x5, XZR, x0              ; Copy return value to BPF R0 (line 717)
```

### 6.5 Data Section Layout

After the instruction stream, the JIT emits:

1. **Dispatcher address** (8 bytes, 4-byte aligned): `emit_dispatched_external_helper_address()` (line 911–928). Accessed via PC-relative `LDR` literal.
2. **Helper table** (64 × 8 = 512 bytes): `emit_helper_table()` (line 930–939). Accessed via `ADR` + offset.

---

## 7. Local Function Calls

**Source:** `emit_local_call()` at `ubpf_jit_arm64.c:724–749`

> **Cross-reference:** REQ-UBPF-ISA-CALL-002 (Program-local function call)

### 7.1 Call Protocol

1. **Read stack usage** of current function from the stack slot pushed by the per-function prolog (line 727)
2. **Adjust BPF frame pointer** (R10/x23) downward by the stack usage amount (line 728)
3. **Save callee-saved state** — 48 bytes (aligned to 16):
   - LR (x30)
   - Stack usage value (x24/temp)
   - BPF R6–R9 (x19–x22, saved as two `STP` pairs)
4. **Branch-and-link** to target: `BL target_pc` (line 739)
5. **Restore** all saved state in reverse order (lines 741–744)
6. **Restore BPF frame pointer**: `ADD x23, x23, x24` (line 748)

### 7.2 Callee-Saved Registers

Per BPF calling convention, R6–R9 are callee-saved. The local call wrapper saves:

| Saved Register | ARM64 | Stack Offset |
|---|:---:|:---:|
| LR | x30 | SP+0 |
| Stack usage | x24 | SP+8 |
| BPF R6 | x19 | SP+16 |
| BPF R7 | x20 | SP+24 |
| BPF R8 | x21 | SP+32 |
| BPF R9 | x22 | SP+40 |

### 7.3 Fallthrough Handling

When a BPF function boundary occurs in the middle of a linear instruction stream (i.e., the previous instruction has a fallthrough path), the JIT emits an unconditional branch around the per-function prolog:

```asm
B    skip_prolog           ; Jump over the new function's prolog (line 1253)
; --- per-function prolog ---
MOVZ x24, #stack_usage
SUB  SP, SP, #16
STP  x24, x24, [SP, #0]
skip_prolog:               ; Fallthrough resumes here (line 1271–1274)
```

Source: `ubpf_jit_arm64.c:1247–1274`

---

## 8. ARM64-Specific Constraints

### 8.1 Immediate Encoding

ARM64 has strict immediate encoding constraints that differ from x86-64's flexible immediate operands.

#### 8.1.1 Add/Subtract Immediates

`emit_addsub_immediate()` (line 179–211) supports:
- **Unshifted:** 12-bit unsigned immediate (0–4095)
- **Shifted:** 12-bit unsigned immediate left-shifted by 12 (values 0x1000–0xFFF000, where lower 12 bits must be zero)

Values outside this range cannot be encoded and must be materialized into a register.

#### 8.1.2 Logical Immediates

The ARM64 logical immediate encoding (bitmask immediates) is **not used** by the uBPF JIT. All logical immediates (OR, AND, XOR) are unconditionally materialized into `temp_register` via `MOVZ`/`MOVK` and the register form is used. This is a deliberate simplification — `is_simple_imm()` returns `false` for all logical immediate operations (line 997–1003).

#### 8.1.3 Move Wide Immediates

`MOVZ`/`MOVN`/`MOVK` each encode a 16-bit immediate with a 2-bit shift selector (`hw` field). A 64-bit value requires up to 4 instructions; a 32-bit value requires up to 2.

#### 8.1.4 Shift Immediates

Shift amounts (LSH/RSH/ARSH with immediate) are always converted to register form — `is_simple_imm()` returns `false` for shifts (line 1004–1010). The immediate is loaded into `temp_register` and the variable-shift instruction (`LSLV`/`LSRV`/`ASRV`) is used.

### 8.2 Load/Store Offset Ranges

`emit_loadstore_immediate()` (line 256–264) uses the **unscaled immediate** addressing mode:
- **Supported range:** -256 ≤ offset ≤ 255 (9-bit signed, `imm9`)
- **Assertion:** `assert(imm9 >= -256 && imm9 < 256)` (line 261)

For offsets outside this range (line 1514–1536):

| Offset Range | Strategy |
|---|---|
| -256 ≤ offset ≤ 255 | Direct unscaled immediate |
| 256 ≤ \|offset\| < 4096 | `ADD`/`SUB` immediate to compute address in `temp_div_register` (x25) |
| \|offset\| ≥ 4096 | `MOVZ`/`MOVK` of offset into `offset_register` (x26), then `ADD`/`SUB` register |

The computed address is stored in `temp_div_register` (x25), and the final load/store uses offset 0 from that register.

### 8.3 Branch Range

| Branch Type | Offset Field | Range |
|---|---|---|
| Conditional (`B.cond`) | 19-bit signed (×4) | ±1 MB |
| Unconditional (`B`) | 26-bit signed (×4) | ±128 MB |
| `BL` (branch and link) | 26-bit signed (×4) | ±128 MB |
| `BLR` (branch to register) | Register | Unlimited |

The JIT does not currently check for branch range overflow. For typical BPF programs (≤65536 instructions × ~16 bytes/instruction ≈ 1 MB), the 19-bit conditional branch range should be sufficient. Extremely large programs could theoretically exceed the ±1 MB conditional branch limit.

**Branch offset encoding:** All branch offsets are in units of 4 bytes (one ARM64 instruction). The `resolve_branch_immediate()` function (line 1716–1735) right-shifts the byte offset by 2 before encoding.

---

## 9. Patchable Targets and Fixups

**Source:** `ubpf_jit_arm64.c:1715–1852`, shared infrastructure in `ubpf_jit_support.h:44–117`

The ARM64 JIT uses a two-pass approach: instructions are emitted with placeholder offsets, then all offsets are resolved after code generation is complete.

### 9.1 Patchable Target Types

| Target Type | Storage | Resolution Function |
|---|---|---|
| Jump targets (conditional/unconditional) | `state->jumps[]` | `resolve_jumps()` (line 1758–1790) |
| PC-relative loads (dispatcher address) | `state->loads[]` | `resolve_loads()` (line 1792–1812) |
| PC-relative LEAs (helper table) | `state->leas[]` | `resolve_leas()` (line 1814–1834) |
| Local call targets | `state->local_calls[]` | `resolve_local_calls()` (line 1836–1852) |

### 9.2 Special Targets

Defined in `ubpf_jit_support.h:54–61`:

| Special Target | Used For | Resolved To |
|---|---|---|
| `Exit` | Epilogue jumps | `state->exit_loc` |
| `Enter` | Entry point call | `state->entry_loc` |
| `ExternalDispatcher` | Dispatcher address load | `state->dispatcher_loc` |
| `LoadHelperTable` | Helper table LEA | `state->helper_table_loc` |

### 9.3 Resolution Details

#### Jump Resolution (`resolve_jumps`, line 1758–1790)

Computes `rel = target_loc - source_offset`, then calls `resolve_branch_immediate()` (line 1716–1735) which:
1. Divides offset by 4 (all ARM64 instructions are 4-byte aligned)
2. Detects instruction type from opcode bits:
   - Conditional branch / compare-and-branch: encodes 19-bit offset in bits [23:5]
   - Unconditional branch: encodes 26-bit offset in bits [25:0]
3. ORs the offset into the existing instruction word

#### Load Literal Resolution (`resolve_loads`, line 1792–1812)

Computes `rel = (target_loc - source_offset) >> 2`, then writes the 19-bit offset into `LDR` literal instruction's `imm19` field via `resolve_load_literal()` (line 1737–1745).

#### ADR Resolution (`resolve_leas`, line 1814–1834)

Computes `rel = (target_loc - source_offset) >> 2`, then writes into the `ADR` instruction's immediate field via `resolve_adr()` (line 1748–1755). The encoding places bits [20:0] of the immediate into bits [28:5] of the instruction (`immhi` field).

#### Local Call Resolution (`resolve_local_calls`, line 1836–1852)

Computes `rel = pc_locs[target_pc] - source_offset - bpf_function_prolog_size`. The prolog size subtraction (line 1848) adjusts for the per-function prolog that the `BL` instruction should skip over — the local call wrapper already handles the prolog's stack setup before branching.

### 9.4 Post-Compilation Patching

The JIT supports updating the dispatcher and helper table in already-compiled code:

- `ubpf_jit_update_dispatcher_arm64()` (line 1854–1867): Writes a new dispatcher function pointer directly into the JIT'd code's data section at `external_dispatcher_offset`.
- `ubpf_jit_update_helper_arm64()` (line 1869–1887): Writes a new helper function pointer at `external_helper_offset + (8 × idx)`.

Both functions perform bounds checking against the JIT buffer size before writing.

---

## 10. Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0.0 | 2026-04-01 | Extracted from source | Initial extraction from `ubpf_jit_arm64.c` and supporting files. Covers register mapping, all instruction categories, prologue/epilogue, security features, dispatch, local calls, ARM64 constraints, and fixup infrastructure. |
