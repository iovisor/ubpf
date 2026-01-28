# Constant Blinding Test

This test verifies the constant blinding feature in the uBPF JIT compiler.

## Test Description

The test performs comprehensive verification of constant blinding:

1. **API Toggle Test**: Verifies that the API toggle works correctly
2. **Randomness Verification**: Compiles the same program twice with blinding enabled and verifies that the generated JIT code is different each time (proving random blinding works)
3. **32-bit ALU Immediate Operations**: Tests all 32-bit immediate ALU operations (ADD, SUB, OR, AND, XOR, MOV, MUL, DIV, MOD) with and without blinding
4. **64-bit ALU Immediate Operations**: Tests all 64-bit immediate ALU operations (ADD64, SUB64, OR64, AND64, XOR64, MOV64, MUL64, DIV64, MOD64) with and without blinding
5. **Edge Cases**: Tests large immediates (max positive int32 values) to verify correct handling

## Expected Behavior

- Programs with and without blinding should produce identical execution results
- JIT compilation should succeed in both modes
- The API should correctly enable/disable blinding
- JIT code should differ between compilations when blinding is enabled (randomness)
- All immediate ALU operations should work correctly with blinding

## Coverage

This test covers all immediate ALU operations that use the blinding macros:
- 32-bit: ADD_IMM, SUB_IMM, OR_IMM, AND_IMM, XOR_IMM, MOV_IMM, MUL_IMM, DIV_IMM, MOD_IMM
- 64-bit: ADD64_IMM, SUB64_IMM, OR64_IMM, AND64_IMM, XOR64_IMM, MOV64_IMM, MUL64_IMM, DIV64_IMM, MOD64_IMM
